import { CodemodeSandbox, loadQuickJSWasm } from "@earendil-works/pi-codemode";
import type {
  CodemodeExecuteOptions,
  CodemodeResult,
  CodemodeSandboxBaseOptions,
  CodemodeTool,
} from "@earendil-works/pi-codemode";
import { CODEMODE_RUNTIME_LIMITS } from "./limits";
import { createWindowsCodemodeSandbox } from "./windows-runtime";
import type { ResolvedRuntimeFiles } from "../runtime-store";
import type { SensitivePath } from "../sensitive-paths";

export type CodemodeRuntimeBackend = "restricted" | "full-access";

export interface CodemodeRuntimeRequest {
  readonly backend: CodemodeRuntimeBackend;
  readonly code: string;
  readonly timeoutMs?: number;
  readonly signal?: AbortSignal;
  readonly store?: Readonly<Record<string, unknown>>;
  readonly tools?: CodemodeTool[];
  readonly globals?: CodemodeTool[];
  readonly sensitivePaths?: readonly SensitivePath[];
}

export interface CodemodeRuntimeSession {
  execute(code: string, options?: CodemodeExecuteOptions): Promise<CodemodeResult>;
  close(): Promise<void>;
}

export interface CodemodeRuntimeFactoryInput {
  readonly backend: CodemodeRuntimeBackend;
  readonly sandboxOptions: Pick<CodemodeSandboxBaseOptions, "tools" | "globals" | "memoryLimitBytes">;
  readonly sensitivePaths?: readonly SensitivePath[];
  transferRuntime(exited: Promise<void>): boolean;
}

export type CodemodeRuntimeFactory = (
  input: CodemodeRuntimeFactoryInput,
) => CodemodeRuntimeSession | Promise<CodemodeRuntimeSession>;

export interface CodemodeRuntimeSupervisorOptions {
  readonly createRuntime: CodemodeRuntimeFactory;
  readonly maxActiveRuntimes?: number;
  readonly maxQueuedRuntimes?: number;
  readonly queueWaitMs?: number;
  readonly onCleanupFailure?: (error: unknown) => void;
}

interface RunRecord {
  readonly request: CodemodeRuntimeRequest;
  readonly resolve: (result: CodemodeResult) => void;
  readonly controller: AbortController;
  readonly deadline: number;
  readonly runtimeExits: Array<Promise<{ readonly ok: true } | { readonly ok: false; readonly error: unknown }>>;
  phase: "queued" | "starting" | "running" | "cleaning" | "finished";
  settled: boolean;
  timedOut: boolean;
  cancelledBeforeStart: boolean;
  deadlineTimer?: ReturnType<typeof setTimeout>;
  queueTimer?: ReturnType<typeof setTimeout>;
  removeAbortListener?: () => void;
}

function resultError(kind: "aborted" | "timeout" | "sandbox", message: string): CodemodeResult {
  return { ok: false, error: { kind, message }, output: [], calls: [] };
}

function resolveMaxActiveRuntimes(configured: number | undefined): number {
  if (configured !== undefined) {
    if (!Number.isInteger(configured) || configured < 1 || configured > CODEMODE_RUNTIME_LIMITS.maxConfiguredActiveRuntimes) {
      throw new RangeError(`maxActiveRuntimes must be an integer from 1 to ${CODEMODE_RUNTIME_LIMITS.maxConfiguredActiveRuntimes}`);
    }
    return configured;
  }
  const environmentValue = Number(process.env.PI_CODEMODE_MAX_WORKERS);
  return Number.isInteger(environmentValue) && environmentValue > 0
    ? Math.min(environmentValue, CODEMODE_RUNTIME_LIMITS.maxConfiguredActiveRuntimes)
    : CODEMODE_RUNTIME_LIMITS.defaultMaxActiveRuntimes;
}

function resolveMaxQueuedRuntimes(configured: number | undefined): number {
  const value = configured ?? CODEMODE_RUNTIME_LIMITS.maxQueuedRuntimes;
  if (!Number.isInteger(value) || value < 0 || value > CODEMODE_RUNTIME_LIMITS.maxQueuedRuntimes) {
    throw new RangeError(`maxQueuedRuntimes must be an integer from 0 to ${CODEMODE_RUNTIME_LIMITS.maxQueuedRuntimes}`);
  }
  return value;
}

function resolveQueueWaitMs(configured: number | undefined): number {
  const value = configured ?? CODEMODE_RUNTIME_LIMITS.runtimeQueueWaitMs;
  if (!Number.isInteger(value) || value < 0 || value > CODEMODE_RUNTIME_LIMITS.runtimeQueueWaitMs) {
    throw new RangeError(`queueWaitMs must be an integer from 0 to ${CODEMODE_RUNTIME_LIMITS.runtimeQueueWaitMs}`);
  }
  return value;
}

function stoppedResult(record: RunRecord): CodemodeResult {
  if (record.timedOut) {
    const timeoutMs = record.request.timeoutMs;
    return resultError(
      "timeout",
      timeoutMs === undefined || timeoutMs === Number.POSITIVE_INFINITY
        ? `Codemode Runtime queue wait timed out after ${CODEMODE_RUNTIME_LIMITS.runtimeQueueWaitMs} ms`
        : `Execution timed out after ${timeoutMs} ms`,
    );
  }
  const reason = record.request.signal?.reason;
  return resultError("aborted", reason instanceof Error ? reason.message : "Execution aborted");
}

function deferredExit() {
  let resolve!: () => void;
  const promise = new Promise<void>(resolvePromise => { resolve = resolvePromise; });
  let settled = false;
  return {
    promise,
    resolve() {
      if (settled) return;
      settled = true;
      resolve();
    },
  };
}

export class CodemodeRuntimeSupervisor {
  private readonly createRuntime: CodemodeRuntimeFactory;
  private readonly maxActiveRuntimes: number;
  private readonly maxQueuedRuntimes: number;
  private readonly queueWaitMs: number;
  private readonly onCleanupFailure: (error: unknown) => void;
  private readonly active = new Set<RunRecord>();
  private readonly queue: RunRecord[] = [];

  constructor(options: CodemodeRuntimeSupervisorOptions) {
    this.createRuntime = options.createRuntime;
    this.maxActiveRuntimes = resolveMaxActiveRuntimes(options.maxActiveRuntimes);
    this.maxQueuedRuntimes = resolveMaxQueuedRuntimes(options.maxQueuedRuntimes);
    this.queueWaitMs = resolveQueueWaitMs(options.queueWaitMs);
    this.onCleanupFailure = options.onCleanupFailure ?? (() => undefined);
  }

  get snapshot(): { readonly activeRuntimes: number; readonly queuedRuntimes: number } {
    return { activeRuntimes: this.active.size, queuedRuntimes: this.queue.length };
  }

  execute(request: CodemodeRuntimeRequest): Promise<CodemodeResult> {
    if (request.signal?.aborted) {
      return Promise.resolve(resultError(
        "aborted",
        request.signal.reason instanceof Error ? request.signal.reason.message : "Execution aborted",
      ));
    }
    const timeoutMs = request.timeoutMs ?? Number.POSITIVE_INFINITY;
    if (Number.isNaN(timeoutMs) || timeoutMs < 0 || timeoutMs > 2_147_483_647 && timeoutMs !== Number.POSITIVE_INFINITY) {
      return Promise.resolve(resultError("sandbox", "Codemode Runtime timeoutMs is invalid"));
    }
    if (timeoutMs === 0) return Promise.resolve(resultError("timeout", "Execution timed out after 0 ms"));

    const startedAt = performance.now();
    let resolveResult!: (value: CodemodeResult) => void;
    const result = new Promise<CodemodeResult>(resolve => { resolveResult = resolve; });
    const record: RunRecord = {
      request,
      resolve: resolveResult,
      controller: new AbortController(),
      deadline: Number.isFinite(timeoutMs) ? startedAt + timeoutMs : Number.POSITIVE_INFINITY,
      runtimeExits: [],
      phase: "queued",
      settled: false,
      timedOut: false,
      cancelledBeforeStart: false,
    };

    const onAbort = () => {
      record.controller.abort(request.signal?.reason);
      if (record.phase === "queued") {
        this.removeQueued(record);
        this.finish(record, stoppedResult(record));
      } else if (record.phase === "starting") {
        record.cancelledBeforeStart = true;
        this.finish(record, stoppedResult(record));
      }
    };
    if (request.signal) {
      request.signal.addEventListener("abort", onAbort, { once: true });
      record.removeAbortListener = () => request.signal?.removeEventListener("abort", onAbort);
    }

    if (Number.isFinite(timeoutMs)) {
      record.deadlineTimer = setTimeout(() => {
        record.timedOut = true;
        record.controller.abort(new Error(`Execution timed out after ${timeoutMs} ms`));
        if (record.phase === "queued") {
          this.removeQueued(record);
          this.finish(record, stoppedResult(record));
        } else if (record.phase === "starting") {
          record.cancelledBeforeStart = true;
          this.finish(record, stoppedResult(record));
        }
      }, timeoutMs);
    }

    if (this.active.size < this.maxActiveRuntimes) {
      this.start(record);
    } else if (this.queue.length >= this.maxQueuedRuntimes) {
      this.finish(record, resultError("sandbox", "Codemode Runtime queue is full"));
    } else {
      this.queue.push(record);
      const queueDeadline = Math.min(this.queueWaitMs, Math.max(0, record.deadline - performance.now()));
      record.queueTimer = setTimeout(() => {
        if (record.phase !== "queued") return;
        record.timedOut = true;
        this.removeQueued(record);
        this.finish(record, resultError(
          "timeout",
          `No Codemode Runtime became available within ${this.queueWaitMs} ms`,
        ));
      }, queueDeadline);
    }
    return result;
  }

  private start(record: RunRecord): void {
    record.phase = "starting";
    this.active.add(record);
    clearTimeout(record.queueTimer);
    void this.run(record);
  }

  private async run(record: RunRecord): Promise<void> {
    let session: CodemodeRuntimeSession | undefined;
    try {
      session = await this.createRuntime({
        backend: record.request.backend,
        ...(record.request.sensitivePaths === undefined ? {} : { sensitivePaths: record.request.sensitivePaths }),
        sandboxOptions: {
          tools: record.request.tools,
          globals: record.request.globals,
          memoryLimitBytes: CODEMODE_RUNTIME_LIMITS.quickJsMemoryBytes,
        },
        transferRuntime: exited => {
          if (record.phase !== "running" || record.settled || record.timedOut || record.cancelledBeforeStart) return false;
          record.runtimeExits.push(exited.then(
            () => ({ ok: true as const }),
            error => ({ ok: false as const, error }),
          ));
          return true;
        },
      });

      if (record.timedOut || record.cancelledBeforeStart) {
        this.finish(record, stoppedResult(record));
        return;
      }
      if (performance.now() >= record.deadline) {
        record.timedOut = true;
        this.finish(record, stoppedResult(record));
        return;
      }

      const remainingMs = Number.isFinite(record.deadline)
        ? Math.max(0, record.deadline - performance.now())
        : Number.POSITIVE_INFINITY;
      record.phase = "running";
      clearTimeout(record.deadlineTimer);
      const executionOptions: CodemodeExecuteOptions = {
        timeoutMs: remainingMs,
        signal: record.controller.signal,
        store: record.request.store,
      };
      const result = await session.execute(record.request.code, executionOptions);
      this.finish(record, result);
    } catch (error) {
      this.finish(record, resultError("sandbox", error instanceof Error ? error.message : String(error)));
    } finally {
      record.phase = "cleaning";
      clearTimeout(record.deadlineTimer);
      clearTimeout(record.queueTimer);
      record.removeAbortListener?.();
      try {
        await session?.close();
      } catch (error) {
        this.onCleanupFailure(error);
      }
      if (record.runtimeExits.length === 0) {
        this.release(record);
      } else {
        const exits = await Promise.all(record.runtimeExits);
        const failedExit = exits.find(exit => !exit.ok);
        if (failedExit && !failedExit.ok) {
          this.onCleanupFailure(failedExit.error);
          return;
        }
        this.release(record);
      }
    }
  }

  private finish(record: RunRecord, result: CodemodeResult): void {
    if (record.settled) return;
    record.settled = true;
    clearTimeout(record.deadlineTimer);
    clearTimeout(record.queueTimer);
    record.removeAbortListener?.();
    record.resolve(result);
  }

  private removeQueued(record: RunRecord): void {
    const index = this.queue.indexOf(record);
    if (index >= 0) this.queue.splice(index, 1);
  }

  private release(record: RunRecord): void {
    if (!this.active.delete(record)) return;
    record.phase = "finished";
    this.admitNext();
  }

  private admitNext(): void {
    while (this.queue.length > 0 && this.active.size < this.maxActiveRuntimes) {
      const record = this.queue.shift()!;
      if (record.phase !== "queued") continue;
      if (record.settled) continue;
      if (performance.now() >= record.deadline) {
        record.timedOut = true;
        this.finish(record, stoppedResult(record));
        continue;
      }
      this.start(record);
    }
  }
}

export function createPiCodemodeRuntimeFactory(runtime: () => ResolvedRuntimeFiles | undefined = () => undefined): CodemodeRuntimeFactory {
  return async input => {
    const options = {
      ...input.sandboxOptions,
      timeoutMs: Number.POSITIVE_INFINITY,
    };
    if (input.backend === "restricted") {
      const selected = runtime();
      if (!selected) throw new Error("sandbox-unavailable: restricted Codemode requires a ready OS runtime");
      return createWindowsCodemodeSandbox(options, { transferRuntime: input.transferRuntime }, selected, input.sensitivePaths);
    }

    const wasm = await loadQuickJSWasm();
    return new CodemodeSandbox({
      ...options,
      wasm,
      acquireWorker: () => {
        const exited = deferredExit();
        if (!input.transferRuntime(exited.promise)) throw new Error("Codemode execution finished before its worker started");
        return exited.resolve;
      },
    });
  };
}
