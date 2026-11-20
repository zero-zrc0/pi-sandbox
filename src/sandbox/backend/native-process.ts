import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { StringDecoder } from "node:string_decoder";
import {
  DEFAULT_CANCEL_GRACE_MS,
  MAX_EXECUTION_STDOUT_BYTES,
  MAX_FILE_CONTENT_BYTES,
  MAX_NATIVE_DIAGNOSTIC_BYTES,
  MAX_NATIVE_OUTPUT_CHUNK_BYTES,
  MAX_WORKER_MESSAGE_BYTES,
  type ExecutionStarted,
} from "../types";
import type { NativeCompletion, NativeCompletionInput, NativeLaunchPlan } from "./direct";

export interface NativeStartedEvent {
  readonly pid?: number;
  readonly startedAt: number;
}

export interface NativeOutputEvent {
  readonly stream: "stdout" | "stderr";
  readonly data: string;
}

export interface NativeProcessResult extends NativeCompletion {
  readonly started: ExecutionStarted;
  readonly signal: string | null;
  readonly cancelled: boolean;
  readonly diagnostics: string;
}

export interface NativeProcessOptions {
  readonly signal?: AbortSignal;
  readonly cancelGraceMs?: number;
  readonly onStarted?: (event: NativeStartedEvent) => void;
  readonly onOutput?: (event: NativeOutputEvent) => void;
}

function appendLimited(current: string, value: string, limit: number): string {
  if (!value || Buffer.byteLength(current, "utf8") >= limit) return current;
  const remaining = limit - Buffer.byteLength(current, "utf8");
  const bytes = Buffer.from(value, "utf8");
  return current + (bytes.length > remaining ? bytes.subarray(0, remaining).toString("utf8") : value);
}

function sendProcessTreeSignal(
  child: ChildProcessWithoutNullStreams,
  signal: NodeJS.Signals,
  force: boolean,
): Promise<void> {
  if (child.pid === undefined) return Promise.resolve();
  if (process.platform === "win32") {
    let treeKill = Promise.resolve();
    if (force) {
      treeKill = new Promise((resolve) => {
        try {
          const killer = spawn("taskkill", ["/PID", String(child.pid), "/T", "/F"], {
            stdio: "ignore",
            windowsHide: true,
            shell: false,
          });
          killer.on("close", () => resolve());
          killer.on("error", () => resolve());
        } catch {
          resolve();
        }
      });
    }
    try { child.kill(signal); } catch { /* The process tree has already exited. */ }
    return treeKill;
  }
  try {
    process.kill(-child.pid, signal);
  } catch {
    try { child.kill(signal); } catch { /* The process tree has already exited. */ }
  }
  return Promise.resolve();
}

function cancelProcessTree(
  child: ChildProcessWithoutNullStreams,
  graceMs: number,
): Promise<void> {
  if (process.platform === "win32") return sendProcessTreeSignal(child, "SIGTERM", true);
  void sendProcessTreeSignal(child, "SIGTERM", false);
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      void sendProcessTreeSignal(child, "SIGKILL", true).finally(resolve);
    }, Math.max(0, graceMs));
    timer.unref?.();
  });
}

function emitOutput(
  callback: NativeProcessOptions["onOutput"],
  stream: NativeOutputEvent["stream"],
  data: string,
): void {
  let part: string[] = [];
  let partBytes = 0;
  for (const character of data) {
    const characterBytes = Buffer.byteLength(character, "utf8");
    if (partBytes + characterBytes > MAX_NATIVE_OUTPUT_CHUNK_BYTES) {
      try { callback?.({ stream, data: part.join("") }); } catch { /* Output observers cannot interrupt cleanup. */ }
      part = [];
      partBytes = 0;
    }
    part.push(character);
    partBytes += characterBytes;
  }
  if (part.length > 0) {
    try { callback?.({ stream, data: part.join("") }); } catch { /* Output observers cannot interrupt cleanup. */ }
  }
}

function result(
  values: NativeCompletion & {
    readonly started: ExecutionStarted;
    readonly signal: string | null;
    readonly cancelled: boolean;
    readonly diagnostics: string;
  },
): NativeProcessResult {
  return values;
}

export function runNativeProcess(
  plan: NativeLaunchPlan,
  options: NativeProcessOptions = {},
): Promise<NativeProcessResult> {
  if (options.signal?.aborted) {
    return Promise.resolve(result({
      started: false,
      exitCode: null,
      signal: null,
      impact: "known",
      cancelled: true,
      diagnostics: "",
    }));
  }

  let child: ChildProcessWithoutNullStreams;
  try {
    child = spawn(plan.executable, [...plan.args], {
      cwd: plan.cwd,
      env: { ...plan.environment },
      stdio: ["pipe", "pipe", "pipe"],
      shell: false,
      windowsHide: true,
      detached: process.platform !== "win32",
    });
  } catch (error) {
    return Promise.resolve(result({
      started: false,
      exitCode: null,
      signal: null,
      impact: "known",
      errorCode: "setup",
      error: error instanceof Error ? error.message : String(error),
      cancelled: false,
      diagnostics: "",
    }));
  }

  return new Promise<NativeProcessResult>((resolve) => {
    const stdoutDecoder = new StringDecoder("utf8");
    const stderrDecoder = new StringDecoder("utf8");
    const readyMarker = plan.readyMarker === undefined ? undefined : Buffer.from(plan.readyMarker, "utf8");
    const cancelGraceMs = options.cancelGraceMs ?? DEFAULT_CANCEL_GRACE_MS;
    let startupBytes = Buffer.alloc(0);
    let output = Buffer.alloc(0);
    let workerText = "";
    let workerResult: Record<string, unknown> | undefined;
    let diagnostics = "";
    let started = false;
    let spawned = false;
    let cancelled = false;
    let outputTooLarge = false;
    let protocolFailure: string | undefined;
    let processTreeTermination: Promise<void> | undefined;
    let settled = false;

    const markStarted = (): void => {
      if (started) return;
      started = true;
      try { options.onStarted?.({ ...(child.pid === undefined ? {} : { pid: child.pid }), startedAt: Date.now() }); }
      catch { /* Start observers cannot interrupt execution. */ }
    };
    const terminate = (force: boolean): void => {
      processTreeTermination = sendProcessTreeSignal(child, force ? "SIGKILL" : "SIGTERM", force);
    };
    const abort = (): void => {
      cancelled = true;
      if (spawned) processTreeTermination ??= cancelProcessTree(child, cancelGraceMs);
    };
    const cleanup = (): void => {
      options.signal?.removeEventListener("abort", abort);
    };
    const finish = (value: NativeProcessResult): void => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(value);
    };
    const capture = (chunk: Buffer): void => {
      const limit = plan.outputLimitBytes ?? (plan.outputMode === "worker" ? MAX_EXECUTION_STDOUT_BYTES : MAX_FILE_CONTENT_BYTES);
      if (output.length + chunk.length > limit) {
        outputTooLarge = true;
        terminate(true);
        return;
      }
      output = Buffer.concat([output, chunk]);
    };
    const parseWorker = (chunk: Buffer): void => {
      workerText += stdoutDecoder.write(chunk);
      if (Buffer.byteLength(workerText, "utf8") > MAX_WORKER_MESSAGE_BYTES) {
        protocolFailure = "worker output exceeded the protocol limit";
        terminate(true);
        return;
      }
      for (;;) {
        const end = workerText.indexOf("\n");
        if (end < 0) return;
        const line = workerText.slice(0, end);
        workerText = workerText.slice(end + 1);
        try {
          const packet: unknown = JSON.parse(line);
          if (typeof packet !== "object" || packet === null || Array.isArray(packet)) throw new Error("invalid worker packet");
          const item = packet as Record<string, unknown>;
          if (item.type === "update" && workerResult === undefined && "result" in item) {
            emitOutput(options.onOutput, "stdout", `${JSON.stringify(item.result)}\n`);
          } else if (item.type === "result" && workerResult === undefined) {
            workerResult = item;
          } else {
            throw new Error("unexpected worker packet");
          }
        } catch {
          protocolFailure = "invalid worker result protocol";
          terminate(true);
          return;
        }
      }
    };
    const handleOutput = (chunk: Buffer): void => {
      if (plan.outputMode === "stream") emitOutput(options.onOutput, "stdout", stdoutDecoder.write(chunk));
      else if (plan.outputMode === "worker") parseWorker(chunk);
      else capture(chunk);
    };

    if (plan.input !== undefined) {
      child.stdin.on("error", () => {});
      child.stdin.end(plan.input, "utf8");
    } else {
      child.stdin.end();
    }
    child.stdout.on("data", (chunk: Buffer) => {
      if (!readyMarker || started) {
        handleOutput(chunk);
        return;
      }
      startupBytes = Buffer.concat([startupBytes, chunk]);
      const prefix = readyMarker.subarray(0, Math.min(startupBytes.length, readyMarker.length));
      if (startupBytes.length < readyMarker.length && prefix.equals(startupBytes)) return;
      if (!startupBytes.subarray(0, readyMarker.length).equals(readyMarker)) {
        diagnostics = appendLimited(diagnostics, "native sandbox readiness marker was missing or invalid", MAX_NATIVE_DIAGNOSTIC_BYTES);
        terminate(true);
        return;
      }
      const remainder = startupBytes.subarray(readyMarker.length);
      startupBytes = Buffer.alloc(0);
      markStarted();
      if (remainder.length) handleOutput(remainder);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      const data = stderrDecoder.write(chunk);
      if (plan.outputMode === "stream" && started) emitOutput(options.onOutput, "stderr", data);
      else diagnostics = appendLimited(diagnostics, data, MAX_NATIVE_DIAGNOSTIC_BYTES);
    });
    child.on("spawn", () => {
      spawned = true;
      if (!readyMarker) markStarted();
      if (options.signal?.aborted) abort();
    });
    child.on("error", (error) => {
      diagnostics = appendLimited(diagnostics, error.message, MAX_NATIVE_DIAGNOSTIC_BYTES);
    });
    child.on("close", async (code, signal) => {
      await processTreeTermination;
      const stdoutTail = plan.outputMode === "worker" || plan.outputMode === "stream" ? stdoutDecoder.end() : "";
      const stderrTail = stderrDecoder.end();
      if (plan.outputMode === "stream" && started && stdoutTail) emitOutput(options.onOutput, "stdout", stdoutTail);
      if (plan.outputMode === "stream" && started && stderrTail) emitOutput(options.onOutput, "stderr", stderrTail);
      if (plan.outputMode === "worker") workerText += stdoutTail;

      const startedState: ExecutionStarted = started ? true : cancelled && spawned ? "unknown" : false;
      if (cancelled) {
        finish(result({
          started: startedState,
          exitCode: code,
          signal,
          impact: startedState === false ? "known" : "unknown",
          cancelled: true,
          diagnostics,
        }));
        return;
      }
      if (!started) {
        finish(result({
          started: false,
          exitCode: code,
          signal,
          impact: "known",
          errorCode: "setup",
          error: diagnostics.trim() || `native sandbox exited before readiness (code=${String(code)})`,
          cancelled: false,
          diagnostics,
        }));
        return;
      }
      if (plan.outputMode === "worker" && (!workerResult || workerText.trim())) {
        protocolFailure ??= diagnostics || "worker exited without a complete result";
      }

      const completionInput: NativeCompletionInput = {
        exitCode: code,
        signal,
        stdout: output,
        stderr: diagnostics + stderrTail,
        ...(workerResult === undefined ? {} : { workerResult }),
      };
      let completion: NativeCompletion;
      if (outputTooLarge) {
        completion = {
          exitCode: 1,
          impact: "known",
          errorCode: plan.outputLimitError?.code ?? "unsupported",
          error: plan.outputLimitError?.reason ?? "native operation output exceeded its limit",
        };
      } else if (protocolFailure) {
        completion = { exitCode: null, impact: "unknown", errorCode: "protocol", error: protocolFailure };
      } else if (plan.complete) {
        try { completion = plan.complete(completionInput); }
        catch (error) {
          completion = { exitCode: null, impact: "unknown", errorCode: "protocol", error: error instanceof Error ? error.message : String(error) };
        }
      } else if (plan.outputMode === "worker" && workerResult) {
        const workerBytes = Buffer.from(JSON.stringify(workerResult));
        if (workerBytes.length > MAX_FILE_CONTENT_BYTES) {
          completion = { exitCode: 1, impact: "known", errorCode: "unsupported", error: "file content exceeds the native result limit" };
        } else {
          const failed = typeof workerResult.error === "string" ||
            (typeof workerResult.result === "object" && workerResult.result !== null &&
              (workerResult.result as { isError?: unknown }).isError === true);
          const workerError = typeof workerResult.error === "string" ? workerResult.error : "worker returned an error result";
          completion = {
            exitCode: failed ? 1 : code,
            impact: code === null || signal !== null ? "unknown" : "known",
            dataBase64: workerBytes.toString("base64"),
            ...(failed ? { errorCode: "tool", error: workerError } : {}),
          };
        }
      } else {
        completion = {
          exitCode: code,
          impact: code === null || signal !== null ? "unknown" : "known",
          ...(plan.outputMode === "capture" ? { dataBase64: output.toString("base64") } : {}),
        };
      }
      finish(result({
        ...completion,
        started: true,
        signal,
        cancelled: false,
        diagnostics,
      }));
    });

    options.signal?.addEventListener("abort", abort, { once: true });
    if (options.signal?.aborted) abort();
  });
}
