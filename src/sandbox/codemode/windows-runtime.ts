import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import {
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { CodemodeSandboxBase, type CodemodeSandboxBaseOptions } from "@earendil-works/pi-codemode";
import type { HostToWorkerMessage, VmStartData } from "@earendil-works/pi-codemode/portable";
import {
  CODEMODE_PROTOCOL_VERSION,
  RuntimeFrameDecoder,
  createRuntimeFrameSequence,
  type RuntimeFrameSequence,
} from "./protocol";
import { CODEMODE_RUNTIME_LIMITS } from "./limits";

type VmLauncher = ConstructorParameters<typeof CodemodeSandboxBase>[1];
type VmEvents = Parameters<VmLauncher>[1];
type VmChannel = Awaited<ReturnType<VmLauncher>>;

export interface WindowsCodemodeRuntimeLifecycle {
  transferRuntime(exited: Promise<void>): boolean;
}

const MAX_STDERR_BYTES = CODEMODE_RUNTIME_LIMITS.maxDiagnosticBytes;
const READY_TIMEOUT_MS = 15_000;
const STOP_GRACE_MS = 300;

function runtimeFile(path: string): string {
  try {
    const resolved = realpathSync.native(path);
    if (!statSync(resolved).isFile()) throw new Error("Codemode Runtime file is unavailable");
    return resolved;
  } catch {
    throw new Error("Codemode Runtime file is unavailable");
  }
}

function resolveRuntimeFiles() {
  const wasm = fileURLToPath(import.meta.resolve("quickjs-wasi/quickjs.wasm"));
  return {
    executable: runtimeFile(process.execPath),
    mxc: runtimeFile(fileURLToPath(new URL("../backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url))),
    bootstrapSource: readFileSync(
      runtimeFile(fileURLToPath(new URL("./runtime-worker.bundle.cjs", import.meta.url))),
      "utf8",
    ),
    workerSource: readFileSync(new URL("./worker.bundle.cjs", import.meta.url), "utf8"),
    wasmBase64: readFileSync(wasm).toString("base64"),
  };
}

function requestFor(input: {
  readonly mxc: string;
  readonly cwd: string;
  readonly executable: string;
  readonly bootstrapSource: string;
}): string {
  const filesystem = [
    { path: input.executable, access: "read", granularity: "file" },
    { path: input.mxc, access: "read", granularity: "file" },
    { path: input.cwd, access: "read", granularity: "directory" },
    { path: input.cwd, access: "write", granularity: "directory" },
  ];
  return JSON.stringify({
    runtimeProfile: "codemode",
    plan: {
      backend: { id: "windows-mxc" },
      cwd: input.cwd,
      filesystem,
      protectedPaths: [],
      network: { kind: "none" },
      environment: {},
    },
    argv: [input.executable, "-e", input.bootstrapSource],
  });
}

async function launchWindowsRuntime(
  data: VmStartData,
  events: VmEvents,
  lifecycle?: WindowsCodemodeRuntimeLifecycle,
): Promise<VmChannel> {
  if (process.platform !== "win32") return Promise.reject(new Error("Codemode restricted Runtime is unavailable on this platform"));
  const files = resolveRuntimeFiles();
  const cwd = realpathSync.native(mkdtempSync(join(tmpdir(), "pi-codemode-runtime-")));
  const generation = `${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const nativeRequest = requestFor({ ...files, cwd });
  if (Buffer.byteLength(nativeRequest, "utf8") > 24_000) {
    rmSync(cwd, { recursive: true, force: true });
    return Promise.reject(new Error("Codemode Runtime grant request exceeds the native limit"));
  }
  let nextMessageId = 1;
  let startSequence: RuntimeFrameSequence;
  try {
    startSequence = createRuntimeFrameSequence({
      version: CODEMODE_PROTOCOL_VERSION,
      generation,
      type: "start",
      data,
      workerSource: files.workerSource,
      wasmBase64: files.wasmBase64,
    }, generation, nextMessageId++);
  } catch (error) {
    rmSync(cwd, { recursive: true, force: true });
    return Promise.reject(error);
  }
  if (startSequence.byteLength > CODEMODE_RUNTIME_LIMITS.maxQueuedMessageBytes) {
    rmSync(cwd, { recursive: true, force: true });
    return Promise.reject(new Error(`Codemode Runtime IPC input queue exceeds ${CODEMODE_RUNTIME_LIMITS.maxQueuedMessageBytes / 1024 / 1024} MiB`));
  }

  let resolveExit!: () => void;
  const exited = new Promise<void>((resolve) => { resolveExit = resolve; });
  if (lifecycle && !lifecycle.transferRuntime(exited)) {
    rmSync(cwd, { recursive: true, force: true });
    return Promise.reject(new Error("Codemode execution finished before its Runtime started"));
  }
  let child: ChildProcessWithoutNullStreams;
  try {
    child = spawn(files.mxc, ["stdio"], {
      cwd,
      env: {
        SystemRoot: process.env.SystemRoot ?? "",
        SystemDrive: process.env.SystemDrive ?? process.env.SystemRoot?.slice(0, 2) ?? "",
        LOCALAPPDATA: process.env.LOCALAPPDATA ?? "",
        PI_MXC_REQUEST: nativeRequest,
      },
      stdio: "pipe",
      windowsHide: true,
    }) as ChildProcessWithoutNullStreams;
  } catch (error) {
    resolveExit();
    rmSync(cwd, { recursive: true, force: true });
    return Promise.reject(error);
  }
  let stderr = Buffer.alloc(0);
  const decoder = new RuntimeFrameDecoder(generation);
  let ready = false;
  let failed = false;
  let queuedInputBytes = 0;
  let inputQueue = Promise.resolve();
  let stopped = false;
  let runtimeStopped = false;
  let closed = false;
  let resolveReady!: () => void;
  let rejectReady!: (error: Error) => void;
  const readyResult = new Promise<void>((resolve, reject) => {
    resolveReady = resolve;
    rejectReady = reject;
  });
  const exitTimer = setTimeout(() => {
    if (!ready && !failed) fail(new Error(`Codemode Runtime did not become ready: ${stderr.toString("utf8")}`));
  }, READY_TIMEOUT_MS);
  const cleanup = () => {
    if (closed) return;
    closed = true;
    clearTimeout(exitTimer);
    rmSync(cwd, { recursive: true, force: true });
    resolveExit();
  };
  const fail = (error: Error) => {
    if (failed) return;
    failed = true;
    if (!ready) rejectReady(error);
    else events.failure({ kind: "sandbox", name: error.name, message: error.message, stack: error.stack });
    if (!child.killed && child.exitCode === null) child.kill();
  };
  const enqueue = (sequence: RuntimeFrameSequence) => {
    if (queuedInputBytes + sequence.byteLength > CODEMODE_RUNTIME_LIMITS.maxQueuedMessageBytes) {
      fail(new Error(`Codemode Runtime IPC input queue exceeds ${CODEMODE_RUNTIME_LIMITS.maxQueuedMessageBytes / 1024 / 1024} MiB`));
      return;
    }
    queuedInputBytes += sequence.byteLength;
    inputQueue = inputQueue.then(async () => {
      for (const frame of sequence.frames) {
        await new Promise<void>((resolve, reject) => {
          if (closed || child.stdin.destroyed) {
            reject(new Error("Codemode Runtime input pipe is closed"));
            return;
          }
          child.stdin.write(frame, (error?: Error | null) => error ? reject(error) : resolve());
        });
      }
    }).finally(() => { queuedInputBytes -= sequence.byteLength; });
    void inputQueue.catch(error => fail(error instanceof Error ? error : new Error(String(error))));
  };
  const send = (value: unknown) => {
    if (closed) return;
    try {
      enqueue(createRuntimeFrameSequence(value, generation, nextMessageId++));
    } catch (error) {
      fail(error instanceof Error ? error : new Error(String(error)));
    }
  };
  const consume = (chunk: Buffer) => {
    let frames;
    try {
      frames = decoder.push(chunk);
    } catch (error) {
      fail(error instanceof Error ? error : new Error(String(error)));
      return;
    }
    for (const envelope of frames) {
      if (envelope.type === "ready") {
        if (ready) { fail(new Error("Codemode Runtime sent duplicate readiness")); return; }
        ready = true;
        clearTimeout(exitTimer);
        resolveReady();
      } else if (envelope.type === "message") {
        if (!ready || stopped || envelope.message === undefined) {
          fail(new Error("Codemode Runtime sent a message in an invalid state"));
          return;
        }
        events.message(envelope.message);
      } else if (envelope.type === "failure") {
        const detail = envelope.error?.message ?? "Codemode Runtime worker failed";
        fail(new Error(detail));
      } else if (envelope.type === "stopped") {
        if (!stopped || runtimeStopped) {
          fail(new Error("Codemode Runtime sent stop confirmation in an invalid state"));
          return;
        }
        runtimeStopped = true;
      }
    }
  };

  child.stdout.on("data", (chunk: Buffer | string) => consume(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
  child.stdin.on("error", error => fail(error));
  child.stderr.on("data", (chunk: Buffer | string) => {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    stderr = Buffer.concat([stderr, bytes]).subarray(-MAX_STDERR_BYTES);
  });
  child.once("error", error => fail(error));
  child.once("close", (code, signal) => {
    try {
      decoder.finish();
    } catch (error) {
      if (!failed) fail(error instanceof Error ? error : new Error(String(error)));
    }
    const exitMessage = stopped
      ? `Codemode Runtime exited without confirming stop (${code ?? signal})`
      : `Codemode Runtime exited with ${code ?? signal}`;
    if (!ready && !failed) rejectReady(new Error(`Codemode Runtime exited before readiness (${code ?? signal}): ${stderr.toString("utf8")}`));
    const unexpectedExit = ready && !failed && (!stopped || !runtimeStopped);
    if (unexpectedExit) failed = true;
    cleanup();
    if (unexpectedExit) {
      const error = new Error(exitMessage);
      events.failure({ kind: "sandbox", name: error.name, message: error.message, stack: error.stack });
    }
  });

  enqueue(startSequence);

  return await readyResult.then(() => ({
    post(message: HostToWorkerMessage) {
      if (stopped || closed) return;
      send({ version: CODEMODE_PROTOCOL_VERSION, generation, type: "message", message });
    },
    async stop() {
      if (!stopped && !closed) {
        stopped = true;
        try {
          send({ version: CODEMODE_PROTOCOL_VERSION, generation, type: "stop" });
          await Promise.race([exited, new Promise<void>(resolve => setTimeout(resolve, STOP_GRACE_MS))]);
        } catch {
          // The hard process stop below owns cleanup when the pipe has failed.
        }
        if (!closed) child.kill();
      }
      await exited;
    },
  }));
}

export function createWindowsCodemodeSandbox(
  options: CodemodeSandboxBaseOptions = {},
  lifecycle?: WindowsCodemodeRuntimeLifecycle,
): CodemodeSandboxBase {
  if (process.platform !== "win32") throw new Error("Codemode restricted Runtime is unavailable on this platform");
  return new CodemodeSandboxBase(options, (data, events) => launchWindowsRuntime(data, events, lifecycle));
}

export const windowsCodemodeRuntimeLimits = CODEMODE_RUNTIME_LIMITS;
