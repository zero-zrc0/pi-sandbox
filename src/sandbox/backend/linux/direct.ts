import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { selectBubblewrapCandidate } from "./bwrap-selection.mjs";
import { buildLaunchArgs, probeBubblewrap } from "./direct-launch.mjs";
import type { EgressGrantRef } from "../../lifecycle";
import type { DirectBackendDriver, DirectBackendProbe, DirectBackendUnavailable, NativeCompletionInput, NativeLaunchPlan } from "../direct";
import { captureRuntimeIdentity } from "../../runtime-identity";
import type { ResolvedRuntimeFiles } from "../../runtime-store";
import type { ExecutionOperation, ExecutionRequest } from "../../types";

const BACKEND_ID = "linux-bwrap-landlock-seccomp";
const BACKEND_VERSION = "1.1.0";
const READY_MARKER = "\x1ePI-LINUX-SANDBOX-READY\x1f";
const MAX_FILE_CONTENT_BYTES = 4 * 1024 * 1024;
const OPERATION_ERROR = /^PI-LINUX-OP-ERROR:(missing|denied|io|unsupported):(.+)$/mu;

interface LinuxBackendOptions {
  readonly runtime: ResolvedRuntimeFiles;
  readonly installRoot: string;
  readonly hostCwd: string;
  readonly hostEnvironment: Readonly<Record<string, string>>;
  readonly systemBubblewrapPath?: string;
}

interface NativeProbeResult {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly error?: string;
  readonly timedOut: boolean;
}

interface LinuxNativeCapabilities {
  readonly landlockAbi?: unknown;
  readonly seccomp?: unknown;
  readonly planVersion?: unknown;
}

function runNativeProbe(executable: string, options: LinuxBackendOptions, bwrapPath: string, signal?: AbortSignal): Promise<NativeProbeResult> {
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let errorText: string | undefined;
    let timedOut = false;
    let settled = false;
    let child;
    try {
      child = spawn(executable, ["probe"], {
        cwd: options.hostCwd,
        env: { ...options.hostEnvironment, PI_SANDBOX_BWRAP_PATH: bwrapPath },
        stdio: ["ignore", "pipe", "pipe"],
        shell: false,
      });
    } catch (error) {
      resolve({ code: null, stdout, stderr, error: error instanceof Error ? error.message : String(error), timedOut });
      return;
    }
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, 3_000);
    timer.unref?.();
    const abort = () => child.kill();
    signal?.addEventListener("abort", abort, { once: true });
    const finish = (code: number | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      resolve({ code, stdout, stderr, ...(errorText === undefined ? {} : { error: errorText }), timedOut });
    };
    child.stdout.on("data", chunk => { if (stdout.length < 16_384) stdout += chunk.toString("utf8"); });
    child.stderr.on("data", chunk => { if (stderr.length < 16_384) stderr += chunk.toString("utf8"); });
    child.on("error", error => { errorText = error.message; });
    child.on("close", code => finish(code));
  });
}

function operationCompletion(operation: ExecutionOperation, input: NativeCompletionInput) {
  const error = OPERATION_ERROR.exec(input.stderr);
  const signalError = input.signal === null ? undefined : `sandboxed process exited on ${input.signal}`;
  return {
    exitCode: error ? 1 : input.exitCode,
    impact: input.exitCode === null || input.signal !== null ? "unknown" as const : "known" as const,
    ...(error ? { errorCode: error[1]!, error: error[2]! } : {}),
    ...(signalError ? { errorCode: "signal", error: signalError } : {}),
    ...(operation.kind === "read-file" && !error && !signalError
      ? { dataBase64: input.stdout.toString("base64") }
      : {}),
  };
}

export function createLinuxDirectBackend(options: LinuxBackendOptions): DirectBackendDriver {
  const validateRuntime = captureRuntimeIdentity(options.runtime);
  const unavailable = (reason: string): DirectBackendUnavailable => ({ ok: false, code: "unavailable", reason });
  let probed: {
    readonly bubblewrapPath: string;
    readonly bubblewrapSha256: string;
    readonly capabilities: DirectBackendProbe["capabilities"];
  } | undefined;

  const selectBwrap = (): { readonly path: string; readonly version: string } | undefined => {
    const bundled = options.runtime.files.bubblewrap;
    const bundledVersion = options.runtime.manifest.components?.bubblewrapVersion;
    return selectBubblewrapCandidate(
      options.systemBubblewrapPath,
      bundled === undefined || bundledVersion === undefined ? undefined : {
        path: bundled,
        version: bundledVersion,
      },
      probeBubblewrap,
    );
  };

  return {
    id: BACKEND_ID,
    version: BACKEND_VERSION,
    async probe(signal?: AbortSignal): Promise<DirectBackendProbe | DirectBackendUnavailable> {
      if (signal?.aborted) return unavailable("runtime probe was cancelled");
      const runtimeReason = validateRuntime();
      if (runtimeReason) return unavailable(runtimeReason);
      const nativePath = options.runtime.files.linuxLauncher;
      const bridgePath = options.runtime.files.egressBridge;
      if (!nativePath || !bridgePath) return unavailable("Linux runtime files are incomplete");
      const selected = selectBwrap();
      if (!selected) return unavailable("no compatible system or bundled bubblewrap passed the required-option and user-namespace probes");
      const bubblewrapSha256 = createHash("sha256").update(readFileSync(selected.path)).digest("hex");
      const native = await runNativeProbe(nativePath, options, selected.path, signal);
      if (native.timedOut || native.error || native.code !== 0) {
        return unavailable(native.stderr.trim() || native.error || "Linux native capability probe failed");
      }
      let capabilities: LinuxNativeCapabilities;
      try { capabilities = JSON.parse(native.stdout) as LinuxNativeCapabilities; }
      catch { return unavailable("Linux native capability probe returned invalid data"); }
      const supported = capabilities.planVersion === 3 && typeof capabilities.landlockAbi === "number" &&
        capabilities.landlockAbi >= 3 && capabilities.seccomp === true;
      if (!supported) {
        return unavailable(`required bwrap, Landlock ABI 3, or seccomp capability is unavailable`);
      }
      let bridgeReady = false;
      try {
        const info = statSync(bridgePath);
        bridgeReady = info.isFile() && (info.mode & 0o111) !== 0;
      } catch {}
      const result: DirectBackendProbe = {
        ok: true,
        capabilities: {
          filesystem: {
            read: true,
            write: true,
            granularity: "file",
            protectedPaths: true,
            environment: true,
            metadataRead: "none",
          },
          network: bridgeReady ? "domains" : "all",
          cancel: true,
          streamOutput: true,
          startedNotification: true,
          processTree: true,
        },
      };
      probed = { bubblewrapPath: selected.path, bubblewrapSha256, capabilities: result.capabilities };
      return result;
    },
    async prepare(request: ExecutionRequest, egress?: EgressGrantRef): Promise<NativeLaunchPlan | DirectBackendUnavailable> {
      const runtimeReason = validateRuntime();
      if (runtimeReason) return { ok: false, code: "setup", reason: runtimeReason };
      const nativePath = options.runtime.files.linuxLauncher;
      const selected = probed ?? (() => {
        const candidate = selectBwrap();
        if (!candidate) return undefined;
        return {
          bubblewrapPath: candidate.path,
          bubblewrapSha256: createHash("sha256").update(readFileSync(candidate.path)).digest("hex"),
          capabilities: undefined,
        };
      })();
      if (!nativePath || !selected) return { ok: false, code: "setup", reason: "Linux runtime files are incomplete" };
      try {
        if (createHash("sha256").update(readFileSync(selected.bubblewrapPath)).digest("hex") !== selected.bubblewrapSha256) {
          return { ok: false, code: "setup", reason: "selected bubblewrap is unavailable or changed" };
        }
        const launch = buildLaunchArgs(request.plan, request.start, request.toolCallId, egress,
          { installRoot: options.installRoot });
        const operation = request.start.operation;
        const mode = operation.kind === "shell" ? "stream"
          : operation.kind === "builtin-tool" || operation.kind === "sandbox-tool" ? "worker" : "capture";
        const completion = mode === "capture"
          ? (input: NativeCompletionInput) => operationCompletion(operation, input)
          : undefined;
        return {
          executable: nativePath,
          args: launch.args,
          cwd: options.hostCwd,
          environment: {
            ...options.hostEnvironment,
            PI_SANDBOX_BWRAP_PATH: selected.bubblewrapPath,
            ...(launch.egressEnv ?? {}),
          },
          ...(launch.operationInput === undefined ? {} : { input: launch.operationInput }),
          readyMarker: READY_MARKER,
          outputMode: mode,
          ...(mode === "capture" ? {
            outputLimitBytes: MAX_FILE_CONTENT_BYTES,
            outputLimitError: { code: "unsupported", reason: "file content exceeds the native result limit" },
            complete: completion,
          } : {}),
        };
      } catch (error) {
        const code = typeof error === "object" && error !== null && "code" in error && typeof error.code === "string"
          ? error.code : "setup";
        return { ok: false, code, reason: error instanceof Error ? error.message : String(error) };
      }
    },
  };
}
