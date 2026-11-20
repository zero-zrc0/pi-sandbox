import { realpathSync } from "node:fs";
import { join } from "node:path";
import { buildSeatbeltProfile, MACOS_SANDBOX_EXEC_PATH, probeMacOSSeatbelt, type SeatbeltInstallation } from "./seatbelt";
import { validatePlan } from "./operations.mjs";
import type { EgressGrantRef } from "../../lifecycle";
import type { DirectBackendDriver, DirectBackendProbe, DirectBackendUnavailable, NativeCompletionInput, NativeLaunchPlan } from "../direct";
import type { ExecutionOperation, ExecutionRequest } from "../../types";

const BACKEND_ID = "macos-seatbelt";
const BACKEND_VERSION = "1.0.0";
const MAX_FILE_CONTENT_BYTES = 4 * 1024 * 1024;
const OPERATION_READY_MARKER = "\x1ePI-MACOS-OPERATION-READY\x1f";

interface MacOSBackendOptions {
  readonly installRoot: string;
  readonly hostEnvironment: Readonly<Record<string, string>>;
}

function operationCompletion(input: NativeCompletionInput) {
  let result: unknown;
  try { result = JSON.parse(input.stdout.toString("utf8")); }
  catch {
    return {
      exitCode: null,
      impact: "unknown" as const,
      errorCode: "protocol",
      error: "file operation returned an invalid result",
    };
  }
  if (typeof result !== "object" || result === null || Array.isArray(result) ||
      !Number.isInteger((result as { exitCode?: unknown }).exitCode)) {
    return {
      exitCode: null,
      impact: "unknown" as const,
      errorCode: "protocol",
      error: "file operation returned an invalid result",
    };
  }
  const outcome = result as { exitCode: number; errorCode?: unknown; error?: unknown; dataBase64?: unknown };
  if (typeof outcome.dataBase64 === "string" && Buffer.from(outcome.dataBase64, "base64").length > MAX_FILE_CONTENT_BYTES) {
    return { exitCode: 1, impact: "known" as const, errorCode: "unsupported", error: "file content exceeds the native result limit" };
  }
  return {
    exitCode: outcome.exitCode,
    impact: input.exitCode === null || input.signal !== null ? "unknown" as const : "known" as const,
    ...(typeof outcome.errorCode === "string" ? { errorCode: outcome.errorCode } : {}),
    ...(typeof outcome.error === "string" ? { error: outcome.error } : {}),
    ...(typeof outcome.dataBase64 === "string" ? { dataBase64: outcome.dataBase64 } : {}),
    ...(input.signal === null ? {} : { errorCode: "signal", error: `sandboxed process exited on ${input.signal}` }),
  };
}

export function createMacOSDirectBackend(options: MacOSBackendOptions): DirectBackendDriver {
  const unavailable = (reason: string, code = "unavailable"): DirectBackendUnavailable => ({ ok: false, code, reason });
  const probe: DirectBackendProbe["capabilities"] = {
    filesystem: { read: true, write: true, granularity: "file", protectedPaths: true, environment: true, metadataRead: "all" },
    network: "none",
    cancel: true,
    streamOutput: true,
    startedNotification: true,
    processTree: true,
  };
  return {
    id: BACKEND_ID,
    version: BACKEND_VERSION,
    async probe(): Promise<DirectBackendProbe | DirectBackendUnavailable> {
      const result = probeMacOSSeatbelt();
      return result.status === "candidate-present" ? { ok: true, capabilities: probe } : unavailable(result.reason);
    },
    async prepare(request: ExecutionRequest, egress?: EgressGrantRef): Promise<NativeLaunchPlan | DirectBackendUnavailable> {
      if (egress !== undefined) return unavailable("Seatbelt does not allow egress grants", "unsupported");
      let validated: ReturnType<typeof validatePlan>;
      try { validated = validatePlan(request.plan, request.start); }
      catch (error) {
        const code = typeof error === "object" && error !== null && "code" in error && typeof error.code === "string"
          ? error.code : "setup";
        return unavailable(error instanceof Error ? error.message : String(error), code);
      }
      const { operation, cwd, environment } = validated;
      let executable: string;
      let args: string[];
      let input: string | undefined;
      let outputMode: NativeLaunchPlan["outputMode"];
      let readyMarker: string | undefined;
      let complete: NativeLaunchPlan["complete"];
      try {
        if (operation.kind === "shell") {
          executable = operation.shell ?? "/bin/sh";
          args = ["-c", operation.command];
          outputMode = "stream";
        } else if (operation.kind === "builtin-tool" || operation.kind === "sandbox-tool") {
          const runner = operation.kind === "sandbox-tool" ? "sandbox-tool-worker.mjs" : "builtin-worker.bundle.mjs";
          const worker = realpathSync(join(options.installRoot, "src", "sandbox", runner));
          executable = realpathSync(process.execPath);
          args = [worker];
          input = `${JSON.stringify({ ...operation, toolCallId: request.toolCallId, cwd })}\n`;
          outputMode = "worker";
        } else {
          const worker = realpathSync(join(options.installRoot, "src", "sandbox", "backend", "macos", "operation-worker.mjs"));
          executable = realpathSync(process.execPath);
          args = [worker];
          input = `${JSON.stringify(operation)}\n`;
          outputMode = "capture";
          readyMarker = OPERATION_READY_MARKER;
          complete = operationCompletion;
        }
      } catch {
        return unavailable("sandbox runtime is unavailable", "setup");
      }
      const installation: SeatbeltInstallation = {
        installRoot: options.installRoot,
        executable,
        args,
      };
      const policy = buildSeatbeltProfile({
        installation,
        executionHome: options.hostEnvironment.HOME,
        plan: request.plan,
        cwd,
      });
      if (!policy.ok) return unavailable(policy.reason, policy.code);
      return {
        executable: MACOS_SANDBOX_EXEC_PATH,
        args: ["-p", policy.profile, executable, ...args],
        cwd,
        environment,
        ...(input === undefined ? {} : { input }),
        ...(readyMarker === undefined ? {} : { readyMarker }),
        outputMode,
        ...(outputMode === "capture" ? {
          outputLimitBytes: MAX_FILE_CONTENT_BYTES * 2,
          outputLimitError: { code: "unsupported", reason: "file content exceeds the native result limit" },
          complete,
        } : {}),
      };
    },
  };
}
