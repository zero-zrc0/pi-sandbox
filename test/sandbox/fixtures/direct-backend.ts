import { fileURLToPath } from "node:url";

import type { BackendCapabilities, ExecutionRequest } from "#sandbox/types";
import type { DirectBackendDriver, DirectBackendProbe, DirectBackendUnavailable, NativeCompletionInput, NativeLaunchPlan } from "#sandbox/backend/direct";

const BACKEND_ID = "fixture-direct";
const BACKEND_VERSION = "1.0.0";
const OPERATION_READY_MARKER = "\x1ePI-MACOS-OPERATION-READY\x1f";
const BUILTIN_WORKER = fileURLToPath(new URL("../../../src/sandbox/builtin-worker.mjs", import.meta.url));
const SANDBOX_TOOL_WORKER = fileURLToPath(new URL("../../../src/sandbox/sandbox-tool-worker.mjs", import.meta.url));
const FILE_OPERATION_WORKER = fileURLToPath(new URL("../../../src/sandbox/backend/macos/operation-worker.mjs", import.meta.url));
const NATIVE_PROCESS_PRELOAD = fileURLToPath(new URL("./native-process-preload.cjs", import.meta.url));

const capabilities: BackendCapabilities = {
  filesystem: {
    read: true,
    write: true,
    granularity: "file",
    protectedPaths: true,
    environment: true,
    metadataRead: "all",
  },
  network: "domains",
  cancel: true,
  streamOutput: true,
  startedNotification: true,
  processTree: true,
};

function nodePlan(
  environment: Readonly<Record<string, string>>,
  code: string,
  outputMode: NativeLaunchPlan["outputMode"] = "stream",
): NativeLaunchPlan {
  return {
    executable: process.execPath,
    args: ["-e", code],
    cwd: process.cwd(),
    environment,
    outputMode,
  };
}

function operationCompletion(input: NativeCompletionInput) {
  let value: unknown;
  try { value = JSON.parse(input.stdout.toString("utf8")); }
  catch {
    return { exitCode: null, impact: "unknown" as const, errorCode: "protocol", error: "file operation returned invalid output" };
  }
  if (typeof value !== "object" || value === null || Array.isArray(value) || !Number.isInteger((value as { exitCode?: unknown }).exitCode)) {
    return { exitCode: null, impact: "unknown" as const, errorCode: "protocol", error: "file operation returned invalid output" };
  }
  const result = value as { exitCode: number; errorCode?: unknown; error?: unknown; dataBase64?: unknown };
  return {
    exitCode: result.exitCode,
    impact: input.exitCode === null || input.signal !== null ? "unknown" as const : "known" as const,
    ...(typeof result.errorCode === "string" ? { errorCode: result.errorCode } : {}),
    ...(typeof result.error === "string" ? { error: result.error } : {}),
    ...(typeof result.dataBase64 === "string" ? { dataBase64: result.dataBase64 } : {}),
  };
}

export function createTestDirectBackend(options: {
  readonly scenario?: string;
  readonly environment?: Readonly<Record<string, string>>;
  readonly id?: string;
  readonly probe?: DirectBackendDriver["probe"];
  readonly prepare?: DirectBackendDriver["prepare"];
} = {}): DirectBackendDriver {
  const scenario = options.scenario ?? "ok";
  const environment = options.environment ?? {};
  const unavailable = (code: string, reason: string): DirectBackendUnavailable => ({ ok: false, code, reason });

  return {
    id: options.id ?? BACKEND_ID,
    version: BACKEND_VERSION,
    async probe(signal): Promise<DirectBackendProbe | DirectBackendUnavailable> {
      if (options.probe) return options.probe(signal);
      if (signal?.aborted) return unavailable("unavailable", "native backend probe was cancelled");
      if (scenario === "unavailable" || scenario === "no-ready" || scenario === "eof") {
        return unavailable("unavailable", "fixture native backend is unavailable");
      }
      return { ok: true, capabilities };
    },
    async prepare(request: ExecutionRequest, egress, signal): Promise<NativeLaunchPlan | DirectBackendUnavailable> {
      if (options.prepare) return options.prepare(request, egress, signal);
      if (signal?.aborted) return unavailable("setup", "native launch was cancelled before preparation");
      if (scenario === "reject") return unavailable("denied", "fixture backend rejected the plan");

      const selectedEnvironment = { ...environment, ...request.start.environment };
      if (selectedEnvironment.FIXTURE_SELF_PID_FILE) {
        selectedEnvironment.NODE_OPTIONS = `${selectedEnvironment.NODE_OPTIONS ?? ""} --require ${NATIVE_PROCESS_PRELOAD}`.trim();
      }
      const executionEnvironment = Object.freeze(selectedEnvironment);
      const operation = request.start.operation;
      if (operation.kind === "shell" && scenario === "start-fail") {
        return { executable: `${process.execPath}.missing`, args: [], cwd: request.start.cwd, environment: executionEnvironment, outputMode: "stream" };
      }
      if (operation.kind === "shell" && scenario === "no-start") {
        return { ...nodePlan(executionEnvironment, "process.exit(0)"), readyMarker: "missing-ready-marker" };
      }
      if (operation.kind === "shell" && scenario === "error-after-start") {
        return nodePlan(executionEnvironment, "process.stdout.write('{invalid\\n')", "worker");
      }
      if (operation.kind === "shell" && scenario === "huge") {
        return nodePlan(executionEnvironment, "process.stdout.write('x'.repeat(5 * 1024 * 1024))");
      }
      if (operation.kind === "shell" && scenario === "slow") {
        const pidPath = JSON.stringify(executionEnvironment.FIXTURE_SELF_PID_FILE ?? "");
        return nodePlan(executionEnvironment, `if (${pidPath}) require('node:fs').writeFileSync(${pidPath}, String(process.pid)); setInterval(() => process.stdout.write('tick\\n'), 20)`);
      }
      if (operation.kind === "shell" && (scenario === "grandchild" || scenario === "stubborn")) {
        const pidPath = JSON.stringify(executionEnvironment.FIXTURE_PID_FILE ?? "");
        const childCode = scenario === "stubborn"
          ? "process.on('SIGTERM', () => {}); setInterval(() => {}, 1000)"
          : "setInterval(() => {}, 1000)";
        const code = `const { spawn } = require('node:child_process'); const fs = require('node:fs'); const child = spawn(process.execPath, ['-e', ${JSON.stringify(childCode)}], { stdio: 'ignore', windowsHide: true }); if (${pidPath}) fs.writeFileSync(${pidPath}, String(child.pid)); setInterval(() => {}, 1000);`;
        return nodePlan(executionEnvironment, code);
      }
      if (operation.kind === "shell" && scenario === "echo-egress") {
        return nodePlan(executionEnvironment, `process.stdout.write(${JSON.stringify(`egress:${egress?.leaseId ?? "none"}`)})`);
      }

      if (operation.kind === "shell") {
        if (operation.command === "ignored") return nodePlan(executionEnvironment, "process.exit(0)");
        const windows = process.platform === "win32";
        const executable = operation.shell ?? (windows ? process.env.ComSpec ?? "cmd.exe" : process.env.SHELL ?? "/bin/sh");
        return {
          executable,
          args: windows ? ["/d", "/s", "/c", operation.command] : ["-c", operation.command],
          cwd: request.start.cwd,
          environment: executionEnvironment,
          outputMode: "stream",
        };
      }
      if (operation.kind === "builtin-tool" || operation.kind === "sandbox-tool") {
        const worker = operation.kind === "sandbox-tool" ? SANDBOX_TOOL_WORKER : BUILTIN_WORKER;
        const input = `${JSON.stringify({
          ...operation,
          toolCallId: request.toolCallId,
          cwd: request.start.cwd,
          ...(operation.kind === "sandbox-tool" ? { stateDirectory: operation.stateDirectory } : {}),
        })}\n`;
        return {
          executable: process.execPath,
          args: [worker],
          cwd: request.start.cwd,
          environment: executionEnvironment,
          input,
          outputMode: "worker",
        };
      }

      return {
        executable: process.execPath,
        args: [FILE_OPERATION_WORKER],
        cwd: request.start.cwd,
        environment: executionEnvironment,
        input: `${JSON.stringify(operation)}\n`,
        readyMarker: OPERATION_READY_MARKER,
        outputMode: "capture",
        complete: operationCompletion,
      };
    },
  };
}
