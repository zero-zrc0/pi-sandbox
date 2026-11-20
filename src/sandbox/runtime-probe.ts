import { resolve } from "node:path";
import { tmpdir } from "node:os";
import { ExecutionController } from "./lifecycle";
import { EXECUTION_INSTALL_ROOT } from "./platform";
import { selectExecutionEnvironment } from "./plan";
import { findSystemBubblewrap } from "./backend/linux/bwrap-selection.mjs";
import { createLinuxDirectBackend } from "./backend/linux/direct";
import { createMacOSDirectBackend } from "./backend/macos/direct";
import { createWindowsDirectBackend } from "./backend/windows/direct";
import type { ResolvedRuntimeFiles } from "./runtime-store";
import type { RuntimeProbeResult } from "./runtime-manager";

export async function probeSandboxRuntime(input: {
  readonly runtime: ResolvedRuntimeFiles;
  readonly workspaceRoot: string;
  readonly signal: AbortSignal;
}): Promise<RuntimeProbeResult> {
  const platform = input.runtime.manifest.platform;
  const macOS = platform === "darwin";
  const hostCwd = resolve(tmpdir());
  const environment = selectExecutionEnvironment(process.env as Record<string, string>);
  const systemBubblewrapPath = platform === "linux"
    ? findSystemBubblewrap(environment.PATH, input.workspaceRoot)
    : undefined;
  const hostEnvironment = {
    ...environment,
    ...(macOS ? {} : {
      PI_SANDBOX_RUNTIME_DIR: input.runtime.directory,
      PI_SANDBOX_RUNTIME_ROOT: input.runtime.storageRoot,
    }),
    PI_SANDBOX_WORKSPACE_ROOT: resolve(input.workspaceRoot),
    ...(process.env.HOME ? { HOME: process.env.HOME } : {}),
    ...(process.env.LOCALAPPDATA ? { LOCALAPPDATA: process.env.LOCALAPPDATA } : {}),
    ...(systemBubblewrapPath === undefined ? {} : { PI_SANDBOX_SYSTEM_BWRAP_PATH: systemBubblewrapPath }),
  };
  const directBackend = platform === "win32"
    ? createWindowsDirectBackend({ runtime: input.runtime, installRoot: EXECUTION_INSTALL_ROOT, hostCwd, hostEnvironment })
    : platform === "linux"
      ? createLinuxDirectBackend({ runtime: input.runtime, installRoot: EXECUTION_INSTALL_ROOT, hostCwd, hostEnvironment,
        ...(systemBubblewrapPath === undefined ? {} : { systemBubblewrapPath }) })
      : platform === "darwin"
        ? createMacOSDirectBackend({ installRoot: EXECUTION_INSTALL_ROOT, hostEnvironment })
        : undefined;
  if (!directBackend) return { available: false, reason: `runtime platform is unsupported: ${platform}` };
  const controller = new ExecutionController({
    directBackend,
    probeTimeoutMs: 15_000,
  });
  const stop = () => { void controller.dispose(); };
  input.signal.addEventListener("abort", stop, { once: true });
  try {
    if (input.signal.aborted) return { available: false, reason: "runtime probe was cancelled" };
    const result = await controller.probe();
    if (input.signal.aborted) return { available: false, reason: "runtime probe was cancelled" };
    if (result.status !== "available") {
      return { available: false, reason: result.reason ?? `runtime probe failed: ${result.status}` };
    }
    const capabilities = result.capabilities;
    // macOS Seatbelt has no proxy path, so the only acceptable network posture
    // is "none"; the downloaded runtimes must also express controlled egress.
    const networkGap = macOS
      ? (capabilities.network !== "none" ? ["no-network default"] : [])
      : (capabilities.network !== "domains" ? ["controlled network egress"] : []);
    const missing = [
      ...(!capabilities.filesystem.read ? ["filesystem read"] : []),
      ...(!capabilities.filesystem.write ? ["filesystem write"] : []),
      ...(capabilities.filesystem.granularity !== "file" ? ["file-level filesystem grants"] : []),
      ...(!capabilities.filesystem.protectedPaths ? ["protected paths"] : []),
      ...(!capabilities.filesystem.environment ? ["environment filtering"] : []),
      ...networkGap,
      ...(!capabilities.cancel ? ["cancellation"] : []),
      ...(macOS && !capabilities.streamOutput ? ["streamed output"] : []),
      ...(!capabilities.startedNotification ? ["start notification"] : []),
      ...(!capabilities.processTree ? ["process tree control"] : []),
    ];
    if (missing.length > 0) return { available: false, reason: `runtime lacks required capabilities: ${missing.join(", ")}` };
    return { available: true };
  } finally {
    input.signal.removeEventListener("abort", stop);
    await controller.dispose();
  }
}
