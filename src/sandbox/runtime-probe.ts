import { resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { ExecutionController } from "./lifecycle";
import { EXECUTION_INSTALL_ROOT } from "./platform";
import { selectExecutionEnvironment } from "./plan";
import { HELPER_PROTOCOL_VERSION } from "./types";
import { prepareMacOSHelperProcess } from "./backend/macos/index";
import type { ResolvedRuntimeFiles } from "./runtime-store";
import type { RuntimeProbeResult } from "./runtime-manager";

function backendDirectory(runtime: ResolvedRuntimeFiles): "macos" | "linux" | "windows" {
  if (runtime.manifest.platform === "darwin") return "macos";
  return runtime.manifest.platform === "linux" ? "linux" : "windows";
}

export async function probeSandboxRuntime(input: {
  readonly runtime: ResolvedRuntimeFiles;
  readonly workspaceRoot: string;
  readonly signal: AbortSignal;
}): Promise<RuntimeProbeResult> {
  const macOS = input.runtime.manifest.platform === "darwin";
  const helper = fileURLToPath(new URL(`./backend/${backendDirectory(input.runtime)}/helper.mjs`, import.meta.url));
  const controller = new ExecutionController({
    installation: {
      installRoot: EXECUTION_INSTALL_ROOT,
      executable: process.execPath,
      args: [helper],
      expectedProtocolVersion: HELPER_PROTOCOL_VERSION,
      expectedBackendId: input.runtime.manifest.backendId,
    },
    helperCwd: resolve(tmpdir()),
    workspace: input.workspaceRoot,
    helperEnvironment: {
      ...selectExecutionEnvironment(process.env as Record<string, string>),
      // The system macOS runtime has no runtime directory to expose.
      ...(macOS ? {} : {
        PI_SANDBOX_RUNTIME_DIR: input.runtime.directory,
        PI_SANDBOX_RUNTIME_ROOT: input.runtime.storageRoot,
      }),
      PI_SANDBOX_WORKSPACE_ROOT: resolve(input.workspaceRoot),
      ...(process.env.HOME ? { HOME: process.env.HOME } : {}),
      ...(process.env.LOCALAPPDATA ? { LOCALAPPDATA: process.env.LOCALAPPDATA } : {}),
    },
    ...(macOS ? { prepareHelperProcess: prepareMacOSHelperProcess } : {}),
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
