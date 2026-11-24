
import { spawn } from "node:child_process";
import { existsSync, lstatSync, realpathSync, statSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, sep } from "node:path";
import type { EgressGrantRef } from "../../lifecycle";
import { jsonDigest } from "../../../json";
import type { DirectBackendDriver, DirectBackendProbe, DirectBackendUnavailable, NativeLaunchPlan } from "../direct";
import { isPathWithin } from "../../path";
import type { ResolvedRuntimeFiles } from "../../runtime-store";

import { MAX_NATIVE_REQUEST_BYTES, type ExecutionFilesystemRule, type ExecutionRequest } from "../../types";

const BACKEND_ID = "windows-mxc";
const BACKEND_VERSION = "1.0.0";

const MXC_READY_MARKER = "\x1ePI-MXC-READY\x1f";
const FILE_ENV_DENY = new Set(["NODE_OPTIONS", "NODE_PATH"]);

interface WindowsBackendOptions {
  readonly runtime: ResolvedRuntimeFiles;
  readonly installRoot: string;
  readonly hostCwd: string;
  readonly hostEnvironment: Readonly<Record<string, string>>;
}

interface NativeProbeOutput {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly error?: string;
  readonly timedOut: boolean;
}

function runProbeProcess(executable: string, options: WindowsBackendOptions, signal?: AbortSignal): Promise<NativeProbeOutput> {
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
        env: { ...options.hostEnvironment },
        stdio: ["ignore", "pipe", "pipe"],
        shell: false,
        windowsHide: true,
      });
    } catch (error) {
      resolve({ code: null, stdout, stderr, error: error instanceof Error ? error.message : String(error), timedOut });
      return;
    }
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, 6_000);
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

function runtimePaths(runtime: ResolvedRuntimeFiles): { readonly executable: string; readonly mxcManifest: string } {
  if (runtime.manifest.platform !== "win32" || runtime.manifest.backendId !== BACKEND_ID ||
      runtime.manifest.protocolVersion !== 3 || runtime.manifest.arch !== process.arch) {
    throw new Error("runtime manifest does not match the Windows backend");
  }
  const directory = runtime.directory;
  if (!isPathWithin(runtime.storageRoot, directory)) {
    throw new Error("runtime directory is outside the trusted runtime root");
  }
  const executable = runtime.files.windowsExecutable;
  const mxcManifest = runtime.files.mxcManifest;
  if (!executable || !mxcManifest || executable !== join(directory, "pi-sandbox-windows-mxc.exe") ||
      mxcManifest !== join(directory, "mxc-runtime.json") ||
      !isPathWithin(directory, executable) || !isPathWithin(directory, mxcManifest)) {
    throw new Error("Windows runtime files are incomplete or outside their fixed paths");
  }
  return { executable, mxcManifest };
}

function validatePathIdentity(path: string): string {
  if (!isAbsolute(path) || path.split(/[\\/]/u).some(part => part === "." || part === "..")) {
    throw new Error("invalid filesystem path");
  }
  let current = path;
  const missing: string[] = [];
  for (;;) {
    try { return join(realpathSync(current), ...missing.reverse()); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      try {
        lstatSync(current);
        throw new Error("unresolved filesystem identity");
      } catch (check) {
        if ((check as NodeJS.ErrnoException).code !== "ENOENT") throw check;
      }
      const parent = dirname(current);
      if (parent === current) throw error;
      missing.push(basename(current));
      current = parent;
    }
  }
}

function preparePlanRules(request: ExecutionRequest): ExecutionRequest["plan"] | DirectBackendUnavailable {
  const plan = request.plan;
  if (plan.version !== 3 || plan.metadataRead !== "none" || plan.filesystem.some(rule =>
    !["read", "write", "deny-write", "deny-access"].includes(rule.access) ||
    !["file", "directory"].includes(rule.granularity))) {
    return { ok: false, code: "unsupported", reason: "execution plan filesystem version is unsupported" };
  }
  return plan;
}

function prepareRequest(
  request: ExecutionRequest,
  egress: EgressGrantRef | undefined,
  options: WindowsBackendOptions,
  runtime: { readonly executable: string; readonly mxcManifest: string },
): NativeLaunchPlan | DirectBackendUnavailable {
  const start = request.start;
  const checkedPlan = preparePlanRules(request);
  if ("ok" in checkedPlan) return checkedPlan;
  let plan: ExecutionRequest["plan"] = checkedPlan;
  const proxyPort = plan.network.kind === "destinations" && egress?.proxyHost === "127.0.0.1" &&
    Number.isInteger(egress.proxyPort) && egress.proxyPort > 0 && egress.proxyPort <= 65_535
    ? egress.proxyPort
    : undefined;
  if (plan.network.kind === "destinations" ? proxyPort === undefined :
      (plan.network.kind !== "none" && plan.network.kind !== "all") || egress !== undefined) {
    return { ok: false, code: "unsupported", reason: "network policy is unsupported" };
  }
  const operation = start.operation;
  if (operation.kind === "builtin-tool" && operation.name === "bash") {
    return { ok: false, code: "unsupported", reason: "the bash builtin is unsupported by the Windows MXC backend" };
  }
  if ((operation.kind === "builtin-tool" || operation.kind === "sandbox-tool") &&
      Object.keys(start.environment).some(name => FILE_ENV_DENY.has(name.toUpperCase()))) {
    return { ok: false, code: "unsupported", reason: `${operation.kind === "builtin-tool" ? "builtin" : "sandbox tool"} runtime injection environment is unsupported` };
  }
  if (operation.kind === "builtin-tool" && ["read", "ls", "grep", "find"].includes(operation.name)) {
    plan = { ...plan, filesystem: plan.filesystem.filter(rule => rule.access !== "write") };
  }
  const writeDirectories = plan.filesystem.filter(rule => rule.access === "write" && rule.granularity === "directory");
  const missingWriteFile = plan.filesystem.some(rule => rule.access === "write" && rule.granularity === "file" &&
    !existsSync(rule.path) && !writeDirectories.some(directory => {
      const path = relative(directory.path, rule.path);
      return path === "" || (!isAbsolute(path) && path !== ".." && !path.startsWith(`..${sep}`));
    }));
  if (missingWriteFile) return { ok: false, code: "unsupported", reason: "permission denied" };

  let argv: string[];
  let input = "";
  const isWorker = operation.kind === "builtin-tool" || operation.kind === "sandbox-tool";
  if (isWorker) {
    try {
      const workerName = operation.kind === "sandbox-tool" ? "sandbox-tool-worker.mjs" : "builtin-worker.bundle.mjs";
      const runnerPath = realpathSync(join(options.installRoot, "src", "sandbox", workerName));
      if (!isPathWithin(options.installRoot, runnerPath)) throw new Error("worker path is outside the install root");
      const nodePath = realpathSync(process.execPath);
      if (operation.kind === "builtin-tool" && (operation.name === "grep" || operation.name === "find") &&
          start.environment.PI_CODING_AGENT_DIR !== undefined && !isAbsolute(start.environment.PI_CODING_AGENT_DIR)) {
        return { ok: false, code: "setup", reason: "agent directory must be absolute" };
      }
      argv = [nodePath, "--preserve-symlinks", "--preserve-symlinks-main", runnerPath];
      const mutationQueuePath = operation.context?.mutationQueuePath;
      input = `${JSON.stringify({
        ...operation,
        toolCallId: request.toolCallId,
        cwd: start.cwd,
        ...(operation.kind === "builtin-tool" && operation.name === "powershell" && proxyPort !== undefined
          ? { useDefaultProxy: true }
          : {}),
        ...(typeof mutationQueuePath === "string" ? { mutationQueuePath } : {}),
      })}\n`;
    } catch {
      return { ok: false, code: "setup", reason: "builtin runtime is unavailable" };
    }
  } else if (operation.kind === "shell" && !operation.command.includes("\0")) {
    if (!isAbsolute(operation.shell ?? "")) return { ok: false, code: "setup", reason: "shell path must be absolute" };
    const shell = operation.shell!;
    const name = basename(shell).toLowerCase();
    argv = name === "cmd.exe" ? [shell, "/d", "/s", "/c", operation.command]
      : name === "powershell.exe" || name === "pwsh.exe"
        ? [shell, "-NoProfile", "-NonInteractive", "-Command", operation.command]
        : [];
    if (argv.length === 0) return { ok: false, code: "unsupported", reason: "shell interpreter is unsupported" };
  } else {
    return { ok: false, code: "unsupported", reason: "execution operation is unsupported" };
  }

  try {
    const filesystem = plan.filesystem.map((rule: ExecutionFilesystemRule) => {
      const path = validatePathIdentity(rule.path);
      try {
        const directory = statSync(path).isDirectory();
        if (rule.granularity !== (directory ? "directory" : "file")) throw new Error("grant type mismatch");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
      return { ...rule, path };
    });
    plan = { ...plan, filesystem };
  } catch {
    return { ok: false, code: "unsupported", reason: "filesystem path identity is unavailable" };
  }

  const nativeRequest = {
    plan,
    operation,
    cwd: start.cwd,
    environment: start.environment,
    deadlineAt: start.deadlineAt,
    argv,
    input,
    ...(proxyPort === undefined ? {} : { proxyPort }),
  };
  const serializedRequest = JSON.stringify(nativeRequest);
  if (Buffer.byteLength(serializedRequest, "utf8") > MAX_NATIVE_REQUEST_BYTES) {
    return { ok: false, code: "unsupported", reason: "native execution request exceeds the native request limit" };
  }
  return {
    executable: runtime.executable,
    args: [],
    cwd: options.hostCwd,
    environment: options.hostEnvironment,
    input: serializedRequest,
    readyMarker: MXC_READY_MARKER,
    outputMode: isWorker ? "worker" : "stream",
  };
}

export function createWindowsDirectBackend(options: WindowsBackendOptions): DirectBackendDriver {
  const unavailable = (error: unknown): DirectBackendUnavailable => ({
    ok: false,
    code: "unavailable",
    reason: error instanceof Error ? error.message : String(error),
  });
  return {
    id: BACKEND_ID,
    version: BACKEND_VERSION,
    probeCacheKey: [BACKEND_ID, BACKEND_VERSION, options.runtime.directory, options.runtime.manifest.version].join(":"),

    async probe(signal?: AbortSignal): Promise<DirectBackendProbe | DirectBackendUnavailable> {
      if (signal?.aborted) return unavailable(new Error("runtime probe was cancelled"));
      let files: ReturnType<typeof runtimePaths>;
      try { files = runtimePaths(options.runtime); }
      catch (error) { return unavailable(error); }
      const output = await runProbeProcess(files.executable, options, signal);
      if (output.timedOut || output.error || output.code !== 0) {
        return unavailable(new Error(output.stderr.trim() || output.error || "native sandbox probe failed"));
      }
      let capabilities: { available?: unknown; deny?: unknown; planVersion?: unknown };
      try { capabilities = JSON.parse(output.stdout) as typeof capabilities; }
      catch { return unavailable(new Error("native sandbox probe returned invalid capabilities")); }
      if (capabilities.available !== true || capabilities.planVersion !== 3) {
        return unavailable(new Error("native runtime does not support execution plan version 3"));
      }
      return {
        ok: true,
        capabilities: {
          filesystem: {
            read: true,
            write: true,
            granularity: "file",
            protectedPaths: capabilities.deny === true,
            environment: true,
            metadataRead: "none",
          },
          network: "domains",
          cancel: true,
          streamOutput: true,
          startedNotification: true,
          processTree: true,
        },
      };
    },
    async prepare(request, egress) {
      let files: ReturnType<typeof runtimePaths>;
      try { files = runtimePaths(options.runtime); }
      catch (error) { return unavailable(error); }
      return prepareRequest(request, egress, options, files);
    },
  };
}
