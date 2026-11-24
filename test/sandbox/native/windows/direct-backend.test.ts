import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, parse } from "node:path";
import { fileURLToPath } from "node:url";
import { rm } from "node:fs/promises";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createWindowsDirectBackend } from "#sandbox/backend/windows/direct";
import { probeDirectBackendOnce } from "#sandbox/backend/direct";
import { ExecutionController } from "#sandbox/lifecycle";
import type { NativeLaunchPlan } from "#sandbox/backend/direct";
import type { ExecutionOperation } from "#sandbox/types";
import { collectSensitivePaths } from "#sandbox/sensitive-paths";
import { windowsRuntimeFilesystem } from "#sandbox/runtime-filesystem";
import type { ResolvedRuntimeFiles } from "#sandbox/runtime-store";
import { compileTestRequest, makeInvocation, runtimeEnvironment, waitFor, waitForProcessGone } from "../../fixtures/harness";
import { installWindowsTestRuntime } from "../../fixtures/runtime";

const sourceExecutable = process.env.PI_SANDBOX_TEST_MXC_EXECUTABLE ??
  fileURLToPath(new URL("../../../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url));
const packageRoot = realpathSync(fileURLToPath(new URL("../../../../", import.meta.url)));
const nativeEnabled = process.platform === "win32" && existsSync(sourceExecutable);
let runtime: ResolvedRuntimeFiles | undefined;
const layouts: string[] = [];

beforeAll(() => {
  if (nativeEnabled) runtime = installWindowsTestRuntime();
});

afterAll(async () => {
  if (runtime) await rm(runtime.directory, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
  for (const root of layouts.splice(0)) await rm(root, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
});

function toolEnvironment(): Record<string, string> {
  const environment: Record<string, string> = {};
  for (const name of ["SystemRoot", "SystemDrive", "LOCALAPPDATA", "PATH"]) {
    const value = process.env[name];
    if (typeof value === "string") environment[name] = value;
  }
  return environment;
}

function createLayout() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "windows-direct-backend-")));
  layouts.push(root);
  const workspace = join(root, "workspace");
  const hostCwd = join(root, "native-cwd");
  const agentDirectory = join(root, "agent");
  for (const path of [workspace, hostCwd, agentDirectory]) mkdirSync(path, { recursive: true });
  return { root, workspace, hostCwd, agentDirectory };
}

function createBackend(layout: ReturnType<typeof createLayout>) {
  if (!runtime) throw new Error("Windows native runtime is unavailable");
  return createWindowsDirectBackend({
    runtime,
    installRoot: packageRoot,
    hostCwd: layout.hostCwd,
    hostEnvironment: {
      ...runtimeEnvironment(),
      PI_MXC_AGENT_DIR: layout.agentDirectory,
      PI_SANDBOX_WORKSPACE_ROOT: layout.workspace,
      ...(process.env.LOCALAPPDATA ? { LOCALAPPDATA: process.env.LOCALAPPDATA } : {}),
      PI_SANDBOX_RUNTIME_DIR: runtime.directory,
      PI_SANDBOX_RUNTIME_ROOT: runtime.storageRoot,
    },
  });
}

function makeRequest(
  layout: ReturnType<typeof createLayout>,
  operation: Extract<ExecutionOperation, { readonly kind: "shell" }> |
    Extract<ExecutionOperation, { readonly kind: "builtin-tool" }>,
  sensitivePaths?: ReturnType<typeof collectSensitivePaths>,
) {
  const environment = toolEnvironment();
  const toolName = operation.kind === "shell" ? "powershell" : operation.name;
  const argumentsValue = operation.kind === "shell" ? { command: operation.command } : operation.arguments;
  const invocation = makeInvocation({ cwd: layout.workspace, toolName, args: argumentsValue });
  const filesystem = windowsRuntimeFilesystem({
    cwd: layout.workspace,
    installRoot: packageRoot,
    agentDirectory: layout.agentDirectory,
    operation,
    environment,
  });
  return compileTestRequest({
    invocation,
    operation,
    workspace: layout.workspace,
    backendId: "windows-mxc",
    runtimeFilesystem: filesystem.grants,
    protectedPaths: filesystem.protectedPaths,
    ...(sensitivePaths === undefined ? {} : { sensitivePaths }),
    environment,
  });
}

function requireLaunchPlan(value: NativeLaunchPlan | { readonly ok: false; readonly reason: string }): NativeLaunchPlan {
  if ("ok" in value) throw new Error(value.reason);
  return value;
}

describe.skipIf(!nativeEnabled)("Windows host-native backend", () => {
  it("omits the working directory volume root when building restricted runtime grants", () => {
    const layout = createLayout();
    const runtimeFilesystem = windowsRuntimeFilesystem({
      cwd: layout.workspace,
      installRoot: packageRoot,
      agentDirectory: layout.agentDirectory,
      operation: { kind: "builtin-tool", name: "read", arguments: {} },
      environment: toolEnvironment(),
      includeWorkingDirectoryVolumeRoot: false,
    });

    expect(runtimeFilesystem.grants.map(grant => grant.path)).not.toContain(parse(layout.workspace).root);
    expect(runtimeFilesystem.grants.map(grant => grant.path)).toContain(realpathSync.native(process.env.SystemRoot!));
    expect(runtimeFilesystem.grants.map(grant => grant.path)).toContain(realpathSync.native(packageRoot));
    expect(runtimeFilesystem.grants.map(grant => grant.path)).toContain(realpathSync.native(process.execPath));
  });

  it("probes the installed native runtime before reporting capabilities", async () => {
    const layout = createLayout();
    const result = await createBackend(layout).probe();

    expect(result).toMatchObject({
      ok: true,
      capabilities: {
        filesystem: { read: true, write: true },
        network: "domains",
        cancel: true,
        startedNotification: true,
        processTree: true,
      },
    });
  });

  it("terminates the actual probe process when its caller cancels", async () => {
    const layout = createLayout();
    if (!runtime) throw new Error("Windows native runtime is unavailable");
    const directory = join(layout.root, "probe-runtime");
    mkdirSync(directory);
    const executable = join(directory, "pi-sandbox-windows-mxc.exe");
    const mxcManifest = join(directory, "mxc-runtime.json");
    copyFileSync(process.execPath, executable);
    writeFileSync(mxcManifest, "{}");
    const testRuntime: ResolvedRuntimeFiles = {
      ...runtime, directory, storageRoot: layout.root, files: { windowsExecutable: executable, mxcManifest },
    };
    const pidFile = join(layout.root, "probe.pid");
    writeFileSync(join(layout.hostCwd, "probe"),
      `require('node:fs').writeFileSync(${JSON.stringify(pidFile)}, String(process.pid)); setInterval(() => {}, 1000);`);
    const backend = createWindowsDirectBackend({
      runtime: testRuntime, installRoot: packageRoot, hostCwd: layout.hostCwd, hostEnvironment: runtimeEnvironment(),
    });
    const controller = new AbortController();
    const pending = probeDirectBackendOnce(backend, controller.signal);
    await waitFor(() => existsSync(pidFile));
    const pid = Number(readFileSync(pidFile, "utf8"));
    controller.abort();
    expect(await pending).toMatchObject({ ok: false });
    await waitForProcessGone(pid);
  });

  it("passes a shell request straight to MXC", async () => {
    const layout = createLayout();
    const shell = join(process.env.SystemRoot ?? "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
    const request = makeRequest(layout, { kind: "shell", shell, command: "Write-Output direct-shell" });
    const prepared = requireLaunchPlan(await createBackend(layout).prepare(request));
    const nativeRequest = JSON.parse(prepared.input ?? "{}") as Record<string, unknown>;

    expect(prepared.executable).toBe(runtime?.files.windowsExecutable);
    expect(prepared.args).toEqual([]);
    expect(prepared.outputMode).toBe("stream");
    expect(nativeRequest).toMatchObject({ argv: [shell, "-NoProfile", "-NonInteractive", "-Command", "Write-Output direct-shell"] });
  });

  it("starts a read builtin worker directly and removes write grants", async () => {
    const layout = createLayout();
    const inputPath = join(layout.workspace, "sample.txt");
    writeFileSync(inputPath, "sample");
    const request = makeRequest(layout, { kind: "builtin-tool", name: "read", arguments: { path: inputPath } });
    const prepared = requireLaunchPlan(await createBackend(layout).prepare(request));
    const nativeRequest = JSON.parse(prepared.input ?? "{}") as {
      argv?: string[];
      input?: string;
      plan?: { filesystem?: { access: string }[] };
    };

    expect(prepared.executable).toBe(runtime?.files.windowsExecutable);
    expect(prepared.args).toEqual([]);
    expect(prepared.outputMode).toBe("worker");
    expect(nativeRequest.argv?.[0]).toBe(realpathSync(process.execPath));
    expect(nativeRequest.argv?.[3]).toMatch(/builtin-worker\.bundle\.mjs$/u);
    expect(nativeRequest.input).toContain('"name":"read"');
    expect(nativeRequest.plan?.filesystem?.some(rule => rule.access === "write")).toBe(false);
  });

  it("reads control directories, denies their writes, and enforces denyPaths natively", async () => {
    const layout = createLayout();
    const agentsFile = join(layout.workspace, ".agents", "skills", "demo", "SKILL.md");
    const codexFile = join(layout.workspace, ".codex", "config.toml");
    mkdirSync(dirname(agentsFile), { recursive: true });
    mkdirSync(dirname(codexFile), { recursive: true });
    writeFileSync(agentsFile, "skill content");
    writeFileSync(codexFile, "model = 'test'");
    const shell = join(process.env.SystemRoot ?? "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
    const command = [
      "$ErrorActionPreference = 'Stop'",
      `$agents = Get-Content -Raw -LiteralPath '${agentsFile}'`,
      `$codex = Get-Content -Raw -LiteralPath '${codexFile}'`,
      "$agentsWriteDenied = $false",
      `try { Set-Content -NoNewline -LiteralPath '${agentsFile}' -Value 'changed' -ErrorAction Stop } catch { $agentsWriteDenied = $true }`,
      "$codexWriteDenied = $false",
      `try { Set-Content -NoNewline -LiteralPath '${codexFile}' -Value 'changed' -ErrorAction Stop } catch { $codexWriteDenied = $true }`,
      "if ($agents -ne 'skill content' -or $codex -ne \"model = 'test'\" -or -not $agentsWriteDenied -or -not $codexWriteDenied) { exit 21 }",
      "Write-Output 'control-policy-ok'",
    ].join("; ");
    const operation = { kind: "shell" as const, shell, command };
    const controller = new ExecutionController({ directBackend: createBackend(layout) });

    try {
      const probe = await controller.probe();
      expect(probe.status).toBe("available");
      const result = await controller.execute({ request: makeRequest(layout, operation) });
      expect(result.state, JSON.stringify(result)).toBe("completed");
      expect(result.state === "completed" ? result.exitCode : undefined).toBe(0);
      expect(result.stdout).toContain("control-policy-ok");
      expect(readFileSync(agentsFile, "utf8")).toBe("skill content");
      expect(readFileSync(codexFile, "utf8")).toBe("model = 'test'");

      const denyCommand = `try { [void](Get-Content -Raw -LiteralPath '${agentsFile}' -ErrorAction Stop); exit 22 } catch { Write-Output 'deny-path-blocked'; exit 0 }`;
      const sensitivePaths = collectSensitivePaths({
        agentDirectory: layout.agentDirectory,
        cwd: layout.workspace,
        home: layout.workspace,
        environment: {},
        platform: "win32",
        denyPaths: [agentsFile],
      });
      const denied = await controller.execute({ request: makeRequest(layout, {
        kind: "shell", shell, command: denyCommand,
      }, sensitivePaths) });
      expect(denied.state, JSON.stringify(denied)).toBe("completed");
      expect(denied.state === "completed" ? denied.exitCode : undefined).toBe(0);
      expect(denied.stdout).toContain("deny-path-blocked");
      expect(denied.stdout).not.toContain("skill content");
    } finally {
      await controller.dispose();
    }
  }, 60_000);

  it("continues using the selected runtime after a manifest file change", async () => {
    if (!runtime?.files.runtimeManifest) throw new Error("runtime manifest is unavailable");
    const layout = createLayout();
    const backend = createBackend(layout);
    const before = readFileSync(runtime.files.runtimeManifest);
    await backend.probe();
    try {
      const changed = JSON.parse(before.toString("utf8")) as { version: string };
      changed.version = "1.0.2";
      writeFileSync(runtime.files.runtimeManifest, JSON.stringify(changed));
      const request = makeRequest(layout, {
        kind: "shell",
        shell: join(process.env.SystemRoot ?? "C:\\Windows", "System32", "cmd.exe"),
        command: "echo must-not-start",
      });

      await expect(backend.prepare(request)).resolves.toMatchObject({ executable: runtime.files.windowsExecutable });
    } finally {
      writeFileSync(runtime.files.runtimeManifest, before);
    }
  });

  it("rejects an unsupported builtin before preparing a native launch", async () => {
    const layout = createLayout();
    const request = makeRequest(layout, { kind: "builtin-tool", name: "bash", arguments: { command: "echo unsupported" } });

    await expect(createBackend(layout).prepare(request)).resolves.toMatchObject({
      ok: false,
      code: "unsupported",
      reason: "the bash builtin is unsupported by the Windows MXC backend",
    });
  });
});
