import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { ExecutionController } from "#sandbox/lifecycle";
import { createWindowsDirectBackend } from "#sandbox/backend/windows/direct";
import { PROTECTED_CONTROL_DIRECTORY_NAMES } from "#sandbox/path";
import { windowsRuntimeFilesystem } from "#sandbox/runtime-filesystem";
import type { ExecutionRequest } from "#sandbox/types";
import type { ResolvedRuntimeFiles } from "#sandbox/runtime-store";
import { compileTestRequest, makeInvocation, runtimeEnvironment, waitFor } from "../../fixtures/harness";
import { installWindowsTestRuntime } from "../../fixtures/runtime";
import {
  COUNTER_MODULE,
  errorTextOf,
  SLOW_MODULE,
  textOf,
  THROWING_MODULE,
  WRITER_MODULE,
  writeModule,
} from "../sandbox-tool-fixtures";

const executable = fileURLToPath(new URL("../../../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url));
const packageRoot = realpathSync(fileURLToPath(new URL("../../../../", import.meta.url)));
const TOOL_NAME = "native_probe_tool";
let runtime: ResolvedRuntimeFiles | undefined;

beforeAll(() => {
  if (process.platform === "win32" && existsSync(executable)) runtime = installWindowsTestRuntime();
});
afterAll(() => {
  if (runtime) rmSync(runtime.directory, { recursive: true, force: true });
});

/** The Windows runtime environment a sandboxed node worker needs. */
function toolEnvironment(): Record<string, string> {
  const environment: Record<string, string> = {};
  for (const name of ["SystemRoot", "SystemDrive", "LOCALAPPDATA", "PATH"]) {
    const value = process.env[name];
    if (typeof value === "string") environment[name] = value;
  }
  return environment;
}

/** Host environment for the native launcher; it resolves its AppContainer from LOCALAPPDATA. */
function nativeEnvironment(): Record<string, string> {
  const environment: Record<string, string> = { ...runtimeEnvironment() };
  const localAppData = process.env.LOCALAPPDATA;
  if (typeof localAppData === "string") environment.LOCALAPPDATA = localAppData;
  if (runtime) environment.PI_SANDBOX_RUNTIME_DIR = runtime.directory;
  return environment;
}

function createController(layout: NativeLayout): ExecutionController {
  if (!runtime) throw new Error("Windows native runtime is unavailable");
  const environment = nativeEnvironment();
  return new ExecutionController({
    directBackend: createWindowsDirectBackend({
      runtime,
      installRoot: packageRoot,
      hostCwd: layout.hostCwd,
      hostEnvironment: environment,
    }),
    startTimeoutMs: 5_000,
    cancelGraceMs: 500,
  });
}

interface NativeLayout {
  readonly root: string;
  readonly workspace: string;
  readonly modules: string;
  readonly stateDirectory: string;
  readonly outside: string;
  readonly hostCwd: string;
}

function createLayout(prefix: string): NativeLayout {
  const root = realpathSync(mkdtempSync(join(tmpdir(), prefix)));
  const workspace = join(root, "workspace");
  const modules = join(root, "modules");
  const stateDirectory = join(workspace, ".pi", "sandbox-tools", TOOL_NAME);
  const outside = join(root, "outside");
  const hostCwd = join(root, "native-cwd");
  for (const directory of [workspace, modules, stateDirectory, outside, hostCwd]) mkdirSync(directory, { recursive: true });
  for (const name of PROTECTED_CONTROL_DIRECTORY_NAMES) mkdirSync(join(workspace, name), { recursive: true });
  return { root, workspace, modules, stateDirectory, outside, hostCwd };
}

/** One host request with exactly the grants a declared sandbox tool needs. */
function toolPlan(options: {
  readonly layout: NativeLayout;
  readonly modulePath: string;
  readonly arguments?: Record<string, string>;
  readonly config?: Record<string, string>;
  readonly protectedPaths?: readonly string[];
}): ExecutionRequest {
  const operation = {
    kind: "sandbox-tool" as const, name: TOOL_NAME, modulePath: options.modulePath,
    stateDirectory: options.layout.stateDirectory, arguments: options.arguments ?? {},
    ...(options.config === undefined ? {} : { config: options.config }),
  };
  const runtime = windowsRuntimeFilesystem({ cwd: options.layout.workspace, installRoot: packageRoot,
    agentDirectory: options.layout.root, operation, environment: toolEnvironment() });
  const filesystem = [
    { path: options.layout.workspace, access: "read" as const, granularity: "directory" as const, source: "baseline" as const },
    { path: options.layout.workspace, access: "write" as const, granularity: "directory" as const, source: "baseline" as const },
    { path: options.layout.modules, access: "read" as const, granularity: "directory" as const, source: "approved-extension" as const },
    { path: options.layout.stateDirectory, access: "write" as const, granularity: "directory" as const, source: "approved-extension" as const },
    ...runtime.grants.map(grant => ({ ...grant, source: "runtime" as const })),
    ...[...(options.protectedPaths ?? []), ...runtime.protectedPaths].map(path => ({ path,
      access: "deny-write" as const, granularity: path === realpathSync.native(process.execPath) ? "file" as const : "directory" as const,
      source: "protection" as const })),
  ];
  const environment = toolEnvironment();
  const plan = { version: 3 as const, filesystem, network: { kind: "none" as const }, metadataRead: "none" as const,
    digest: "0".repeat(64) };
  return {
    plan,
    requestId: "native-sandbox-tool",
    toolCallId: TOOL_NAME,
    actionDigest: "0".repeat(64),
    sessionId: "native-sandbox-tool-session",
    toolName: TOOL_NAME,
    mode: "default",
    policyRevision: "native-test-policy",
    configRevision: "native-test-config",
    backendId: "windows-mxc",
    start: { cwd: options.layout.workspace, operation, environment, deadlineAt: Date.now() + 30_000 },
  };
}

describe.skipIf(process.platform !== "win32" || !existsSync(executable))("Windows native sandbox tool", () => {
  it("executes a declared third-party tool inside the native boundary", async () => {
    const layout = createLayout("mxc-sandbox-tool-");
    const modulePath = writeModule(layout, "counter.mjs", COUNTER_MODULE);
    const controller = createController(layout);
    try {
      const first = await controller.execute({ request: toolPlan({
        layout, modulePath, arguments: { value: "one" }, config: { mode: "native" },
      }) });
      expect(first, JSON.stringify(first)).toMatchObject({ state: "completed", started: true, exitCode: 0 });
      const firstText = JSON.parse(textOf(first)) as Record<string, unknown>;
      expect(firstText).toMatchObject({
        count: "1",
        value: "one",
        cwd: layout.workspace,
        toolName: TOOL_NAME,
        config: { mode: "native" },
      });

      // A second one-shot worker sees the state the first call persisted.
      const second = await controller.execute({ request: toolPlan({
        layout, modulePath, arguments: { value: "two" },
      }) });
      expect(second, JSON.stringify(second)).toMatchObject({ state: "completed", started: true, exitCode: 0 });
      expect(JSON.parse(textOf(second))).toMatchObject({ count: "2", value: "two" });
      expect(readFileSync(join(layout.stateDirectory, "count.txt"), "utf8")).toBe("2");
    } finally {
      await controller.dispose();
      rmSync(layout.root, { recursive: true, force: true });
    }
  }, 30_000);

  it("denies a tool write outside the granted directories and keeps the controller usable", async () => {
    const layout = createLayout("mxc-sandbox-tool-outside-");
    const modulePath = writeModule(layout, "writer.mjs", WRITER_MODULE);
    const target = join(layout.outside, "escaped.txt");
    const controller = createController(layout);
    try {
      const denied = await controller.execute({ request: toolPlan({
        layout, modulePath, arguments: { target },
      }) });
      expect(denied, JSON.stringify(denied)).toMatchObject({ state: "failed", started: true, code: "execution-failed" });
      expect(errorTextOf(denied)).toContain(target);
      expect(existsSync(target)).toBe(false);

      // Each call gets a fresh native process while the controller remains usable.
      const next = await controller.execute({ request: toolPlan({
        layout, modulePath: writeModule(layout, "counter.mjs", COUNTER_MODULE), arguments: { value: "after-denial" },
      }) });
      expect(next, JSON.stringify(next)).toMatchObject({ state: "completed", started: true, exitCode: 0 });
      expect(JSON.parse(textOf(next))).toMatchObject({ count: "1", value: "after-denial" });
    } finally {
      await controller.dispose();
      rmSync(layout.root, { recursive: true, force: true });
    }
  }, 30_000);

  it("denies a tool write into a protected control directory", async () => {
    const layout = createLayout("mxc-sandbox-tool-protected-");
    const modulePath = writeModule(layout, "writer.mjs", WRITER_MODULE);
    const protectedDirectory = join(layout.workspace, ".git");
    const target = join(protectedDirectory, "config");
    writeFileSync(target, "protected-original");
    const controller = createController(layout);
    try {
      const denied = await controller.execute({ request: toolPlan({
        layout, modulePath, arguments: { target }, protectedPaths: [protectedDirectory],
      }) });
      expect(denied, JSON.stringify(denied)).toMatchObject({ state: "failed", started: true, code: "execution-failed" });
      expect(errorTextOf(denied)).toContain(target);
      expect(readFileSync(target, "utf8")).toBe("protected-original");
    } finally {
      await controller.dispose();
      rmSync(layout.root, { recursive: true, force: true });
    }
  }, 30_000);

  it("returns a readable error when the tool throws and keeps the controller usable", async () => {
    const layout = createLayout("mxc-sandbox-tool-throw-");
    const modulePath = writeModule(layout, "throwing.mjs", THROWING_MODULE);
    const controller = createController(layout);
    try {
      const thrown = await controller.execute({ request: toolPlan({ layout, modulePath }) });
      expect(thrown, JSON.stringify(thrown)).toMatchObject({ state: "failed", started: true, code: "execution-failed" });
      expect(errorTextOf(thrown)).toContain("native sandbox tool boom");

      const next = await controller.execute({ request: toolPlan({
        layout, modulePath: writeModule(layout, "counter.mjs", COUNTER_MODULE), arguments: { value: "after-throw" },
      }) });
      expect(next, JSON.stringify(next)).toMatchObject({ state: "completed", started: true, exitCode: 0 });
      expect(JSON.parse(textOf(next))).toMatchObject({ count: "1", value: "after-throw" });
    } finally {
      await controller.dispose();
      rmSync(layout.root, { recursive: true, force: true });
    }
  }, 30_000);

  it("terminates a cancelled slow tool and keeps the controller usable", async () => {
    const layout = createLayout("mxc-sandbox-tool-cancel-");
    const marker = join(layout.stateDirectory, "slow-started.txt");
    const modulePath = writeModule(layout, "slow.mjs", `import { writeFileSync } from "node:fs";
export async function execute(_args, ctx) {
  writeFileSync(ctx.stateDirectory + "/slow-started.txt", "started");
  await new Promise(resolve => setTimeout(resolve, 600_000));
  return { content: [] };
}
`);
    const controller = createController(layout);
    try {
      const request = toolPlan({ layout, modulePath });
      const pending = controller.execute({ request });
      await waitFor(() => existsSync(marker), 15_000);
      const startedAt = Date.now();
      await controller.cancel(request.requestId);
      const cancelled = await pending;
      expect(cancelled, JSON.stringify(cancelled)).toMatchObject({ state: "cancelled", started: true });
      expect(Date.now() - startedAt).toBeLessThan(15_000);

      const next = await controller.execute({ request: toolPlan({
        layout, modulePath: writeModule(layout, "counter.mjs", COUNTER_MODULE), arguments: { value: "after-cancel" },
      }) });
      expect(next, JSON.stringify(next)).toMatchObject({ state: "completed", started: true, exitCode: 0 });
      expect(JSON.parse(textOf(next))).toMatchObject({ count: "1", value: "after-cancel" });
    } finally {
      await controller.dispose();
      rmSync(layout.root, { recursive: true, force: true });
    }
  }, 30_000);
});

/**
 * The fixed 60 s adapter bound is exercised through the plan deadline instead:
 * the controller is the component that turns an expired deadline into a
 * termination plus a readable timeout outcome (design §6.4).
 */
describe.skipIf(process.platform !== "win32" || !existsSync(executable))("Windows native sandbox tool deadline", () => {
  function controllerPlan(options: {
    readonly layout: NativeLayout;
    readonly modulePath: string;
    readonly requestId: string;
    readonly toolCallId: string;
    readonly arguments?: Record<string, string>;
    readonly deadlineMs: number;
  }): ExecutionRequest {
    const invocation = makeInvocation({
      cwd: options.layout.workspace,
      toolName: TOOL_NAME,
      args: options.arguments ?? {},
      requestId: options.requestId,
      toolCallId: options.toolCallId,
      scopes: [
        { id: "sandbox-tool:module", surface: "path_read", target: options.layout.modules, access: "read", state: "allow", source: "native-test" },
        { id: "sandbox-tool:state", surface: "path_write", target: options.layout.stateDirectory, access: "write", state: "allow", source: "native-test" },
      ],
    });
    const operation = { kind: "sandbox-tool" as const, name: TOOL_NAME, modulePath: options.modulePath,
      stateDirectory: options.layout.stateDirectory, arguments: options.arguments ?? {} };
    const runtime = windowsRuntimeFilesystem({ cwd: options.layout.workspace, installRoot: packageRoot,
      agentDirectory: options.layout.root, operation, environment: toolEnvironment() });
    return compileTestRequest({
      invocation,
      operation,
      runtimeFilesystem: runtime.grants,
      protectedPaths: runtime.protectedPaths,
      workspace: options.layout.workspace,
      backendId: "windows-mxc",
      approved: {
        filesystem: [
          { path: options.layout.modules, access: "read", granularity: "directory" },
          { path: options.layout.stateDirectory, access: "write", granularity: "directory" },
        ],
      },
      environment: toolEnvironment(),
      deadlineMs: options.deadlineMs,
    });
  }

  it("terminates a slow tool at the plan deadline and reports a readable timeout", async () => {
    const layout = createLayout("mxc-sandbox-tool-deadline-");
    const slowPath = writeModule(layout, "slow.mjs", SLOW_MODULE);
    const counterPath = writeModule(layout, "counter.mjs", COUNTER_MODULE);
    const controller = createController(layout);
    try {
      const startedAt = Date.now();
      const outcome = await controller.execute({
        request: controllerPlan({ layout, modulePath: slowPath, requestId: "deadline", toolCallId: "deadline", deadlineMs: 2_000 }),
      });
      const elapsed = Date.now() - startedAt;
      expect(outcome.state, JSON.stringify(outcome)).toBe("cancelled");
      expect(outcome.state === "cancelled" ? outcome.code : undefined).toBe("execution-timeout");
      expect(outcome.state === "cancelled" ? outcome.reason : "").toContain("execution deadline expired");
      expect(elapsed).toBeGreaterThanOrEqual(1_000);
      expect(elapsed).toBeLessThan(20_000);

      // The same controller still runs the next declared tool call.
      const next = await controller.execute({
        request: controllerPlan({
          layout, modulePath: counterPath, requestId: "deadline-next", toolCallId: "deadline-next",
          arguments: { value: "after-timeout" }, deadlineMs: 20_000,
        }),
      });
      expect(next.state, JSON.stringify(next)).toBe("completed");
      expect(textOf(next)).toContain("after-timeout");
    } finally {
      await controller.dispose();
      rmSync(layout.root, { recursive: true, force: true });
    }
  }, 40_000);
});
