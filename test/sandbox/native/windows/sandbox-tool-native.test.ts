import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { ExecutionController } from "#sandbox/lifecycle";
import { PROTECTED_CONTROL_DIRECTORY_NAMES } from "#sandbox/path";
import type { ExecutionPlan } from "#sandbox/types";
import { compileTestPlan, makeInvocation, runtimeEnvironment } from "../../fixtures/harness";
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

const helper = fileURLToPath(new URL("../../../../src/sandbox/backend/windows/helper.mjs", import.meta.url));
const executable = fileURLToPath(new URL("../../../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url));
const packageRoot = realpathSync(fileURLToPath(new URL("../../../../", import.meta.url)));
const TOOL_NAME = "native_probe_tool";
let runtimeDirectory: string | undefined;

beforeAll(() => {
  if (process.platform === "win32" && existsSync(executable)) runtimeDirectory = installWindowsTestRuntime().directory;
});
afterAll(() => {
  if (runtimeDirectory) rmSync(runtimeDirectory, { recursive: true, force: true });
});

/** The Windows runtime environment a sandboxed node worker needs. */
function toolEnvironment(): Record<string, string> {
  const environment: Record<string, string> = {};
  for (const name of ["SystemRoot", "PATH"]) {
    const value = process.env[name];
    if (typeof value === "string") environment[name] = value;
  }
  return environment;
}

/** Helper process environment; the native launcher resolves its AppContainer from LOCALAPPDATA. */
function helperEnvironment(): Record<string, string> {
  const environment: Record<string, string> = { ...runtimeEnvironment() };
  const localAppData = process.env.LOCALAPPDATA;
  if (typeof localAppData === "string") environment.LOCALAPPDATA = localAppData;
  if (runtimeDirectory) environment.PI_SANDBOX_RUNTIME_DIR = runtimeDirectory;
  return environment;
}

interface HelperCall {
  readonly started: Promise<Record<string, unknown>>;
  readonly result: Promise<Record<string, unknown>>;
}

interface HelperClient {
  readonly ready: () => Promise<Record<string, unknown>>;
  readonly start: (requestId: string, plan: Record<string, unknown>) => HelperCall;
  readonly cancel: (requestId: string) => void;
  readonly close: () => void;
}

/** Drive the helper's one-shot JSON protocol, as the execution controller does. */
function createHelperClient(): HelperClient {
  const child: ChildProcessWithoutNullStreams = spawn(process.execPath, [helper], {
    stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, PI_SANDBOX_RUNTIME_DIR: runtimeDirectory },
  });
  let buffer = "";
  let readyResolve!: (message: Record<string, unknown>) => void;
  let fail!: (error: Error) => void;
  const ready = new Promise<Record<string, unknown>>((resolve, reject) => {
    readyResolve = resolve;
    fail = reject;
  });
  const started = new Map<string, (message: Record<string, unknown>) => void>();
  const results = new Map<string, (message: Record<string, unknown>) => void>();
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => {
    buffer += chunk;
    for (;;) {
      const end = buffer.indexOf("\n");
      if (end < 0) break;
      const message = JSON.parse(buffer.slice(0, end)) as Record<string, unknown>;
      buffer = buffer.slice(end + 1);
      const requestId = String(message.requestId ?? "");
      if (message.type === "ready") readyResolve(message);
      else if (message.type === "started") started.get(requestId)?.(message);
      else if (message.type === "result" || message.type === "rejected" || message.type === "error" || message.type === "cancelled") results.get(requestId)?.(message);
      else if (message.type !== "output") fail(new Error(`unexpected helper message: ${JSON.stringify(message)}`));
    }
  });
  child.on("error", fail);
  child.on("exit", code => fail(new Error(`helper exited before a response: ${String(code)}`)));
  child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "hello", generation: 1 }) + "\n");
  return {
    ready: () => ready,
    start: (requestId, plan) => {
      let startedResolve!: (message: Record<string, unknown>) => void;
      let resultResolve!: (message: Record<string, unknown>) => void;
      const startedPromise = new Promise<Record<string, unknown>>(resolve => { startedResolve = resolve; });
      const resultPromise = new Promise<Record<string, unknown>>((resolve) => { resultResolve = resolve; });
      started.set(requestId, startedResolve);
      results.set(requestId, resultResolve);
      child.stdin.write(JSON.stringify({ type: "start", requestId, generation: 1, plan }) + "\n");
      return { started: startedPromise, result: resultPromise };
    },
    cancel: requestId => child.stdin.write(JSON.stringify({ type: "cancel", requestId, generation: 1 }) + "\n"),
    close: () => child.kill(),
  };
}

interface NativeLayout {
  readonly root: string;
  readonly workspace: string;
  readonly modules: string;
  readonly stateDirectory: string;
  readonly outside: string;
  readonly helperCwd: string;
}

function createLayout(prefix: string): NativeLayout {
  const root = realpathSync(mkdtempSync(join(tmpdir(), prefix)));
  const workspace = join(root, "workspace");
  const modules = join(root, "modules");
  const stateDirectory = join(workspace, ".pi", "sandbox-tools", TOOL_NAME);
  const outside = join(root, "outside");
  const helperCwd = join(root, "helper-cwd");
  for (const directory of [workspace, modules, stateDirectory, outside, helperCwd]) mkdirSync(directory, { recursive: true });
  for (const name of PROTECTED_CONTROL_DIRECTORY_NAMES) mkdirSync(join(workspace, name), { recursive: true });
  return { root, workspace, modules, stateDirectory, outside, helperCwd };
}

/** One raw helper plan with exactly the grants a declared sandbox tool needs. */
function toolPlan(options: {
  readonly layout: NativeLayout;
  readonly modulePath: string;
  readonly arguments?: Record<string, string>;
  readonly config?: Record<string, string>;
  readonly protectedPaths?: readonly string[];
}): Record<string, unknown> {
  return {
    backend: { id: "windows-mxc" },
    cwd: options.layout.workspace,
    toolCallId: TOOL_NAME,
    filesystem: [
      { path: options.layout.workspace, access: "read", granularity: "directory" },
      { path: options.layout.workspace, access: "write", granularity: "directory" },
      { path: options.layout.modules, access: "read", granularity: "directory" },
      { path: options.layout.stateDirectory, access: "write", granularity: "directory" },
    ],
    protectedPaths: [...(options.protectedPaths ?? [])],
    network: { kind: "none" },
    environment: toolEnvironment(),
    operation: {
      kind: "sandbox-tool",
      name: TOOL_NAME,
      modulePath: options.modulePath,
      stateDirectory: options.layout.stateDirectory,
      arguments: options.arguments ?? {},
      ...(options.config === undefined ? {} : { config: options.config }),
    },
  };
}

describe.skipIf(process.platform !== "win32" || !existsSync(executable))("Windows native sandbox tool", () => {
  it("executes a declared third-party tool inside the native boundary", async () => {
    const layout = createLayout("mxc-sandbox-tool-");
    const modulePath = writeModule(layout, "counter.mjs", COUNTER_MODULE);
    const client = createHelperClient();
    try {
      await client.ready();
      const first = await client.start("counter-1", toolPlan({
        layout, modulePath, arguments: { value: "one" }, config: { mode: "native" },
      })).result;
      expect(first, JSON.stringify(first)).toMatchObject({ type: "result", started: true, exitCode: 0 });
      const firstText = JSON.parse(textOf(first)) as Record<string, unknown>;
      expect(firstText).toMatchObject({
        count: "1",
        value: "one",
        cwd: layout.workspace,
        toolName: TOOL_NAME,
        config: { mode: "native" },
      });

      // A second one-shot worker sees the state the first call persisted.
      const second = await client.start("counter-2", toolPlan({
        layout, modulePath, arguments: { value: "two" },
      })).result;
      expect(second, JSON.stringify(second)).toMatchObject({ type: "result", started: true, exitCode: 0 });
      expect(JSON.parse(textOf(second))).toMatchObject({ count: "2", value: "two" });
      expect(readFileSync(join(layout.stateDirectory, "count.txt"), "utf8")).toBe("2");
    } finally {
      client.close();
      rmSync(layout.root, { recursive: true, force: true });
    }
  }, 30_000);

  it("denies a tool write outside the granted directories and keeps the helper usable", async () => {
    const layout = createLayout("mxc-sandbox-tool-outside-");
    const modulePath = writeModule(layout, "writer.mjs", WRITER_MODULE);
    const target = join(layout.outside, "escaped.txt");
    const client = createHelperClient();
    try {
      await client.ready();
      const denied = await client.start("outside-write", toolPlan({
        layout, modulePath, arguments: { target },
      })).result;
      expect(denied, JSON.stringify(denied)).toMatchObject({ type: "result", started: true, exitCode: 1, errorCode: "tool" });
      expect(String(denied.error)).toMatch(/EPERM|EACCES|permission denied/iu);
      expect(String(denied.error)).toContain(target);
      expect(errorTextOf(denied)).toContain(target);
      expect(existsSync(target)).toBe(false);

      // The denial is one tool result: the helper and the session continue.
      const next = await client.start("outside-write-next", toolPlan({
        layout, modulePath: writeModule(layout, "counter.mjs", COUNTER_MODULE), arguments: { value: "after-denial" },
      })).result;
      expect(next, JSON.stringify(next)).toMatchObject({ type: "result", started: true, exitCode: 0 });
      expect(JSON.parse(textOf(next))).toMatchObject({ count: "1", value: "after-denial" });
    } finally {
      client.close();
      rmSync(layout.root, { recursive: true, force: true });
    }
  }, 30_000);

  it("denies a tool write into a protected control directory", async () => {
    const layout = createLayout("mxc-sandbox-tool-protected-");
    const modulePath = writeModule(layout, "writer.mjs", WRITER_MODULE);
    const protectedDirectory = join(layout.workspace, ".git");
    const target = join(protectedDirectory, "config");
    writeFileSync(target, "protected-original");
    const client = createHelperClient();
    try {
      await client.ready();
      const denied = await client.start("protected-write", toolPlan({
        layout, modulePath, arguments: { target }, protectedPaths: [protectedDirectory],
      })).result;
      expect(denied, JSON.stringify(denied)).toMatchObject({ type: "result", started: true, exitCode: 1, errorCode: "tool" });
      expect(String(denied.error)).toMatch(/EPERM|EACCES|permission denied/iu);
      expect(String(denied.error)).toContain(target);
      expect(readFileSync(target, "utf8")).toBe("protected-original");
    } finally {
      client.close();
      rmSync(layout.root, { recursive: true, force: true });
    }
  }, 30_000);

  it("returns a readable error when the tool throws and keeps the helper usable", async () => {
    const layout = createLayout("mxc-sandbox-tool-throw-");
    const modulePath = writeModule(layout, "throwing.mjs", THROWING_MODULE);
    const client = createHelperClient();
    try {
      await client.ready();
      const thrown = await client.start("throwing", toolPlan({ layout, modulePath })).result;
      expect(thrown, JSON.stringify(thrown)).toMatchObject({ type: "result", started: true, exitCode: 1, errorCode: "tool" });
      expect(String(thrown.error)).toContain("native sandbox tool boom");
      expect(errorTextOf(thrown)).toContain("native sandbox tool boom");

      const next = await client.start("throwing-next", toolPlan({
        layout, modulePath: writeModule(layout, "counter.mjs", COUNTER_MODULE), arguments: { value: "after-throw" },
      })).result;
      expect(next, JSON.stringify(next)).toMatchObject({ type: "result", started: true, exitCode: 0 });
      expect(JSON.parse(textOf(next))).toMatchObject({ count: "1", value: "after-throw" });
    } finally {
      client.close();
      rmSync(layout.root, { recursive: true, force: true });
    }
  }, 30_000);

  it("terminates a cancelled slow tool and keeps the helper usable", async () => {
    const layout = createLayout("mxc-sandbox-tool-cancel-");
    const modulePath = writeModule(layout, "slow.mjs", SLOW_MODULE);
    const client = createHelperClient();
    try {
      await client.ready();
      const call = client.start("slow", toolPlan({ layout, modulePath }));
      await call.started;
      const startedAt = Date.now();
      client.cancel("slow");
      const cancelled = await call.result;
      expect(cancelled, JSON.stringify(cancelled)).toMatchObject({ type: "cancelled", started: true });
      expect(Date.now() - startedAt).toBeLessThan(15_000);

      const next = await client.start("slow-next", toolPlan({
        layout, modulePath: writeModule(layout, "counter.mjs", COUNTER_MODULE), arguments: { value: "after-cancel" },
      })).result;
      expect(next, JSON.stringify(next)).toMatchObject({ type: "result", started: true, exitCode: 0 });
      expect(JSON.parse(textOf(next))).toMatchObject({ count: "1", value: "after-cancel" });
    } finally {
      client.close();
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
  }): ExecutionPlan {
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
    return compileTestPlan({
      invocation,
      operation: {
        kind: "sandbox-tool",
        name: TOOL_NAME,
        modulePath: options.modulePath,
        stateDirectory: options.layout.stateDirectory,
        arguments: options.arguments ?? {},
      },
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
    const controller = new ExecutionController({
      installation: {
        installRoot: packageRoot,
        executable: process.execPath,
        args: [helper],
        expectedBackendId: "windows-mxc",
      },
      helperCwd: layout.helperCwd,
      workspace: layout.workspace,
      helperEnvironment: helperEnvironment(),
      startTimeoutMs: 5_000,
      cancelGraceMs: 500,
    });
    try {
      const startedAt = Date.now();
      const outcome = await controller.execute({
        plan: controllerPlan({ layout, modulePath: slowPath, requestId: "deadline", toolCallId: "deadline", deadlineMs: 2_000 }),
      });
      const elapsed = Date.now() - startedAt;
      expect(outcome.state, JSON.stringify(outcome)).toBe("cancelled");
      expect(outcome.state === "cancelled" ? outcome.code : undefined).toBe("execution-timeout");
      expect(outcome.state === "cancelled" ? outcome.reason : "").toContain("execution deadline expired");
      expect(elapsed).toBeGreaterThanOrEqual(1_000);
      expect(elapsed).toBeLessThan(20_000);

      // The same controller still runs the next declared tool call.
      const next = await controller.execute({
        plan: controllerPlan({
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
