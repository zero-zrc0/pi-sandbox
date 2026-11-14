import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { ExecutionController } from "#sandbox/lifecycle";
import { PROTECTED_CONTROL_DIRECTORY_NAMES } from "#sandbox/path";
import type { ExecutionPlan } from "#sandbox/types";
import { compileTestPlan, makeInvocation } from "../../fixtures/harness";
import {
  COUNTER_MODULE,
  errorTextOf,
  SLOW_MODULE,
  textOf,
  THROWING_MODULE,
  WRITER_MODULE,
  writeModule,
} from "../sandbox-tool-fixtures";

const backendId = "linux-bwrap-landlock-seccomp";
const backendVersion = "1.1.0";
const backendSource = fileURLToPath(new URL("../../../../src/sandbox/backend/linux/", import.meta.url));
const workerSource = fileURLToPath(new URL("../../../../src/sandbox/sandbox-tool-worker.mjs", import.meta.url));
const TOOL_NAME = "native_probe_tool";

interface LinuxLayout {
  readonly root: string;
  readonly installRoot: string;
  readonly helperDir: string;
  readonly helperCwd: string;
  readonly workspace: string;
  readonly modules: string;
  readonly stateDirectory: string;
  readonly outside: string;
}

/**
 * Build the native launcher and install the helper in a package-shaped layout:
 * the helper resolves its runner (`../../sandbox-tool-worker.mjs`) and the
 * read-only package root from its own location, exactly like the real install.
 */
function createLinuxLayout(prefix: string): LinuxLayout {
  const root = realpathSync(mkdtempSync(join(tmpdir(), prefix)));
  const installRoot = join(root, "trusted-install");
  const helperDir = join(installRoot, "src", "sandbox", "backend", "linux");
  const helperCwd = join(root, "helper-cwd");
  const workspace = join(root, "workspace");
  const modules = join(root, "modules");
  const stateDirectory = join(workspace, ".pi", "sandbox-tools", TOOL_NAME);
  const outside = join(root, "outside");
  for (const directory of [helperDir, helperCwd, workspace, modules, stateDirectory, outside]) {
    mkdirSync(directory, { recursive: true });
  }
  for (const name of PROTECTED_CONTROL_DIRECTORY_NAMES) {
    mkdirSync(join(workspace, name), { recursive: true });
  }
  execFileSync("bash", [join(backendSource, "build.sh"), join(helperDir, "linux-sandbox")]);
  copyFileSync(join(backendSource, "helper.mjs"), join(helperDir, "helper.mjs"));
  copyFileSync(workerSource, join(installRoot, "src", "sandbox", "sandbox-tool-worker.mjs"));
  return { root, installRoot, helperDir, helperCwd, workspace, modules, stateDirectory, outside };
}

const PING_MODULE = `export async function execute(args, ctx) {
  return { content: [{ type: "text", text: JSON.stringify({ pong: args.value, cwd: ctx.cwd }) }] };
}
`;

describe.skipIf(process.platform !== "linux")("native Linux sandbox tool", () => {
  let layout: LinuxLayout;
  let controller: ExecutionController;

  beforeAll(() => {
    layout = createLinuxLayout("plan13-linux-sandbox-tool-");
    controller = new ExecutionController({
      installation: {
        installRoot: layout.installRoot,
        executable: process.execPath,
        args: [join(layout.helperDir, "helper.mjs")],
        expectedBackendId: backendId,
        expectedBackendVersion: backendVersion,
      },
      helperCwd: layout.helperCwd,
      workspace: layout.workspace,
      helperEnvironment: { HOME: "/nonexistent", LANG: "C.UTF-8", PATH: "/usr/bin:/bin" },
      startTimeoutMs: 5_000,
      cancelGraceMs: 250,
    });
  });

  afterAll(async () => {
    await controller?.dispose();
    if (layout) rmSync(layout.root, { recursive: true, force: true });
  });

  function sandboxToolPlan(options: {
    readonly modulePath: string;
    readonly requestId: string;
    readonly toolCallId: string;
    readonly arguments?: Record<string, string>;
    readonly config?: Record<string, string>;
    readonly deadlineMs?: number;
  }): ExecutionPlan {
    const invocation = makeInvocation({
      cwd: layout.workspace,
      toolName: TOOL_NAME,
      args: options.arguments ?? {},
      requestId: options.requestId,
      toolCallId: options.toolCallId,
      scopes: [
        { id: "sandbox-tool:module", surface: "path_read", target: layout.modules, access: "read", state: "allow", source: "native-test" },
        { id: "sandbox-tool:state", surface: "path_write", target: layout.stateDirectory, access: "write", state: "allow", source: "native-test" },
      ],
    });
    return compileTestPlan({
      invocation,
      operation: {
        kind: "sandbox-tool",
        name: TOOL_NAME,
        modulePath: options.modulePath,
        stateDirectory: layout.stateDirectory,
        arguments: options.arguments ?? {},
        ...(options.config === undefined ? {} : { config: options.config }),
      },
      workspace: layout.workspace,
      backendId,
      approved: {
        filesystem: [
          { path: layout.modules, access: "read", granularity: "directory" },
          { path: layout.stateDirectory, access: "write", granularity: "directory" },
        ],
      },
      deadlineMs: options.deadlineMs ?? 20_000,
    });
  }

  it("executes a declared third-party tool inside the native boundary", async () => {
    const modulePath = writeModule(layout, "counter.mjs", COUNTER_MODULE);
    const first = await controller.execute({
      plan: sandboxToolPlan({
        modulePath, requestId: "tool-1", toolCallId: "tool-1",
        arguments: { value: "one" }, config: { mode: "native" },
      }),
    });
    expect(first.state, JSON.stringify(first)).toBe("completed");
    const firstResult = JSON.parse(textOf(first));
    expect(firstResult).toMatchObject({
      value: "one",
      cwd: layout.workspace,
      toolName: TOOL_NAME,
      config: { mode: "native" },
    });

    // A second one-shot worker sees the state the first call persisted.
    const second = await controller.execute({
      plan: sandboxToolPlan({
        modulePath, requestId: "tool-2", toolCallId: "tool-2",
        arguments: { value: "two" },
      }),
    });
    expect(second.state, JSON.stringify(second)).toBe("completed");
    const secondResult = JSON.parse(textOf(second));
    expect(secondResult).toMatchObject({ value: "two" });
    expect(Number(secondResult.count)).toBe(Number(firstResult.count) + 1);
    expect(readFileSync(join(layout.stateDirectory, "count.txt"), "utf8")).toBe(String(secondResult.count));
  }, 30_000);

  it("denies a tool write outside the granted directories and keeps the session usable", async () => {
    const modulePath = writeModule(layout, "writer.mjs", WRITER_MODULE);
    const target = join(layout.outside, "escaped.txt");
    const denied = await controller.execute({
      plan: sandboxToolPlan({
        modulePath, requestId: "outside-write", toolCallId: "outside-write",
        arguments: { target },
      }),
    });
    expect(denied.state, JSON.stringify(denied)).toBe("failed");
    expect(denied.state === "failed" ? denied.code : undefined).toBe("execution-failed");
    const reason = denied.state === "failed" ? denied.reason : "";
    // bwrap exposes unapproved paths as a read-only mount, so the native
    // denial text is EROFS rather than EACCES (Windows MXC says EPERM).
    expect(reason).toMatch(/EACCES|EPERM|EROFS|read-only file system|permission denied/iu);
    expect(reason).toContain(target);
    expect(errorTextOf(denied)).toContain(target);
    expect(existsSync(target)).toBe(false);

    // The denial is one tool result: the session and the helper continue.
    const next = await controller.execute({
      plan: sandboxToolPlan({
        modulePath: writeModule(layout, "ping.mjs", PING_MODULE),
        requestId: "outside-write-next", toolCallId: "outside-write-next",
        arguments: { value: "after-denial" },
      }),
    });
    expect(next.state, JSON.stringify(next)).toBe("completed");
    expect(JSON.parse(textOf(next))).toMatchObject({ pong: "after-denial" });
  }, 30_000);

  it("denies a tool write into a protected control directory", async () => {
    const modulePath = writeModule(layout, "writer.mjs", WRITER_MODULE);
    const protectedDirectory = join(layout.workspace, ".git");
    const target = join(protectedDirectory, "config");
    writeFileSync(target, "protected-original");
    const denied = await controller.execute({
      plan: sandboxToolPlan({
        modulePath, requestId: "protected-write", toolCallId: "protected-write",
        arguments: { target },
      }),
    });
    expect(denied.state, JSON.stringify(denied)).toBe("failed");
    expect(denied.state === "failed" ? denied.code : undefined).toBe("execution-failed");
    const reason = denied.state === "failed" ? denied.reason : "";
    expect(reason).toMatch(/EACCES|EPERM|EROFS|read-only file system|permission denied/iu);
    // A launch failure (for example a worker that cannot exec node) reports the
    // same state and syntax but relays no result envelope and never names the
    // target, so the two facts below are what makes this case a real guard.
    expect(reason).toContain(target);
    expect(errorTextOf(denied)).toContain(target);
    expect(readFileSync(target, "utf8")).toBe("protected-original");
  }, 30_000);

  it("returns a readable error when the tool throws and keeps the session usable", async () => {
    const modulePath = writeModule(layout, "throwing.mjs", THROWING_MODULE);
    const thrown = await controller.execute({
      plan: sandboxToolPlan({ modulePath, requestId: "throwing", toolCallId: "throwing" }),
    });
    expect(thrown.state, JSON.stringify(thrown)).toBe("failed");
    expect(thrown.state === "failed" ? thrown.code : undefined).toBe("execution-failed");
    expect(thrown.state === "failed" ? thrown.reason : "").toContain("native sandbox tool boom");
    expect(errorTextOf(thrown)).toContain("native sandbox tool boom");

    const next = await controller.execute({
      plan: sandboxToolPlan({
        modulePath: writeModule(layout, "ping.mjs", PING_MODULE),
        requestId: "throwing-next", toolCallId: "throwing-next",
        arguments: { value: "after-throw" },
      }),
    });
    expect(next.state, JSON.stringify(next)).toBe("completed");
    expect(JSON.parse(textOf(next))).toMatchObject({ pong: "after-throw" });
  }, 30_000);

  it("terminates a slow tool at the plan deadline and reports a readable timeout", async () => {
    const modulePath = writeModule(layout, "slow.mjs", SLOW_MODULE);
    const startedAt = Date.now();
    const outcome = await controller.execute({
      plan: sandboxToolPlan({
        modulePath, requestId: "deadline", toolCallId: "deadline", deadlineMs: 2_000,
      }),
    });
    const elapsed = Date.now() - startedAt;
    expect(outcome.state, JSON.stringify(outcome)).toBe("cancelled");
    expect(outcome.state === "cancelled" ? outcome.code : undefined).toBe("execution-timeout");
    expect(outcome.state === "cancelled" ? outcome.reason : "").toContain("execution deadline expired");
    expect(elapsed).toBeGreaterThanOrEqual(1_000);
    expect(elapsed).toBeLessThan(20_000);

    // The same controller still runs the next declared tool call.
    const next = await controller.execute({
      plan: sandboxToolPlan({
        modulePath: writeModule(layout, "ping.mjs", PING_MODULE),
        requestId: "deadline-next", toolCallId: "deadline-next",
        arguments: { value: "after-timeout" },
      }),
    });
    expect(next.state, JSON.stringify(next)).toBe("completed");
    expect(JSON.parse(textOf(next))).toMatchObject({ pong: "after-timeout" });
  }, 40_000);
});
