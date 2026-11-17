import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { prepareMacOSHelperProcess } from "#sandbox/backend/macos/index";
import type { TrustedHelperInstallation } from "#sandbox/helper";
import { ExecutionController } from "#sandbox/lifecycle";
import type { ExecutionOperation, ExecutionPlan } from "#sandbox/types";

import { compileTestPlan, makeInvocation } from "../fixtures/harness";

const backendId = "macos-seatbelt";
const backendVersion = "1.0.0";
const helperSource = fileURLToPath(
  new URL("../../../src/sandbox/backend/macos/helper.mjs", import.meta.url),
);
const builtinWorkerSource = fileURLToPath(
  new URL("../../../src/sandbox/builtin-worker.bundle.mjs", import.meta.url),
);

interface MacOSLayout {
  readonly root: string;
  readonly installRoot: string;
  readonly helperDir: string;
  readonly helperCwd: string;
  readonly workspace: string;
  readonly outside: string;
}

/**
 * Install the helper in a package-shaped layout: it resolves its worker runner
 * from `../../` and is read through the install-root grant, exactly like the
 * real package install.
 */
function createLayout(prefix: string): MacOSLayout {
  const root = realpathSync(mkdtempSync(join(realpathSync(tmpdir()), prefix)));
  const installRoot = join(root, "trusted-install");
  const helperDir = join(installRoot, "src", "sandbox", "backend", "macos");
  const helperCwd = join(root, "helper-cwd");
  const workspace = join(root, "workspace");
  const outside = join(root, "outside");
  for (const directory of [helperDir, helperCwd, workspace, outside]) {
    mkdirSync(directory, { recursive: true });
  }
  writeFileSync(join(installRoot, "package.json"), '{"type":"module"}');
  copyFileSync(helperSource, join(helperDir, "helper.mjs"));
  copyFileSync(builtinWorkerSource, join(installRoot, "src", "sandbox", "builtin-worker.bundle.mjs"));
  return { root, installRoot, helperDir, helperCwd, workspace, outside };
}

describe.skipIf(process.platform !== "darwin")("native macOS Seatbelt helper", () => {
  let layout: MacOSLayout;
  let controller: ExecutionController;

  beforeAll(() => {
    layout = createLayout("macos-seatbelt-helper-");
    const installation: TrustedHelperInstallation = {
      installRoot: layout.installRoot,
      executable: process.execPath,
      args: [join(layout.helperDir, "helper.mjs")],
      expectedBackendId: backendId,
      expectedBackendVersion: backendVersion,
    };
    controller = new ExecutionController({
      installation,
      helperCwd: layout.helperCwd,
      workspace: layout.workspace,
      helperEnvironment: {
        HOME: layout.root,
        LANG: "C.UTF-8",
        PATH: "/usr/bin:/bin",
      },
      prepareHelperProcess: prepareMacOSHelperProcess,
      startTimeoutMs: 10_000,
      cancelGraceMs: 500,
      probeTimeoutMs: 10_000,
    });
  });

  afterAll(async () => {
    await controller?.dispose();
    if (layout) rmSync(layout.root, { recursive: true, force: true });
  });

  function planFor(
    operation: ExecutionOperation,
    toolName = "write",
    args: Record<string, string> = {},
  ): ExecutionPlan {
    const invocation = makeInvocation({
      cwd: layout.workspace,
      toolName,
      args,
    });
    return compileTestPlan({
      invocation,
      operation,
      workspace: layout.workspace,
      backendId,
      environment: { HOME: layout.root, LANG: "C.UTF-8", PATH: "/usr/bin:/bin" },
    });
  }

  it("probes the sandboxed helper from inside sandbox-exec", async () => {
    const probe = await controller.probe();

    expect(probe).toMatchObject({
      status: "available",
      backend: { id: backendId, version: backendVersion },
      capabilities: {
        filesystem: { read: true, write: true, granularity: "file" },
        network: "none",
        cancel: true,
        startedNotification: true,
      },
    });
  }, 20_000);

  it("runs a builtin write tool inside a granted directory", async () => {
    const target = join(layout.workspace, "out.txt");
    const operation: ExecutionOperation = {
      kind: "builtin-tool",
      name: "write",
      arguments: { path: "out.txt", content: "written inside the sandbox\n" },
    };
    const outcome = await controller.execute({
      plan: planFor(operation, "write", { path: "out.txt", content: "written inside the sandbox\n" }),
    });

    expect(outcome).toMatchObject({ state: "completed", exitCode: 0 });
    expect(outcome.record).toMatchObject({ started: true, state: "completed" });
    expect(readFileSync(target, "utf8")).toBe("written inside the sandbox\n");
  }, 20_000);

  it("reads an approved file through the helper and returns its bytes", async () => {
    const source = join(layout.workspace, "readable.txt");
    writeFileSync(source, "inside\n");
    const outcome = await controller.execute({
      plan: planFor({ kind: "read-file", path: source }, "read", { path: "readable.txt" }),
    });

    expect(outcome).toMatchObject({ state: "completed", exitCode: 0 });
    expect(outcome.dataBase64).toBe(Buffer.from("inside\n").toString("base64"));
  }, 20_000);

  it("denies a write outside every grant with EPERM", async () => {
    const target = join(layout.outside, "denied.txt");
    const command = `printf denied > '${target}'`;
    const outcome = await controller.execute({
      plan: planFor({ kind: "shell", command, shell: "/bin/sh" }, "bash", { command }),
    });

    expect(outcome.state).toBe("completed");
    if (outcome.state !== "completed") return;
    expect(outcome.exitCode).not.toBe(0);
    expect(outcome.stderr).toMatch(/Operation not permitted|Permission denied/u);
    expect(existsSync(target)).toBe(false);
  }, 20_000);
});
