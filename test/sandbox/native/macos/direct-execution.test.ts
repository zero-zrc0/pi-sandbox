import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { ExecutionController } from "#sandbox/lifecycle";
import { EXECUTION_INSTALL_ROOT } from "#sandbox/platform";
import { createMacOSDirectBackend } from "#sandbox/backend/macos/direct";
import { probeMacOSSeatbelt } from "#sandbox/backend/macos/index";
import { probeSandboxRuntime } from "#sandbox/runtime-probe";
import type { ResolvedRuntimeFiles } from "#sandbox/runtime-store";
import { compileTestRequest as compileBaseTestPlan, makeInvocation } from "../../fixtures/harness";
import { macOSRuntimeFilesystem } from "#sandbox/runtime-filesystem";
import { collectSensitivePaths } from "#sandbox/sensitive-paths";
import { resolveHostPathIdentity } from "#sandbox/path";
import { getAgentDir } from "@earendil-works/pi-coding-agent";

const operationWorkerPath = fileURLToPath(new URL("../../../../src/sandbox/backend/macos/operation-worker.mjs", import.meta.url));
const seatbelt = process.platform === "darwin" ? probeMacOSSeatbelt() : undefined;
const nativeReady = process.platform === "darwin" && existsSync(operationWorkerPath) && seatbelt?.status === "candidate-present";

// The Seatbelt backend is the system runtime: no downloaded files, so the
// synthetic runtime mirrors what runtime-manager produces on darwin.
const systemRuntime = (workspaceRoot: string): ResolvedRuntimeFiles => ({
  directory: join(tmpdir(), "pi-sandbox-native-macos-runtime"),
  storageRoot: tmpdir(),
  source: "manual",
  manifest: {
    schemaVersion: 1,
    version: "1.0.0",
    stable: true,
    platform: "darwin",
    arch: process.arch === "arm64" ? "arm64" : "x64",
    protocolVersion: 3,
    minPluginVersion: "0.0.0",
    maxPluginVersionExclusive: "999999.999.999",
    backendId: "macos-seatbelt",
    files: [],
  },
  files: {},
});

describe.skipIf(!nativeReady)("native macOS Seatbelt execution", () => {
  let root: string | undefined;
  let workspace: string;
  let granted: string;
  let controller: ExecutionController | undefined;

  function compileTestRequest(options: Parameters<typeof compileBaseTestPlan>[0]) {
    const runtime = macOSRuntimeFilesystem(EXECUTION_INSTALL_ROOT);
    return compileBaseTestPlan({ ...options, runtimeFilesystem: runtime.grants,
      protectedPaths: [...runtime.protectedPaths, ...(options.protectedPaths ?? [])],
      sensitivePaths: [...collectSensitivePaths({ agentDirectory: getAgentDir(), cwd: options.workspace }), ...(options.sensitivePaths ?? [])],
      resolvePath: resolveHostPathIdentity });
  }

  function getController(): ExecutionController {
    if (!controller) throw new Error("macOS direct controller was not created");
    return controller;
  }

  beforeAll(() => {
    root = realpathSync.native(mkdtempSync(join(tmpdir(), "pi-sandbox-native-macos-")));
    workspace = join(root, "workspace");
    granted = join(root, "granted");
    for (const directory of [workspace, granted]) mkdirSync(directory, { recursive: true });
    const hostEnvironment = {
      PATH: process.env.PATH ?? "/usr/bin:/bin",
      ...(process.env.HOME ? { HOME: process.env.HOME } : {}),
      LANG: "C.UTF-8",
      PI_SANDBOX_WORKSPACE_ROOT: workspace,
    };
    controller = new ExecutionController({
      directBackend: createMacOSDirectBackend({
        installRoot: EXECUTION_INSTALL_ROOT,
        hostEnvironment,
      }),
      startTimeoutMs: 20_000,
      probeTimeoutMs: 20_000,
    });
  });

  afterAll(async () => {
    await controller?.dispose();
    if (root) rmSync(root, { recursive: true, force: true });
  });

  it("probes the installed system runtime as available", async () => {
    const result = await probeSandboxRuntime({
      runtime: systemRuntime(workspace),
      workspaceRoot: workspace,
      signal: new AbortController().signal,
    });

    expect(result).toEqual({ available: true });
  }, 30_000);

  it("keeps sibling writes while denying access and metadata for existing sensitive paths", async () => {
    const readonly = join(granted, "readonly");
    const secretDir = join(granted, "secret-dir");
    const secretFile = join(granted, "secret-file");
    mkdirSync(readonly);
    mkdirSync(secretDir);
    writeFileSync(join(readonly, "data"), "readable");
    writeFileSync(join(secretDir, "data"), "private-directory");
    writeFileSync(secretFile, "private-file");
    const command = "set -eu; test \"$(cat readonly/data)\" = readable; " +
      "if printf x > readonly/data 2>/dev/null; then exit 11; fi; printf saved > sibling; " +
      "if cat secret-dir/data >/dev/null 2>&1; then exit 12; fi; " +
      "if cat secret-file >/dev/null 2>&1; then exit 13; fi; " +
      "if stat secret-file >/dev/null 2>&1; then exit 14; fi";
    const invocation = makeInvocation({ toolName: "bash", toolCallId: "macos-sensitive",
      cwd: granted, args: { command } });
    const plan = compileTestRequest({ invocation, operation: { kind: "shell", command, shell: "/bin/sh" },
      workspace: granted, backendId: "macos-seatbelt", protectedPaths: [readonly],
      sensitivePaths: collectSensitivePaths({ agentDirectory: join(root!, "empty-agent"), cwd: granted,
        home: join(root!, "empty-home"), environment: {}, denyPaths: [secretDir, secretFile], platform: "linux" }),
      environment: { HOME: process.env.HOME ?? "/tmp", PATH: process.env.PATH ?? "/usr/bin:/bin" } });
    const outcome = await getController().execute({ request: plan });
    expect(outcome.state, JSON.stringify(outcome)).toBe("completed");
    expect(outcome.record.exitCode).toBe(0);
    expect(readFileSync(join(granted, "sibling"), "utf8")).toBe("saved");
    expect(readFileSync(secretFile, "utf8")).toBe("private-file");
    const renamed = join(granted, "secret-file-old");
    renameSync(secretFile, renamed);
    writeFileSync(secretFile, "replacement");
    const rejected = await getController().execute({ request: plan });
    expect(rejected.state).toBe("failed");
    expect(rejected.record.started).toBe(false);
  }, 30_000);

  it("writes a builtin-tool file inside the granted directory", async () => {
    const target = join(granted, "inside.txt");
    const argumentsValue = { path: target, content: "inside" };
    const invocation = makeInvocation({ toolName: "write", toolCallId: "macos-write-inside",
      cwd: granted, args: argumentsValue });
    const plan = compileTestRequest({
      invocation,
      operation: { kind: "builtin-tool", name: "write", arguments: argumentsValue },
      workspace,
      baselineFilesystem: [
        { path: granted, access: "read", granularity: "directory" },
        { path: granted, access: "write", granularity: "directory" },
      ],
      backendId: "macos-seatbelt",
      environment: { HOME: process.env.HOME ?? "/tmp", PATH: process.env.PATH ?? "/usr/bin:/bin" },
    });

    const outcome = await getController().execute({ request: plan });

    expect(outcome.state).toBe("completed");
    expect(outcome.record.exitCode).toBe(0);
    expect(readFileSync(target, "utf8")).toBe("inside");
  }, 30_000);

  it("denies a write outside every grant without touching the host", async () => {
    const outside = join(root!, "outside.txt");
    const command = `printf denied > "${outside}"`;
    const invocation = makeInvocation({ toolName: "bash", toolCallId: "macos-write-outside",
      cwd: granted, args: { command } });
    const plan = compileTestRequest({
      invocation,
      operation: { kind: "shell", command, shell: "/bin/sh" },
      workspace,
      baselineFilesystem: [
        { path: granted, access: "read", granularity: "directory" },
        { path: granted, access: "write", granularity: "directory" },
      ],
      backendId: "macos-seatbelt",
      environment: { HOME: process.env.HOME ?? "/tmp", PATH: process.env.PATH ?? "/usr/bin:/bin" },
    });

    const outcome = await getController().execute({ request: plan });

    expect(existsSync(outside)).toBe(false);
    // The sandboxed shell must have started and been refused by Seatbelt; a
    // pre-spawn controller failure would make this assertion meaningless.
    expect(outcome.record.started).toBe(true);
    expect(outcome.state).not.toBe("cancelled");
    const denied = outcome.state === "failed" ||
      (outcome.state === "completed" && outcome.exitCode !== 0);
    expect(denied).toBe(true);
    expect(outcome.stderr).toContain("Operation not permitted");
  }, 30_000);

  it("denies system credential stores and keeps ordinary system reads working", async () => {
    const command = [
      "if stat /private/var/db/dslocal >/dev/null 2>&1; then echo dslocal-visible; else echo dslocal-hidden; fi",
      "if head -c 16 /Library/Keychains/System.keychain >/dev/null 2>&1; then echo keychain-readable; else echo keychain-denied; fi",
      "head -1 /etc/passwd >/dev/null 2>&1 && echo passwd-readable",
    ].join("; ");
    const invocation = makeInvocation({ toolName: "bash", toolCallId: "macos-credential-stores",
      cwd: granted, args: { command } });
    const plan = compileTestRequest({
      invocation,
      operation: { kind: "shell", command, shell: "/bin/sh" },
      workspace,
      baselineFilesystem: [
        { path: granted, access: "read", granularity: "directory" },
        { path: granted, access: "write", granularity: "directory" },
      ],
      backendId: "macos-seatbelt",
      environment: { HOME: process.env.HOME ?? "/tmp", PATH: process.env.PATH ?? "/usr/bin:/bin" },
    });

    const outcome = await getController().execute({ request: plan });

    expect(outcome.state).toBe("completed");
    expect(outcome.stdout).toContain("dslocal-hidden");
    expect(outcome.stdout).toContain("keychain-denied");
    expect(outcome.stdout).toContain("passwd-readable");
  }, 30_000);
});
