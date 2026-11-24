import { copyFileSync, mkdirSync, mkdtempSync, realpathSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  buildSeatbeltProfile,
  MACOS_SANDBOX_EXEC_PATH,
  probeMacOSSeatbelt,
} from "#sandbox/backend/macos/seatbelt";
import type { ExecutionPlan } from "#sandbox/types";
import { macOSRuntimeFilesystem } from "#sandbox/runtime-filesystem";
import { collectSensitivePaths } from "#sandbox/sensitive-paths";
import { resolveHostPathIdentity } from "#sandbox/path";
import type { SeatbeltInstallation } from "#sandbox/backend/macos/seatbelt";

import { compileTestPlan, makeInvocation } from "../fixtures/harness";

const backendId = "macos-seatbelt";
const operationWorkerSource = fileURLToPath(
  new URL("../../../src/sandbox/backend/macos/operation-worker.mjs", import.meta.url),
);

describe.skipIf(process.platform !== "darwin")("macOS Seatbelt profiles", () => {
  let root: string;
  let installRoot: string;
  let workspace: string;
  let installation: SeatbeltInstallation;

  beforeAll(() => {
    root = realpathSync(mkdtempSync(join(realpathSync(tmpdir()), "macos-seatbelt-profile-")));
    installRoot = join(root, "install");
    workspace = join(root, "workspace");
    mkdirSync(installRoot, { recursive: true });
    mkdirSync(workspace, { recursive: true });
    mkdirSync(join(root, "home", ".ssh"), { recursive: true });
    mkdirSync(join(root, "home", "Library", "Application Support", "com.apple.TCC"), { recursive: true });
    writeFileSync(join(root, "home", "Library", "Application Support", "com.apple.TCC", "TCC.db"), "fixture");
    copyFileSync(operationWorkerSource, join(installRoot, "operation-worker.mjs"));
    installation = {
      installRoot,
      executable: process.execPath,
      args: [join(installRoot, "operation-worker.mjs")],
    };
  });

  afterAll(() => {
    rmSync(root, { recursive: true, force: true });
  });

  function plan(overrides: {
    readonly network?: "none" | "all";
    readonly metadataRead?: "none" | "all";
    readonly baselineFilesystem?: readonly {
      readonly path: string;
      readonly access: "read" | "write";
      readonly granularity: "file" | "directory";
    }[];
  } = {}): ExecutionPlan {
    const invocation = makeInvocation({
      cwd: workspace,
      toolName: "write",
      args: { path: "out.txt", content: "seatbelt" },
    });
    const runtime = macOSRuntimeFilesystem(installRoot);
    return compileTestPlan({
      invocation,
      operation: { kind: "write-file", path: join(workspace, "out.txt"), content: "seatbelt" },
      workspace,
      backendId,
      runtimeFilesystem: runtime.grants,
      protectedPaths: runtime.protectedPaths,
      sensitivePaths: collectSensitivePaths({ agentDirectory: join(root, "agent"), cwd: workspace,
        home: join(root, "home"), environment: {}, platform: "darwin" }),
      resolvePath: resolveHostPathIdentity,
      network: { kind: overrides.network ?? "none" },
      ...(overrides.baselineFilesystem === undefined
        ? {}
        : { baselineFilesystem: overrides.baselineFilesystem }),
      metadataRead: overrides.metadataRead ?? "none",
    });
  }

  it("keeps the volume root literal rule a file literal, never a subpath", () => {
    const result = buildSeatbeltProfile({ installation, plan: plan(), cwd: workspace });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.profile).toContain("(deny default)");
    expect(result.profile).toContain('(allow file-read* (literal "/"))');
    expect(result.profile).not.toContain('(allow file-read* (subpath "/"))');
    expect(result.profile).not.toContain('(allow file-read-metadata (subpath "/"))');
  });

  it("grants the canonical node executable and its directory for an nvm install", () => {
    const result = buildSeatbeltProfile({ installation, plan: plan(), cwd: workspace });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const node = realpathSync.native(process.execPath);
    expect(result.profile).toContain(`(allow file-read* (literal "${node}"))`);
    expect(result.profile).toContain(`(allow file-read* (subpath "${dirname(node)}"))`);
  });

  it("translates global metadata access and rechecks sensitive identities on cache hits", () => {
    const permissions = plan({ metadataRead: "all" });
    const first = buildSeatbeltProfile({ installation, plan: permissions, cwd: workspace });
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    expect(first.profile).toContain('(allow file-read-metadata (subpath "/"))');
    expect(buildSeatbeltProfile({ installation, plan: permissions, cwd: workspace })).toEqual(first);

    const protectedFile = join(root, "home", "Library", "Application Support", "com.apple.TCC", "TCC.db");
    const movedFile = `${protectedFile}.old`;
    renameSync(protectedFile, movedFile);
    writeFileSync(protectedFile, "replacement");
    expect(buildSeatbeltProfile({ installation, plan: permissions, cwd: workspace })).toMatchObject({
      ok: false,
      code: "sandbox-capability-unsupported",
    });
  });

  it("emits canonical grant paths and denies writes to the install root", () => {
    const result = buildSeatbeltProfile({ installation, plan: plan(), cwd: workspace });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const canonicalWorkspace = realpathSync.native(workspace);
    expect(result.profile).toContain(`(allow file-read* (subpath "${canonicalWorkspace}"))`);
    expect(result.profile).toContain(`(allow file-write* (subpath "${canonicalWorkspace}"))`);
    expect(result.profile).toContain(`(deny file-write* (subpath "${installRoot}"))`);
  });

  it("denies system credential stores after every allow rule", () => {
    const result = buildSeatbeltProfile({ installation, plan: plan(), cwd: workspace });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const lines = result.profile.split("\n").filter((line) => line.length > 0);
    let lastAllow = -1;
    lines.forEach((line, index) => {
      if (line.startsWith("(allow ")) lastAllow = index;
    });
    const targets = [`subpath "${join(root, "home", ".ssh")}"`,
      `literal "${join(root, "home", "Library", "Application Support", "com.apple.TCC", "TCC.db")}"`];
    for (const target of targets) {
      for (const operation of ["file-read-metadata", "file-read*", "file-write*"]) {
        expect(lines.indexOf(`(deny ${operation} (${target}))`)).toBeGreaterThan(lastAllow);
      }
    }
  });

  it("denies the per-user TCC database inside every home", () => {
    const result = buildSeatbeltProfile({ installation, plan: plan(), cwd: workspace });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const home = join(root, "home");
    const tcc = `${home}/Library/Application Support/com.apple.TCC/TCC.db`;
    expect(result.profile).toContain(`(deny file-read* (literal "${tcc}"))`);
    expect(result.profile).toContain(`(deny file-write* (literal "${tcc}"))`);
  });

  it("refuses a plan that requests network access", () => {
    const result = buildSeatbeltProfile({ installation, plan: plan({ network: "all" }), cwd: workspace });

    expect(result).toMatchObject({ ok: false, code: "sandbox-capability-unsupported" });
  });

  it("refuses a filesystem grant that targets the filesystem root", () => {
    const result = buildSeatbeltProfile({
      installation,
      plan: plan({
        baselineFilesystem: [{ path: "/", access: "write", granularity: "directory" }],
      }),
      cwd: workspace,
    });

    expect(result).toMatchObject({ ok: false, code: "sandbox-capability-unsupported" });
  });

  it("probes the fixed sandbox-exec and reports the backend as a candidate", async () => {
    const probe = await probeMacOSSeatbelt();

    expect(MACOS_SANDBOX_EXEC_PATH).toBe("/usr/bin/sandbox-exec");
    expect(probe).toMatchObject({
      status: "candidate-present",
      executable: MACOS_SANDBOX_EXEC_PATH,
      defaultDenyProbePassed: true,
    });
  });

  it("cancels the active Seatbelt probe and permits a later probe", async () => {
    const controller = new AbortController();
    const pending = probeMacOSSeatbelt(controller.signal);
    controller.abort();
    expect(await pending).toMatchObject({ status: "unavailable", reason: expect.stringContaining("cancelled") });
    expect(await probeMacOSSeatbelt()).toMatchObject({ status: "candidate-present" });
  });
});
