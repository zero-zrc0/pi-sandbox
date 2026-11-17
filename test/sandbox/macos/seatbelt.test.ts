import { copyFileSync, mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  buildSeatbeltProfile,
  MACOS_SANDBOX_EXEC_PATH,
  probeMacOSSeatbelt,
} from "#sandbox/backend/macos/seatbelt";
import type { TrustedHelperInstallation } from "#sandbox/helper";
import type { ExecutionPlan } from "#sandbox/types";

import { compileTestPlan, makeInvocation } from "../fixtures/harness";

const backendId = "macos-seatbelt";
const helperSource = fileURLToPath(
  new URL("../../../src/sandbox/backend/macos/helper.mjs", import.meta.url),
);

describe.skipIf(process.platform !== "darwin")("macOS Seatbelt profiles", () => {
  let root: string;
  let installRoot: string;
  let workspace: string;
  let installation: TrustedHelperInstallation;

  beforeAll(() => {
    root = realpathSync(mkdtempSync(join(realpathSync(tmpdir()), "macos-seatbelt-profile-")));
    installRoot = join(root, "install");
    workspace = join(root, "workspace");
    mkdirSync(installRoot, { recursive: true });
    mkdirSync(workspace, { recursive: true });
    copyFileSync(helperSource, join(installRoot, "helper.mjs"));
    installation = {
      installRoot,
      executable: process.execPath,
      args: [join(installRoot, "helper.mjs")],
      expectedBackendId: backendId,
    };
  });

  afterAll(() => {
    rmSync(root, { recursive: true, force: true });
  });

  function plan(overrides: {
    readonly network?: "none" | "all";
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
    return compileTestPlan({
      invocation,
      operation: { kind: "write-file", path: join(workspace, "out.txt"), content: "seatbelt" },
      workspace,
      backendId,
      network: { kind: overrides.network ?? "none" },
      ...(overrides.baselineFilesystem === undefined
        ? {}
        : { baselineFilesystem: overrides.baselineFilesystem }),
    });
  }

  it("keeps the volume root literal rule a file literal, never a subpath", () => {
    const result = buildSeatbeltProfile({ installation, plan: plan() });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.profile).toContain("(deny default)");
    expect(result.profile).toContain('(allow file-read* (literal "/"))');
    expect(result.profile).not.toContain('(allow file-read* (subpath "/"))');
  });

  it("grants the canonical node executable and its directory for an nvm install", () => {
    const result = buildSeatbeltProfile({ installation, plan: plan() });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const node = realpathSync.native(process.execPath);
    expect(result.profile).toContain(`(allow file-read* (literal "${node}"))`);
    expect(result.profile).toContain(`(allow file-read* (subpath "${dirname(node)}"))`);
  });

  it("emits canonical grant paths and denies writes to the install root", () => {
    const result = buildSeatbeltProfile({ installation, plan: plan() });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const canonicalWorkspace = realpathSync.native(workspace);
    expect(result.profile).toContain(`(allow file-read* (subpath "${canonicalWorkspace}"))`);
    expect(result.profile).toContain(`(allow file-write* (subpath "${canonicalWorkspace}"))`);
    expect(result.profile).toContain(`(deny file-write* (subpath "${installRoot}"))`);
  });

  it("denies system credential stores after every allow rule", () => {
    const result = buildSeatbeltProfile({ installation, plan: plan() });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const lines = result.profile.split("\n").filter((line) => line.length > 0);
    let lastAllow = -1;
    lines.forEach((line, index) => {
      if (line.startsWith("(allow ")) lastAllow = index;
    });
    const targets = [
      'subpath "/private/var/db/dslocal"',
      'subpath "/private/var/db/DarwinDirectory"',
      'literal "/private/var/db/auth.db"',
      'literal "/private/etc/master.passwd"',
      'literal "/private/etc/sudoers"',
      'subpath "/private/etc/sudoers.d"',
      'subpath "/private/var/db/sudo"',
      'subpath "/private/var/db/SystemPolicyConfiguration"',
      'literal "/Library/Keychains/System.keychain"',
      'literal "/Library/Application Support/com.apple.TCC/TCC.db"',
    ];
    for (const target of targets) {
      for (const operation of ["file-read-metadata", "file-read*", "file-write*"]) {
        expect(lines.indexOf(`(deny ${operation} (${target}))`)).toBeGreaterThan(lastAllow);
      }
    }
  });

  it("denies the per-user TCC database inside every home", () => {
    const result = buildSeatbeltProfile({ installation, plan: plan() });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const home = realpathSync.native(process.env.HOME ?? "/");
    const tcc = `${home}/Library/Application Support/com.apple.TCC/TCC.db`;
    expect(result.profile).toContain(`(deny file-read* (literal "${tcc}"))`);
    expect(result.profile).toContain(`(deny file-write* (literal "${tcc}"))`);
  });

  it("refuses a plan that requests network access", () => {
    const result = buildSeatbeltProfile({ installation, plan: plan({ network: "all" }) });

    expect(result).toMatchObject({ ok: false, code: "sandbox-capability-unsupported" });
  });

  it("refuses a filesystem grant that targets the filesystem root", () => {
    const result = buildSeatbeltProfile({
      installation,
      plan: plan({
        baselineFilesystem: [{ path: "/", access: "write", granularity: "directory" }],
      }),
    });

    expect(result).toMatchObject({ ok: false, code: "sandbox-capability-unsupported" });
  });

  it("probes the fixed sandbox-exec and reports the backend as a candidate", () => {
    const probe = probeMacOSSeatbelt();

    expect(MACOS_SANDBOX_EXEC_PATH).toBe("/usr/bin/sandbox-exec");
    expect(probe).toMatchObject({
      status: "candidate-present",
      executable: MACOS_SANDBOX_EXEC_PATH,
      defaultDenyProbePassed: true,
    });
  });
});
