import { dirname, join } from "node:path";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";

import {
  DEFAULT_CONTROLLED_TOOLS,
  effectiveBaselineForOperation,
  operationMatchesApprovedAction,
  prepareExecutionOperation,
  UNCONTROLLED_BUILTIN_TOOLS,
  validateOperationPermissions,
} from "#sandbox/pi";
import type { ExecutionOperation } from "#sandbox/types";
import { makeInvocation } from "./fixtures/harness";
import { resolveHostPathIdentity } from "#sandbox/path";

const CWD = process.platform === "win32" ? "C:\\work\\project" : "/work/project";

function invocation(toolName: string, args: Record<string, unknown>) {
  return makeInvocation({ cwd: CWD, toolName, args });
}

describe("Pi SDK 1.0.0 tool inventory", () => {
  it("keeps controlled and host-executed tool definitions disjoint", () => {
    expect(DEFAULT_CONTROLLED_TOOLS).toEqual(["bash", "powershell", "read", "write", "edit", "grep", "find", "ls"]);
    expect(UNCONTROLLED_BUILTIN_TOOLS).toEqual([]);
    expect(
      new Set([...DEFAULT_CONTROLLED_TOOLS, ...UNCONTROLLED_BUILTIN_TOOLS]).size,
    ).toBe(8);
  });
});

describe("operation binding to the approved action", () => {
  it("binds relative builtin paths to the resolved approved file, including read fallbacks", () => {
    const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-bound-target-"));
    const storedName = join(cwd, "cafe\u0301.txt");
    writeFileSync(storedName, "contents");
    try {
      const facts = makeInvocation({ cwd, toolName: "read", args: { path: "@café.txt" } });
      const operation: ExecutionOperation = { kind: "builtin-tool", name: "read", arguments: { path: "@café.txt" } };
      expect(operationMatchesApprovedAction(facts, operation)).toBeNull();
      const prepared = prepareExecutionOperation(operation, facts, resolveHostPathIdentity);
      expect(prepared.ok).toBe(true);
      if (!prepared.ok || prepared.operation.kind !== "builtin-tool") return;
      expect(prepared.operation.arguments.path).toBe(resolveHostPathIdentity(storedName));
    } finally {
      rmSync(cwd, { recursive: true, force: true });
    }
  });

  it("checks target grants and explicit control-file access in the host", () => {
    const root = mkdtempSync(join(tmpdir(), "pi-sandbox-target-scope-"));
    const controlFile = join(root, ".git", "config");
    mkdirSync(dirname(controlFile), { recursive: true });
    writeFileSync(controlFile, "fixture");
    const canonicalRoot = `${root}-canonical`;
    const resolvePath = (path: string) => path.startsWith(root)
      ? `${canonicalRoot}${path.slice(root.length)}`
      : resolveHostPathIdentity(path);
    try {
      const operation: ExecutionOperation = { kind: "read-file", path: controlFile };
      const baseline = { filesystem: [{ path: root, access: "read" as const, granularity: "directory" as const }], network: { kind: "none" as const } };
      const denied = validateOperationPermissions({ operation, baseline, approved: { filesystem: [] }, runtime: [], resolvePath });
      expect(denied).toMatchObject({ ok: false, code: "protected-path" });
      const approved = validateOperationPermissions({ operation, baseline,
        approved: { filesystem: [{ path: controlFile, access: "read", granularity: "file" }] }, runtime: [],
        resolvePath });
      expect(approved).toEqual({ ok: true, additionalProtectedPaths: [] });
      const outside = validateOperationPermissions({ operation: { kind: "read-file", path: join(root, "..", "outside.txt") },
        baseline, approved: { filesystem: [] }, runtime: [], resolvePath });
      expect(outside).toMatchObject({ ok: false, code: "scope-expansion" });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("allows a protected read under .agents while keeping its write protected", () => {
    const root = mkdtempSync(join(tmpdir(), "pi-sandbox-agents-read-"));
    const skill = join(root, ".agents", "skills", "deploy", "SKILL.md");
    mkdirSync(dirname(skill), { recursive: true });
    writeFileSync(skill, "skill");
    const baseline = { filesystem: [
      { path: root, access: "read" as const, granularity: "directory" as const },
      { path: root, access: "write" as const, granularity: "directory" as const },
    ], network: { kind: "none" as const } };
    try {
      const read = validateOperationPermissions({ operation: { kind: "read-file", path: skill },
        baseline, approved: { filesystem: [] }, runtime: [], resolvePath: resolveHostPathIdentity });
      expect(read).toEqual({ ok: true, additionalProtectedPaths: [] });
      const write = validateOperationPermissions({ operation: { kind: "write-file", path: skill, content: "changed" },
        baseline, approved: { filesystem: [] }, runtime: [], resolvePath: resolveHostPathIdentity });
      expect(write).toMatchObject({ ok: false, code: "protected-path" });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("limits a parent-directory check to its exact writable file", () => {
    const parent = process.platform === "win32" ? "D:\\data" : "/data";
    const file = join(parent, "report.txt");
    const operation: ExecutionOperation = { kind: "access-dir", path: parent, forFile: file };
    const result = validateOperationPermissions({ operation,
      baseline: { filesystem: [], network: { kind: "none" } },
      approved: { filesystem: [{ path: file, access: "write", granularity: "file" }] },
      runtime: [], resolvePath: path => path,
    });
    expect(result).toMatchObject({ ok: true });
    const denied = validateOperationPermissions({ operation,
      baseline: { filesystem: [], network: { kind: "none" } },
      approved: { filesystem: [{ path: file, access: "read", granularity: "file" }] },
      runtime: [], resolvePath: path => path,
    });
    expect(denied).toMatchObject({ ok: false, code: "scope-expansion" });
  });

  it("accepts only the approved shell command", () => {
    const facts = invocation("bash", { command: "echo ok" });
    expect(
      operationMatchesApprovedAction(facts, {
        kind: "shell",
        command: "echo ok",
      }),
    ).toBeNull();
    expect(
      operationMatchesApprovedAction(facts, {
        kind: "shell",
        command: "echo changed",
      }),
    ).toContain("command differs");
  });

  it("binds write paths, directory creation and content", () => {
    const facts = invocation("write", { path: "out.txt", content: "data" });
    expect(
      operationMatchesApprovedAction(facts, {
        kind: "write-file",
        path: join(CWD, "out.txt"),
        content: "data",
      }),
    ).toBeNull();
    expect(
      operationMatchesApprovedAction(facts, {
        kind: "mkdir",
        path: CWD,
      }),
    ).toBeNull();
    expect(
      operationMatchesApprovedAction(facts, {
        kind: "write-file",
        path: join(CWD, "out.txt"),
        content: "other",
      }),
    ).toContain("content differs");
    expect(
      operationMatchesApprovedAction(facts, {
        kind: "write-file",
        path: join(CWD, "other.txt"),
        content: "data",
      }),
    ).toContain("path differs");
    expect(
      operationMatchesApprovedAction(facts, {
        kind: "mkdir",
        path: join(CWD, "sub"),
      }),
    ).toContain("mkdir path differs");
  });

  it("binds a parent directory check to the approved write file", () => {
    const facts = invocation("write", { path: "out.txt", content: "data" });
    expect(
      operationMatchesApprovedAction(facts, {
        kind: "access-dir",
        path: CWD,
        forFile: join(CWD, "out.txt"),
      }),
    ).toBeNull();
    expect(
      operationMatchesApprovedAction(facts, {
        kind: "access-dir",
        path: dirname(CWD),
        forFile: join(dirname(CWD), "out.txt"),
      }),
    ).toContain("access-dir");
    expect(
      operationMatchesApprovedAction(facts, {
        kind: "access-dir",
        path: join(CWD, "sub"),
        forFile: join(CWD, "sub", "other.txt"),
      }),
    ).toContain("access-dir");
  });

  it("binds read and edit paths but not edit content", () => {
    const read = invocation("read", { path: "notes.txt" });
    expect(
      operationMatchesApprovedAction(read, {
        kind: "read-file",
        path: join(CWD, "notes.txt"),
      }),
    ).toBeNull();
    expect(
      operationMatchesApprovedAction(read, {
        kind: "write-file",
        path: join(CWD, "notes.txt"),
        content: "x",
      } satisfies ExecutionOperation),
    ).toContain("file read operation");
    expect(
      operationMatchesApprovedAction(read, {
        kind: "read-file",
        path: join(CWD, "other.txt"),
      }),
    ).toContain("path differs");

    const edit = invocation("edit", {
      path: "notes.txt",
      edits: [{ oldText: "a", newText: "b" }],
    });
    expect(
      operationMatchesApprovedAction(edit, {
        kind: "write-file",
        path: join(CWD, "notes.txt"),
        content: "b",
      }),
    ).toBeNull();
  });
});

describe("shell baseline grants", () => {
  it("adds configured shell grants only to shell operations", () => {
    const baseline = {
      filesystem: [{ path: CWD, access: "read" as const, granularity: "directory" as const }],
      network: { kind: "all" as const },
    };
    const shellBaseline = {
      filesystem: [{ path: join(CWD, "external"), access: "write" as const, granularity: "directory" as const }],
      network: { kind: "destinations" as const, destinations: [{ host: "api.example.com", port: 443 }] },
    };
    const shellOperation: ExecutionOperation = {
      kind: "builtin-tool",
      name: "powershell",
      arguments: { command: "Get-Content input.txt" },
    };
    const readOperation: ExecutionOperation = {
      kind: "builtin-tool",
      name: "read",
      arguments: { path: "input.txt" },
    };

    expect(effectiveBaselineForOperation(baseline, shellBaseline, shellOperation)).toEqual({
      filesystem: [
        { path: CWD, access: "read", granularity: "directory" },
        { path: join(CWD, "external"), access: "write", granularity: "directory" },
      ],
      network: { kind: "destinations", destinations: [{ host: "api.example.com", port: 443 }] },
    });
    expect(effectiveBaselineForOperation(baseline, shellBaseline, readOperation)).toBe(baseline);
  });
});
