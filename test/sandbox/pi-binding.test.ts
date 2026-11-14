import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  DEFAULT_CONTROLLED_TOOLS,
  effectiveBaselineForOperation,
  operationMatchesApprovedAction,
  UNCONTROLLED_BUILTIN_TOOLS,
} from "#sandbox/pi";
import type { ExecutionOperation } from "#sandbox/types";
import { makeInvocation } from "./fixtures/harness";

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
