import { describe, expect, it } from "vitest";
import type { ProgramInvocation, ShellOperationFact } from "#approve-core/policy/shell-policy/facts";
import { evaluateShellPolicySubject, type ShellPolicySubject } from "#approve-core/policy/shell-policy/evaluate";
import type { ShellPolicy, ShellPolicyRule } from "#config/shell-policy-schema";

function facts(overrides: Partial<ShellOperationFact> = {}): ShellOperationFact {
  return {
    operationId: "call-1:op:0-10:abc",
    unitId: "call-1:u0-10:def",
    owner: "external-command",
    effects: { status: "known", value: ["file.read"] },
    fileTargets: { status: "known", value: [] },
    networkTargets: { status: "known", value: [] },
    dynamicExecution: { status: "known", value: false },
    processSpawn: { status: "known", value: false },
    complete: true,
    source: "program-adapter",
    ...overrides,
  };
}

function invocation(overrides: Partial<ProgramInvocation> = {}): ProgramInvocation {
  return {
    operationId: "call-1:op:0-10:abc",
    unitId: "call-1:u0-10:def",
    shell: "powershell",
    program: { status: "known", value: "git" },
    executable: {
      status: "known",
      value: {
        name: "git",
        path: { status: "known", value: "C:\\Program Files\\Git\\bin\\git.exe" },
      },
    },
    argv: { status: "known", value: ["--pre=x", "status"] },
    cwd: { status: "known", value: "C:\\workspace" },
    extent: { start: 0, end: 10 },
    ...overrides,
  };
}

function subject(overrides: Partial<ShellPolicySubject> = {}): ShellPolicySubject {
  return {
    node: "builtin/external-command",
    toolName: "powershell",
    shell: "powershell",
    mode: "default",
    cwd: { status: "known", value: "C:\\workspace" },
    invocation: invocation(),
    operation: facts(),
    ...overrides,
  };
}

function rule(id: string, decision: "allow" | "ask" | "deny", when: ShellPolicyRule["when"]): ShellPolicyRule {
  return { id, node: "builtin/external-command", when, then: { decision } };
}

function policy(...rules: ShellPolicyRule[]): ShellPolicy {
  return { version: 1, rules };
}

describe("shell policy condition evaluation", () => {
  it("matches structured program names, exact argv, and long options before --", () => {
    const matched = evaluateShellPolicySubject({
      policy: policy(rule("deny-pre", "deny", {
        all: [
          { program: "git" },
          { args: { exact: ["--pre=x", "status"] } },
          { options: { present: ["--pre"], absent: ["--force"] } },
        ],
      })),
      subject: subject(),
      platform: "win32",
    });

    expect(matched.decision).toBe("deny");
    expect(matched.ruleIds).toEqual(["deny-pre"]);
  });

  it("does not treat option-like positional text after -- as an option", () => {
    const matched = evaluateShellPolicySubject({
      policy: policy(rule("deny-pre", "deny", { options: { present: ["--pre"] } })),
      subject: subject({ invocation: invocation({ argv: { status: "known", value: ["--", "--pre"] } }) }),
      platform: "win32",
    });

    expect(matched.decision).toBeUndefined();
  });

  it("returns ask when allow matches but an unknown deny rule can still match", () => {
    const operation = facts({ effects: { status: "unknown", reason: "unknown-effects" }, complete: false });
    const matched = evaluateShellPolicySubject({
      policy: policy(
        rule("allow-git", "allow", { program: "git" }),
        rule("deny-network", "deny", { effects: { hasAny: ["network"] } }),
      ),
      subject: subject({ operation }),
      platform: "win32",
    });

    expect(matched).toMatchObject({ decision: "ask", uncertain: true, allowEligible: false });
  });

  it("requires every file target to be outside the configured roots", () => {
    const operation = facts({
      fileTargets: {
        status: "known",
        value: [
          { path: "C:\\workspace\\inside.txt", effect: "file.write" },
          { path: "C:\\outside\\outside.txt", effect: "file.write" },
        ],
      },
    });
    const matched = evaluateShellPolicySubject({
      policy: policy(rule("outside-writes", "deny", {
        targets: { fileWrites: { allOutside: ["C:\\workspace"] } },
      })),
      subject: subject({ operation }),
      platform: "win32",
    });

    expect(matched.decision).toBeUndefined();
  });

  it("keeps not unknown as unknown", () => {
    const matched = evaluateShellPolicySubject({
      policy: policy(rule("unknown-deny", "deny", { not: { effects: { hasAny: ["network"] } } })),
      subject: subject({ operation: facts({ effects: { status: "unknown", reason: "unresolved" } }) }),
      platform: "win32",
    });

    expect(matched).toMatchObject({ decision: "ask", uncertain: true });
  });

  it("matches PowerShell cmdlet names case-insensitively on POSIX", () => {
    const matched = evaluateShellPolicySubject({
      policy: { version: 1, rules: [{
        id: "deny-set-content",
        node: "builtin/powershell",
        when: { program: "Set-Content" },
        then: { decision: "deny" },
      }] },
      subject: subject({
        node: "builtin/powershell",
        toolName: "powershell",
        mode: "full-access",
        invocation: invocation({ program: { status: "known", value: "set-content" } }),
        operation: facts({ owner: "powershell", source: "powershell-parser" }),
      }),
      platform: "linux",
    });

    expect(matched.decision).toBe("deny");
  });
});
