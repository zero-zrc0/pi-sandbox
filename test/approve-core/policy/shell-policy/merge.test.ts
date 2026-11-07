import { describe, expect, it } from "vitest";
import { mergeShellPolicies } from "#approve-core/policy/shell-policy/merge";
import { shellPolicySchema } from "#config/shell-policy-schema";

const policy = (value: Record<string, unknown>) => shellPolicySchema.parse({ version: 1, ...value });

describe("mergeShellPolicies", () => {
  it("retains global rules and appends unique project rules", () => {
    const global = policy({
      rules: [{ id: "global-read", node: "builtin/external-command", when: { program: "git" }, then: { decision: "ask" } }],
    });
    const project = policy({
      rules: [{ id: "project-read", node: "builtin/external-command", when: { program: "rg" }, then: { decision: "allow" } }],
    });

    const merged = mergeShellPolicies(global, project);

    expect(merged.issues).toEqual([]);
    expect(merged.policy?.rules.map((rule) => rule.id)).toEqual(["global-read", "project-read"]);
  });

  it("does not let a project rule replace a global id", () => {
    const global = policy({
      rules: [{ id: "same", node: "builtin/external-command", when: { program: "git" }, then: { decision: "deny" } }],
    });
    const project = policy({
      rules: [{ id: "same", node: "builtin/external-command", when: { program: "git" }, then: { decision: "allow" } }],
    });

    const merged = mergeShellPolicies(global, project);

    expect(merged.policy?.rules[0]?.then.decision).toBe("deny");
    expect(merged.issues).toHaveLength(1);
    expect(merged.issues[0]?.code).toBe("duplicate-project-rule");
  });

  it("keeps the stricter mode policy and the global read-only exceptions", () => {
    const global = policy({
      rules: [{
        id: "allow-write",
        node: "builtin/powershell",
        scope: { modes: ["read-only"] },
        when: { all: [
          { program: "Set-Content" },
          { effects: { only: ["file.create", "file.write"] } },
          { targets: { fileWrites: { allWithin: ["${workspace}/cache"] } } },
        ] },
        then: { decision: "allow" },
      }],
      modes: {
        "read-only": { unmatched: "ask", exceptions: [{ ruleId: "allow-write", effects: ["file.create", "file.write"] }] },
        default: { uncertain: "ask" },
      },
      analysis: { timeoutMs: 3000, maxInputBytes: 262144 },
    });
    const project = policy({
      modes: { "read-only": { unmatched: "deny" }, default: { uncertain: "deny" } },
      analysis: { timeoutMs: 1000, maxInputBytes: 1048576 },
    });

    const merged = mergeShellPolicies(global, project);

    expect(merged.policy?.modes?.["read-only"]).toMatchObject({
      unmatched: "deny",
      exceptions: [{ ruleId: "allow-write", effects: ["file.create", "file.write"] }],
    });
    expect(merged.policy?.modes?.default?.uncertain).toBe("deny");
    expect(merged.policy?.analysis).toMatchObject({ timeoutMs: 1000, maxInputBytes: 262144 });
    expect(merged.issues).toEqual([]);
  });

  it("ignores project read-only exceptions", () => {
    const project = policy({
      rules: [{
        id: "project-write",
        node: "builtin/powershell",
        scope: { modes: ["read-only"] },
        when: { all: [
          { program: "Set-Content" },
          { effects: { only: ["file.create", "file.write"] } },
          { targets: { fileWrites: { allWithin: ["${workspace}/cache"] } } },
        ] },
        then: { decision: "allow" },
      }],
      modes: { "read-only": { exceptions: [{ ruleId: "project-write", effects: ["file.create", "file.write"] }] } },
      analysis: { timeoutMs: 1000 },
    });

    const merged = mergeShellPolicies(undefined, project);

    expect(merged.policy?.rules.map((rule) => rule.id)).toEqual(["project-write"]);
    expect(merged.policy?.modes?.["read-only"]?.exceptions).toBeUndefined();
    expect(merged.policy?.analysis?.timeoutMs).toBe(1000);
    expect(merged.issues[0]?.code).toBe("project-readonly-exception");
  });

  it("retains restrictive project policy beside a rejected project exception", () => {
    const global = policy({
      rules: [{
        id: "global-read",
        node: "builtin/powershell",
        scope: { modes: ["read-only"] },
        when: { all: [
          { program: "Get-Content" },
          { effects: { only: ["file.read"] } },
          { targets: { fileReads: { allWithin: ["${workspace}"] } } },
        ] },
        then: { decision: "allow" },
      }],
      modes: {
        "read-only": {
          forbidEffects: ["file.read"],
          exceptions: [{ ruleId: "global-read", effects: ["file.read"] }],
        },
        default: { uncertain: "ask" },
      },
    });
    const project = policy({
      rules: [
        { id: "project-deny", node: "builtin/external-command", when: { program: "npm" }, then: { decision: "deny" } },
        {
          id: "project-write",
          node: "builtin/external-command",
          scope: { modes: ["read-only"] },
          when: { all: [
            { program: "npm" },
            { effects: { only: ["file.create", "file.write"] } },
            { targets: { fileWrites: { allWithin: ["${workspace}/cache"] } } },
          ] },
          then: { decision: "allow" },
        },
      ],
      modes: { "read-only": { exceptions: [{ ruleId: "project-write", effects: ["file.create", "file.write"] }] }, default: { uncertain: "deny" } },
    });

    const merged = mergeShellPolicies(global, project);

    expect(merged.policy?.rules.map((rule) => rule.id)).toEqual(["global-read", "project-deny", "project-write"]);
    expect(merged.policy?.modes?.["read-only"]?.exceptions).toEqual([
      { ruleId: "global-read", effects: ["file.read"] },
    ]);
    expect(merged.policy?.modes?.default?.uncertain).toBe("deny");
    expect(merged.issues.map((issue) => issue.code)).toEqual(["project-readonly-exception"]);
  });
});
