import { describe, expect, it } from "vitest";
import { shellPolicySchema } from "#config/shell-policy-schema";
import { approvalChainConfigSchema } from "#config/schema";

const gitStatusRule = {
  id: "allow-git-status",
  node: "builtin/external-command",
  scope: { shells: ["bash", "powershell"], modes: ["read-only", "default"] },
  when: { program: "git", args: { exact: ["status"] } },
  then: { decision: "allow" },
};

describe("shell policy schema", () => {
  it("accepts a scoped cross-shell command rule and preserves defaults only when declared", () => {
    expect(shellPolicySchema.parse({ version: 1, rules: [gitStatusRule] })).toMatchObject({
      version: 1,
      rules: [gitStatusRule],
    });
    expect(approvalChainConfigSchema.parse({})).not.toHaveProperty("shellPolicy");
    expect(approvalChainConfigSchema.parse({ shellPolicy: { version: 1 } }).shellPolicy?.rules).toEqual([]);
  });

  it("rejects empty conditions, empty groups, and unsupported fields", () => {
    for (const when of [{}, { all: [] }, { program: "git", regex: ".*" }]) {
      expect(shellPolicySchema.safeParse({
        version: 1,
        rules: [{ ...gitStatusRule, when }],
      }).success).toBe(false);
    }
  });

  it("preserves empty argv tokens while rejecting empty argument lists", () => {
    expect(shellPolicySchema.safeParse({
      version: 1,
      rules: [{ ...gitStatusRule, when: { args: { exact: [""] } } }],
    }).success).toBe(true);
    expect(shellPolicySchema.safeParse({
      version: 1,
      rules: [{ ...gitStatusRule, when: { args: { exact: [] } } }],
    }).success).toBe(false);
  });

  it("rejects duplicate rule ids and exceptions that do not reference an allow rule", () => {
    expect(shellPolicySchema.safeParse({
      version: 1,
      rules: [gitStatusRule, { ...gitStatusRule, node: "builtin/powershell" }],
    }).success).toBe(false);
    expect(shellPolicySchema.safeParse({
      version: 1,
      modes: { "read-only": { exceptions: [{ ruleId: "missing", effects: ["file.write"] }] } },
    }).success).toBe(false);
  });

  it("requires read-only exceptions to use a read-only-only scoped allow rule", () => {
    const exceptionRule = {
      id: "allow-cache-write",
      node: "builtin/powershell",
      scope: { modes: ["read-only"] },
      when: { all: [
        { effects: { only: ["file.create", "file.write"] } },
        { targets: { fileWrites: { allWithin: ["${workspace}/cache"] } } },
      ] },
      then: { decision: "allow" },
    };
    const exception = {
      version: 1,
      modes: { "read-only": { exceptions: [{ ruleId: exceptionRule.id, effects: ["file.create", "file.write"] }] } },
      rules: [exceptionRule],
    };

    const parsed = shellPolicySchema.safeParse(exception);
    expect(parsed.success, JSON.stringify(parsed.success ? [] : parsed.error.issues)).toBe(true);
    expect(shellPolicySchema.safeParse({
      ...exception,
      rules: [{ ...exceptionRule, scope: { modes: ["read-only", "default"] } }],
    }).success).toBe(false);
    expect(shellPolicySchema.safeParse({
      ...exception,
      rules: [{ ...exceptionRule, when: { effects: { only: ["file.create", "file.write"] } } }],
    }).success).toBe(false);
  });

  it("keeps uncertain shell behavior reviewable outside full access", () => {
    expect(shellPolicySchema.safeParse({
      version: 1,
      modes: { default: { uncertain: "allow" } },
    }).success).toBe(false);
    expect(shellPolicySchema.safeParse({
      version: 1,
      modes: { "full-access": { uncertain: "allow" } },
    }).success).toBe(true);
  });

  it("validates the additional shell execution grant as a strict object", () => {
    const execution = {
      shell: {
        filesystem: { read: [{ path: "${workspace}", granularity: "directory" }], write: [] },
        network: { mode: "none" },
      },
    };
    expect(approvalChainConfigSchema.safeParse({ execution }).success).toBe(true);
    expect(approvalChainConfigSchema.safeParse({
      execution: { ...execution, shell: { ...execution.shell, extra: true } },
    }).success).toBe(false);
  });
});
