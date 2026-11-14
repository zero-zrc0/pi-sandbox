import { describe, expect, it } from "vitest";
import {
  applyYoloRewrite,
  mcpBaselineRules,
  synthesizePolicy,
} from "#approve-core/policy/synthesize";

describe("default rule", () => {
  it("falls back to a builtin ask when no scope sets a universal default", () => {
    const policy = synthesizePolicy({ scopes: {} });
    expect(policy.defaultRule).toMatchObject({
      action: "ask",
      origin: "builtin",
      layer: "default",
      pattern: "*",
    });
  });

  it("uses the configured fallback action", () => {
    const policy = synthesizePolicy({ scopes: {}, defaultAction: "deny" });
    expect(policy.defaultRule.action).toBe("deny");
  });

  it("takes the universal default and its scope", () => {
    const policy = synthesizePolicy({
      scopes: { project: { permission: { "*": "allow" } } },
    });
    expect(policy.defaultRule).toMatchObject({ action: "allow", origin: "project" });
  });
});

describe("config rules", () => {
  it("attributes each rule to the scope that last contributed it", () => {
    const policy = synthesizePolicy({
      scopes: {
        global: { permission: { bash: { "git *": "allow" } } },
        project: { permission: { bash: { "git push": "deny" } } },
      },
    });
    expect(policy.rules.map((rule) => [rule.surface, rule.pattern, rule.action, rule.origin]))
      .toEqual([
        ["bash", "git *", "allow", "global"],
        ["bash", "git push", "deny", "project"],
      ]);
  });
});

describe("MCP baseline", () => {
  it("is absent without an explicit mcp allow", () => {
    const policy = synthesizePolicy({
      scopes: { global: { permission: { mcp: { "github__x": "deny" } } } },
    });
    expect(policy.rules.some((rule) => rule.origin === "baseline")).toBe(false);
  });

  it("is added before the config rules when mcp allows anything", () => {
    const policy = synthesizePolicy({
      scopes: { global: { permission: { mcp: "allow", bash: "ask" } } },
    });
    const baseline = policy.rules.filter((rule) => rule.origin === "baseline");
    expect(baseline.map((rule) => rule.surface)).toEqual([
      "mcp_status",
      "mcp_list",
      "mcp_search",
      "mcp_describe",
      "mcp_connect",
    ]);
    expect(policy.rules[0].origin).toBe("baseline");
    expect(policy.rules.filter((rule) => rule.origin !== "baseline")[0])
      .toMatchObject({ surface: "mcp", action: "allow" });
    expect(mcpBaselineRules()).toHaveLength(5);
  });

  it("is added for a pattern map that allows one mcp name", () => {
    const policy = synthesizePolicy({
      scopes: { global: { permission: { mcp: { "github__*": "allow" } } } },
    });
    expect(policy.rules.some((rule) => rule.surface === "mcp_list")).toBe(true);
  });

  it("is not triggered by a copied single Pi MCP tool allow", () => {
    const policy = synthesizePolicy({
      scopes: { global: { permission: { "mcp__github__issues": "allow" } } },
    });
    expect(policy.rules.some((rule) => rule.origin === "baseline")).toBe(false);
    expect(policy.rules.some((rule) => rule.surface === "mcp")).toBe(true);
  });
});

describe("fail-closed clamp", () => {
  it("lowers inherited allows to ask for an invalid non-global scope", () => {
    const policy = synthesizePolicy({
      scopes: {
        global: {
          permission: {
            "*": "allow",
            mcp: "allow",
            bash: "allow",
            tool: { dangerous: "allow", blocked: "deny" },
          },
        },
        project: { invalid: true },
      },
    });
    expect(policy.defaultRule).toMatchObject({ action: "ask", origin: "fail-closed" });
    expect(policy.rules.find((rule) => rule.surface === "mcp_status"))
      .toMatchObject({ action: "ask", origin: "fail-closed" });
    expect(policy.rules.find((rule) => rule.surface === "bash"))
      .toMatchObject({ action: "ask", origin: "fail-closed" });
    expect(policy.rules.find((rule) => rule.pattern === "dangerous"))
      .toMatchObject({ action: "ask", origin: "fail-closed" });
    expect(policy.rules.find((rule) => rule.pattern === "blocked"))
      .toMatchObject({ action: "deny", origin: "global" });
  });

  it("does not clamp when only the global scope is invalid", () => {
    const policy = synthesizePolicy({
      scopes: {
        global: { permission: { bash: "allow" }, invalid: true },
        project: { permission: { tool: "allow" } },
      },
    });
    expect(policy.invalidScopes).toEqual(["global"]);
    expect(policy.rules.find((rule) => rule.surface === "bash")?.action).toBe("allow");
  });

  it("does not clamp a view without allows", () => {
    const policy = synthesizePolicy({
      scopes: {
        global: { permission: { bash: { "git *": "deny" } } },
        agent: { invalid: true },
      },
    });
    expect(policy.rules[0]).toMatchObject({ action: "deny", origin: "global" });
  });
});

describe("yolo rewrite", () => {
  it("raises asks to allow and keeps denies", () => {
    const policy = synthesizePolicy({
      scopes: {
        global: { permission: { bash: { "git *": "ask", "rm -rf /": "deny" } } },
      },
    });
    const rewritten = applyYoloRewrite(policy.rules, policy.defaultRule);
    expect(rewritten.defaultRule).toMatchObject({ action: "allow", origin: "yolo" });
    expect(rewritten.rules[0]).toMatchObject({ action: "allow", origin: "yolo" });
    expect(rewritten.rules[1]).toMatchObject({ action: "deny", origin: "global" });
  });

  it("leaves an already-allow rule untouched", () => {
    const policy = synthesizePolicy({
      scopes: { global: { permission: { bash: "allow" } } },
    });
    expect(applyYoloRewrite(policy.rules, policy.defaultRule).rules[0].origin).toBe("global");
  });
});
