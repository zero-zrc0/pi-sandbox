/**
 * Tool admission rules (docs/tool-rules-and-sandbox-tools-design.md §5).
 *
 * Pure evaluator tests: each case is written from the design text — precedence,
 * project-before-global ordering, anchored wildcard semantics and the
 * session-scoped `ask` memory.
 */
import { describe, expect, it } from "vitest";
import {
  ASK_SESSION_LIMIT,
  askSessionKey,
  collectToolRuleLocations,
  createAskSessionMemory,
  evaluateToolRules,
  globMatches,
  globToRegExpSource,
  type ScopedToolRule,
  type ToolRule,
} from "#approve-core/policy/tool-rules";

function rule(overrides: Partial<ToolRule> & Pick<ToolRule, "id">): ToolRule {
  return {
    match: { tool: "bash" },
    decision: "allow",
    ...overrides,
  } as ToolRule;
}

function scoped(scope: "global" | "project", value: ToolRule): ScopedToolRule {
  return { scope, rule: value };
}

describe("glob semantics (§5.3)", () => {
  it("anchors the whole value", () => {
    expect(globMatches("foo", "foo")).toBe(true);
    expect(globMatches("foo", "foobar")).toBe(false);
    expect(globMatches("foo", "barfoo")).toBe(false);
  });

  it("keeps `*` inside one path segment", () => {
    expect(globMatches("src/*", "src/a.ts")).toBe(true);
    expect(globMatches("src/*", "src/a/b.ts")).toBe(false);
    expect(globMatches("src/*", "src/")).toBe(true);
  });

  it("lets `**` cross path separators", () => {
    expect(globMatches("src/**", "src/a/b.ts")).toBe(true);
    expect(globMatches("src/**", "src/")).toBe(true);
    expect(globMatches("**/tool", "a/b/tool")).toBe(true);
  });

  it("matches `?` as exactly one non-separator character", () => {
    expect(globMatches("watchdog_?iff", "watchdog_diff")).toBe(true);
    expect(globMatches("a?c", "a/c")).toBe(false);
    expect(globMatches("a?c", "ac")).toBe(false);
  });

  it("treats unsupported escapes literally", () => {
    expect(globMatches("\\*", "*")).toBe(false);
    expect(globMatches("\\*", "\\anything")).toBe(true);
  });

  it("compiles other regex characters as literals", () => {
    expect(globToRegExpSource("a.b(c)")).toBe("^a\\.b\\(c\\)$");
    expect(globMatches("mcp__*", "mcp__shell")).toBe(true);
  });
});

describe("rule precedence (§5.2)", () => {
  it("asks when no rule matches", () => {
    expect(evaluateToolRules([], { tool: "bash", args: {} })).toEqual({ kind: "ask" });
    expect(evaluateToolRules([scoped("global", rule({ id: "a", match: { tool: "read" } }))], {
      tool: "bash",
      args: {},
    })).toEqual({ kind: "ask" });
  });

  it("matches a tool-level allow", () => {
    const match = evaluateToolRules([scoped("global", rule({ id: "allow-bash" }))], {
      tool: "bash",
      args: { command: "ls" },
    });
    expect(match.kind).toBe("allow");
    expect(match.kind === "allow" ? match.ruleId : "").toBe("allow-bash");
  });

  it("prefers an argument-level deny over a tool-level allow", () => {
    const match = evaluateToolRules([
      scoped("global", rule({ id: "allow-bash" })),
      scoped("global", rule({
        id: "deny-rm",
        decision: "deny",
        match: { tool: "bash", args: { "/command": "*rm -rf*" } },
      })),
    ], { tool: "bash", args: { command: "sudo rm -rf build" } });
    expect(match.kind).toBe("deny");
    expect(match.kind === "deny" ? match.ruleId : "").toBe("deny-rm");
    expect(match.kind === "deny" ? match.argumentLevel : false).toBe(true);
    // `*` never crosses `/`, so the same wildcard misses a slash-containing value.
    expect(evaluateToolRules([
      scoped("global", rule({
        id: "deny-rm",
        decision: "deny",
        match: { tool: "bash", args: { "/command": "*rm -rf*" } },
      })),
    ], { tool: "bash", args: { command: "rm -rf /" } })).toEqual({ kind: "ask" });
  });

  it("prefers an argument-level allow over a tool-level deny", () => {
    const match = evaluateToolRules([
      scoped("global", rule({ id: "deny-all-mcp", decision: "deny", match: { tool: "mcp__*" } })),
      scoped("global", rule({
        id: "allow-readonly",
        match: { tool: "mcp__*", args: { "/command": "ls*" } },
      })),
    ], { tool: "mcp__shell", args: { command: "ls -la" } });
    expect(match.kind).toBe("allow");
    expect(match.kind === "allow" ? match.ruleId : "").toBe("allow-readonly");
  });

  it("prefers a tool-level deny over a tool-level allow", () => {
    const match = evaluateToolRules([
      scoped("global", rule({ id: "allow-all", match: { tool: "*" } })),
      scoped("global", rule({ id: "deny-mcp", decision: "deny", match: { tool: "mcp__*" } })),
    ], { tool: "mcp__shell", args: {} });
    expect(match.kind).toBe("deny");
  });

  it("only matches argument rules when every declared pointer matches", () => {
    const entries = [scoped("global", rule({
      id: "allow-src",
      match: { tool: "read", args: { "/path": "src/**", "/encoding": "utf8" } },
    }))];
    expect(evaluateToolRules(entries, { tool: "read", args: { path: "src/a.ts", encoding: "utf8" } }).kind).toBe("allow");
    expect(evaluateToolRules(entries, { tool: "read", args: { path: "src/a.ts", encoding: "latin1" } }).kind).toBe("ask");
    expect(evaluateToolRules(entries, { tool: "read", args: { path: "src/a.ts" } }).kind).toBe("ask");
    expect(evaluateToolRules(entries, { tool: "read", args: { path: "test/a.ts", encoding: "utf8" } }).kind).toBe("ask");
  });

  it("does not let a non-string argument satisfy an argument rule", () => {
    const entries = [scoped("global", rule({
      id: "deny-numeric",
      decision: "deny",
      match: { tool: "bash", args: { "/timeout": "*" } },
    }))];
    expect(evaluateToolRules(entries, { tool: "bash", args: { timeout: 30 } })).toEqual({ kind: "ask" });
  });

  it("evaluates nested pointer values", () => {
    const entries = [scoped("global", rule({
      id: "deny-nested",
      decision: "deny",
      match: { tool: "mcp__x", args: { "/options/shell": "bash" } },
    }))];
    expect(evaluateToolRules(entries, { tool: "mcp__x", args: { options: { shell: "bash" } } }).kind).toBe("deny");
    expect(evaluateToolRules(entries, { tool: "mcp__x", args: { options: { shell: "sh" } } }).kind).toBe("ask");
  });

  it("prefers the project scope within one priority", () => {
    const match = evaluateToolRules([
      scoped("project", rule({ id: "project-first" })),
      scoped("global", rule({ id: "global-second" })),
    ], { tool: "bash", args: {} });
    expect(match.kind === "allow" ? match.ruleId : "").toBe("project-first");
    // The declaration order the caller passes is the tie-breaker.
    const globalFirst = evaluateToolRules([
      scoped("global", rule({ id: "global-first" })),
      scoped("project", rule({ id: "project-second" })),
    ], { tool: "bash", args: {} });
    expect(globalFirst.kind === "allow" ? globalFirst.ruleId : "").toBe("global-first");
  });

  it("reports the matched scope and argument level for audit", () => {
    const match = evaluateToolRules([
      scoped("project", rule({
        id: "allow-diff",
        match: { tool: "watchdog_diff", args: { "/path": "src/**" } },
      })),
    ], { tool: "watchdog_diff", args: { path: "src/a.ts" } });
    expect(match).toMatchObject({ kind: "allow", ruleId: "allow-diff", scope: "project", argumentLevel: true });
  });

  it("ignores malformed rules instead of matching everything", () => {
    const entries = [
      { scope: "global", rule: { id: "", match: { tool: "*" }, decision: "allow" } },
      { scope: "global", rule: { id: "bad-decision", match: { tool: "*" }, decision: "maybe" } },
    ] as unknown as readonly ScopedToolRule[];
    expect(evaluateToolRules(entries, { tool: "bash", args: {} })).toEqual({ kind: "ask" });
  });
});

describe("declared locations (§5.1)", () => {
  it("reads a string location relative to cwd", () => {
    const verdict = collectToolRuleLocations(rule({
      id: "diff",
      match: { tool: "watchdog_diff" },
      profile: "file-reader",
      locations: [{ pointer: "/path", access: "read" }],
    }), { path: "src/a.ts" }, "/work");
    expect(verdict).toEqual({
      ok: true,
      facts: [{ path: "/work/src/a.ts", access: "read", operation: "read" }],
    });
  });

  it("accepts a string-array location", () => {
    const verdict = collectToolRuleLocations(rule({
      id: "diff",
      match: { tool: "watchdog_diff" },
      profile: "file-reader",
      locations: [{ pointer: "/paths", access: "read" }],
    }), { paths: ["a.ts", "b.ts"] }, "/work");
    expect(verdict.ok && verdict.facts.map((fact) => fact.path)).toEqual(["/work/a.ts", "/work/b.ts"]);
  });

  it("fails a missing location unless it falls back to cwd", () => {
    const strict = rule({
      id: "strict",
      match: { tool: "grep" },
      profile: "file-search",
      locations: [{ pointer: "/path", access: "read" }],
    });
    expect(collectToolRuleLocations(strict, { pattern: "a" }, "/work"))
      .toEqual({ ok: false, reason: "missing-location" });

    const fallback = rule({
      id: "fallback",
      match: { tool: "grep" },
      profile: "file-search",
      locations: [{ pointer: "/path", access: "read", whenAbsent: "cwd" }],
    });
    expect(collectToolRuleLocations(fallback, { pattern: "a" }, "/work"))
      .toEqual({ ok: true, facts: [{ path: "/work", access: "read", operation: "read" }] });
  });

  it("rejects an access the profile does not allow", () => {
    const verdict = collectToolRuleLocations(rule({
      id: "writer",
      match: { tool: "write_file" },
      profile: "file-writer",
      locations: [{ pointer: "/path", access: "read" }],
    }), { path: "a.ts" }, "/work");
    expect(verdict).toEqual({ ok: false, reason: "profile-access-mismatch" });
  });

  it("rejects URLs and empty paths", () => {
    const entries = rule({
      id: "reader",
      match: { tool: "read" },
      profile: "file-reader",
      locations: [{ pointer: "/path", access: "read" }],
    });
    expect(collectToolRuleLocations(entries, { path: "https://example.com/a" }, "/work").ok).toBe(false);
    expect(collectToolRuleLocations(entries, { path: "   " }, "/work").ok).toBe(false);
    expect(collectToolRuleLocations(entries, { path: ["a", ""] }, "/work").ok).toBe(false);
  });

  it("yields no facts for a rule without locations", () => {
    expect(collectToolRuleLocations(rule({ id: "none", match: { tool: "ls" } }), {}, "/work"))
      .toEqual({ ok: true, facts: [] });
  });
});

describe("ask session memory (§5.6)", () => {
  it("keys by tool name and canonical arguments", () => {
    expect(askSessionKey("bash", { b: 1, a: 2 })).toBe(askSessionKey("bash", { a: 2, b: 1 }));
    expect(askSessionKey("bash", { a: 1 })).not.toBe(askSessionKey("bash", { a: 2 }));
    expect(askSessionKey("bash", { a: 1 })).not.toBe(askSessionKey("read", { a: 1 }));
  });

  it("remembers and looks up one decision", () => {
    const memory = createAskSessionMemory();
    memory.remember("bash", { command: "ls" }, "allow", "req-1");
    expect(memory.lookup("bash", { command: "ls" })).toEqual({ decision: "allow", requestId: "req-1" });
    expect(memory.lookup("bash", { command: "pwd" })).toBeUndefined();
    expect(memory.lookup("read", { command: "ls" })).toBeUndefined();
  });

  it("evicts the oldest decision at the capacity limit", () => {
    const memory = createAskSessionMemory(2);
    memory.remember("bash", { command: "one" }, "allow", "req-1");
    memory.remember("bash", { command: "two" }, "allow", "req-2");
    memory.remember("bash", { command: "three" }, "deny", "req-3");
    expect(memory.size).toBe(2);
    expect(memory.lookup("bash", { command: "one" })).toBeUndefined();
    expect(memory.lookup("bash", { command: "three" })).toEqual({ decision: "deny", requestId: "req-3" });
  });

  it("defaults to the documented limit", () => {
    const memory = createAskSessionMemory();
    for (let index = 0; index < ASK_SESSION_LIMIT + 5; index += 1) {
      memory.remember("bash", { command: `c${index}` }, "allow", `req-${index}`);
    }
    expect(memory.size).toBe(ASK_SESSION_LIMIT);
  });

  it("never stores a malformed selection", () => {
    const memory = createAskSessionMemory();
    memory.remember("", {}, "allow", "req");
    memory.remember("bash", {}, "maybe" as never, "req");
    memory.remember("bash", {}, "allow", "");
    expect(memory.size).toBe(0);
  });

  it("clears every decision", () => {
    const memory = createAskSessionMemory();
    memory.remember("bash", {}, "allow", "req");
    memory.clear();
    expect(memory.lookup("bash", {})).toBeUndefined();
  });
});
