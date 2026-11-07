import { describe, expect, it } from "vitest";
import {
  MAX_SCOPE_RULES,
  matchesPiMcpToolName,
  normalizePermissionConfig,
} from "#approve-core/policy/normalize";

describe("surface values", () => {
  it("turns a string catch-all into a * pattern", () => {
    const { rules } = normalizePermissionConfig({ bash: "allow" }, "global");
    expect(rules).toEqual([
      { surface: "bash", pattern: "*", action: "allow", origin: "global", layer: "config" },
    ]);
  });

  it("keeps pattern order and denial reasons", () => {
    const { rules } = normalizePermissionConfig({
      bash: {
        "git *": "allow",
        "git push *": { action: "deny", reason: "no pushes" },
      },
    }, "project");
    expect(rules.map((rule) => [rule.pattern, rule.action])).toEqual([
      ["git *", "allow"],
      ["git push *", "deny"],
    ]);
    expect(rules[1].reason).toBe("no pushes");
    expect(rules[1].origin).toBe("project");
  });

  it("skips invalid actions and values but keeps legal entries", () => {
    const { rules } = normalizePermissionConfig({
      bash: { a: "yes", b: "deny", c: 3, d: { action: "ask" } },
      tool: 5,
      "": "allow",
    }, "global");
    expect(rules.map((rule) => [rule.surface, rule.pattern, rule.action])).toEqual([
      ["bash", "b", "deny"],
    ]);
  });

  it("produces no rules for empty pattern maps or explicit undefined", () => {
    expect(normalizePermissionConfig({ bash: {}, tool: undefined }, "global").rules).toEqual([]);
  });

  it("does not turn the universal key into a regular rule", () => {
    const normalized = normalizePermissionConfig({ "*": "allow", bash: "ask" }, "global");
    expect(normalized.universal).toEqual({ action: "allow" });
    expect(normalized.rules.map((rule) => rule.surface)).toEqual(["bash"]);
  });

  it("reads a universal default from the * pattern of an object value", () => {
    expect(normalizePermissionConfig({ "*": { "*": "deny" } }, "global").universal)
      .toEqual({ action: "deny" });
  });
});

describe("bare path family expansion", () => {
  it("expands into read and write surfaces with sugar before explicit patterns", () => {
    const { rules } = normalizePermissionConfig({
      path: { "*.log": "allow" },
      path_read: { "/etc/*": "deny" },
    }, "global");
    expect(rules.filter((rule) => rule.surface === "path_read").map((rule) => rule.pattern))
      .toEqual(["*.log", "/etc/*"]);
    expect(rules.filter((rule) => rule.surface === "path_write").map((rule) => rule.pattern))
      .toEqual(["*.log"]);
    expect(rules.some((rule) => rule.surface === "path")).toBe(false);
  });

  it("keeps only the explicit position for a pattern defined in that direction", () => {
    const { rules } = normalizePermissionConfig({
      path: { "*": "allow" },
      path_read: { "*": "deny" },
    }, "global");
    expect(rules.map((rule) => [rule.surface, rule.pattern, rule.action])).toEqual([
      ["path_read", "*", "deny"],
      ["path_write", "*", "allow"],
    ]);
  });

  it("orders sugar first regardless of the key order in the file", () => {
    const { rules } = normalizePermissionConfig({
      path_read: { "/etc/*": "deny" },
      path: { "*.log": "allow" },
    }, "global");
    expect(rules.filter((rule) => rule.surface === "path_read").map((rule) => rule.pattern))
      .toEqual(["*.log", "/etc/*"]);
  });

  it("expands the external_directory family the same way", () => {
    const { rules } = normalizePermissionConfig({
      external_directory: "deny",
      external_directory_write: { "/tmp/*": "allow" },
    }, "global");
    expect(rules.map((rule) => [rule.surface, rule.pattern, rule.action])).toEqual([
      ["external_directory_read", "*", "deny"],
      ["external_directory_write", "*", "deny"],
      ["external_directory_write", "/tmp/*", "allow"],
    ]);
  });
});

describe("Pi MCP compatibility copies", () => {
  it("copies a catch-all surface that matches a full Pi MCP name to the mcp surface", () => {
    const { rules } = normalizePermissionConfig({
      "mcp__github__*": "allow",
      bash: "ask",
    }, "global");
    expect(rules.map((rule) => [rule.surface, rule.pattern])).toEqual([
      ["mcp__github__*", "*"],
      ["bash", "*"],
      ["mcp", "mcp__github__*"],
    ]);
  });

  it("does not copy non-catch-all or non-Pi-MCP keys", () => {
    expect(normalizePermissionConfig({
      "mcp__github__*": { "x": "allow" },
      "git*": "allow",
    }, "global").rules.some((rule) => rule.surface === "mcp")).toBe(false);
  });

  it("recognizes broad wildcards that can still match a Pi MCP name", () => {
    expect(matchesPiMcpToolName("mcp__*")).toBe(true);
    expect(matchesPiMcpToolName("mcp*")).toBe(true);
    expect(matchesPiMcpToolName("mcp__github__*")).toBe(true);
    expect(matchesPiMcpToolName("mcp")).toBe(false);
    expect(matchesPiMcpToolName("foo*")).toBe(false);
  });
});

describe("resource bound", () => {
  it("stops at the scope rule limit and reports truncation", () => {
    const patterns: Record<string, "allow"> = {};
    for (let index = 0; index < MAX_SCOPE_RULES + 10; index += 1) {
      patterns[`cmd-${index}`] = "allow";
    }
    const normalized = normalizePermissionConfig({ bash: patterns }, "global");
    expect(normalized.truncated).toBe(true);
    expect(normalized.rules).toHaveLength(MAX_SCOPE_RULES);
  });
});
