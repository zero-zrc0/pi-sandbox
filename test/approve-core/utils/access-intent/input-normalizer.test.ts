import { describe, expect, it } from "vitest";
import {
  extractShellInvocation,
  normalizeBashCommand,
  normalizeToolTargets,
} from "#approve-core/utils/access-intent/input-normalizer";

describe("extractShellInvocation", () => {
  it("reads command from the native bash tool only", () => {
    expect(extractShellInvocation("bash", { command: "ls" })).toEqual({ command: "ls" });
    expect(extractShellInvocation("bash", { command: "  " })).toEqual({ command: "" });
    expect(extractShellInvocation("bash", { command: 42 })).toEqual({ command: "" });
    expect(extractShellInvocation("bash", {})).toEqual({ command: "" });
  });

  it("reads declared alias arguments and workdir", () => {
    const shellTools = { shell: { commandArgument: "cmd", workdirArgument: "cwd" } };
    expect(extractShellInvocation("shell", { cmd: "ls", cwd: "/w" }, shellTools)).toEqual({
      command: "ls",
      workdir: "/w",
    });
    expect(extractShellInvocation("shell", { cmd: "ls" }, shellTools)).toEqual({ command: "ls" });
  });

  it("treats an invalid workdir as not provided", () => {
    const shellTools = { shell: { commandArgument: "cmd", workdirArgument: "cwd" } };
    expect(extractShellInvocation("shell", { cmd: "ls", cwd: 42 }, shellTools)).toEqual({ command: "ls" });
    expect(extractShellInvocation("shell", { cmd: "ls", cwd: "  " }, shellTools)).toEqual({ command: "ls" });
  });

  it("returns no shell semantics for non-shell tools", () => {
    expect(extractShellInvocation("read", { command: "ls" })).toBeUndefined();
    expect(extractShellInvocation("bash", { command: "ls" }, { other: { commandArgument: "c" } })).toEqual({
      command: "ls",
    });
  });
});

describe("normalizeBashCommand", () => {
  it("removes a leading full-line comment and trims", () => {
    expect(normalizeBashCommand("# note\ngit status")).toEqual({
      command: "git status",
      original: "# note\ngit status",
      spellings: ["git status", "# note\ngit status"],
    });
  });

  it("falls back to the original when only a comment remains", () => {
    expect(normalizeBashCommand("   # just a comment").command).toBe("   # just a comment");
  });

  it("keeps commands that do not start with a comment unchanged", () => {
    expect(normalizeBashCommand("git status")).toEqual({
      command: "git status",
      original: "git status",
      spellings: ["git status"],
    });
  });

  it("does not treat indented command text after a comment line as part of the comment", () => {
    const result = normalizeBashCommand("# c\n  git log");
    expect(result.command).toBe("git log");
  });
});

describe("normalizeToolTargets", () => {
  it("normalizes skill to its name with a * fallback", () => {
    expect(normalizeToolTargets("skill", { name: "deploy" })).toEqual({
      surface: "skill",
      targets: ["deploy"],
    });
    expect(normalizeToolTargets("skill", {}).targets).toEqual(["*"]);
    expect(normalizeToolTargets("skill", { name: 42 }).targets).toEqual(["*"]);
  });

  it("normalizes bash through the bash pipeline", () => {
    const result = normalizeToolTargets("bash", { command: "# c\nmake" });
    expect(result.surface).toBe("bash");
    expect(result.targets).toEqual(["make", "# c\nmake"]);
  });

  it("reads shell aliases from their declared arguments", () => {
    const result = normalizeToolTargets("shell", { cmd: "make", cwd: "/w" }, {
      shellTools: { shell: { commandArgument: "cmd", workdirArgument: "cwd" } },
    });
    expect(result.surface).toBe("bash");
    expect(result.workdir).toBe("/w");
    expect(result.targets).toEqual(["make"]);
  });

  it("appends the surface-level mcp candidate for proxy and Pi MCP tools", () => {
    const proxy = normalizeToolTargets("mcp", { tool: "gh:pr" });
    expect(proxy.surface).toBe("mcp");
    expect(proxy.targets.at(-1)).toBe("mcp");
    expect(proxy.targets).toContain("gh_pr");

    const pi = normalizeToolTargets("mcp__gh__pr", { x: 1 });
    expect(pi.surface).toBe("mcp");
    expect(pi.targets.at(-1)).toBe("mcp");
    expect(pi.targets).toContain("mcp__gh__pr");
  });

  it("maps other tools to their own surface with a catch-all target", () => {
    expect(normalizeToolTargets("read", { path: "/a" })).toEqual({ surface: "read", targets: ["*"] });
    expect(normalizeToolTargets("whatever", null)).toEqual({ surface: "whatever", targets: ["*"] });
  });

  it("never throws on invalid inputs", () => {
    expect(() => normalizeToolTargets("bash", "a string")).not.toThrow();
    expect(() => normalizeToolTargets("mcp", 42)).not.toThrow();
    expect(normalizeToolTargets("mcp", 42).targets).toContain("mcp");
  });
});
