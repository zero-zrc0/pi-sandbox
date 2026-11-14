import { describe, expect, it } from "vitest";
import {
  PermissionManager,
  type PolicyScopeView,
} from "#approve-core/policy/permission-manager";
import { SessionRuleStore } from "#approve-core/policy/session-rules";
import {
  bashCommandIntent,
  fixedValuesIntent,
  pathValuesIntent,
  rawToolIntent,
} from "#approve-core/utils/access-intent/access-intent";
import { compileWildcard } from "#approve-core/policy/wildcard-matcher";
import { POSIX_PATH_FLAVOR as POSIX } from "#approve-core/utils/path/path-flavor";
import type { RuleOrigin } from "#approve-core/policy/rule";

interface HarnessOptions {
  readonly permission?: unknown;
  readonly scopes?: Partial<Record<RuleOrigin, PolicyScopeView>>;
  readonly onCompile?: () => void;
}

function harness(options: HarnessOptions = {}) {
  const session = new SessionRuleStore({
    flavor: POSIX,
    ...(options.onCompile === undefined ? {} : {
      compilePattern: (pattern, matchOptions) => {
        options.onCompile?.();
        return compileWildcard(pattern, matchOptions);
      },
    }),
  });
  let stamp = "stamp-1";
  let scopes: Partial<Record<RuleOrigin, PolicyScopeView>> = options.scopes ??
    { global: { permission: options.permission ?? {} } };
  let yolo = false;
  const manager = new PermissionManager({
    flavor: POSIX,
    session,
    loadPolicy: () => ({
      stamp,
      scopes,
      mcpServerNames: ["gh"],
    }),
    readYolo: () => yolo,
    compilePattern: (pattern, matchOptions) => {
      options.onCompile?.();
      return compileWildcard(pattern, matchOptions);
    },
  });
  return {
    manager,
    session,
    setScopes(next: Partial<Record<RuleOrigin, PolicyScopeView>>): void {
      scopes = next;
      stamp = `stamp-${Math.random()}`;
    },
    setYolo(value: boolean): void {
      yolo = value;
    },
  };
}

describe("raw tool intents", () => {
  it("evaluates the tool surface catch-all", () => {
    const { manager } = harness({ permission: { tool: "allow" } });
    const result = manager.check(rawToolIntent("tool", {}));
    expect(result).toMatchObject({
      toolName: "tool",
      state: "allow",
      source: "tool",
      origin: "global",
      matchedPattern: "*",
      target: "*",
    });
  });

  it("reports the builtin default without a matched pattern", () => {
    const { manager } = harness({ permission: {} });
    const result = manager.check(rawToolIntent("mystery", {}));
    expect(result).toMatchObject({ state: "ask", origin: "builtin", source: "default" });
    expect(result.matchedPattern).toBeUndefined();
  });

  it("uses the universal default for unconfigured tools", () => {
    const { manager } = harness({ permission: { "*": "allow" } });
    expect(manager.check(rawToolIntent("mystery", {}))).toMatchObject({
      state: "allow",
      origin: "global",
      source: "default",
    });
  });

  it("reports the matched MCP candidate as the target", () => {
    const { manager } = harness({ permission: { mcp: { gh_pr: "allow" } } });
    const result = manager.check(rawToolIntent("mcp", { tool: "gh:pr" }));
    expect(result).toMatchObject({
      toolName: "mcp",
      state: "allow",
      source: "mcp",
      target: "gh_pr",
      matchedPattern: "gh_pr",
    });
  });

  it("checks Pi MCP names on the mcp surface", () => {
    const { manager } = harness({ permission: { mcp: "allow" } });
    const result = manager.check(rawToolIntent("mcp__gh__issues", {}));
    expect(result).toMatchObject({ toolName: "mcp__gh__issues", state: "allow", source: "mcp" });
  });
});

describe("bash intents", () => {
  it("evaluates the original command text", () => {
    const { manager } = harness({ permission: { bash: { "git *": "deny" } } });
    const result = manager.check(bashCommandIntent("git status", ["git status"]));
    expect(result).toMatchObject({
      state: "deny",
      source: "bash",
      command: "git status",
      matchedPattern: "git *",
    });
    expect(result.matchedSpelling).toBeUndefined();
  });

  it("reports the equivalent spelling that actually matched", () => {
    const { manager } = harness({ permission: { bash: { "/usr/bin/git *": "allow" } } });
    const result = manager.check(
      bashCommandIntent("git status", ["git status", "/usr/bin/git status"]),
    );
    expect(result).toMatchObject({
      state: "allow",
      command: "git status",
      matchedSpelling: "/usr/bin/git status",
    });
  });

  it("evaluates an empty command as a whole string", () => {
    const { manager } = harness({ permission: { bash: "deny" } });
    const result = manager.check(bashCommandIntent("", []));
    expect(result).toMatchObject({ state: "deny", command: "" });
  });

  it("keeps the original tool name for shell aliases", () => {
    const { manager } = harness({ permission: { bash: "allow" } });
    const result = manager.check(rawToolIntent("run_shell", { command: "ls" }), {
      toolName: "run_shell",
    });
    expect(result.toolName).toBe("run_shell");
  });
});

describe("path intents", () => {
  const path = (display: string, matchValues = [display]) =>
    ({ display, matchValues, boundary: "" });

  it("evaluates a directional surface with the display target", () => {
    const { manager } = harness({ permission: { path_read: { "*.log": "allow" } } });
    const result = manager.check(pathValuesIntent("path_read", [path("/w/a.log")]));
    expect(result).toMatchObject({
      state: "allow",
      source: "special",
      target: "/w/a.log",
      matchedPattern: "*.log",
    });
  });

  it("takes the most restrictive direction of a bare family", () => {
    const { manager } = harness({
      permission: { path_read: "allow", path_write: { "/w/*": "deny" } },
    });
    const result = manager.check(pathValuesIntent("path", [path("/w/a.log")]));
    expect(result).toMatchObject({ state: "deny", target: "/w/a.log" });
  });

  it("takes the most restrictive independent path", () => {
    const { manager } = harness({
      permission: { path_read: { "/a": "allow", "/b": "ask" } },
    });
    const result = manager.check(pathValuesIntent("path_read", [path("/a"), path("/b")]));
    expect(result.state).toBe("ask");
    expect(result.target).toBe("/b");
  });

  it("falls back to * for an empty path set", () => {
    const { manager } = harness({ permission: { path_read: "deny" } });
    expect(manager.check(pathValuesIntent("path_read", [])).state).toBe("deny");
  });
});

describe("session rules", () => {
  it("applies session approvals to checks", () => {
    const { manager, session } = harness({ permission: { bash: "ask" } });
    session.approve("bash", "git *");
    const result = manager.check(bashCommandIntent("git status", ["git status"]));
    expect(result).toMatchObject({
      state: "allow",
      source: "session",
      origin: "session",
      matchedPattern: "git *",
    });
  });

  it("keeps tool-level queries free of session rules", () => {
    const { manager, session } = harness({ permission: {} });
    session.approve("tool", "*");
    expect(manager.toolState("tool")).toBe("ask");
  });

  it("re-evaluates after a session change", () => {
    const { manager, session } = harness({ permission: { bash: "ask" } });
    expect(manager.check(bashCommandIntent("git status", ["git status"])).state).toBe("ask");
    session.approve("bash", "git *");
    expect(manager.check(bashCommandIntent("git status", ["git status"])).state).toBe("allow");
  });
});

describe("yolo", () => {
  it("rewrites asks to allows for checks only", () => {
    const { manager, setYolo } = harness({ permission: { bash: "ask" } });
    setYolo(true);
    expect(manager.check(bashCommandIntent("git status", ["git status"])))
      .toMatchObject({ state: "allow", origin: "yolo" });
    expect(manager.toolState("bash")).toBe("ask");
    expect(manager.configRules()[0].action).toBe("ask");
  });
});

describe("fail-closed scopes", () => {
  it("clamps inherited allows when a non-global scope is invalid", () => {
    const { manager } = harness({
      scopes: {
        global: { permission: { tool: "allow" } },
        project: { invalid: true },
      },
    });
    expect(manager.check(rawToolIntent("tool", {}))).toMatchObject({
      state: "ask",
      origin: "fail-closed",
    });
  });
});

describe("cache and view replacement", () => {
  it("compiles each surface once per stamp and agent", () => {
    let compiles = 0;
    const { manager } = harness({
      permission: { bash: "allow", tool: { "*": "allow" } },
      onCompile: () => { compiles += 1; },
    });
    manager.check(bashCommandIntent("ls", ["ls"]));
    manager.check(bashCommandIntent("ls", ["ls"]));
    expect(compiles).toBe(1);
    manager.check(rawToolIntent("tool", {}));
    expect(compiles).toBe(2);
    manager.check(bashCommandIntent("ls", ["ls"]));
    expect(compiles).toBe(2);
  });

  it("rebuilds the evaluator when the loader stamp changes", () => {
    let compiles = 0;
    const { manager, setScopes } = harness({
      permission: { bash: "allow" },
      onCompile: () => { compiles += 1; },
    });
    manager.check(bashCommandIntent("ls", ["ls"]));
    expect(compiles).toBe(1);
    setScopes({ global: { permission: { bash: "deny" } } });
    expect(manager.check(bashCommandIntent("ls", ["ls"])).state).toBe("deny");
    expect(compiles).toBe(2);
  });
});

describe("tool-level queries", () => {
  it("evaluates the surface catch-all", () => {
    const { manager } = harness({ permission: { tool: { blocked: "allow" } } });
    expect(manager.toolState("tool")).toBe("ask");
  });

  it("probes reachability without treating a partial deny as full denial", () => {
    const closed = harness({ permission: { tool: "deny" } });
    expect(closed.manager.isToolFullyDenied("tool")).toBe(true);

    const partial = harness({
      permission: { tool: { "*": "deny", safe: "allow" } },
    });
    expect(partial.manager.isToolFullyDenied("tool")).toBe(false);
  });

  it("probes the mcp surface for Pi MCP tools", () => {
    const { manager } = harness({ permission: { mcp: "deny" } });
    expect(manager.toolState("mcp__gh__issues")).toBe("deny");
    expect(manager.isToolFullyDenied("mcp__gh__issues")).toBe(true);
  });
});

describe("fixed-value intents", () => {
  it("evaluates the given candidates in order", () => {
    const { manager } = harness({ permission: { skill: { deploy: "deny" } } });
    const result = manager.check(fixedValuesIntent("skill", ["deploy"]));
    expect(result).toMatchObject({ toolName: "skill", state: "deny", source: "skill" });
  });
});
