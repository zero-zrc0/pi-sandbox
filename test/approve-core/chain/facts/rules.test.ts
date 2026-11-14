import { describe, expect, it } from "vitest";
import { MAX_REASON_LENGTH, type CallState, type StepState, type UnitState } from "#approve-core/contracts";
import type { RuleFact, RuleUnitFacts } from "#approve-core/nodes/rules";
import type { RulesFactsResolver } from "#approve-core/nodes/rules";
import { createRuleEvaluator, type Rule, type RuleOrigin } from "#approve-core/policy/rule";
import type { StepContext } from "#approve-core/runtime";
import { POSIX_PATH_FLAVOR, WIN32_PATH_FLAVOR } from "#approve-core/utils/path/path-flavor";
import {
  projectRuleFacts,
  type RuleFactsOptions,
  type ProjectRuleFactsInput,
} from "#approve-core/chain/facts/rules";

const CALL_ID = "call-1";
const CWD = "/work/project";

function unit(unitId: string): UnitState {
  return { unitId, decision: "ask", reason: "initial", source: "initial", history: [] };
}

function callState(
  toolName: string,
  args: Readonly<Record<string, string>>,
  unitIds: readonly string[] = ["call-1:u1"],
): CallState {
  return {
    toolCallId: CALL_ID,
    toolName,
    arguments: args,
    argumentsDigest: "arguments-digest",
    digest: "call-digest",
    units: unitIds.map(unit),
  };
}

function stepContext(call: CallState): StepContext {
  const state: StepState = {
    stepKey: "step",
    sessionId: "session",
    sourceEntryId: "entry",
    captureDigest: "capture-digest",
    revision: 0,
    calls: [call],
    digest: "state-digest",
  };
  return {
    capture: {
      stepKey: "step",
      sessionId: "session",
      sourceEntryId: "entry",
      manifestRevision: 0,
      complete: true,
      digest: "capture-digest",
      directCalls: [{
        toolCallId: call.toolCallId,
        toolName: call.toolName,
        arguments: call.arguments,
        argumentsDigest: call.argumentsDigest,
        digest: call.digest,
      }],
    },
    state,
    node: { id: "builtin/rules", position: "front", priority: null },
    signal: new AbortController().signal,
    deadlineAt: null,
  };
}

function rule(
  surface: string,
  pattern: string,
  action: Rule["action"],
  origin: RuleOrigin = "project",
): Rule {
  return { surface, pattern, action, origin, layer: "config" };
}

function fact(surface: string, value: string): RuleFact {
  return { surface, value };
}

function entry(
  unitId: string,
  facts: readonly RuleFact[],
  incomplete = false,
): RuleUnitFacts {
  return { unitId, facts, ...(incomplete ? { incomplete: true } : {}) };
}

function resolverOf(entries: readonly RuleUnitFacts[]): RulesFactsResolver {
  return () => entries;
}

function input(
  call: CallState,
  options: RuleFactsOptions,
): ProjectRuleFactsInput {
  return { call, context: stepContext(call), options };
}

function options(overrides: Partial<RuleFactsOptions>): RuleFactsOptions {
  return { rules: [], flavor: POSIX_PATH_FLAVOR, ...overrides };
}

async function project(call: CallState, overrides: Partial<RuleFactsOptions>) {
  return projectRuleFacts(input(call, options(overrides)));
}


describe("projectRuleFacts — explicit rules as facts", () => {
  it("returns no fact when the builtin default wins", async () => {
    const facts = await project(callState("write", { path: `${CWD}/notes.md` }), {});
    expect(facts.size).toBe(0);
  });

  it("projects a matching allow rule onto the call-level unit", async () => {
    const facts = await project(callState("write", { path: `${CWD}/notes.md` }), {
      rules: [rule("path_write", "*", "allow")],
    });
    expect(facts.get("call-1:u1")).toEqual({ decision: "allow", pattern: "*", origin: "project" });
  });

  it("keeps the stricter rank when several facts match", async () => {
    const facts = await project(callState("write", { path: `${CWD}/notes.md` }), {
      rules: [rule("tool", "write", "allow"), rule("path_write", "*", "ask")],
    });
    expect(facts.get("call-1:u1")?.decision).toBe("ask");
  });

  it("lets the last matching rule of one surface win", async () => {
    const facts = await project(callState("write", { path: `${CWD}/notes.md` }), {
      rules: [rule("path_write", "*", "allow"), rule("path_write", "*", "deny")],
    });
    expect(facts.get("call-1:u1")?.decision).toBe("deny");
  });

  it("ignores a builtin-origin rule", async () => {
    const facts = await project(callState("write", { path: `${CWD}/notes.md` }), {
      rules: [rule("path_write", "*", "deny", "builtin")],
    });
    expect(facts.size).toBe(0);
  });

  it("ignores a baseline-origin rule", async () => {
    const facts = await project(callState("write", { path: `${CWD}/notes.md` }), {
      rules: [rule("path_write", "*", "deny", "baseline")],
    });
    expect(facts.size).toBe(0);
  });

  it("expands a call-level entry to every unit of the call", async () => {
    const call = callState("bash", { command: "true" }, ["call-1:u1", "call-1:u2"]);
    const facts = await project(call, {
      rules: [rule("bash", "*", "ask")],
      resolveFacts: resolverOf([entry("*", [fact("bash", "true")])]),
    });
    expect([...facts.keys()]).toEqual(["call-1:u1", "call-1:u2"]);
    expect(facts.get("call-1:u2")?.decision).toBe("ask");
  });

  it("keeps per-unit entries apart", async () => {
    const call = callState("bash", { command: "true" }, ["call-1:u1", "call-1:u2"]);
    const facts = await project(call, {
      rules: [rule("bash", "a", "deny"), rule("bash", "b", "allow")],
      resolveFacts: resolverOf([
        entry("call-1:u1", [fact("bash", "a")]),
        entry("call-1:u2", [fact("bash", "b")]),
      ]),
    });
    expect(facts.get("call-1:u1")?.decision).toBe("deny");
    expect(facts.get("call-1:u2")?.decision).toBe("allow");
  });

  it("merges entries of one unit by rank", async () => {
    const call = callState("bash", { command: "true" }, ["call-1:u1"]);
    const facts = await project(call, {
      rules: [rule("bash", "a", "allow"), rule("bash", "b", "deny")],
      resolveFacts: resolverOf([
        entry("call-1:u1", [fact("bash", "a")]),
        entry("call-1:u1", [fact("bash", "b")]),
      ]),
    });
    expect(facts.get("call-1:u1")?.decision).toBe("deny");
  });

  it("keeps the first pattern when two entries tie on rank", async () => {
    const call = callState("bash", { command: "true" }, ["call-1:u1"]);
    const facts = await project(call, {
      rules: [rule("bash", "a", "deny"), rule("bash", "b", "deny")],
      resolveFacts: resolverOf([
        entry("call-1:u1", [fact("bash", "a")]),
        entry("call-1:u1", [fact("bash", "b")]),
      ]),
    });
    expect(facts.get("call-1:u1")?.pattern).toBe("a");
  });

  it("drops an allow from an incomplete fact set", async () => {
    const call = callState("bash", { command: "npm run build" });
    const facts = await project(call, {
      rules: [rule("bash", "npm run build", "allow")],
      resolveFacts: resolverOf([entry("call-1:u1", [fact("bash", "npm run build")], true)]),
    });
    expect(facts.size).toBe(0);
  });

  it("keeps a deny from an incomplete fact set", async () => {
    const call = callState("bash", { command: "npm run build" });
    const facts = await project(call, {
      rules: [rule("bash", "npm run build", "deny")],
      resolveFacts: resolverOf([entry("call-1:u1", [fact("bash", "npm run build")], true)]),
    });
    expect(facts.get("call-1:u1")?.decision).toBe("deny");
  });

  it("keeps an ask from an incomplete fact set", async () => {
    const call = callState("bash", { command: "npm run build" });
    const facts = await project(call, {
      rules: [rule("bash", "npm run build", "ask")],
      resolveFacts: resolverOf([entry("call-1:u1", [fact("bash", "npm run build")], true)]),
    });
    expect(facts.get("call-1:u1")?.decision).toBe("ask");
  });

  it("ignores entries of unknown units", async () => {
    const call = callState("bash", { command: "true" }, ["call-1:u1"]);
    const facts = await project(call, {
      rules: [rule("bash", "*", "deny")],
      resolveFacts: resolverOf([entry("call-1:u9", [fact("bash", "true")])]),
    });
    expect(facts.size).toBe(0);
  });

  it("returns an empty map when the resolver returns no entries", async () => {
    const facts = await project(callState("bash", { command: "true" }), {
      rules: [rule("bash", "*", "deny")],
      resolveFacts: resolverOf([]),
    });
    expect(facts.size).toBe(0);
  });

  it("maps each rule origin onto one of the three fact scopes", async () => {
    const cases: ReadonlyArray<[RuleOrigin, string]> = [
      ["global", "global"],
      ["project", "project"],
      ["session", "session"],
      ["agent", "global"],
      ["project-agent", "project"],
      ["fail-closed", "project"],
      ["yolo", "global"],
      ["unavailable", "global"],
    ];
    for (const [origin, expected] of cases) {
      const facts = await project(callState("write", { path: `${CWD}/notes.md` }), {
        rules: [rule("path_write", "*", "ask", origin)],
      });
      expect(facts.get("call-1:u1")?.origin).toBe(expected);
    }
  });

  it("clips a long pattern the way the node clipped reasons", async () => {
    const long = "a".repeat(MAX_REASON_LENGTH + 500);
    const call = callState("bash", { command: "true" });
    const facts = await project(call, {
      rules: [rule("bash", long, "ask")],
      resolveFacts: resolverOf([entry("call-1:u1", [fact("bash", long)])]),
    });
    const pattern = facts.get("call-1:u1")?.pattern ?? "";
    expect(pattern).toHaveLength(MAX_REASON_LENGTH);
    expect(pattern.endsWith("...")).toBe(true);
  });

  it("never sets locked on an ask", async () => {
    const facts = await project(callState("write", { path: `${CWD}/notes.md` }), {
      rules: [rule("path_write", "*", "ask")],
    });
    expect(facts.get("call-1:u1")?.locked).toBeUndefined();
  });

  it("uses the provided evaluator instead of building one from rules", async () => {
    const facts = await project(callState("write", { path: `${CWD}/notes.md` }), {
      rules: [],
      evaluator: createRuleEvaluator([rule("path_write", "*", "deny")], POSIX_PATH_FLAVOR),
    });
    expect(facts.get("call-1:u1")?.decision).toBe("deny");
  });

  it("returns frozen values", async () => {
    const facts = await project(callState("write", { path: `${CWD}/notes.md` }), {
      rules: [rule("path_write", "*", "ask")],
    });
    expect(Object.isFrozen(facts.get("call-1:u1"))).toBe(true);
  });
});

describe("projectRuleFacts — file allowlist", () => {
  it("allows through the file allowlist when it covers every path fact", async () => {
    const facts = await project(callState("read", { path: `${CWD}/notes.md` }), {
      fileAllowlist: [`${CWD}/*`],
    });
    expect(facts.get("call-1:u1")).toEqual({
      decision: "allow",
      pattern: "file-allowlist",
      origin: "global",
    });
  });

  it("drops the file allowlist when one path fact is uncovered", async () => {
    const facts = await project(callState("read", { path: `${CWD}/notes.md` }), {
      fileAllowlist: [`${CWD}/other/*`],
    });
    expect(facts.size).toBe(0);
  });

  it("keeps an explicit ask above the file allowlist", async () => {
    const facts = await project(callState("tool" === "tool" ? "read" : "read", { path: `${CWD}/notes.md` }), {
      fileAllowlist: [`${CWD}/*`],
      rules: [rule("tool", "read", "ask")],
    });
    expect(facts.get("call-1:u1")?.decision).toBe("ask");
  });

  it("keeps an explicit deny above the file allowlist", async () => {
    const facts = await project(callState("read", { path: `${CWD}/notes.md` }), {
      fileAllowlist: [`${CWD}/*`],
      rules: [rule("tool", "read", "deny")],
    });
    expect(facts.get("call-1:u1")?.decision).toBe("deny");
  });

  it("drops a file allowlist allow on an incomplete fact set", async () => {
    const call = callState("read", { path: `${CWD}/notes.md` });
    const facts = await project(call, {
      fileAllowlist: [`${CWD}/*`],
      resolveFacts: resolverOf([entry("call-1:u1", [fact("path_read", `${CWD}/notes.md`)], true)]),
    });
    expect(facts.size).toBe(0);
  });

  it("matches a win32 allowlist across separators", async () => {
    const facts = await project(callState("read", { path: "C:\\work\\project\\notes.md" }), {
      flavor: WIN32_PATH_FLAVOR,
      fileAllowlist: ["C:\\work\\project\\*"],
    });
    expect(facts.get("call-1:u1")?.decision).toBe("allow");
  });
});
