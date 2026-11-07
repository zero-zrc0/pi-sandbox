import { describe, expect, it } from "vitest";
import {
  assessToolAccessFacts,
  type ToolAccessAssessment,
  type ToolAccessScope,
  type ToolExecutorCapability,
} from "#approve-core/utils/tool-access/assessment";
import type { ToolAccessFactsResult } from "#approve-core/utils/tool-access/access-facts";

const tool = { name: "read", origin: "builtin:read", revision: "7" };

function facts(overrides: Partial<ToolAccessFactsResult> = {}): ToolAccessFactsResult {
  return {
    status: "verified",
    source: "builtin",
    complete: true,
    unknownEffects: [],
    accesses: [{ path: "C:/work/a.txt", access: "read", operation: "read" }],
    tool,
    ...overrides,
  };
}

function scope(
  target: string,
  access: ToolAccessScope["access"],
  state: ToolAccessScope["state"],
  overrides: Partial<ToolAccessScope> = {},
): ToolAccessScope {
  return { id: `${state}:${target}:${access}`, surface: `path_${access}`, target, access, state, ...overrides };
}

function executor(overrides: Partial<ToolExecutorCapability> = {}): ToolExecutorCapability {
  return {
    available: true,
    enforcesAllScopes: true,
    checksAllTargetsBeforeStart: true,
    boundary: "windows-mxc",
    ...overrides,
  };
}

function assess(
  inputFacts: ToolAccessFactsResult,
  scopes: readonly ToolAccessScope[],
  executorCapability?: ToolExecutorCapability,
): ToolAccessAssessment {
  return assessToolAccessFacts({
    facts: inputFacts,
    scopes,
    ...(executorCapability === undefined ? {} : { executor: executorCapability }),
  });
}

describe("assessToolAccessFacts routes", () => {
  it("runs a verified call with no asks once the executor proves coverage", () => {
    const scopes = [scope("C:/work/a.txt", "read", "allow")];
    const result = assess(facts(), scopes, executor());

    expect(result.route).toBe("run");
    expect(result.reason).toBe("controlled-execution");
    expect(result.execution).toBe("controlled");
    expect(result.modelRequests).toBe(0);
    expect(result.scopes).toEqual(scopes);
    expect(result.missingScopes).toBeUndefined();
  });

  it("runs a verified call with no accesses at all when the executor can run it", () => {
    const result = assess(facts({ accesses: [] }), [], executor());
    expect(result.route).toBe("run");
  });

  it("adds one ask missing-scope per uncovered fact and reviews", () => {
    const result = assess(facts(), [scope("C:/work/other.txt", "read", "allow")], executor());

    expect(result.route).toBe("review");
    expect(result.reason).toBe("missing-scopes");
    expect(result.execution).toBe("unavailable");
    expect(result.missingScopes).toEqual([{
      id: "missing-scope:0",
      surface: "path_read",
      target: "C:/work/a.txt",
      access: "read",
      state: "ask",
      source: "missing-scope",
    }]);
    expect(result.scopes).toHaveLength(2);
  });

  it("treats the same path with a different access as uncovered", () => {
    const result = assess(
      facts({
        accesses: [
          { path: "C:/work/a.txt", access: "read" },
          { path: "C:/work/a.txt", access: "write" },
        ],
      }),
      [scope("C:/work/a.txt", "read", "allow")],
      executor(),
    );

    expect(result.route).toBe("review");
    expect(result.missingScopes?.map((item) => item.access)).toEqual(["write"]);
    expect(result.missingScopes?.[0]?.surface).toBe("path_write");
  });

  it("keeps a host ask as review even when the executor could run", () => {
    const result = assess(facts(), [scope("C:/work/a.txt", "read", "ask")], executor());

    expect(result.route).toBe("review");
    expect(result.reason).toBe("scope-review");
    expect(result.missingScopes).toBeUndefined();
    expect(result.execution).toBe("unavailable");
  });

  it("blocks on any deny scope before anything else", () => {
    const result = assess(
      facts(),
      [scope("C:/work/a.txt", "read", "allow"), scope("C:/elsewhere", "write", "deny")],
      executor(),
    );

    expect(result.route).toBe("block");
    expect(result.reason).toBe("explicit-deny");
    expect(result.execution).toBe("unavailable");
  });

  it("blocks even when facts are unbound or incomplete", () => {
    expect(assess(facts({ status: "unbound" }), [scope("C:/elsewhere", "write", "deny")]).route).toBe("block");
    expect(assess(facts({ status: "incomplete", complete: false }), [scope("C:/elsewhere", "write", "deny")]).route)
      .toBe("block");
  });

  it("defers unbound facts without inventing unknown-effects scopes", () => {
    const result = assess(facts({ status: "unbound", accesses: [], complete: false }), []);

    expect(result.route).toBe("defer");
    expect(result.reason).toBe("tool-unbound");
    expect(result.execution).toBe("unavailable");
    expect(result.scopes).toEqual([]);
  });

  it("adds a tool-level unknown-effects ask for incomplete facts with a tool identity", () => {
    const result = assess(
      facts({ status: "incomplete", complete: false, unknownEffects: ["invalid-file-path"] }),
      [scope("C:/work/a.txt", "read", "allow")],
      executor(),
    );

    expect(result.route).toBe("review");
    expect(result.reason).toBe("unknown-effects");
    expect(result.execution).toBe("unavailable");
    expect(result.scopes).toContainEqual({
      id: "unknown-effects",
      surface: "tool",
      target: "read",
      access: "other",
      state: "ask",
      source: "unknown-effects",
    });
  });

  it("defers incomplete facts that carry no tool identity", () => {
    const result = assess(
      facts({ status: "incomplete", complete: false, tool: undefined }),
      [],
    );

    expect(result.route).toBe("defer");
    expect(result.reason).toBe("tool-identity-unavailable");
    expect(result.execution).toBe("unavailable");
  });

  it("defers invalid fact objects instead of trusting them", () => {
    const result = assess(undefined as unknown as ToolAccessFactsResult, [], executor());
    expect(result.route).toBe("defer");
    expect(result.reason).toBe("incomplete-facts");
  });
});

describe("assessToolAccessFacts executor gate", () => {
  it("requires an executor for an otherwise runnable call", () => {
    const result = assess(facts(), [scope("C:/work/a.txt", "read", "allow")]);
    expect(result.route).toBe("defer");
    expect(result.reason).toBe("executor-unavailable");
    expect(result.execution).toBe("unavailable");
  });

  it("defers an unavailable executor and keeps the host-provided reason", () => {
    expect(assess(facts(), [scope("C:/work/a.txt", "read", "allow")], executor({ available: false })).reason)
      .toBe("executor-unavailable");
    expect(assess(
      facts(),
      [scope("C:/work/a.txt", "read", "allow")],
      executor({ available: false, reason: "probe failed" }),
    ).reason).toBe("probe failed");
  });

  it("defers an executor that cannot enforce every granted scope", () => {
    let result = assess(facts(), [scope("C:/work/a.txt", "read", "allow")], executor({ enforcesAllScopes: false }));
    expect(result.route).toBe("defer");
    expect(result.reason).toBe("executor-scope-unavailable");

    result = assess(
      facts(),
      [scope("C:/work/a.txt", "read", "allow")],
      executor({ enforcesAllScopes: false, reason: "cannot express write" }),
    );
    expect(result.reason).toBe("cannot express write");
  });

  it("defers an executor that does not check every target before start", () => {
    const result = assess(
      facts(),
      [scope("C:/work/a.txt", "read", "allow")],
      executor({ checksAllTargetsBeforeStart: false }),
    );
    expect(result.route).toBe("defer");
    expect(result.reason).toBe("executor-target-unchecked");
  });

  it("defers an executor without a named boundary", () => {
    for (const boundary of ["", "   "]) {
      const result = assess(facts(), [scope("C:/work/a.txt", "read", "allow")], executor({ boundary }));
      expect(result.route).toBe("defer");
      expect(result.reason).toBe("executor-boundary-unavailable");
    }
  });

  it("does not consult the executor while facts are unverified or an ask remains", () => {
    const capable = executor();
    expect(assess(facts({ status: "incomplete", complete: false }), [scope("C:/work/a.txt", "read", "allow")], capable).route)
      .toBe("review");
    expect(assess(facts(), [], capable).route).toBe("review");
  });
});

describe("assessToolAccessFacts output stability", () => {
  it("never mutates the caller's scope list", () => {
    const scopes = [scope("C:/work/other.txt", "read", "allow")];
    assess(facts(), scopes, executor());
    expect(scopes).toHaveLength(1);
  });

  it("keeps modelRequests at zero on every route", () => {
    const routes: ToolAccessAssessment[] = [
      assess(facts(), [scope("C:/work/a.txt", "read", "allow")], executor()),
      assess(facts(), [scope("C:/work/a.txt", "read", "allow")]),
      assess(facts(), []),
      assess(facts(), [scope("C:/work/a.txt", "read", "deny")]),
      assess(facts({ status: "unbound" }), []),
    ];
    for (const result of routes) expect(result.modelRequests).toBe(0);
  });

  it("returns complete scopes including the appended asks", () => {
    const result = assess(
      facts({
        status: "incomplete",
        complete: false,
        accesses: [{ path: "C:/work/b.txt", access: "write" }],
      }),
      [scope("C:/work/a.txt", "read", "ask")],
    );

    expect(result.scopes.map((item) => item.id)).toEqual([
      "ask:C:/work/a.txt:read",
      "missing-scope:0",
      "unknown-effects",
    ]);
    expect(result.missingScopes).toHaveLength(1);
  });
});
