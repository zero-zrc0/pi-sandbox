import { describe, expect, it } from "vitest";
import {
  EXACT_ACTION_CONTRACT_VERSION,
  canonicalJson,
  sha256Hex,
  type ActionScope,
  type ExactAction,
  type ProjectIdentity,
  type RuleToolIdentity,
  type StoredProjectRule,
} from "#approve-core/policy/project-rules/types";
import { buildExactMatch, exactMatchDigest, matchExactAction } from "#approve-core/policy/project-rules/match";

const identity: ProjectIdentity = { rootPath: "/work/project", displayName: "project", slug: "project", identityHash: "0123456789abcdef" };
const tool: RuleToolIdentity = { name: "bash", origin: "builtin", definitionRevision: "7" };

function scope(id: string, surface: string, target: string, access: ActionScope["access"]): ActionScope {
  return { id, surface, target, access };
}

function action(overrides: Partial<ExactAction> = {}): ExactAction {
  return {
    requestId: "req-1",
    tool,
    definitionDigest: "def-1",
    arguments: { command: "cat file.txt" },
    argumentsDigest: sha256Hex(canonicalJson({ command: "cat file.txt" })),
    cwd: "/work/project",
    environmentDigest: "env-1",
    scopes: [scope("s1", "bash", "cat file.txt", "other")],
    ...overrides,
  };
}

function ruleFor(target: ExactAction, overrides: Partial<StoredProjectRule> = {}): StoredProjectRule {
  const match = buildExactMatch(target)!;
  return {
    id: "rule-0123456789abcdef01234567",
    effect: "allow",
    status: "active",
    match,
    provenance: {
      sessionId: "session-1",
      sourceEntryId: "entry-1",
      quote: "always allow this",
      confidence: 0.95,
      judge: "judge-1",
      actor: "user-1",
    },
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z",
    ...overrides,
  };
}

describe("exact action match construction", () => {
  it("sorts required scopes by surface, target and access without deduplicating equal triples", () => {
    const result = buildExactMatch(action({
      scopes: [
        scope("b", "bash", "b", "write"),
        scope("a", "bash", "a", "read"),
        scope("c", "bash", "a", "read"),
      ],
    }));
    expect(result?.requiredScopes).toEqual([
      { surface: "bash", target: "a", access: "read" },
      { surface: "bash", target: "a", access: "read" },
      { surface: "bash", target: "b", access: "write" },
    ]);
  });

  it("stamps the contract version and the tool identity", () => {
    const result = buildExactMatch(action());
    expect(result).toMatchObject({
      contractVersion: EXACT_ACTION_CONTRACT_VERSION,
      type: "exact_action",
      tool,
      definitionDigest: "def-1",
      cwd: "/work/project",
      environmentDigest: "env-1",
    });
  });

  it("canonicalizes the working directory with the injected function", () => {
    const result = buildExactMatch(action(), { canonicalizeCwd: (cwd) => `/real${cwd}` });
    expect(result?.cwd).toBe("/real/work/project");
  });

  it("rejects an action with a hard deny, no ask scope, or non-object arguments", () => {
    expect(buildExactMatch(action({ hardDeny: true }))).toBeUndefined();
    expect(buildExactMatch(action({ scopes: [] }))).toBeUndefined();
    expect(buildExactMatch(action({ arguments: "text" }))).toBeUndefined();
    expect(buildExactMatch(action({ arguments: [] }))).toBeUndefined();
    expect(buildExactMatch(action({ arguments: null }))).toBeUndefined();
  });

  it("rejects arguments that are sensitive or not learnable", () => {
    expect(buildExactMatch(action({ arguments: { apiToken: "value" } }))).toBeUndefined();
    expect(buildExactMatch(action({ arguments: { authorization: "Bearer abcdefghijklmnop" } }))).toBeUndefined();
  });

  it("rejects arguments that cannot be frozen as JSON", () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(buildExactMatch(action({ arguments: cyclic }))).toBeUndefined();
    expect(buildExactMatch(action({ arguments: { when: () => 1 } }))).toBeUndefined();
  });

  it("computes a digest over the exact action semantics only", () => {
    const first = buildExactMatch(action());
    const second = buildExactMatch(action({ requestId: "req-2" }));
    expect(exactMatchDigest(first!)).toBe(exactMatchDigest(second!));
    const otherArguments = { command: "cat other.txt" };
    const variants = [
      buildExactMatch(action({ definitionDigest: "def-2" }))!,
      buildExactMatch(action({ tool: { ...tool, definitionRevision: "8" } }))!,
      buildExactMatch(action({ arguments: otherArguments, argumentsDigest: sha256Hex(canonicalJson(otherArguments)) }))!,
      buildExactMatch(action({ cwd: "/work" }))!,
      buildExactMatch(action({ environmentDigest: "env-2" }))!,
      buildExactMatch(action({ scopes: [scope("s1", "bash", "other", "other")] }))!,
    ];
    for (const variant of variants) expect(exactMatchDigest(variant)).not.toBe(exactMatchDigest(first!));
  });

  it("preserves the host argument digest on the stored match", () => {
    expect(buildExactMatch(action({ argumentsDigest: "host-digest" }))?.argumentsDigest).toBe("host-digest");
  });
});

describe("exact action rule matching", () => {
  it("returns the match and the covered scope IDs for a matching action", () => {
    const target = action({
      scopes: [
        scope("s1", "bash", "cat file.txt", "other"),
        scope("extra", "path", "/work/project/other.txt", "read"),
      ],
    });
    const rule = ruleFor(action());
    const result = matchExactAction(rule, target);
    expect(result).toMatchObject({ kind: "match" });
    if (result.kind !== "match") throw new Error("expected match");
    expect(result.match).toEqual(rule.match);
    expect(result.coveredScopeIds).toEqual(["s1"]);
  });

  it("covers every current scope with a required triple and leaves extra ask scopes independent", () => {
    const rule = ruleFor(action({ scopes: [scope("s1", "bash", "a", "read"), scope("s2", "bash", "b", "write")] }));
    const target = action({
      scopes: [scope("x1", "bash", "b", "write"), scope("x2", "path", "/a", "read"), scope("x3", "bash", "a", "read")],
    });
    const result = matchExactAction(rule, target);
    if (result.kind !== "match") throw new Error("expected match");
    expect(result.coveredScopeIds).toEqual(["x1", "x3"]);
  });

  it("treats a missing required scope as no match", () => {
    const rule = ruleFor(action({ scopes: [scope("s1", "bash", "a", "read"), scope("s2", "bash", "b", "write")] }));
    expect(matchExactAction(rule, action({ scopes: [scope("x1", "bash", "a", "read")] }))).toEqual({ kind: "no-match" });
  });

  it("passes transport fields through without comparing them", () => {
    const rule = ruleFor(action());
    expect(matchExactAction(rule, action({ requestId: "other-request" })).kind).toBe("match");
  });

  it("ignores rules that are not active or that carry a revocation", () => {
    const target = action();
    expect(matchExactAction(ruleFor(target, { status: "needs_review" }), target)).toEqual({ kind: "no-match" });
    expect(matchExactAction(ruleFor(target, { status: "revoked", revocation: { revokedAt: "2026-01-02T00:00:00.000Z", actor: "user-1" } }), target)).toEqual({ kind: "no-match" });
  });

  it("reports a changed tool definition before comparing the environment", () => {
    const rule = ruleFor(action());
    expect(matchExactAction(rule, action({ definitionDigest: "def-2", environmentDigest: "env-2" }))).toEqual({ kind: "definition-changed" });
    expect(matchExactAction(rule, action({ environmentDigest: "env-2" }))).toEqual({ kind: "environment-changed" });
  });

  it("treats a different tool identity, cwd or argument digest as no match", () => {
    const rule = ruleFor(action());
    expect(matchExactAction(rule, action({ tool: { ...tool, definitionRevision: "8" } }))).toEqual({ kind: "no-match" });
    expect(matchExactAction(rule, action({ tool: { ...tool, origin: "sdk" } }))).toEqual({ kind: "no-match" });
    expect(matchExactAction(rule, action({ tool: { ...tool, name: "write" } }))).toEqual({ kind: "no-match" });
    expect(matchExactAction(rule, action({ cwd: "/work" }))).toEqual({ kind: "no-match" });
    expect(matchExactAction(rule, action({ argumentsDigest: "different" }))).toEqual({ kind: "no-match" });
  });

  it("does not apply a learned allow when the action has a hard deny", () => {
    const rule = ruleFor(action());
    expect(matchExactAction(rule, action({ hardDeny: true }))).toEqual({ kind: "no-match" });
  });

  it("rejects a stored rule whose saved arguments do not match their own digest", () => {
    const rule = ruleFor(action());
    const tampered = { ...rule, match: { ...rule.match, arguments: { command: "rm -rf /" } } };
    expect(matchExactAction(tampered, action())).toEqual({ kind: "no-match" });
  });
});
