import { describe, expect, it } from "vitest";
import {
  PROJECT_RULES_LIMITS,
  PROJECT_RULES_SCHEMA_VERSION,
  canonicalJson,
  sha256Hex,
  type ProjectIdentity,
  type ProjectRulesFile,
  type StoredProjectRule,
} from "#approve-core/policy/project-rules/types";
import { validateProjectRulesFile } from "#approve-core/policy/project-rules/schema";

const identity: ProjectIdentity = {
  rootPath: "/work/project",
  displayName: "project",
  slug: "project",
  identityHash: "0123456789abcdef",
};

const argumentsValue = { command: "cat file.txt" };
const argumentsDigest = sha256Hex(canonicalJson(argumentsValue));

function rule(overrides: Partial<StoredProjectRule> = {}): StoredProjectRule {
  return {
    id: "rule-0123456789abcdef01234567",
    effect: "allow",
    status: "active",
    match: {
      contractVersion: 1,
      type: "exact_action",
      tool: { name: "bash", origin: "builtin", definitionRevision: "7" },
      definitionDigest: "definition-digest",
      arguments: argumentsValue,
      argumentsDigest,
      cwd: "/work/project",
      environmentDigest: "environment-digest",
      requiredScopes: [{ surface: "bash", target: "cat file.txt", access: "other" }],
    },
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

function file(overrides: Partial<ProjectRulesFile> = {}): ProjectRulesFile {
  return {
    schemaVersion: PROJECT_RULES_SCHEMA_VERSION,
    revision: 3,
    identity,
    rules: [rule()],
    tombstones: [],
    ...overrides,
  };
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function expectProblem(value: unknown, kind: string): void {
  const result = validateProjectRulesFile(value, identity);
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.problem.kind).toBe(kind);
}

describe("project rules file validation", () => {
  it("accepts a valid file and returns a deeply frozen model", () => {
    const result = validateProjectRulesFile(file(), identity);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.file.revision).toBe(3);
    expect(Object.isFrozen(result.file)).toBe(true);
    expect(Object.isFrozen(result.file.rules)).toBe(true);
    expect(Object.isFrozen(result.file.rules[0])).toBe(true);
    expect(Object.isFrozen(result.file.rules[0]!.match)).toBe(true);
    expect(Object.isFrozen(result.file.rules[0]!.match.arguments)).toBe(true);
    expect(Object.isFrozen(result.file.rules[0]!.provenance)).toBe(true);
    expect(Object.isFrozen(result.file.rules[0]!.match.requiredScopes)).toBe(true);
  });

  it("rejects non-objects and unknown schema versions", () => {
    expectProblem(null, "not-object");
    expectProblem([], "not-object");
    expectProblem("text", "not-object");
    expectProblem({ ...clone(file()), schemaVersion: 2 }, "unknown-version");
    expectProblem({ ...clone(file()), schemaVersion: "1" }, "unknown-version");
  });

  it("rejects unknown fields and malformed shapes at every level", () => {
    expectProblem({ ...clone(file()), extra: true }, "schema-invalid");
    expectProblem({ ...clone(file()), revision: -1 }, "schema-invalid");
    expectProblem({ ...clone(file()), revision: 1.5 }, "schema-invalid");
    expectProblem({ ...clone(file()), rules: {} }, "schema-invalid");
    expectProblem({ ...clone(file()), identity: { ...identity, extra: true } }, "schema-invalid");
    const badRule = clone(file());
    (badRule.rules[0] as unknown as Record<string, unknown>).extra = 1;
    expectProblem(badRule, "schema-invalid");
    const badMatch = clone(file());
    (badMatch.rules[0]!.match as unknown as Record<string, unknown>).extra = 1;
    expectProblem(badMatch, "schema-invalid");
    const badScope = clone(file());
    (badScope.rules[0]!.match.requiredScopes[0] as unknown as Record<string, unknown>).extra = 1;
    expectProblem(badScope, "schema-invalid");
    const badProvenance = clone(file());
    (badProvenance.rules[0]!.provenance as unknown as Record<string, unknown>).extra = 1;
    expectProblem(badProvenance, "schema-invalid");
  });

  it("rejects malformed rule fields", () => {
    for (const id of ["rule-123", "rule-ZZZZZZZZZZZZZZZZ", "0123456789abcdef01234567", "rule-0123"]) {
      expectProblem(file({ rules: [rule({ id })] }), "schema-invalid");
    }
    expectProblem(file({ rules: [rule({ effect: "ask" as never })] }), "schema-invalid");
    expectProblem(file({ rules: [rule({ status: "unknown" as never })] }), "schema-invalid");
    const emptyScopes = clone(file());
    (emptyScopes.rules[0]!.match as unknown as { requiredScopes: unknown[] }).requiredScopes = [];
    expectProblem(emptyScopes, "schema-invalid");
    const badAccess = clone(file());
    (badAccess.rules[0]!.match.requiredScopes[0] as unknown as Record<string, unknown>).access = "read-write";
    expectProblem(badAccess, "schema-invalid");
    const emptySurface = clone(file());
    (emptySurface.rules[0]!.match.requiredScopes[0] as unknown as Record<string, unknown>).surface = "";
    expectProblem(emptySurface, "schema-invalid");
    expectProblem(file({ rules: [rule({ provenance: { ...rule().provenance, sessionId: "" } })] }), "schema-invalid");
    expectProblem(file({ rules: [rule({ provenance: { ...rule().provenance, quote: "" } })] }), "schema-invalid");
    expectProblem(file({ rules: [rule({ provenance: { ...rule().provenance, confidence: 1.5 } })] }), "schema-invalid");
    expectProblem(file({ rules: [rule({ provenance: { ...rule().provenance, confidence: 0.5 } })] }), "schema-invalid");
    expectProblem(file({ rules: [rule({ provenance: { ...rule().provenance, confidence: Number.NaN } })] }), "schema-invalid");
    expectProblem(file({ rules: [rule({ createdAt: "not-a-date" })] }), "schema-invalid");
  });

  it("rejects an identity that does not belong to the current project", () => {
    expectProblem(file({ identity: { ...identity, identityHash: "ffffffffffffffff" } }), "identity-mismatch");
    expectProblem(file({ identity: { ...identity, rootPath: "/work/other" } }), "identity-mismatch");
  });

  it("rejects duplicate rule and tombstone IDs", () => {
    expectProblem(file({ rules: [rule(), rule()] }), "duplicate-rule-id");
    const revoked = rule({
      id: "rule-aaaaaaaaaaaaaaaaaaaaaaaa",
      status: "revoked",
      revocation: { revokedAt: "2026-01-02T00:00:00.000Z", actor: "user-1" },
    });
    const tombstone = {
      ruleId: revoked.id,
      effect: revoked.effect,
      matchDigest: "match-digest",
      revokedAt: "2026-01-02T00:00:00.000Z",
      revision: 4,
    };
    expectProblem(file({ rules: [revoked], tombstones: [tombstone, tombstone] }), "duplicate-tombstone-id");
  });

  it("enforces status and revocation consistency", () => {
    expectProblem(file({ rules: [rule({ status: "revoked" })] }), "revocation-mismatch");
    expectProblem(file({ rules: [rule({ revocation: { revokedAt: "2026-01-02T00:00:00.000Z", actor: "user-1" } })] }), "revocation-mismatch");
    const tombstone = {
      ruleId: rule().id,
      effect: "allow" as const,
      matchDigest: "match-digest",
      revokedAt: "2026-01-02T00:00:00.000Z",
      revision: 4,
    };
    expectProblem(file({ rules: [rule()], tombstones: [tombstone] }), "revocation-mismatch");
    const revoked = rule({
      status: "revoked",
      revocation: { revokedAt: "2026-01-02T00:00:00.000Z", actor: "user-1" },
    });
    expect(validateProjectRulesFile(file({ rules: [revoked], tombstones: [tombstone] }), identity).ok).toBe(true);
  });

  it("enforces rule and tombstone count limits", () => {
    const rules = Array.from({ length: PROJECT_RULES_LIMITS.maxRules + 1 }, (_, index) => rule({
      id: `rule-${index.toString(16).padStart(24, "0")}`,
    }));
    expectProblem(file({ rules }), "limit-exceeded");
    const tombstones = Array.from({ length: PROJECT_RULES_LIMITS.maxTombstones + 1 }, (_, index) => ({
      ruleId: `rule-${index.toString(16).padStart(24, "0")}`,
      effect: "allow" as const,
      matchDigest: "match-digest",
      revokedAt: "2026-01-02T00:00:00.000Z",
      revision: index + 1,
    }));
    expectProblem(file({ rules: [], tombstones }), "limit-exceeded");
  });

  it("enforces the quote, argument and file byte limits", () => {
    expectProblem(file({ rules: [rule({ provenance: { ...rule().provenance, quote: "q".repeat(PROJECT_RULES_LIMITS.maxQuoteChars + 1) } })] }), "limit-exceeded");
    const bigArguments = { command: "x".repeat(PROJECT_RULES_LIMITS.maxRuleArgumentBytes) };
    const bigRule = rule({
      match: { ...rule().match, arguments: bigArguments, argumentsDigest: sha256Hex(canonicalJson(bigArguments)) },
    });
    expectProblem(file({ rules: [bigRule] }), "limit-exceeded");
    const padded = Array.from({ length: 300 }, (_, index) => rule({
      id: `rule-${index.toString(16).padStart(24, "0")}`,
      match: {
        ...rule().match,
        arguments: { command: "y".repeat(4000) },
        argumentsDigest: sha256Hex(canonicalJson({ command: "y".repeat(4000) })),
      },
    }));
    const result = validateProjectRulesFile(file({ rules: padded }), identity);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(["limit-exceeded", "schema-invalid"]).toContain(result.problem.kind);
  });

  it("rejects sensitive content in arguments, provenance and revocation reasons", () => {
    const sensitiveArguments = { authorization: "Bearer abcdefghijklmnop" };
    const sensitiveRule = rule({
      match: { ...rule().match, arguments: sensitiveArguments, argumentsDigest: sha256Hex(canonicalJson(sensitiveArguments)) },
    });
    expectProblem(file({ rules: [sensitiveRule] }), "sensitive-content");
    expectProblem(file({ rules: [rule({ provenance: { ...rule().provenance, quote: "use token ghp_abcdefghijklmnopqrstuvwxyz012345" } })] }), "sensitive-content");
    expectProblem(file({ rules: [rule({ match: { ...rule().match, cwd: "/work/eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" } })] }), "sensitive-content");
    const revoked = rule({
      status: "revoked",
      revocation: { revokedAt: "2026-01-02T00:00:00.000Z", actor: "user-1", reason: "Bearer abcdefghijklmnopqrstuvwxyz" },
    });
    expectProblem(file({ rules: [revoked] }), "sensitive-content");
  });

  it("rejects a tombstone with a malformed revision or timestamp", () => {
    const revoked = rule({
      status: "revoked",
      revocation: { revokedAt: "2026-01-02T00:00:00.000Z", actor: "user-1" },
    });
    const tombstone = {
      ruleId: revoked.id,
      effect: "allow" as const,
      matchDigest: "match-digest",
      revokedAt: "2026-01-02T00:00:00.000Z",
      revision: 4,
    };
    expectProblem(file({ rules: [revoked], tombstones: [{ ...tombstone, revision: -1 }] }), "schema-invalid");
    expectProblem(file({ rules: [revoked], tombstones: [{ ...tombstone, revokedAt: "nope" }] }), "schema-invalid");
    expectProblem(file({ rules: [revoked], tombstones: [{ ...tombstone, effect: "deny" }] }), "revocation-mismatch");
  });
});
