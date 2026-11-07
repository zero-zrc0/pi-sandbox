import { describe, expect, it } from "vitest";
import {
  PROJECT_RULES_SCHEMA_VERSION,
  canonicalJson,
  sha256Hex,
  type ActionScope,
  type ExactAction,
  type ExactActionMatch,
  type ProjectIdentity,
  type ProjectRulesFile,
  type RuleEffect,
  type RuleTombstone,
  type RuleToolIdentity,
  type StoredProjectRule,
} from "#approve-core/policy/project-rules/types";
import { buildExactMatch, exactMatchDigest } from "#approve-core/policy/project-rules/match";
import { SENSITIVE_REASON_PLACEHOLDER } from "#approve-core/policy/project-rules/sensitive";
import {
  ProjectRulesService,
  type ProjectRulesAuditEvent,
  type ProjectRulesIntentBarrier,
  type ProjectRulesServiceOptions,
} from "#approve-core/policy/project-rules/service";
import type {
  ProjectRulesChange,
  ProjectRulesCommitGuard,
  ProjectRulesCommitResult,
  ProjectRulesLoadResult,
  ProjectRulesStore,
  ProjectRulesUnavailableCategory,
} from "#approve-core/policy/project-rules/storage";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const identity: ProjectIdentity = {
  rootPath: "/work/project",
  displayName: "project",
  slug: "project",
  identityHash: "0123456789abcdef",
};

const otherIdentity: ProjectIdentity = {
  rootPath: "/work/other",
  displayName: "other",
  slug: "other",
  identityHash: "fedcba9876543210",
};

const tool: RuleToolIdentity = { name: "bash", origin: "builtin", definitionRevision: "7" };
const NOW = new Date("2026-03-01T12:00:00.000Z");
const NOW_ISO = NOW.toISOString();
const DEFAULT_ARGUMENTS = { command: "cat file.txt" };
const STORE_PATH = "/pi/project-rules.json";
const RULE_ID = "rule-0123456789abcdef01234567";
const SECOND_RULE_ID = "rule-0123456789abcdef01234568";
const THIRD_RULE_ID = "rule-0123456789abcdef01234569";

function scope(id: string, surface: string, target: string, access: ActionScope["access"]): ActionScope {
  return { id, surface, target, access };
}

function action(overrides: Partial<ExactAction> = {}): ExactAction {
  const args = overrides.arguments ?? DEFAULT_ARGUMENTS;
  const base: ExactAction = {
    requestId: "req-1",
    tool,
    definitionDigest: "def-1",
    arguments: args,
    argumentsDigest: sha256Hex(canonicalJson(args)),
    cwd: "/work/project",
    environmentDigest: "env-1",
    scopes: [scope("s1", "bash", "cat file.txt", "other")],
  };
  return { ...base, ...overrides };
}

function matchFor(target: ExactAction): ExactActionMatch {
  const match = buildExactMatch(target);
  if (match === undefined) throw new Error("fixture action is not learnable");
  return match;
}

function rule(id: string, effect: RuleEffect = "allow", overrides: Partial<StoredProjectRule> = {}): StoredProjectRule {
  return {
    id,
    effect,
    status: "active",
    match: matchFor(action()),
    provenance: {
      sessionId: "session-1",
      sourceEntryId: "entry-1",
      quote: "always allow this",
      actor: "user-1",
    },
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z",
    ...overrides,
  };
}

function revokedRule(id: string, overrides: Partial<StoredProjectRule> = {}): StoredProjectRule {
  return rule(id, "allow", {
    status: "revoked",
    revocation: { revokedAt: "2026-01-02T00:00:00.000Z", actor: "user-1" },
    ...overrides,
  });
}

function projectFile(
  revision: number,
  rules: readonly StoredProjectRule[],
  tombstones: readonly RuleTombstone[] = [],
): ProjectRulesFile {
  return { schemaVersion: PROJECT_RULES_SCHEMA_VERSION, revision, identity, rules, tombstones };
}

function tombstone(ruleId: string, revision: number, revokedAt = "2026-01-02T00:00:00.000Z"): RuleTombstone {
  return { ruleId, effect: "allow", matchDigest: `digest-${ruleId}`, revokedAt, revision };
}

function fakeRuleId(index: number): string {
  return `rule-${index.toString(16).padStart(24, "0")}`;
}

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

class FakeBarrier implements ProjectRulesIntentBarrier {
  revision = 0;
  reconciliation = false;
  paused = false;
  disabled = false;
  guardCurrent = true;
  readonly holdsRevisionRevisions: number[] = [];

  needsReconciliation(): boolean {
    return this.reconciliation;
  }

  currentTaskPaused(): boolean {
    return this.paused;
  }

  learningDisabled(): boolean {
    return this.disabled;
  }

  holdsRevision(revision: number): ProjectRulesCommitGuard {
    this.holdsRevisionRevisions.push(revision);
    return { isCurrent: () => this.guardCurrent && this.revision === revision };
  }
}

/**
 * In-memory store with the same load/commit result model as the file store.
 * It intentionally skips schema validation (the real store owns that) but
 * applies changes, bumps revisions, checks guards and lets tests inject
 * revision races and terminal commit results.
 */
class FakeStore implements ProjectRulesStore {
  file: ProjectRulesFile | undefined;
  unavailable: { category: ProjectRulesUnavailableCategory; diagnostic?: string } | undefined;
  readonly loadQueue: ProjectRulesLoadResult[] = [];
  readonly commitQueue: ProjectRulesCommitResult[] = [];
  loadCalls = 0;
  commitCalls = 0;
  readonly expectedRevisions: number[] = [];
  readonly guards: Array<ProjectRulesCommitGuard | undefined> = [];
  beforeCommit: (() => void) | undefined;
  afterCommit: (() => void) | undefined;

  constructor(file?: ProjectRulesFile) {
    this.file = file;
  }

  async load(): Promise<ProjectRulesLoadResult> {
    this.loadCalls += 1;
    const queued = this.loadQueue.shift();
    if (queued !== undefined) return queued;
    if (this.unavailable !== undefined) {
      return { kind: "unavailable", path: STORE_PATH, category: this.unavailable.category, diagnostic: this.unavailable.diagnostic };
    }
    if (this.file === undefined) return { kind: "missing", path: STORE_PATH, revision: 0 };
    return { kind: "available", path: STORE_PATH, contentHash: `hash-${this.file.revision}`, file: this.file };
  }

  async commit(change: ProjectRulesChange, expectedRevision: number, guard?: ProjectRulesCommitGuard): Promise<ProjectRulesCommitResult> {
    this.commitCalls += 1;
    this.expectedRevisions.push(expectedRevision);
    this.guards.push(guard);

    const queued = this.commitQueue.shift();
    if (queued !== undefined) return queued;

    this.beforeCommit?.();
    const currentRevision = this.file?.revision ?? 0;
    if (guard !== undefined && !(await inspectGuard(guard))) {
      return { kind: "stale-guard", revision: currentRevision };
    }
    if (expectedRevision !== currentRevision) {
      return { kind: "revision-conflict", expectedRevision, revision: currentRevision };
    }

    const inputFile = this.file ?? projectFile(0, []);
    const outcome = await change.apply({ revision: currentRevision, file: inputFile });
    if (outcome.kind === "reject") return { kind: "rejected", revision: currentRevision, reason: outcome.reason };
    if (outcome.kind === "no-change") return { kind: "no-change", revision: currentRevision };
    if (guard !== undefined && !(await inspectGuard(guard))) {
      return { kind: "stale-guard", revision: currentRevision };
    }

    const nextFile = projectFile(currentRevision + 1, outcome.rules, outcome.tombstones);
    this.file = nextFile;
    this.afterCommit?.();
    return {
      kind: "committed",
      previousRevision: currentRevision,
      revision: nextFile.revision,
      ruleIds: nextFile.rules.map((item) => item.id),
      tombstoneIds: nextFile.tombstones.map((item) => item.ruleId),
    };
  }

  clearCache(): void {}

  cacheSize(): number {
    return this.file === undefined ? 0 : 1;
  }
}

async function inspectGuard(guard: ProjectRulesCommitGuard): Promise<boolean> {
  try {
    return await guard.isCurrent();
  } catch {
    return false;
  }
}

interface Harness {
  readonly service: ProjectRulesService;
  readonly store: FakeStore;
  readonly barrier: FakeBarrier;
  readonly audits: ProjectRulesAuditEvent[];
}

function createService(options: {
  file?: ProjectRulesFile;
  unavailable?: { category: ProjectRulesUnavailableCategory; diagnostic?: string };
  barrier?: FakeBarrier;
  audit?: (event: ProjectRulesAuditEvent) => void | Promise<void>;
  revisionRetries?: number;
  commitQueue?: readonly ProjectRulesCommitResult[];
} = {}): Harness {
  const store = new FakeStore(options.file);
  if (options.unavailable !== undefined) store.unavailable = options.unavailable;
  if (options.commitQueue !== undefined) store.commitQueue.push(...options.commitQueue);

  const barrier = options.barrier ?? new FakeBarrier();
  const audits: ProjectRulesAuditEvent[] = [];
  const audit = options.audit ?? ((event: ProjectRulesAuditEvent): void => { audits.push(event); });
  const serviceOptions: ProjectRulesServiceOptions = {
    store,
    identity,
    barrier,
    now: () => NOW,
    audit,
    ...(options.revisionRetries === undefined ? {} : { revisionRetries: options.revisionRetries }),
  };
  return { service: new ProjectRulesService(serviceOptions), store, barrier, audits };
}

// ---------------------------------------------------------------------------
// list (§5)
// ---------------------------------------------------------------------------

describe("ProjectRulesService.list", () => {
  it("summarizes available rules sorted active, needs_review, revoked, then createdAt and ID", async () => {
    const file = projectFile(4, [
      rule(RULE_ID, "allow", { status: "revoked", createdAt: "2026-01-05T00:00:00.000Z", revocation: { revokedAt: "2026-01-06T00:00:00.000Z", actor: "user-1" } }),
      rule(THIRD_RULE_ID, "deny", { status: "needs_review", createdAt: "2026-01-03T00:00:00.000Z" }),
      rule(SECOND_RULE_ID, "allow", { createdAt: "2026-01-02T00:00:00.000Z" }),
      rule("rule-000000000000000000000002", "allow", { createdAt: "2026-01-01T00:00:00.000Z" }),
      rule("rule-000000000000000000000001", "deny", { createdAt: "2026-01-01T00:00:00.000Z" }),
    ]);
    const { service } = createService({ file });

    const result = await service.list();

    expect(result.kind).toBe("available");
    if (result.kind !== "available") throw new Error("unreachable");
    expect(result.revision).toBe(4);
    expect(result.rules.map((item) => item.id)).toEqual([
      "rule-000000000000000000000001",
      "rule-000000000000000000000002",
      SECOND_RULE_ID,
      THIRD_RULE_ID,
      RULE_ID,
    ]);
  });

  it("returns a safe summary without full arguments or environment values", async () => {
    const { service } = createService({ file: projectFile(2, [rule(RULE_ID)]) });

    const result = await service.list();
    if (result.kind !== "available") throw new Error("unreachable");
    const summary = result.rules[0]!;

    expect(summary).toMatchObject({
      id: RULE_ID,
      effect: "allow",
      status: "active",
      createdAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:00:00.000Z",
      provenance: { quote: "always allow this", actor: "user-1" },
      tool,
      cwd: "/work/project",
      requiredScopes: [{ surface: "bash", target: "cat file.txt", access: "other" }],
    });
    expect(Object.keys(summary).sort()).toEqual([
      "createdAt",
      "cwd",
      "effect",
      "id",
      "provenance",
      "requiredScopes",
      "status",
      "tool",
      "updatedAt",
    ]);
  });

  it("marks active rules with the barrier or write-failed suspension reason", async () => {
    const file = projectFile(1, [rule(RULE_ID), rule(SECOND_RULE_ID), rule(THIRD_RULE_ID)]);
    const barrier = new FakeBarrier();
    const { service } = createService({ file, barrier });
    service.suspendRuleIds([RULE_ID]);

    const writeFailed = await service.list();
    if (writeFailed.kind !== "available") throw new Error("unreachable");
    expect(writeFailed.rules.find((item) => item.id === RULE_ID)?.suspension).toBe("write-failed");
    expect(writeFailed.rules.find((item) => item.id === SECOND_RULE_ID)?.suspension).toBeUndefined();

    barrier.reconciliation = true;
    const needingReconciliation = await service.list();
    if (needingReconciliation.kind !== "available") throw new Error("unreachable");
    expect(needingReconciliation.rules.find((item) => item.id === SECOND_RULE_ID)?.suspension).toBe("needs-reconciliation");

    barrier.reconciliation = false;
    barrier.paused = true;
    const paused = await service.list();
    if (paused.kind !== "available") throw new Error("unreachable");
    expect(paused.rules.find((item) => item.id === SECOND_RULE_ID)?.suspension).toBe("current-task-paused");

    barrier.paused = false;
    barrier.disabled = true;
    const disabled = await service.list();
    if (disabled.kind !== "available") throw new Error("unreachable");
    expect(disabled.rules.find((item) => item.id === SECOND_RULE_ID)?.suspension).toBe("learning-disabled");
  });

  it("returns an empty revision-zero list for a missing file", async () => {
    const { service, audits } = createService();

    const result = await service.list();

    expect(result).toEqual({ kind: "missing", revision: 0, rules: [] });
    expect(audits).toEqual([]);
  });

  it("returns an empty list with the stable category for an unavailable file", async () => {
    const { service, audits } = createService({ unavailable: { category: "corrupt", diagnostic: "bad json" } });

    const result = await service.list();

    expect(result).toEqual({ kind: "unavailable", revision: 0, category: "corrupt", diagnostic: "bad json", rules: [] });
    expect(audits).toEqual([{ kind: "rules-unavailable", reason: "corrupt" }]);
  });

  it("reads the current file on every call", async () => {
    const { service, store } = createService({ file: projectFile(1, [rule(RULE_ID)]) });
    await service.list();
    store.file = projectFile(2, [rule(SECOND_RULE_ID)]);

    const result = await service.list();

    if (result.kind !== "available") throw new Error("unreachable");
    expect(result.revision).toBe(2);
    expect(result.rules.map((item) => item.id)).toEqual([SECOND_RULE_ID]);
    expect(store.loadCalls).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// evaluate (§6)
// ---------------------------------------------------------------------------

describe("ProjectRulesService.evaluate", () => {
  it("defers when the rules file is unavailable", async () => {
    const { service, audits } = createService({ unavailable: { category: "io" } });

    const result = await service.evaluate(action());

    expect(result).toEqual({ kind: "defer", revision: 0, intentRevision: 0, category: "io" });
    expect(audits).toEqual([{ kind: "rules-unavailable", reason: "io" }]);
  });

  it("never applies a learned allow when the action carries a hard deny", async () => {
    const { service } = createService({ file: projectFile(3, [rule(RULE_ID)]) });

    const result = await service.evaluate(action({ hardDeny: true }));

    expect(result).toEqual({ kind: "none", revision: 3, intentRevision: 0, needsReviewRuleIds: [] });
  });

  it("returns none for a missing file", async () => {
    const barrier = new FakeBarrier();
    barrier.reconciliation = true;
    const { service } = createService({ barrier });

    const result = await service.evaluate(action());

    expect(result).toEqual({ kind: "none", revision: 0, intentRevision: 0, needsReviewRuleIds: [] });
  });

  it("asks for intent reconciliation before applying learned rules", async () => {
    const barrier = new FakeBarrier();
    barrier.reconciliation = true;
    const { service } = createService({ file: projectFile(5, [rule(RULE_ID)]), barrier });

    const result = await service.evaluate(action());

    expect(result).toEqual({ kind: "needs-reconciliation", revision: 5, intentRevision: 0 });
  });

  it("returns none while the current task is paused or learning is disabled", async () => {
    const barrier = new FakeBarrier();
    const { service } = createService({ file: projectFile(5, [rule(RULE_ID)]), barrier });

    barrier.paused = true;
    expect(await service.evaluate(action())).toEqual({ kind: "none", revision: 5, intentRevision: 0, needsReviewRuleIds: [] });

    barrier.paused = false;
    barrier.disabled = true;
    expect(await service.evaluate(action())).toEqual({ kind: "none", revision: 5, intentRevision: 0, needsReviewRuleIds: [] });
  });

  it("returns none when the action has no ask scope", async () => {
    const { service } = createService({ file: projectFile(5, [rule(RULE_ID)]) });

    const result = await service.evaluate(action({ scopes: [] }));

    expect(result).toEqual({ kind: "none", revision: 5, intentRevision: 0, needsReviewRuleIds: [] });
  });

  it("returns the matching allow rule and covers its scopes", async () => {
    const { service } = createService({ file: projectFile(7, [rule(RULE_ID)]) });

    const result = await service.evaluate(action());

    expect(result).toEqual({
      kind: "allow",
      revision: 7,
      intentRevision: 0,
      ruleIds: [RULE_ID],
      coveredScopeIds: ["s1"],
      remainingAskScopeIds: [],
      needsReviewRuleIds: [],
    });
  });

  it("keeps extra ask scopes independent from a learned allow", async () => {
    const target = action({
      scopes: [
        scope("s1", "bash", "cat file.txt", "other"),
        scope("extra", "path", "/work/project/other.txt", "read"),
      ],
    });
    const { service } = createService({ file: projectFile(7, [rule(RULE_ID)]) });

    const result = await service.evaluate(target);

    if (result.kind !== "allow") throw new Error("expected allow");
    expect(result.coveredScopeIds).toEqual(["s1"]);
    expect(result.remainingAskScopeIds).toEqual(["extra"]);
  });

  it("unions the scopes covered by every matching allow rule in action order", async () => {
    const firstRule = rule(RULE_ID, "allow", { match: matchFor(action({ scopes: [scope("a1", "bash", "a", "read")] })) });
    const secondRule = rule(SECOND_RULE_ID, "allow", { match: matchFor(action({ scopes: [scope("b1", "bash", "b", "write")] })) });
    const { service } = createService({ file: projectFile(8, [firstRule, secondRule]) });

    const result = await service.evaluate(action({
      scopes: [
        scope("x1", "bash", "a", "read"),
        scope("x2", "bash", "b", "write"),
        scope("x3", "path", "/work/project/c", "read"),
      ],
    }));

    if (result.kind !== "allow") throw new Error("expected allow");
    expect(result.ruleIds).toEqual([RULE_ID, SECOND_RULE_ID]);
    expect(result.coveredScopeIds).toEqual(["x1", "x2"]);
    expect(result.remainingAskScopeIds).toEqual(["x3"]);
  });

  it("denies when any matching rule denies, even when another rule allows", async () => {
    const allow = rule(RULE_ID, "allow");
    const deny = rule(SECOND_RULE_ID, "deny");
    const { service } = createService({ file: projectFile(9, [allow, deny]) });

    const result = await service.evaluate(action());

    expect(result).toEqual({ kind: "deny", revision: 9, intentRevision: 0, ruleIds: [SECOND_RULE_ID], needsReviewRuleIds: [] });
  });

  it("reports definition and environment changes for needs review without applying them", async () => {
    const definitionChanged = rule(RULE_ID, "allow", { match: matchFor(action({ definitionDigest: "def-old" })) });
    const environmentChanged = rule(SECOND_RULE_ID, "deny", { match: matchFor(action({ environmentDigest: "env-old" })) });
    const { service } = createService({ file: projectFile(2, [definitionChanged, environmentChanged]) });

    const result = await service.evaluate(action());

    expect(result).toEqual({ kind: "none", revision: 2, intentRevision: 0, needsReviewRuleIds: [RULE_ID, SECOND_RULE_ID] });
  });

  it("skips suspended rules and every non-active status", async () => {
    const suspended = rule(RULE_ID, "allow");
    const needsReview = rule(SECOND_RULE_ID, "allow", { status: "needs_review" });
    const revoked = revokedRule(THIRD_RULE_ID);
    const { service } = createService({ file: projectFile(2, [suspended, needsReview, revoked]) });
    service.suspendRuleIds([RULE_ID]);

    const result = await service.evaluate(action());

    expect(result).toEqual({ kind: "none", revision: 2, intentRevision: 0, needsReviewRuleIds: [] });
  });

  it("keeps the revision on every branch", async () => {
    const barrier = new FakeBarrier();
    barrier.revision = 11;
    const { service } = createService({ file: projectFile(3, [rule(RULE_ID)]), barrier });
    for (const target of [action(), action({ hardDeny: true }), action({ scopes: [] })]) {
      const result = await service.evaluate(target);
      expect(result.revision).toBe(3);
      expect(result.intentRevision).toBe(11);
    }
  });
});

// ---------------------------------------------------------------------------
// revoke (§7)
// ---------------------------------------------------------------------------

describe("ProjectRulesService.revoke", () => {
  it("revokes an active rule with revocation facts and a matching tombstone", async () => {
    const target = rule(RULE_ID);
    const { service, store, audits } = createService({ file: projectFile(3, [target]) });

    const result = await service.revoke({ ruleId: RULE_ID, actor: "user-1", reason: "not needed" });

    expect(result).toEqual({ kind: "revoked", revision: 4, ruleIds: [RULE_ID] });
    const file = store.file!;
    expect(file.revision).toBe(4);
    expect(file.rules[0]).toMatchObject({
      id: RULE_ID,
      status: "revoked",
      updatedAt: NOW_ISO,
      revocation: { revokedAt: NOW_ISO, actor: "user-1", reason: "not needed" },
    });
    expect(file.tombstones).toEqual([{
      ruleId: RULE_ID,
      effect: "allow",
      matchDigest: exactMatchDigest(target.match),
      revokedAt: NOW_ISO,
      revision: 4,
    }]);
    expect(audits).toEqual([{ kind: "rules-revoked", ruleIds: [RULE_ID], revision: 4 }]);
  });

  it("revokes a needs_review target", async () => {
    const { service, store } = createService({ file: projectFile(1, [rule(RULE_ID, "deny", { status: "needs_review" })]) });

    const result = await service.revoke({ ruleId: RULE_ID, actor: "user-1" });

    expect(result.kind).toBe("revoked");
    expect(store.file!.rules[0]!.status).toBe("revoked");
  });

  it("stores only the generic placeholder for a sensitive reason", async () => {
    const { service, store } = createService({ file: projectFile(1, [rule(RULE_ID)]) });

    await service.revoke({ ruleId: RULE_ID, actor: "user-1", reason: "password=hunter2" });

    expect(store.file!.rules[0]!.revocation?.reason).toBe(SENSITIVE_REASON_PLACEHOLDER);
  });

  it("does not touch the file when the rule is absent, invalid or the file is missing", async () => {
    const absent = createService({ file: projectFile(2, [rule(SECOND_RULE_ID)]) });
    expect(await absent.service.revoke({ ruleId: RULE_ID, actor: "user-1" })).toEqual({ kind: "not-found", revision: 2 });
    expect(absent.store.commitCalls).toBe(0);

    const invalid = createService({ file: projectFile(2, [rule(RULE_ID)]) });
    expect(await invalid.service.revoke({ ruleId: "not-a-rule", actor: "user-1" })).toEqual({ kind: "not-found", revision: 2 });
    expect(invalid.store.commitCalls).toBe(0);

    const missing = createService();
    expect(await missing.service.revoke({ ruleId: RULE_ID, actor: "user-1" })).toEqual({ kind: "not-found", revision: 0 });
    expect(missing.store.commitCalls).toBe(0);
  });

  it("reports an already revoked target without rewriting it", async () => {
    const { service, store, audits } = createService({ file: projectFile(6, [revokedRule(RULE_ID)]) });

    const result = await service.revoke({ ruleId: RULE_ID, actor: "user-1" });

    expect(result).toEqual({ kind: "already-revoked", revision: 6, ruleIds: [RULE_ID] });
    expect(store.commitCalls).toBe(0);
    expect(audits).toEqual([]);
  });

  it("re-reads, re-validates the target and retries after a revision conflict", async () => {
    const { service, store } = createService({ file: projectFile(2, [rule(RULE_ID)]) });
    let first = true;
    store.beforeCommit = () => {
      if (!first) return;
      first = false;
      store.file = projectFile(3, store.file!.rules);
    };

    const result = await service.revoke({ ruleId: RULE_ID, actor: "user-1" });

    expect(result).toMatchObject({ kind: "revoked", revision: 4 });
    expect(store.commitCalls).toBe(2);
    expect(store.loadCalls).toBe(2);
    expect(store.expectedRevisions).toEqual([2, 3]);
  });

  it("stops retrying when the reloaded target is already revoked", async () => {
    const { service, store } = createService({ file: projectFile(2, [rule(RULE_ID)]) });
    let first = true;
    store.beforeCommit = () => {
      if (!first) return;
      first = false;
      store.file = projectFile(3, [revokedRule(RULE_ID)]);
    };

    const result = await service.revoke({ ruleId: RULE_ID, actor: "user-1" });

    expect(result).toEqual({ kind: "already-revoked", revision: 3, ruleIds: [RULE_ID] });
    expect(store.commitCalls).toBe(1);
    expect(store.loadCalls).toBe(2);
  });

  it("gives up after the configured number of conflict retries", async () => {
    const conflict: ProjectRulesCommitResult = { kind: "revision-conflict", expectedRevision: 2, revision: 9 };
    const { service, store } = createService({
      file: projectFile(2, [rule(RULE_ID)]),
      commitQueue: [conflict, conflict, conflict],
    });

    const result = await service.revoke({ ruleId: RULE_ID, actor: "user-1" });

    expect(result).toEqual({ kind: "revision-conflict", expectedRevision: 2, revision: 9 });
    expect(store.commitCalls).toBe(3);
    expect(store.loadCalls).toBe(3);
  });

  it("honours a custom revision retry budget", async () => {
    const conflict: ProjectRulesCommitResult = { kind: "revision-conflict", expectedRevision: 2, revision: 9 };
    const { service, store } = createService({
      file: projectFile(2, [rule(RULE_ID)]),
      commitQueue: [conflict, conflict],
      revisionRetries: 0,
    });

    const result = await service.revoke({ ruleId: RULE_ID, actor: "user-1" });

    expect(result).toEqual({ kind: "revision-conflict", expectedRevision: 2, revision: 9 });
    expect(store.commitCalls).toBe(1);
  });

  it("suspends the target and audits a write failure", async () => {
    const { service, store, audits } = createService({
      file: projectFile(2, [rule(RULE_ID)]),
      commitQueue: [{ kind: "failed", category: "lock", diagnostic: "lock timeout" }],
    });

    const result = await service.revoke({ ruleId: RULE_ID, actor: "user-1" });

    expect(result).toEqual({ kind: "failed", category: "lock", diagnostic: "lock timeout" });
    expect(service.isSuspended(RULE_ID)).toBe(true);
    expect(audits).toEqual([{ kind: "write-failed", ruleIds: [RULE_ID], reason: "lock" }]);
    expect(store.file!.rules[0]!.status).toBe("active");
  });

  it("keeps a write-failed allow from applying on later evaluations", async () => {
    const { service } = createService({
      file: projectFile(2, [rule(RULE_ID)]),
      commitQueue: [{ kind: "failed", category: "io" }],
    });
    await service.revoke({ ruleId: RULE_ID, actor: "user-1" });

    const result = await service.evaluate(action());

    expect(result).toEqual({ kind: "none", revision: 2, intentRevision: 0, needsReviewRuleIds: [] });
  });

  it("reports an unavailable commit and audits it without suspending", async () => {
    const { service, audits } = createService({
      file: projectFile(2, [rule(RULE_ID)]),
      commitQueue: [{ kind: "unavailable", category: "io" }],
    });

    const result = await service.revoke({ ruleId: RULE_ID, actor: "user-1" });

    expect(result).toEqual({ kind: "unavailable", category: "io" });
    expect(service.isSuspended(RULE_ID)).toBe(false);
    expect(audits).toEqual([{ kind: "rules-unavailable", reason: "io" }]);
  });

  it("clears suspension for settled rules", async () => {
    const { service } = createService({ file: projectFile(2, [rule(RULE_ID)]) });
    service.suspendRuleIds([RULE_ID]);
    expect(service.isSuspended(RULE_ID)).toBe(true);
    service.clearRuleSuspension([RULE_ID]);
    expect(service.isSuspended(RULE_ID)).toBe(false);
  });

  it("clears a prior suspension after a durable revoke", async () => {
    const { service } = createService({ file: projectFile(2, [rule(RULE_ID)]) });
    service.suspendRuleIds([RULE_ID]);

    await service.revoke({ ruleId: RULE_ID, actor: "user-1" });

    expect(service.isSuspended(RULE_ID)).toBe(false);
  });

  it("passes the intent guard for a reconciliation revoke and reports a valid intent", async () => {
    const barrier = new FakeBarrier();
    barrier.revision = 14;
    const { service, store } = createService({ file: projectFile(2, [rule(RULE_ID)]), barrier });

    const result = await service.revoke({ ruleId: RULE_ID, actor: "user-1", reconciliationIntentRevision: 14 });

    expect(result).toEqual({ kind: "revoked", revision: 3, ruleIds: [RULE_ID], currentIntentValid: true });
    expect(barrier.holdsRevisionRevisions).toEqual([14]);
    expect(store.guards[0]).toBeDefined();
  });

  it("returns stale-guard and does not suspend when the intent guard fails", async () => {
    const barrier = new FakeBarrier();
    barrier.revision = 21;
    barrier.guardCurrent = false;
    const { service, store, audits } = createService({ file: projectFile(2, [rule(RULE_ID)]), barrier });

    const result = await service.revoke({ ruleId: RULE_ID, actor: "user-1", reconciliationIntentRevision: 21 });

    expect(result).toEqual({ kind: "stale-guard", revision: 2 });
    expect(service.isSuspended(RULE_ID)).toBe(false);
    expect(store.file!.rules[0]!.status).toBe("active");
    expect(audits).toEqual([]);
  });

  it("reports a durable revoke whose intent expired before the result was reported", async () => {
    const barrier = new FakeBarrier();
    barrier.revision = 30;
    const { service, store, audits } = createService({ file: projectFile(2, [rule(RULE_ID)]), barrier });
    store.afterCommit = () => { barrier.revision = 31; };

    const result = await service.revoke({ ruleId: RULE_ID, actor: "user-1", reconciliationIntentRevision: 30 });

    expect(result).toEqual({ kind: "revoked", revision: 3, ruleIds: [RULE_ID], currentIntentValid: false });
    expect(store.file!.rules[0]!.status).toBe("revoked");
    expect(audits).toEqual([{ kind: "rules-revoked", ruleIds: [RULE_ID], revision: 3 }]);
  });

  it("keeps only the last 512 tombstones", async () => {
    const existing = Array.from({ length: 512 }, (_, index) => tombstone(fakeRuleId(index + 10), index + 1));
    const { service, store } = createService({ file: projectFile(600, [rule(RULE_ID)], existing) });

    await service.revoke({ ruleId: RULE_ID, actor: "user-1" });

    const tombstones = store.file!.tombstones;
    expect(tombstones).toHaveLength(512);
    expect(tombstones[0]!.ruleId).toBe(existing[1]!.ruleId);
    expect(tombstones[511]!.ruleId).toBe(RULE_ID);
    expect(tombstones[511]!.revision).toBe(601);
  });

  it("never lets a throwing audit change the revoke outcome", async () => {
    const synchronous = createService({
      file: projectFile(2, [rule(RULE_ID)]),
      audit: () => { throw new Error("audit sink down"); },
    });
    expect(await synchronous.service.revoke({ ruleId: RULE_ID, actor: "user-1" })).toMatchObject({ kind: "revoked", revision: 3 });
    expect(synchronous.store.file!.rules[0]!.status).toBe("revoked");

    const asynchronous = createService({
      file: projectFile(2, [rule(RULE_ID)]),
      audit: async () => { throw new Error("audit sink down"); },
    });
    expect(await asynchronous.service.revoke({ ruleId: RULE_ID, actor: "user-1" })).toMatchObject({ kind: "revoked", revision: 3 });
    expect(asynchronous.store.file!.revision).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// markNeedsReview (§7)
// ---------------------------------------------------------------------------

describe("ProjectRulesService.markNeedsReview", () => {
  it("marks an active rule for review without adding a tombstone", async () => {
    const { service, store, audits } = createService({ file: projectFile(2, [rule(RULE_ID)]) });

    const result = await service.markNeedsReview({ ruleId: RULE_ID, reason: "definition-changed" });

    expect(result).toEqual({ kind: "marked", revision: 3, ruleIds: [RULE_ID] });
    expect(store.file!.rules[0]).toMatchObject({ status: "needs_review", updatedAt: NOW_ISO });
    expect(store.file!.rules[0]!.revocation).toBeUndefined();
    expect(store.file!.tombstones).toEqual([]);
    expect(audits).toEqual([{ kind: "needs-review-marked", ruleIds: [RULE_ID], revision: 3, reason: "definition-changed" }]);
  });

  it("is idempotent for a rule already needing review", async () => {
    const { service, store, audits } = createService({ file: projectFile(4, [rule(RULE_ID, "allow", { status: "needs_review" })]) });

    const result = await service.markNeedsReview({ ruleId: RULE_ID });

    expect(result).toEqual({ kind: "already-needs-review", revision: 4, ruleIds: [RULE_ID] });
    expect(store.commitCalls).toBe(0);
    expect(audits).toEqual([]);
  });

  it("treats a revoked or unknown target as not found", async () => {
    const revoked = createService({ file: projectFile(4, [revokedRule(RULE_ID)]) });
    expect(await revoked.service.markNeedsReview({ ruleId: RULE_ID })).toEqual({ kind: "not-found", revision: 4 });
    expect(revoked.store.commitCalls).toBe(0);

    const unknown = createService({ file: projectFile(4, [rule(RULE_ID)]) });
    expect(await unknown.service.markNeedsReview({ ruleId: SECOND_RULE_ID })).toEqual({ kind: "not-found", revision: 4 });
    expect(unknown.store.commitCalls).toBe(0);

    const missing = createService();
    expect(await missing.service.markNeedsReview({ ruleId: RULE_ID })).toEqual({ kind: "not-found", revision: 0 });
  });

  it("retries the same CAS after a revision conflict", async () => {
    const { service, store } = createService({ file: projectFile(2, [rule(RULE_ID)]) });
    let first = true;
    store.beforeCommit = () => {
      if (!first) return;
      first = false;
      store.file = projectFile(3, store.file!.rules);
    };

    const result = await service.markNeedsReview({ ruleId: RULE_ID });

    expect(result).toEqual({ kind: "marked", revision: 4, ruleIds: [RULE_ID] });
    expect(store.commitCalls).toBe(2);
    expect(store.expectedRevisions).toEqual([2, 3]);
  });

  it("reports a write failure without suspending the rule", async () => {
    const { service, audits } = createService({
      file: projectFile(2, [rule(RULE_ID)]),
      commitQueue: [{ kind: "failed", category: "io", diagnostic: "fsync failed" }],
    });

    const result = await service.markNeedsReview({ ruleId: RULE_ID });

    expect(result).toEqual({ kind: "failed", category: "io", diagnostic: "fsync failed" });
    expect(service.isSuspended(RULE_ID)).toBe(false);
    expect(audits).toEqual([{ kind: "write-failed", ruleIds: [RULE_ID], reason: "io" }]);
  });

  it("reports an unavailable file and audits it", async () => {
    const { service, audits } = createService({ unavailable: { category: "schema-invalid" } });

    const result = await service.markNeedsReview({ ruleId: RULE_ID });

    expect(result).toEqual({ kind: "unavailable", category: "schema-invalid" });
    expect(audits).toEqual([{ kind: "rules-unavailable", reason: "schema-invalid" }]);
  });

  it("keeps a throwing audit from changing the marked outcome", async () => {
    const { service, store } = createService({
      file: projectFile(2, [rule(RULE_ID)]),
      audit: () => { throw new Error("audit sink down"); },
    });

    expect(await service.markNeedsReview({ ruleId: RULE_ID })).toMatchObject({ kind: "marked", revision: 3 });
    expect(store.file!.rules[0]!.status).toBe("needs_review");
  });
});

// ---------------------------------------------------------------------------
// snapshot (§8)
// ---------------------------------------------------------------------------

describe("ProjectRulesService.snapshot", () => {
  function snapshotRequest(overrides: Partial<Parameters<ProjectRulesService["snapshot"]>[0]> = {}): Parameters<ProjectRulesService["snapshot"]>[0] {
    return {
      owner: identity,
      viewOwner: identity,
      revisionOwner: identity,
      projectRulesRevision: 2,
      intentRevision: 0,
      ...overrides,
    };
  }

  it("freezes the applicable rules and the match facts of a matching request", async () => {
    const active = rule(RULE_ID, "allow", { createdAt: "2026-01-01T00:00:00.000Z" });
    const needingReview = rule(SECOND_RULE_ID, "deny", { status: "needs_review" });
    const revoked = revokedRule(THIRD_RULE_ID);
    const { service } = createService({ file: projectFile(2, [active, needingReview, revoked]) });

    const snapshot = await service.snapshot(snapshotRequest());

    expect(snapshot).toBeDefined();
    expect(snapshot!.revision).toBe(2);
    expect(snapshot!.intentRevision).toBe(0);
    expect(snapshot!.rules.map((item) => [item.id, item.effect, item.status, item.applicable])).toEqual([
      [RULE_ID, "allow", "active", true],
      [SECOND_RULE_ID, "deny", "needs_review", false],
      [THIRD_RULE_ID, "allow", "revoked", false],
    ]);
    expect(Object.keys(snapshot!.rules[0]!.match).sort()).toEqual([
      "arguments",
      "argumentsDigest",
      "contractVersion",
      "cwd",
      "definitionDigest",
      "environmentDigest",
      "requiredScopes",
      "tool",
      "type",
    ]);
    expect(snapshot!.rules[0]!.match.environmentDigest).toBe("env-1");
    expect(snapshot!.rules[0]!.match).not.toHaveProperty("environment");
    expect(JSON.stringify(snapshot)).not.toContain("environmentValues");
  });

  it("deep freezes the snapshot and its match facts", async () => {
    const { service } = createService({ file: projectFile(2, [rule(RULE_ID)]) });

    const snapshot = await service.snapshot(snapshotRequest());

    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(Object.isFrozen(snapshot!.rules)).toBe(true);
    expect(Object.isFrozen(snapshot!.rules[0])).toBe(true);
    expect(Object.isFrozen(snapshot!.rules[0]!.match)).toBe(true);
    expect(Object.isFrozen(snapshot!.rules[0]!.match.arguments)).toBe(true);
    expect(Object.isFrozen(snapshot!.rules[0]!.match.requiredScopes)).toBe(true);
  });

  it("marks rules inapplicable while the intent gate is closed or a rule is suspended", async () => {
    const barrier = new FakeBarrier();
    barrier.revision = 5;
    const { service } = createService({ file: projectFile(2, [rule(RULE_ID), rule(SECOND_RULE_ID)]), barrier });
    service.suspendRuleIds([SECOND_RULE_ID]);

    const open = await service.snapshot(snapshotRequest({ intentRevision: 5 }));
    expect(open!.rules.map((item) => item.applicable)).toEqual([true, false]);

    barrier.reconciliation = true;
    const reconciled = await service.snapshot(snapshotRequest({ intentRevision: 5 }));
    expect(reconciled!.rules.map((item) => item.applicable)).toEqual([false, false]);

    barrier.reconciliation = false;
    barrier.paused = true;
    const paused = await service.snapshot(snapshotRequest({ intentRevision: 5 }));
    expect(paused!.rules.every((item) => !item.applicable)).toBe(true);

    barrier.paused = false;
    barrier.disabled = true;
    const disabled = await service.snapshot(snapshotRequest({ intentRevision: 5 }));
    expect(disabled!.rules.every((item) => !item.applicable)).toBe(true);
  });

  it("returns a revision-zero empty snapshot for a missing file", async () => {
    const barrier = new FakeBarrier();
    barrier.revision = 3;
    const { service } = createService({ barrier });

    const snapshot = await service.snapshot(snapshotRequest({ projectRulesRevision: 0, intentRevision: 3 }));

    expect(snapshot).toEqual({ revision: 0, intentRevision: 3, rules: [] });
    expect(Object.isFrozen(snapshot)).toBe(true);
  });

  it("refuses snapshots when any owner identity differs", async () => {
    const { service } = createService({ file: projectFile(2, [rule(RULE_ID)]) });

    expect(await service.snapshot(snapshotRequest({ viewOwner: otherIdentity }))).toBeUndefined();
    expect(await service.snapshot(snapshotRequest({ revisionOwner: otherIdentity }))).toBeUndefined();
    expect(await service.snapshot(snapshotRequest({ owner: otherIdentity }))).toBeUndefined();
  });

  it("refuses a snapshot when the project rules revision is stale", async () => {
    const { service } = createService({ file: projectFile(2, [rule(RULE_ID)]) });

    expect(await service.snapshot(snapshotRequest({ projectRulesRevision: 3 }))).toBeUndefined();
  });

  it("refuses a missing-file snapshot whose revision is not zero", async () => {
    const { service } = createService();

    expect(await service.snapshot(snapshotRequest({ projectRulesRevision: 2 }))).toBeUndefined();
  });

  it("refuses a snapshot when the intent revision is stale", async () => {
    const barrier = new FakeBarrier();
    barrier.revision = 4;
    const { service } = createService({ file: projectFile(2, [rule(RULE_ID)]), barrier });

    expect(await service.snapshot(snapshotRequest({ intentRevision: 3 }))).toBeUndefined();
    expect(await service.snapshot(snapshotRequest({ intentRevision: 4 }))).toBeDefined();
  });

  it("refuses a snapshot when the file is unavailable and audits it", async () => {
    const { service, audits } = createService({ unavailable: { category: "corrupt" } });

    expect(await service.snapshot(snapshotRequest({ projectRulesRevision: 0 }))).toBeUndefined();
    expect(audits).toEqual([{ kind: "rules-unavailable", reason: "corrupt" }]);
  });

  it("refuses the whole snapshot when any rule cannot be frozen", async () => {
    const withFunction = rule(RULE_ID, "allow", {
      match: { ...matchFor(action()), arguments: { run: () => 1 } },
    });
    const first = createService({ file: projectFile(2, [withFunction]) });
    expect(await first.service.snapshot(snapshotRequest())).toBeUndefined();

    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    const withCycle = rule(RULE_ID, "allow", { match: { ...matchFor(action()), arguments: cyclic } });
    const second = createService({ file: projectFile(2, [withCycle]) });
    expect(await second.service.snapshot(snapshotRequest())).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// service plumbing
// ---------------------------------------------------------------------------

describe("ProjectRulesService suspension seam", () => {
  it("adds and reports suspended rule IDs", () => {
    const { service } = createService();
    expect(service.isSuspended(RULE_ID)).toBe(false);

    service.suspendRuleIds([RULE_ID, SECOND_RULE_ID]);

    expect(service.isSuspended(RULE_ID)).toBe(true);
    expect(service.isSuspended(SECOND_RULE_ID)).toBe(true);
    expect(service.isSuspended(THIRD_RULE_ID)).toBe(false);
  });
});
