import { describe, expect, it } from "vitest";
import {
  PROJECT_RULES_SCHEMA_VERSION,
  canonicalJson,
  ruleIdFor,
  sha256Hex,
  type ActionScope,
  type AuthorizationEntry,
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
import {
  ProjectRulesService,
  type ProjectRulesIntentBarrier,
} from "#approve-core/policy/project-rules/service";
import type {
  ProjectRulesChange,
  ProjectRulesCommitGuard,
  ProjectRulesCommitResult,
  ProjectRulesLoadResult,
  ProjectRulesStore,
  ProjectRulesUnavailableCategory,
} from "#approve-core/policy/project-rules/storage";
import type { LearningCandidate, LearningRejection } from "#approve-core/policy/project-rules/candidates";
import { LearningCandidateCollector } from "#approve-core/policy/project-rules/candidates";
import { LearningIntentBarrier, type LearningBarrierOutcome } from "#approve-core/policy/project-rules/barrier";
import { createProjectRulePolicyTools } from "#approve-core/policy/project-rules/policy-tools";
import {
  ProjectRuleLearningService,
  actionDigestOf,
  canHandOffDeferredLearning,
  validateLearningAdmission,
  wrapLearningApprover,
  type LearningAuditEvent,
  type LearningCollectorPort,
} from "#approve-core/policy/project-rules/learning";

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

const owners = { owner: "user-1", viewOwner: "user-1", revisionOwner: "user-1" } as const;
const tool: RuleToolIdentity = { name: "bash", origin: "builtin", definitionRevision: "7" };
const NOW = new Date("2026-03-01T12:00:00.000Z");
const NOW_ISO = NOW.toISOString();
const STORE_PATH = "/pi/project-rules.json";
const RULE_TIMESTAMP = "2026-01-01T00:00:00.000Z";
const SESSION = "session-1";
const JUDGE = "judge-1";

function scope(id: string, surface: string, target: string, access: ActionScope["access"]): ActionScope {
  return { id, surface, target, access };
}

function action(overrides: Partial<ExactAction> = {}): ExactAction {
  const args = overrides.arguments ?? { command: "cat file.txt" };
  const base: ExactAction = {
    requestId: "req-1",
    tool,
    definitionDigest: "def-1",
    arguments: args,
    argumentsDigest: sha256Hex(canonicalJson(args)),
    cwd: "/work/project",
    environmentDigest: "env-1",
    scopes: [scope("s1", "bash", "file.txt", "read")],
  };
  return { ...base, ...overrides };
}

function secondAction(): ExactAction {
  const args = { command: "cat other.txt" };
  return {
    requestId: "req-2",
    tool,
    definitionDigest: "def-1",
    arguments: args,
    argumentsDigest: sha256Hex(canonicalJson(args)),
    cwd: "/work/project",
    environmentDigest: "env-1",
    scopes: [scope("s2", "bash", "other.txt", "read")],
  };
}

const allowEntry: AuthorizationEntry = { id: "entry-1", source: "user", text: "以后允许读取 file.txt" };
const denyEntry: AuthorizationEntry = { id: "entry-deny", source: "user", text: "以后禁止读取 file.txt" };
const otherEntry: AuthorizationEntry = { id: "entry-2", source: "user", text: "以后允许读取 other.txt" };

function revokeEntry(ruleId: string): AuthorizationEntry {
  return { id: "entry-revoke", source: "user", text: `以后撤销规则 ${ruleId}` };
}

function matchFor(target: ExactAction): ExactActionMatch {
  const match = buildExactMatch(target);
  if (match === undefined) throw new Error("fixture action is not learnable");
  return match;
}

function createRuleId(
  effect: RuleEffect,
  target: ExactAction = action(),
  sourceEntryId = "entry-1",
  sessionId = SESSION,
): string {
  return ruleIdFor({ effect, matchDigest: exactMatchDigest(matchFor(target)), sourceEntryId, sessionId });
}

function storedRule(id: string, effect: RuleEffect = "allow", overrides: Partial<StoredProjectRule> = {}): StoredProjectRule {
  return {
    id,
    effect,
    status: "active",
    match: matchFor(action()),
    provenance: {
      sessionId: SESSION,
      sourceEntryId: "entry-1",
      quote: "以后允许读取 file.txt",
      actor: "user-1",
    },
    createdAt: RULE_TIMESTAMP,
    updatedAt: RULE_TIMESTAMP,
    ...overrides,
  };
}

function revokedRule(id: string, effect: RuleEffect = "allow", overrides: Partial<StoredProjectRule> = {}): StoredProjectRule {
  return storedRule(id, effect, {
    status: "revoked",
    revocation: { revokedAt: RULE_TIMESTAMP, actor: "user-1" },
    ...overrides,
  });
}

function tombstoneFor(rule: StoredProjectRule, revision = 1): RuleTombstone {
  return {
    ruleId: rule.id,
    effect: rule.effect,
    matchDigest: exactMatchDigest(rule.match),
    revokedAt: RULE_TIMESTAMP,
    revision,
  };
}

function projectFile(
  revision: number,
  rules: readonly StoredProjectRule[],
  tombstones: readonly RuleTombstone[] = [],
): ProjectRulesFile {
  return { schemaVersion: PROJECT_RULES_SCHEMA_VERSION, revision, identity, rules, tombstones };
}

function syntheticRule(index: number): StoredProjectRule {
  const args = { command: `cat f${index}.txt` };
  const match: ExactActionMatch = {
    contractVersion: 1,
    type: "exact_action",
    tool,
    definitionDigest: "def-1",
    arguments: args,
    argumentsDigest: sha256Hex(canonicalJson(args)),
    cwd: "/work/project",
    environmentDigest: "env-1",
    requiredScopes: [scope(`s-${index}`, "bash", `f${index}.txt`, "read")],
  };
  return {
    id: `rule-${index.toString(16).padStart(24, "0")}`,
    effect: "allow",
    status: "active",
    match,
    provenance: { sessionId: SESSION, sourceEntryId: "entry-1", quote: "以后允许读取 f.txt", actor: "user-1" },
    createdAt: RULE_TIMESTAMP,
    updatedAt: RULE_TIMESTAMP,
  };
}

// ---------------------------------------------------------------------------
// Candidate payload fixtures (model-proposed, untrusted)
// ---------------------------------------------------------------------------

function createCandidate(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    effect: "allow",
    scope: "exact_action",
    actionRef: "current-action",
    sourceEntryId: "entry-1",
    quote: "以后允许读取 file.txt",
    confidence: 0.95,
    ...overrides,
  };
}

function denyCreateCandidate(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    effect: "deny",
    scope: "exact_action",
    actionRef: "current-action",
    sourceEntryId: "entry-deny",
    quote: "以后禁止读取 file.txt",
    confidence: 0.95,
    ...overrides,
  };
}

function secondCreateCandidate(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    effect: "allow",
    scope: "exact_action",
    actionRef: "req-2",
    sourceEntryId: "entry-2",
    quote: "以后允许读取 other.txt",
    confidence: 0.95,
    ...overrides,
  };
}

function revokeCandidate(ruleId: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    ruleId,
    sourceEntryId: "entry-revoke",
    quote: `以后撤销规则 ${ruleId}`,
    confidence: 0.95,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Admission fixture
// ---------------------------------------------------------------------------

function makeMember(overrides: {
  readonly requestId?: string;
  readonly action?: ExactAction;
  readonly verdict?: "allow" | "deny" | "defer";
  readonly actionDigest?: string;
} = {}): Record<string, unknown> {
  const target = overrides.action ?? action();
  return {
    requestId: overrides.requestId ?? target.requestId,
    actionDigest: overrides.actionDigest ?? actionDigestOf(target),
    action: target,
    verdict: overrides.verdict ?? "allow",
  };
}

function makeAdmission(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    identity,
    owners,
    mode: "auto-review",
    judge: JUDGE,
    session: SESSION,
    expectedRevision: 0,
    projectRulesRevision: 0,
    intentRevision: 0,
    viewHistoryRevision: 0,
    viewCaptureRevision: 0,
    dependenciesVerified: true,
    members: [makeMember()],
    authorization: [allowEntry],
    signal: new AbortController().signal,
    deadline: NOW.getTime() + 60_000,
    ...overrides,
  };
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
  ownCommitResult = true;
  ownCommitCalls = 0;
  requireReconciliationCalls = 0;
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

  recordOwnCommit(): boolean {
    this.ownCommitCalls += 1;
    return this.ownCommitResult;
  }

  requireReconciliation(): void {
    this.requireReconciliationCalls += 1;
  }
}

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
      return {
        kind: "unavailable",
        path: STORE_PATH,
        category: this.unavailable.category,
        ...(this.unavailable.diagnostic === undefined ? {} : { diagnostic: this.unavailable.diagnostic }),
      };
    }
    if (this.file === undefined) return { kind: "missing", path: STORE_PATH, revision: 0 };
    return { kind: "available", path: STORE_PATH, contentHash: `hash-${this.file.revision}`, file: this.file };
  }

  async commit(
    change: ProjectRulesChange,
    expectedRevision: number,
    guard?: ProjectRulesCommitGuard,
  ): Promise<ProjectRulesCommitResult> {
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

interface Bucket {
  readonly candidates: LearningCandidate[];
  readonly rejections: LearningRejection[];
}

/** Minimal structural stand-in for the real collector (partitioned by attempt). */
class FakeCollector implements LearningCollectorPort {
  attemptId: string | undefined = "attempt-1";
  readonly buckets = new Map<string, Map<string, Bucket>>();
  readonly takeCalls: Array<{ attemptId: string; requestIds: readonly string[] }> = [];
  readonly discarded: string[] = [];
  stageCalls = 0;

  stage(attemptId: string, requestId: string, field: "create" | "revoke", index: number, value: Readonly<Record<string, unknown>>): void {
    this.stageCalls += 1;
    let attempt = this.buckets.get(attemptId);
    if (attempt === undefined) {
      attempt = new Map();
      this.buckets.set(attemptId, attempt);
    }
    const current = attempt.get(requestId) ?? { candidates: [], rejections: [] };
    attempt.set(requestId, {
      candidates: [
        ...current.candidates,
        { attemptId, requestId, field, index, value },
      ],
      rejections: current.rejections,
    });
  }

  stageRejection(attemptId: string, requestId: string, rejection: Omit<LearningRejection, "attemptId" | "requestId">): void {
    let attempt = this.buckets.get(attemptId);
    if (attempt === undefined) {
      attempt = new Map();
      this.buckets.set(attemptId, attempt);
    }
    const current = attempt.get(requestId) ?? { candidates: [], rejections: [] };
    attempt.set(requestId, {
      candidates: current.candidates,
      rejections: [...current.rejections, { attemptId, requestId, ...rejection }],
    });
  }

  currentAttemptId(): string | undefined {
    return this.attemptId;
  }

  take(attemptId: string, requestIds: readonly string[]): { candidates: readonly LearningCandidate[]; rejections: readonly LearningRejection[] } {
    this.takeCalls.push({ attemptId, requestIds: [...requestIds] });
    const attempt = this.buckets.get(attemptId);
    const candidates: LearningCandidate[] = [];
    const rejections: LearningRejection[] = [];
    if (attempt !== undefined) {
      for (const requestId of requestIds) {
        const bucket = attempt.get(requestId);
        if (bucket === undefined) continue;
        candidates.push(...bucket.candidates);
        rejections.push(...bucket.rejections);
        attempt.delete(requestId);
      }
      if (attempt.size === 0) this.buckets.delete(attemptId);
    }
    return Object.freeze({ candidates: Object.freeze(candidates), rejections: Object.freeze(rejections) });
  }

  hasStagedData(attemptId?: string): boolean {
    if (attemptId !== undefined) {
      const attempt = this.buckets.get(attemptId);
      if (attempt === undefined) return false;
      for (const bucket of attempt.values()) {
        if (bucket.candidates.length > 0 || bucket.rejections.length > 0) return true;
      }
      return false;
    }
    for (const attempt of this.buckets.values()) {
      for (const bucket of attempt.values()) {
        if (bucket.candidates.length > 0 || bucket.rejections.length > 0) return true;
      }
    }
    return false;
  }

  discardAttempt(attemptId: string): void {
    this.discarded.push(attemptId);
    this.buckets.delete(attemptId);
  }
}

interface Harness {
  readonly store: FakeStore;
  readonly barrier: FakeBarrier;
  readonly collector: FakeCollector;
  readonly service: ProjectRulesService;
  readonly learning: ProjectRuleLearningService;
  readonly audits: LearningAuditEvent[];
  readonly learningState: { enabled: boolean; mode: string };
}

function createHarness(options: {
  readonly file?: ProjectRulesFile;
  readonly unavailable?: { category: ProjectRulesUnavailableCategory; diagnostic?: string };
  readonly now?: () => Date;
  readonly learningEnabled?: () => boolean;
  readonly mode?: () => string;
  readonly serviceOwners?: { owner: string; viewOwner: string; revisionOwner: string };
  readonly commitQueue?: readonly ProjectRulesCommitResult[];
} = {}): Harness {
  const store = new FakeStore(options.file);
  if (options.unavailable !== undefined) store.unavailable = options.unavailable;
  if (options.commitQueue !== undefined) store.commitQueue.push(...options.commitQueue);
  const barrier = new FakeBarrier();
  const collector = new FakeCollector();
  const service = new ProjectRulesService({
    store,
    identity,
    barrier,
    now: options.now ?? (() => NOW),
    audit: () => {},
  });
  const learningState = {
    enabled: options.learningEnabled === undefined ? true : options.learningEnabled(),
    mode: options.mode === undefined ? "auto-review" : options.mode(),
  };
  const audits: LearningAuditEvent[] = [];
  const learning = new ProjectRuleLearningService({
    store,
    service,
    identity,
    collector,
    barrier,
    now: options.now ?? (() => NOW),
    learningEnabled: options.learningEnabled ?? (() => learningState.enabled),
    mode: options.mode ?? (() => learningState.mode),
    audit: (event) => {
      audits.push(event);
    },
    ...(options.serviceOwners === undefined ? {} : { owners: options.serviceOwners }),
  });
  return { store, barrier, collector, service, learning, audits, learningState };
}

function stageCreate(collector: FakeCollector, requestId: string, value: Record<string, unknown>, index = 0): void {
  collector.stage(collector.attemptId ?? "attempt-1", requestId, "create", index, value);
}

function stageRevoke(collector: FakeCollector, requestId: string, value: Record<string, unknown>, index = 0): void {
  collector.stage(collector.attemptId ?? "attempt-1", requestId, "revoke", index, value);
}

function admissionFor(harness: Harness, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return makeAdmission({
    expectedRevision: harness.store.file?.revision ?? 0,
    projectRulesRevision: harness.store.file?.revision ?? 0,
    intentRevision: harness.barrier.revision,
    ...overrides,
  });
}

// ---------------------------------------------------------------------------
// actionDigestOf
// ---------------------------------------------------------------------------

describe("actionDigestOf", () => {
  it("is the canonical JSON SHA-256 of the whole action", () => {
    const target = action();
    expect(actionDigestOf(target)).toBe(sha256Hex(canonicalJson(target)));
  });

  it("differs when the action identity differs", () => {
    expect(actionDigestOf(action())).not.toBe(actionDigestOf(action({ requestId: "req-9" })));
  });
});

// ---------------------------------------------------------------------------
// validateLearningAdmission (§3)
// ---------------------------------------------------------------------------

describe("validateLearningAdmission", () => {
  it("accepts a complete plain-data admission and returns a frozen copy", () => {
    const result = validateLearningAdmission(makeAdmission());
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("unreachable");
    expect(Object.isFrozen(result.admission)).toBe(true);
    expect(Object.isFrozen(result.admission.members)).toBe(true);
    expect(Object.isFrozen(result.admission.members[0])).toBe(true);
    expect(Object.isFrozen(result.admission.members[0]?.action)).toBe(true);
    expect(Object.isFrozen(result.admission.authorization)).toBe(true);
    expect(result.admission.identity).toEqual(identity);
    expect(result.admission.members[0]?.verdict).toBe("allow");
  });

  it("rejects non-plain containers", () => {
    for (const value of [null, [], "admission", 42, undefined]) {
      const result = validateLearningAdmission(value);
      expect(result.ok).toBe(false);
    }
    const withPrototype = Object.assign(Object.create({ judge: JUDGE }), makeAdmission());
    expect(validateLearningAdmission(withPrototype).ok).toBe(false);
  });

  it("rejects unknown own fields", () => {
    expect(validateLearningAdmission(makeAdmission({ extra: true })).ok).toBe(false);
  });

  it("rejects symbol properties and accessors", () => {
    const withSymbol = makeAdmission();
    (withSymbol as Record<symbol, unknown>)[Symbol("extra")] = 1;
    expect(validateLearningAdmission(withSymbol).ok).toBe(false);

    const withGetter = makeAdmission();
    Object.defineProperty(withGetter, "judge", { enumerable: true, get: () => JUDGE });
    expect(validateLearningAdmission(withGetter).ok).toBe(false);
  });

  it("rejects missing required fields", () => {
    const incomplete = makeAdmission();
    delete incomplete.deadline;
    expect(validateLearningAdmission(incomplete).ok).toBe(false);
  });

  it("rejects a malformed project identity", () => {
    expect(validateLearningAdmission(makeAdmission({ identity: { rootPath: "/x" } })).ok).toBe(false);
    expect(validateLearningAdmission(makeAdmission({ identity: { ...identity, identityHash: "" } })).ok).toBe(false);
  });

  it("rejects incomplete or empty owner relations", () => {
    expect(validateLearningAdmission(makeAdmission({ owners: { owner: "user-1" } })).ok).toBe(false);
    expect(validateLearningAdmission(makeAdmission({ owners: { ...owners, viewOwner: " " } })).ok).toBe(false);
  });

  it("accepts only auto-review mode", () => {
    expect(validateLearningAdmission(makeAdmission({ mode: "ask" })).ok).toBe(false);
    expect(validateLearningAdmission(makeAdmission({ mode: "auto-review" })).ok).toBe(true);
  });

  it("rejects empty or sensitive judge and session", () => {
    expect(validateLearningAdmission(makeAdmission({ judge: "  " })).ok).toBe(false);
    expect(validateLearningAdmission(makeAdmission({ session: "" })).ok).toBe(false);
    expect(validateLearningAdmission(makeAdmission({ judge: "judge-1" })).ok).toBe(true);
  });

  it("requires safe-integer, non-negative revisions and view counters", () => {
    expect(validateLearningAdmission(makeAdmission({ expectedRevision: -1 })).ok).toBe(false);
    expect(validateLearningAdmission(makeAdmission({ expectedRevision: 1.5 })).ok).toBe(false);
    expect(validateLearningAdmission(makeAdmission({ projectRulesRevision: Number.MAX_SAFE_INTEGER + 2 })).ok).toBe(false);
    expect(validateLearningAdmission(makeAdmission({ intentRevision: "1" })).ok).toBe(false);
    expect(validateLearningAdmission(makeAdmission({ viewHistoryRevision: -2 })).ok).toBe(false);
    expect(validateLearningAdmission(makeAdmission({ viewCaptureRevision: -1 })).ok).toBe(false);
  });

  it("requires a boolean dependenciesVerified fact", () => {
    expect(validateLearningAdmission(makeAdmission({ dependenciesVerified: "yes" })).ok).toBe(false);
    expect(validateLearningAdmission(makeAdmission({ dependenciesVerified: undefined })).ok).toBe(false);
  });

  it("requires a non-empty member list with unique request ids", () => {
    expect(validateLearningAdmission(makeAdmission({ members: [] })).ok).toBe(false);
    const duplicated = [makeMember(), makeMember()];
    expect(validateLearningAdmission(makeAdmission({ members: duplicated })).ok).toBe(false);
  });

  it("rejects more members than one learning request allows", () => {
    const members = Array.from({ length: 65 }, (_, index) => {
      const target = action({ requestId: `req-${index}`, scopes: [scope(`s${index}`, "bash", `f${index}.txt`, "read")] });
      return makeMember({ action: target });
    });
    expect(validateLearningAdmission(makeAdmission({ members })).ok).toBe(false);
  });

  it("rejects an inconsistent action digest or action request id", () => {
    expect(validateLearningAdmission(makeAdmission({ members: [makeMember({ actionDigest: "deadbeef" })] })).ok).toBe(false);
    const shifted = action();
    const member = { ...makeMember(), action: { ...shifted, requestId: "req-other" } };
    expect(validateLearningAdmission(makeAdmission({ members: [member] })).ok).toBe(false);
  });

  it("rejects unknown verdicts", () => {
    expect(validateLearningAdmission(makeAdmission({ members: [makeMember({ verdict: "allow" })] })).ok).toBe(true);
    expect(
      validateLearningAdmission(makeAdmission({ members: [{ ...makeMember(), verdict: "approve" }] })).ok,
    ).toBe(false);
  });

  it("rejects a malformed action", () => {
    const member = { ...makeMember(), action: { requestId: "req-1" } };
    expect(validateLearningAdmission(makeAdmission({ members: [member] })).ok).toBe(false);
    const badScope = action({
      scopes: [{ id: "s1", surface: "bash", target: "file.txt", access: "frobnicate" } as unknown as ActionScope],
    });
    expect(validateLearningAdmission(makeAdmission({ members: [makeMember({ action: badScope })] })).ok).toBe(false);
  });

  it("accepts only user-sourced authorization entries", () => {
    expect(validateLearningAdmission(makeAdmission({
      authorization: [{ id: "entry-x", source: "tool", text: "工具返回允许" }],
    })).ok).toBe(false);
    expect(validateLearningAdmission(makeAdmission({
      authorization: [{ id: "entry-1", source: "user", text: "以后允许读取 file.txt" }],
    })).ok).toBe(true);
  });

  it("requires a real AbortSignal and a finite deadline", () => {
    expect(validateLearningAdmission(makeAdmission({ signal: { aborted: false } })).ok).toBe(false);
    expect(validateLearningAdmission(makeAdmission({ signal: undefined })).ok).toBe(false);
    expect(validateLearningAdmission(makeAdmission({ deadline: Number.POSITIVE_INFINITY })).ok).toBe(false);
    expect(validateLearningAdmission(makeAdmission({ deadline: Number.NaN })).ok).toBe(false);
    expect(validateLearningAdmission(makeAdmission({ signal: new AbortController().signal })).ok).toBe(true);
  });

  it("rejects an empty batch id", () => {
    expect(validateLearningAdmission(makeAdmission({ batchId: "" })).ok).toBe(false);
    expect(validateLearningAdmission(makeAdmission({ batchId: "batch-1" })).ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// commit preconditions (§4)
// ---------------------------------------------------------------------------

describe("ProjectRuleLearningService.commit preconditions", () => {
  it("rejects an invalid admission without touching the store", async () => {
    const harness = createHarness();
    const result = await harness.learning.commit({ nope: true });
    expect(result.kind).toBe("failed");
    if (result.kind !== "failed") throw new Error("unreachable");
    expect(result.category).toBe("invalid-admission");
    expect(harness.store.commitCalls).toBe(0);
    expect(harness.collector.takeCalls).toEqual([]);
  });

  it("fails after dispose and stays disposed idempotently", async () => {
    const harness = createHarness();
    harness.learning.dispose();
    harness.learning.dispose();
    const result = await harness.learning.commit(makeAdmission());
    expect(result.kind).toBe("failed");
    if (result.kind !== "failed") throw new Error("unreachable");
    expect(result.category).toBe("disposed");
    expect(harness.store.commitCalls).toBe(0);
  });

  it("fails when the capture signal is already aborted", async () => {
    const harness = createHarness();
    const controller = new AbortController();
    controller.abort();
    const result = await harness.learning.commit(makeAdmission({ signal: controller.signal }));
    expect(result.kind).toBe("failed");
    if (result.kind !== "failed") throw new Error("unreachable");
    expect(result.category).toBe("aborted");
  });

  it("fails when the deadline has passed", async () => {
    const harness = createHarness();
    const result = await harness.learning.commit(makeAdmission({ deadline: NOW.getTime() - 1 }));
    expect(result.kind).toBe("failed");
    if (result.kind !== "failed") throw new Error("unreachable");
    expect(result.category).toBe("timeout");
  });

  it("requires learning to be enabled and the mode to be auto-review", async () => {
    const disabled = createHarness({ learningEnabled: () => false });
    const disabledResult = await disabled.learning.commit(admissionFor(disabled));
    expect(disabledResult.kind).toBe("failed");
    if (disabledResult.kind !== "failed") throw new Error("unreachable");
    expect(disabledResult.category).toBe("disabled");

    const manual = createHarness({ mode: () => "manual" });
    const manualResult = await manual.learning.commit(admissionFor(manual));
    expect(manualResult.kind).toBe("failed");
    if (manualResult.kind !== "failed") throw new Error("unreachable");
    expect(manualResult.category).toBe("disabled");
  });

  it("requires host-verified dependencies", async () => {
    const harness = createHarness();
    const result = await harness.learning.commit(makeAdmission({ dependenciesVerified: false }));
    expect(result.kind).toBe("failed");
    if (result.kind !== "failed") throw new Error("unreachable");
    expect(result.category).toBe("dependencies-unverified");
  });

  it("requires the admission identity and owners to match the service", async () => {
    const harness = createHarness();
    const identityResult = await harness.learning.commit(makeAdmission({ identity: otherIdentity }));
    expect(identityResult.kind).toBe("failed");
    if (identityResult.kind !== "failed") throw new Error("unreachable");
    expect(identityResult.category).toBe("identity-mismatch");

    const ownedHarness = createHarness({ serviceOwners: owners });
    const ownerResult = await ownedHarness.learning.commit(makeAdmission({ owners: { ...owners, viewOwner: "user-2" } }));
    expect(ownerResult.kind).toBe("failed");
    if (ownerResult.kind !== "failed") throw new Error("unreachable");
    expect(ownerResult.category).toBe("owner-mismatch");
  });

  it("rejects sensitive judge or session values", async () => {
    const harness = createHarness();
    const result = await harness.learning.commit(makeAdmission({ session: "Bearer abcdefghijklmnopqrst" }));
    expect(result.kind).toBe("failed");
    if (result.kind !== "failed") throw new Error("unreachable");
    expect(result.category).toBe("sensitive");
  });

  it("fails when the project rule file is unavailable", async () => {
    const harness = createHarness({ unavailable: { category: "corrupt" } });
    const result = await harness.learning.commit(admissionFor(harness));
    expect(result.kind).toBe("failed");
    if (result.kind !== "failed") throw new Error("unreachable");
    expect(result.category).toBe("unavailable");
    expect(harness.store.commitCalls).toBe(0);
  });

  it("fails stale when the file revision or expected revision moved", async () => {
    const harness = createHarness({ file: projectFile(3, []) });
    const result = await harness.learning.commit(makeAdmission({ expectedRevision: 2, projectRulesRevision: 2 }));
    expect(result.kind).toBe("failed");
    if (result.kind !== "failed") throw new Error("unreachable");
    expect(result.category).toBe("stale");
    expect(result.reason).toBe("revision-changed");
    expect(result.currentIntentValid).toBe(false);
    expect(harness.store.commitCalls).toBe(0);
  });

  it("fails stale when the intent revision moved", async () => {
    const harness = createHarness();
    harness.barrier.revision = 4;
    const result = await harness.learning.commit(makeAdmission({ intentRevision: 3 }));
    expect(result.kind).toBe("failed");
    if (result.kind !== "failed") throw new Error("unreachable");
    expect(result.category).toBe("stale");
    expect(result.reason).toBe("intent-changed");
  });

  it("returns no-change with the collector's parse rejections when nothing was staged", async () => {
    const harness = createHarness();
    harness.collector.stageRejection("attempt-1", "req-1", { field: "create", index: 0, reason: "invalid-candidate" });
    const result = await harness.learning.commit(makeAdmission());
    expect(result.kind).toBe("no-change");
    if (result.kind !== "no-change") throw new Error("unreachable");
    expect(result.revision).toBe(0);
    expect(result.previousRevision).toBe(0);
    expect(result.rejections).toHaveLength(1);
    expect(result.rejections[0]).toMatchObject({ stage: "parse", reason: "invalid-candidate" });
    expect(result.currentIntentValid).toBe(true);
    expect(harness.store.commitCalls).toBe(0);
    expect(harness.audits.map((event) => event.kind)).toContain("learning-no-change");
  });

  it("takes candidates only for the admission's request ids", async () => {
    const harness = createHarness();
    stageCreate(harness.collector, "req-1", createCandidate());
    stageCreate(harness.collector, "req-9", createCandidate());
    const result = await harness.learning.commit(makeAdmission());
    expect(result.kind).toBe("committed");
    expect(harness.collector.takeCalls[0]).toEqual({ attemptId: "attempt-1", requestIds: ["req-1"] });
    expect(harness.collector.buckets.get("attempt-1")?.has("req-9")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// commit transaction (§5)
// ---------------------------------------------------------------------------

describe("ProjectRuleLearningService.commit transaction", () => {
  it("commits one allow rule from a verified create candidate", async () => {
    const harness = createHarness();
    stageCreate(harness.collector, "req-1", createCandidate());
    const result = await harness.learning.commit(makeAdmission());
    expect(result.kind).toBe("committed");
    if (result.kind !== "committed") throw new Error("unreachable");
    expect(result.durable).toBe(true);
    expect(result.revision).toBe(1);
    expect(result.previousRevision).toBe(0);
    expect(result.currentIntentValid).toBe(true);
    expect(result.needsReconciliation).toBe(false);
    expect(result.ownCommitRecorded).toBe(true);
    expect(result.durableRuleIds).toEqual([createRuleId("allow")]);

    const file = harness.store.file;
    expect(file?.revision).toBe(1);
    const rule = file?.rules[0];
    expect(rule?.id).toBe(createRuleId("allow"));
    expect(rule?.effect).toBe("allow");
    expect(rule?.status).toBe("active");
    expect(rule?.match).toEqual(matchFor(action()));
    expect(rule?.provenance).toMatchObject({
      sessionId: SESSION,
      sourceEntryId: "entry-1",
      quote: "以后允许读取 file.txt",
      actor: "user-1",
    });
    expect(rule?.createdAt).toBe(NOW_ISO);
    expect(harness.audits.map((event) => event.kind)).toContain("rules-committed");
  });

  it("applies revokes before creates in one transaction", async () => {
    const existing = storedRule("rule-000000000000000000000001", "allow");
    const harness = createHarness({ file: projectFile(1, [existing]) });
    harness.collector.attemptId = "attempt-1";
    stageRevoke(harness.collector, "req-1", revokeCandidate(existing.id), 0);
    stageCreate(harness.collector, "req-1", createCandidate(), 1);
    const result = await harness.learning.commit(admissionFor(harness, {
      authorization: [allowEntry, revokeEntry(existing.id)],
    }));
    expect(result.kind).toBe("committed");
    if (result.kind !== "committed") throw new Error("unreachable");
    expect(result.revokedRuleIds).toEqual([existing.id]);
    expect(result.durableRuleIds).toEqual([createRuleId("allow")]);

    const file = harness.store.file;
    expect(file?.revision).toBe(2);
    expect(file?.rules.find((rule) => rule.id === existing.id)?.status).toBe("revoked");
    expect(file?.rules.find((rule) => rule.id === createRuleId("allow"))?.status).toBe("active");
    expect(file?.tombstones.map((item) => item.ruleId)).toEqual([existing.id]);
  });

  it("handles deny candidates before allow candidates regardless of candidate order", async () => {
    const harness = createHarness();
    stageCreate(harness.collector, "req-1", createCandidate(), 0);
    stageCreate(harness.collector, "req-1", denyCreateCandidate(), 1);
    const result = await harness.learning.commit(makeAdmission({ authorization: [allowEntry, denyEntry] }));
    expect(result.kind).toBe("committed");
    if (result.kind !== "committed") throw new Error("unreachable");
    expect(result.durableRuleIds).toEqual([createRuleId("deny", action(), "entry-deny")]);
    expect(result.rejections.some((item) => item.stage === "rule" && item.reason === "conflict-with-deny")).toBe(true);

    const file = harness.store.file;
    expect(file?.rules).toHaveLength(1);
    expect(file?.rules[0]?.effect).toBe("deny");
  });

  it("lets a new deny supersede an active allow with the same match and appends a tombstone", async () => {
    const existing = storedRule("rule-000000000000000000000002", "allow");
    const harness = createHarness({ file: projectFile(1, [existing]) });
    stageCreate(harness.collector, "req-1", denyCreateCandidate());
    const result = await harness.learning.commit(admissionFor(harness, {
      authorization: [denyEntry],
    }));
    expect(result.kind).toBe("committed");
    if (result.kind !== "committed") throw new Error("unreachable");
    expect(result.revokedRuleIds).toContain(existing.id);
    expect(result.durableRuleIds).toEqual([createRuleId("deny", action(), "entry-deny")]);

    const file = harness.store.file;
    const superseded = file?.rules.find((rule) => rule.id === existing.id);
    expect(superseded?.status).toBe("revoked");
    expect(superseded?.revocation?.reason).toBe("superseded-by-deny");
    expect(file?.tombstones.map((item) => item.ruleId)).toEqual([existing.id]);
    expect(file?.tombstones[0]?.revision).toBe(2);
    expect(file?.rules.find((rule) => rule.id === createRuleId("deny", action(), "entry-deny"))?.effect).toBe("deny");
  });

  it("treats an active identical rule as an idempotent duplicate", async () => {
    const duplicateId = createRuleId("allow");
    const harness = createHarness({ file: projectFile(1, [storedRule(duplicateId, "allow")]) });
    stageCreate(harness.collector, "req-1", createCandidate());
    const result = await harness.learning.commit(admissionFor(harness));
    expect(result.kind).toBe("no-change");
    if (result.kind !== "no-change") throw new Error("unreachable");
    expect(result.revision).toBe(1);
    expect(result.rejections.some((item) => item.stage === "duplicate" && item.reason === "duplicate-rule")).toBe(true);
    expect(harness.store.file?.rules).toHaveLength(1);
    expect(harness.store.file?.revision).toBe(1);
  });

  it("treats an active rule with the same match and effect as an idempotent duplicate", async () => {
    const harness = createHarness({ file: projectFile(1, [storedRule("rule-000000000000000000000003", "allow")]) });
    stageCreate(harness.collector, "req-1", createCandidate());
    const result = await harness.learning.commit(admissionFor(harness));
    expect(result.kind).toBe("no-change");
    if (result.kind !== "no-change") throw new Error("unreachable");
    expect(result.rejections.some((item) => item.stage === "duplicate" && item.reason === "duplicate-match")).toBe(true);
    expect(harness.store.file?.rules).toHaveLength(1);
  });

  it("never revives a tombstoned rule id", async () => {
    const deadId = createRuleId("allow");
    const dead = revokedRule(deadId, "allow");
    const harness = createHarness({ file: projectFile(1, [dead], [tombstoneFor(dead)]) });
    stageCreate(harness.collector, "req-1", createCandidate());
    const result = await harness.learning.commit(admissionFor(harness));
    expect(result.kind).toBe("no-change");
    if (result.kind !== "no-change") throw new Error("unreachable");
    expect(result.rejections.some((item) => item.stage === "rule" && item.reason === "tombstoned")).toBe(true);
  });

  it("refuses a rule id already marked needs_review", async () => {
    const reviewId = createRuleId("allow");
    const harness = createHarness({ file: projectFile(1, [storedRule(reviewId, "allow", { status: "needs_review" })]) });
    stageCreate(harness.collector, "req-1", createCandidate());
    const result = await harness.learning.commit(admissionFor(harness));
    expect(result.kind).toBe("no-change");
    if (result.kind !== "no-change") throw new Error("unreachable");
    expect(result.rejections.some((item) => item.stage === "rule" && item.reason === "needs-review")).toBe(true);
  });

  it("fails the whole change atomically when the rule cap would be exceeded", async () => {
    const rules = Array.from({ length: 512 }, (_, index) => syntheticRule(index + 1));
    const harness = createHarness({ file: projectFile(2, rules) });
    stageCreate(harness.collector, "req-1", createCandidate());
    const result = await harness.learning.commit(admissionFor(harness));
    expect(result.kind).toBe("failed");
    if (result.kind !== "failed") throw new Error("unreachable");
    expect(result.category).toBe("capacity");
    expect(harness.store.file?.revision).toBe(2);
    expect(harness.store.file?.rules).toHaveLength(512);
  });

  it("rejects an allow create whose member verdict is not allow", async () => {
    const harness = createHarness();
    stageCreate(harness.collector, "req-1", createCandidate());
    const result = await harness.learning.commit(makeAdmission({ members: [makeMember({ verdict: "defer" })] }));
    expect(result.kind).toBe("no-change");
    if (result.kind !== "no-change") throw new Error("unreachable");
    expect(result.rejections.some((item) => item.stage === "rule" && item.reason === "verdict-not-allow")).toBe(true);
    expect(harness.store.file).toBeUndefined();
  });

  it("rejects a create candidate that cites an unknown authorization entry", async () => {
    const harness = createHarness();
    stageCreate(harness.collector, "req-1", createCandidate({ sourceEntryId: "entry-missing" }));
    const result = await harness.learning.commit(makeAdmission());
    expect(result.kind).toBe("no-change");
    if (result.kind !== "no-change") throw new Error("unreachable");
    expect(result.rejections.some((item) => item.stage === "rule" && item.reason.startsWith("evidence-"))).toBe(true);
  });

  it("rejects a candidate whose scope or actionRef is not host-bound", async () => {
    const harness = createHarness();
    stageCreate(harness.collector, "req-1", createCandidate({ scope: "pattern" }), 0);
    stageCreate(harness.collector, "req-1", createCandidate({ actionRef: "req-2" }), 1);
    const result = await harness.learning.commit(makeAdmission());
    expect(result.kind).toBe("no-change");
    if (result.kind !== "no-change") throw new Error("unreachable");
    expect(result.rejections.some((item) => item.stage === "candidate" && item.reason === "invalid-scope")).toBe(true);
    expect(result.rejections.some((item) => item.stage === "candidate" && item.reason === "invalid-action-ref")).toBe(true);
  });

  it("accepts a candidate that refers to its own request id as actionRef", async () => {
    const harness = createHarness();
    stageCreate(harness.collector, "req-1", createCandidate({ actionRef: "req-1" }));
    const result = await harness.learning.commit(makeAdmission());
    expect(result.kind).toBe("committed");
  });

  it("rejects a candidate bound to a request id outside the admission", async () => {
    const harness = createHarness();
    harness.collector.stage("attempt-1", "req-outer", "create", 0, createCandidate());
    stageCreate(harness.collector, "req-1", createCandidate({ sourceEntryId: "entry-1", quote: "以后允许读取 file.txt" }));
    const result = await harness.learning.commit(makeAdmission());
    expect(result.kind).toBe("committed");
    expect(harness.collector.buckets.get("attempt-1")?.has("req-outer")).toBe(true);
  });

  it("rejects a revoke candidate for an unknown rule", async () => {
    const harness = createHarness();
    stageRevoke(harness.collector, "req-1", revokeCandidate("rule-0000000000000000000000ff"), 0);
    const result = await harness.learning.commit(makeAdmission({
      authorization: [revokeEntry("rule-0000000000000000000000ff")],
    }));
    expect(result.kind).toBe("no-change");
    if (result.kind !== "no-change") throw new Error("unreachable");
    expect(result.rejections.some((item) => item.stage === "rule" && item.reason === "unknown-rule")).toBe(true);
  });

  it("treats a revoke of an already revoked rule as an idempotent no-op", async () => {
    const dead = revokedRule("rule-000000000000000000000004");
    const harness = createHarness({ file: projectFile(1, [dead], [tombstoneFor(dead)]) });
    stageRevoke(harness.collector, "req-1", revokeCandidate(dead.id), 0);
    const result = await harness.learning.commit(admissionFor(harness, {
      authorization: [revokeEntry(dead.id)],
    }));
    expect(result.kind).toBe("no-change");
    if (result.kind !== "no-change") throw new Error("unreachable");
    expect(result.rejections.some((item) => item.stage === "duplicate" && item.reason === "already-revoked")).toBe(true);
  });

  it("revokes one rule with verified evidence and records a durable tombstone", async () => {
    const target = storedRule("rule-000000000000000000000005", "allow");
    const harness = createHarness({ file: projectFile(1, [target]) });
    stageRevoke(harness.collector, "req-1", revokeCandidate(target.id));
    const result = await harness.learning.commit(admissionFor(harness, {
      authorization: [revokeEntry(target.id)],
    }));
    expect(result.kind).toBe("committed");
    if (result.kind !== "committed") throw new Error("unreachable");
    expect(result.revokedRuleIds).toEqual([target.id]);
    expect(harness.store.file?.tombstones.map((item) => item.ruleId)).toEqual([target.id]);
    expect(harness.store.file?.rules[0]?.revocation?.actor).toBe("user-1");
  });

  it("suspends revoke targets and audits write-failed when the commit fails", async () => {
    const target = storedRule("rule-000000000000000000000006", "allow");
    const harness = createHarness({
      file: projectFile(1, [target]),
      commitQueue: [{ kind: "failed", category: "io" }],
    });
    stageRevoke(harness.collector, "req-1", revokeCandidate(target.id));
    const result = await harness.learning.commit(admissionFor(harness, {
      authorization: [revokeEntry(target.id)],
    }));
    expect(result.kind).toBe("failed");
    if (result.kind !== "failed") throw new Error("unreachable");
    expect(result.category).toBe("write-failed");
    expect(harness.service.isSuspended(target.id)).toBe(true);
    expect(harness.audits.some((event) => event.kind === "write-failed")).toBe(true);
  });

  it("reports durable but stale intent validity after a commit whose intent moved", async () => {
    const harness = createHarness();
    stageCreate(harness.collector, "req-1", createCandidate());
    harness.store.afterCommit = () => {
      harness.barrier.revision += 1;
    };
    const result = await harness.learning.commit(makeAdmission());
    expect(result.kind).toBe("committed");
    if (result.kind !== "committed") throw new Error("unreachable");
    expect(result.durable).toBe(true);
    expect(result.currentIntentValid).toBe(false);
    expect(result.needsReconciliation).toBe(true);
    expect(result.ownCommitRecorded).toBe(false);
    expect(harness.barrier.requireReconciliationCalls).toBeGreaterThan(0);
  });

  it("records its own commit for a narrow transaction covering every active rule", async () => {
    const harness = createHarness();
    stageCreate(harness.collector, "req-1", createCandidate());
    const result = await harness.learning.commit(makeAdmission());
    expect(result.kind).toBe("committed");
    if (result.kind !== "committed") throw new Error("unreachable");
    expect(result.ownCommitRecorded).toBe(true);
    expect(harness.barrier.ownCommitCalls).toBe(1);
  });

  it("does not record its own commit when other active rules exist", async () => {
    const harness = createHarness({ file: projectFile(1, [storedRule("rule-000000000000000000000007", "allow")]) });
    stageCreate(harness.collector, "req-1", createCandidate());
    stageCreate(harness.collector, "req-2", secondCreateCandidate(), 1);
    const result = await harness.learning.commit(admissionFor(harness, {
      authorization: [allowEntry, otherEntry],
      members: [makeMember(), makeMember({ action: secondAction() })],
    }));
    expect(result.kind).toBe("committed");
    if (result.kind !== "committed") throw new Error("unreachable");
    expect(result.needsReconciliation).toBe(true);
    expect(result.ownCommitRecorded).toBe(false);
    expect(harness.barrier.requireReconciliationCalls).toBeGreaterThan(0);
  });

  it("requires reconciliation after a broad create", async () => {
    const harness = createHarness();
    const broadEntry: AuthorizationEntry = { id: "entry-broad", source: "user", text: "以后允许所有读取操作" };
    stageCreate(harness.collector, "req-1", createCandidate({
      sourceEntryId: "entry-broad",
      quote: "以后允许所有读取操作",
    }));
    const result = await harness.learning.commit(makeAdmission({ authorization: [broadEntry] }));
    expect(result.kind).toBe("committed");
    if (result.kind !== "committed") throw new Error("unreachable");
    expect(result.needsReconciliation).toBe(true);
    expect(result.ownCommitRecorded).toBe(false);
    expect(harness.barrier.requireReconciliationCalls).toBeGreaterThan(0);
  });

  it("re-checks the learning switch inside the transaction", async () => {
    const harness = createHarness();
    stageCreate(harness.collector, "req-1", createCandidate());
    harness.store.beforeCommit = () => {
      harness.learningState.enabled = false;
    };
    const result = await harness.learning.commit(makeAdmission());
    expect(result.kind).toBe("failed");
    if (result.kind !== "failed") throw new Error("unreachable");
    expect(result.category).toBe("disabled");
    expect(harness.store.file).toBeUndefined();
  });

  it("re-checks the intent revision inside the transaction", async () => {
    const harness = createHarness();
    stageCreate(harness.collector, "req-1", createCandidate());
    harness.store.beforeCommit = () => {
      harness.barrier.revision += 1;
    };
    const result = await harness.learning.commit(makeAdmission());
    expect(result.kind).toBe("failed");
    if (result.kind !== "failed") throw new Error("unreachable");
    expect(result.category).toBe("stale");
    expect(result.reason).toBe("intent-changed");
    expect(harness.store.file).toBeUndefined();
  });

  it("re-checks cancellation inside the transaction", async () => {
    const harness = createHarness();
    const controller = new AbortController();
    stageCreate(harness.collector, "req-1", createCandidate());
    harness.store.beforeCommit = () => {
      controller.abort();
    };
    const result = await harness.learning.commit(makeAdmission({ signal: controller.signal }));
    expect(result.kind).toBe("failed");
    if (result.kind !== "failed") throw new Error("unreachable");
    expect(result.category).toBe("aborted");
  });

  it("maps a store revision conflict to a stale failure", async () => {
    const harness = createHarness({
      commitQueue: [{ kind: "revision-conflict", expectedRevision: 0, revision: 2 }],
    });
    stageCreate(harness.collector, "req-1", createCandidate());
    const result = await harness.learning.commit(makeAdmission());
    expect(result.kind).toBe("failed");
    if (result.kind !== "failed") throw new Error("unreachable");
    expect(result.category).toBe("stale");
    expect(result.reason).toBe("revision-changed");
  });

  it("keeps a valid candidate when another candidate in the same field is rejected", async () => {
    const harness = createHarness();
    stageCreate(harness.collector, "req-1", createCandidate({ confidence: 0.5 }), 0);
    stageCreate(harness.collector, "req-1", createCandidate(), 1);
    const result = await harness.learning.commit(makeAdmission());
    expect(result.kind).toBe("committed");
    if (result.kind !== "committed") throw new Error("unreachable");
    expect(result.durableRuleIds).toEqual([createRuleId("allow")]);
    expect(result.rejections.length).toBeGreaterThan(0);
  });

  it("never learns a create for a host hard-denied action", async () => {
    const harness = createHarness();
    stageCreate(harness.collector, "req-1", denyCreateCandidate());
    const hardDenied = action({ hardDeny: true });
    const result = await harness.learning.commit(makeAdmission({
      members: [makeMember({ action: hardDenied })],
      authorization: [allowEntry, denyEntry],
    }));
    expect(result.kind).toBe("no-change");
    if (result.kind !== "no-change") throw new Error("unreachable");
    expect(result.rejections.some((item) => item.stage === "rule" && item.reason === "unlearnable"),
      JSON.stringify(result.rejections)).toBe(true);
  });

  it("rejects a candidate whose evidence quote carries sensitive content", async () => {
    const harness = createHarness();
    stageCreate(harness.collector, "req-1", createCandidate({
      quote: "以后允许读取 file.txt bearer abcdefghijklmnopqrstuvwxyz",
    }));
    const result = await harness.learning.commit(makeAdmission());
    expect(result.kind).toBe("no-change");
    if (result.kind !== "no-change") throw new Error("unreachable");
    expect(result.rejections.some((item) => item.stage === "candidate" && item.reason === "sensitive")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// wrapLearningApprover (§7)
// ---------------------------------------------------------------------------

function admissionFacts(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const admission = makeAdmission(overrides);
  delete admission.members;
  delete admission.mode;
  return admission;
}

function reviewInput(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    members: [{ requestId: "req-1", actionDigest: actionDigestOf(action()), action: action() }],
    admission: admissionFacts(),
    ...overrides,
  };
}

function approverResult(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    source: "approver",
    modelRequestCount: 1,
    members: [{ requestId: "req-1", actionDigest: actionDigestOf(action()), verdict: "allow" }],
    ...overrides,
  };
}

describe("wrapLearningApprover", () => {
  it("freezes the review input, returns the approver verdict and commits staged candidates", async () => {
    const harness = createHarness();
    stageCreate(harness.collector, "req-1", createCandidate());
    let received: unknown;
    const wrapped = wrapLearningApprover({
      inner: async (input) => {
        received = input;
        return approverResult();
      },
      learning: harness.learning,
      collector: harness.collector,
      mode: () => "auto-review",
      learningEnabled: () => true,
    });

    const result = await wrapped(reviewInput());

    expect(Object.isFrozen(received)).toBe(true);
    expect(Object.isFrozen((received as { members: unknown[] }).members)).toBe(true);
    expect(Object.isFrozen((received as { members: unknown[] }).members[0])).toBe(true);
    expect(result).toMatchObject({ members: [{ requestId: "req-1", verdict: "allow" }] });
    expect(harness.store.file?.rules).toHaveLength(1);
    expect(harness.collector.discarded).toEqual(["attempt-1"]);
  });

  it("passes through without learning when the review input cannot be validated", async () => {
    const harness = createHarness();
    stageCreate(harness.collector, "req-1", createCandidate());
    let called = 0;
    const wrapped = wrapLearningApprover({
      inner: async () => {
        called += 1;
        return approverResult();
      },
      learning: harness.learning,
      collector: harness.collector,
      mode: () => "auto-review",
      learningEnabled: () => true,
    });

    const result = await wrapped(reviewInput({ members: [{ requestId: "req-other", actionDigest: "bad", action: action() }] }));

    expect(called).toBe(1);
    expect(harness.store.commitCalls).toBe(0);
    expect(result).toMatchObject({ members: [{ verdict: "allow" }] });
  });

  it("does not learn a single request whose source is not the approver", async () => {
    const harness = createHarness();
    stageCreate(harness.collector, "req-1", createCandidate());
    const wrapped = wrapLearningApprover({
      inner: async () => approverResult({ source: "policy" }),
      learning: harness.learning,
      collector: harness.collector,
      mode: () => "auto-review",
      learningEnabled: () => true,
    });

    await wrapped(reviewInput());
    expect(harness.store.commitCalls).toBe(0);
  });

  it("does not learn a single request without a model request", async () => {
    const harness = createHarness();
    stageCreate(harness.collector, "req-1", createCandidate());
    const wrapped = wrapLearningApprover({
      inner: async () => approverResult({ modelRequestCount: 0 }),
      learning: harness.learning,
      collector: harness.collector,
      mode: () => "auto-review",
      learningEnabled: () => true,
    });

    await wrapped(reviewInput());
    expect(harness.store.commitCalls).toBe(0);
  });

  it("learns a batch only when at least one member is learnable and none is a technical defer", async () => {
    const harness = createHarness();
    const unitTwo = { requestId: "req-2", actionDigest: actionDigestOf(secondAction()), verdict: "allow" };
    stageCreate(harness.collector, "req-1", createCandidate());
    stageCreate(harness.collector, "req-2", secondCreateCandidate());
    const wrapped = wrapLearningApprover({
      inner: async () => approverResult({
        members: [{ requestId: "req-1", actionDigest: actionDigestOf(action()), verdict: "allow" }, unitTwo],
      }),
      learning: harness.learning,
      collector: harness.collector,
      mode: () => "auto-review",
      learningEnabled: () => true,
    });

    const result = await wrapped(reviewInput({
      members: [
        { requestId: "req-1", actionDigest: actionDigestOf(action()), action: action() },
        { requestId: "req-2", actionDigest: actionDigestOf(secondAction()), action: secondAction() },
      ],
      admission: admissionFacts({
        batchId: "batch-1",
        members: undefined,
        authorization: [allowEntry, otherEntry],
      }),
    }));

    expect(result).toMatchObject({ members: expect.any(Array) });
    expect(harness.store.file?.rules).toHaveLength(2);
  });

  it("refuses a batch without a batch id", async () => {
    const harness = createHarness();
    stageCreate(harness.collector, "req-2", secondCreateCandidate());
    const wrapped = wrapLearningApprover({
      inner: async () => approverResult({
        members: [
          { requestId: "req-1", actionDigest: actionDigestOf(action()), verdict: "allow" },
          { requestId: "req-2", actionDigest: actionDigestOf(secondAction()), verdict: "allow" },
        ],
      }),
      learning: harness.learning,
      collector: harness.collector,
      mode: () => "auto-review",
      learningEnabled: () => true,
    });

    await wrapped(reviewInput({
      members: [
        { requestId: "req-1", actionDigest: actionDigestOf(action()), action: action() },
        { requestId: "req-2", actionDigest: actionDigestOf(secondAction()), action: secondAction() },
      ],
      admission: admissionFacts({ authorization: [allowEntry, otherEntry] }),
    }));
    expect(harness.store.commitCalls).toBe(0);
  });

  it("refuses a batch that contains a technical defer", async () => {
    const harness = createHarness();
    stageCreate(harness.collector, "req-1", createCandidate());
    const wrapped = wrapLearningApprover({
      inner: async () => approverResult({
        members: [
          { requestId: "req-1", actionDigest: actionDigestOf(action()), verdict: "allow" },
          { requestId: "req-2", actionDigest: actionDigestOf(secondAction()), verdict: "defer", deferCategory: "transport" },
        ],
      }),
      learning: harness.learning,
      collector: harness.collector,
      mode: () => "auto-review",
      learningEnabled: () => true,
    });

    await wrapped(reviewInput({
      members: [
        { requestId: "req-1", actionDigest: actionDigestOf(action()), action: action() },
        { requestId: "req-2", actionDigest: actionDigestOf(secondAction()), action: secondAction() },
      ],
      admission: admissionFacts({ batchId: "batch-1", authorization: [allowEntry, otherEntry] }),
    }));
    expect(harness.store.commitCalls).toBe(0);
  });

  it("refuses a batch whose units contain a non-learning verdict", async () => {
    const harness = createHarness();
    stageCreate(harness.collector, "req-1", createCandidate());
    const wrapped = wrapLearningApprover({
      inner: async () => approverResult({
        members: [
          { requestId: "req-1", actionDigest: actionDigestOf(action()), verdict: "allow" },
          { requestId: "req-2", actionDigest: actionDigestOf(secondAction()), verdict: "ask" },
        ],
      }),
      learning: harness.learning,
      collector: harness.collector,
      mode: () => "auto-review",
      learningEnabled: () => true,
    });

    const result = await wrapped(reviewInput({
      members: [
        { requestId: "req-1", actionDigest: actionDigestOf(action()), action: action() },
        { requestId: "req-2", actionDigest: actionDigestOf(secondAction()), action: secondAction() },
      ],
      admission: admissionFacts({ batchId: "batch-1", authorization: [allowEntry, otherEntry] }),
    }));

    expect(harness.store.commitCalls).toBe(0);
    expect(result).toMatchObject({ members: [{ verdict: "allow" }, { verdict: "ask" }] });
  });

  it("learns a non-technical defer only when data was actually staged", async () => {
    const harness = createHarness({ file: projectFile(1, [storedRule("rule-000000000000000000000008", "allow")]) });
    stageRevoke(harness.collector, "req-1", revokeCandidate("rule-000000000000000000000008"));
    const wrapped = wrapLearningApprover({
      inner: async () => approverResult({
        members: [{ requestId: "req-1", actionDigest: actionDigestOf(action()), verdict: "defer" }],
      }),
      learning: harness.learning,
      collector: harness.collector,
      mode: () => "auto-review",
      learningEnabled: () => true,
    });

    await wrapped(reviewInput({
      admission: admissionFacts({
        expectedRevision: 1,
        projectRulesRevision: 1,
        authorization: [allowEntry, revokeEntry("rule-000000000000000000000008")],
      }),
    }));

    expect(harness.store.file?.rules[0]?.status).toBe("revoked");
  });

  it("does not learn a non-technical defer without staged data", async () => {
    const harness = createHarness();
    const wrapped = wrapLearningApprover({
      inner: async () => approverResult({
        members: [{ requestId: "req-1", actionDigest: actionDigestOf(action()), verdict: "defer" }],
      }),
      learning: harness.learning,
      collector: harness.collector,
      mode: () => "auto-review",
      learningEnabled: () => true,
    });

    await wrapped(reviewInput());
    expect(harness.store.commitCalls).toBe(0);
  });

  it("downgrades the current allow to defer when the committed facts are stale", async () => {
    const harness = createHarness();
    stageCreate(harness.collector, "req-1", createCandidate());
    harness.store.afterCommit = () => {
      harness.barrier.revision += 1;
    };
    const wrapped = wrapLearningApprover({
      inner: async () => approverResult(),
      learning: harness.learning,
      collector: harness.collector,
      mode: () => "auto-review",
      learningEnabled: () => true,
    });

    const result = await wrapped(reviewInput());

    expect(result).toMatchObject({ members: [{ requestId: "req-1", verdict: "defer" }] });
  });

  it("keeps a legal deny when the learning commit fails as stale", async () => {
    const harness = createHarness();
    harness.store.beforeCommit = () => {
      harness.barrier.revision += 1;
    };
    const wrapped = wrapLearningApprover({
      inner: async () => approverResult({
        members: [{ requestId: "req-1", actionDigest: actionDigestOf(action()), verdict: "deny" }],
      }),
      learning: harness.learning,
      collector: harness.collector,
      mode: () => "auto-review",
      learningEnabled: () => true,
    });

    const result = await wrapped(reviewInput());

    expect(result).toMatchObject({ members: [{ requestId: "req-1", verdict: "deny" }] });
  });

  it("does not start learning when learning is disabled in the current configuration", async () => {
    const harness = createHarness();
    stageCreate(harness.collector, "req-1", createCandidate());
    const wrapped = wrapLearningApprover({
      inner: async () => approverResult(),
      learning: harness.learning,
      collector: harness.collector,
      mode: () => "auto-review",
      learningEnabled: () => false,
    });

    await wrapped(reviewInput());
    expect(harness.store.commitCalls).toBe(0);
  });

  it("stops learning after dispose and releases the inner approver", async () => {
    const harness = createHarness();
    stageCreate(harness.collector, "req-1", createCandidate());
    let innerDisposeCalls = 0;
    const inner = Object.assign(
      async () => approverResult(),
      { dispose: () => { innerDisposeCalls += 1; } },
    );
    const wrapped = wrapLearningApprover({
      inner,
      learning: harness.learning,
      collector: harness.collector,
      mode: () => "auto-review",
      learningEnabled: () => true,
    });

    wrapped.dispose();
    const result = await wrapped(reviewInput());

    expect(innerDisposeCalls).toBe(1);
    expect(harness.store.commitCalls).toBe(0);
    expect(result).toMatchObject({ members: [{ verdict: "allow" }] });
  });
});

// ---------------------------------------------------------------------------
// Deferred learning handoff (§9)
// ---------------------------------------------------------------------------

describe("canHandOffDeferredLearning", () => {
  const base = {
    verdict: "allow",
    mode: "auto-review",
    learningEnabled: true,
    actionDigest: "digest-1",
    expectedActionDigest: "digest-1",
    units: [{ verdict: "allow" }],
    candidateCount: 2,
  } as const;

  it("accepts a legal allow with auto-review, learning enabled and unchanged identity", () => {
    expect(canHandOffDeferredLearning(base)).toBe(true);
  });

  it("rejects non-allow verdicts", () => {
    expect(canHandOffDeferredLearning({ ...base, verdict: "defer" })).toBe(false);
    expect(canHandOffDeferredLearning({ ...base, verdict: "deny" })).toBe(false);
    expect(canHandOffDeferredLearning({ ...base, verdict: "ask" })).toBe(false);
  });

  it("rejects changed mode, disabled learning, changed action identity or empty candidates", () => {
    expect(canHandOffDeferredLearning({ ...base, mode: "manual" })).toBe(false);
    expect(canHandOffDeferredLearning({ ...base, learningEnabled: false })).toBe(false);
    expect(canHandOffDeferredLearning({ ...base, expectedActionDigest: "digest-2" })).toBe(false);
    expect(canHandOffDeferredLearning({ ...base, candidateCount: 0 })).toBe(false);
  });

  it("rejects any non-allow unit in the batch", () => {
    expect(canHandOffDeferredLearning({ ...base, units: [{ verdict: "allow" }, { verdict: "ask" }] })).toBe(false);
    expect(canHandOffDeferredLearning({ ...base, units: [] })).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Integration with the real Phase 9 collector and barrier
// ---------------------------------------------------------------------------

function realBarrier(): LearningIntentBarrier {
  return new LearningIntentBarrier({
    learningEnabled: () => true,
    run: () => new Promise<LearningBarrierOutcome>(() => {}),
  });
}

describe("learning integration with the real candidate collector and intent barrier", () => {
  it("commits candidates staged through the real collector under the real barrier", async () => {
    const store = new FakeStore();
    const collector = new LearningCandidateCollector();
    const barrier = realBarrier();
    const service = new ProjectRulesService({ store, identity, barrier, now: () => NOW });
    const learning = new ProjectRuleLearningService({
      store,
      service,
      identity,
      collector,
      barrier,
      now: () => NOW,
      learningEnabled: () => true,
      mode: () => "auto-review",
      owners,
    });

    const attemptId = collector.runAttempt((id) => {
      collector.parse({ create: [createCandidate()] }, { requestId: "req-1" });
      return id;
    });
    const result = await learning.commit(makeAdmission({ intentRevision: 1 }), attemptId);

    expect(result.kind).toBe("committed");
    expect(store.file?.rules.map((rule) => rule.id)).toEqual([createRuleId("allow")]);
    learning.dispose();
    barrier.dispose();
  });

  it("wraps an approver over the real collector attempt and discards it afterwards", async () => {
    const store = new FakeStore();
    const collector = new LearningCandidateCollector();
    const barrier = realBarrier();
    const service = new ProjectRulesService({ store, identity, barrier, now: () => NOW });
    const learning = new ProjectRuleLearningService({
      store,
      service,
      identity,
      collector,
      barrier,
      now: () => NOW,
      learningEnabled: () => true,
      mode: () => "auto-review",
      owners,
    });
    const attemptId = collector.runAttempt((id) => {
      collector.parse({ create: [createCandidate()] }, { requestId: "req-1" });
      return id;
    });
    const wrapped = wrapLearningApprover({
      inner: async () => approverResult(),
      learning,
      collector,
      mode: () => "auto-review",
      learningEnabled: () => true,
    });

    const result = await wrapped(reviewInput({ attemptId, admission: admissionFacts({ intentRevision: 1 }) }));

    expect(result).toMatchObject({ members: [{ verdict: "allow" }] });
    expect(store.file?.rules).toHaveLength(1);
    expect(collector.currentAttemptId()).toBeUndefined();
    expect(collector.hasStagedData(attemptId)).toBe(false);
    learning.dispose();
    barrier.dispose();
  });

  it("accepts a revoke staged by the restricted policy tool for the reviewed action", async () => {
    const target = storedRule("rule-00000000000000000000000a", "allow");
    const store = new FakeStore(projectFile(1, [target]));
    const collector = new LearningCandidateCollector();
    const barrier = realBarrier();
    const service = new ProjectRulesService({ store, identity, barrier, now: () => NOW });
    const learning = new ProjectRuleLearningService({
      store,
      service,
      identity,
      collector,
      barrier,
      now: () => NOW,
      learningEnabled: () => true,
      mode: () => "auto-review",
      owners,
    });
    const tools = createProjectRulePolicyTools({
      service,
      collector,
      learning,
      now: () => NOW,
      requestId: () => "req-1",
    });

    let attemptId: string | undefined;
    const staged = await collector.runAttempt((id) => {
      attemptId = id;
      return tools.revoke({
        ruleId: target.id,
        confidence: 0.95,
        reason: "用户要求撤销该规则",
        expectedRevision: 1,
        evidence: {
          sourceEntryId: "entry-revoke",
          quote: `以后撤销规则 ${target.id}`,
          confidence: 0.95,
          judge: JUDGE,
          sessionId: SESSION,
          actor: "user-1",
        },
      });
    });
    expect(staged).toMatchObject({ ok: true, staged: true, durable: false, requestId: "req-1" });

    const result = await learning.commit(
      makeAdmission({
        intentRevision: 1,
        expectedRevision: 1,
        projectRulesRevision: 1,
        members: [makeMember()],
        authorization: [revokeEntry(target.id)],
      }),
      attemptId,
    );

    expect(result.kind).toBe("committed");
    expect(store.file?.rules[0]?.status).toBe("revoked");
    learning.dispose();
    barrier.dispose();
  });
});
