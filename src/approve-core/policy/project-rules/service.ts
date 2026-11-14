/**
 * Project rule service layer (specs/project-rule-storage.md §5-§9).
 *
 * The service turns the storage seam into the operations the host and the
 * learning transaction consume: a safe rule list, exact-action evaluation,
 * durable revoke, needs-review marking and a frozen review snapshot. Every
 * operation reloads the current file through {@link ProjectRulesStore}; the
 * service never touches the filesystem, never mutates a loaded file and never
 * lets an audit failure change an outcome.
 *
 * The intent barrier is a read-only dependency here. Phase 9 implements it;
 * tests inject a fake. Revision retries are bounded by
 * {@link ProjectRulesServiceOptions.revisionRetries} (default 2), and every
 * retry reloads the file and re-validates the target before committing again.
 */
import { exactMatchDigest, matchExactAction } from "./match";
import { redactSensitiveReason } from "./sensitive";
import {
  PROJECT_RULES_LIMITS,
  isRuleId,
  type ExactAction,
  type ExactActionMatch,
  type ProjectIdentity,
  type ProjectRulesFile,
  type RuleEffect,
  type RuleScope,
  type RuleStatus,
  type RuleToolIdentity,
  type RuleTombstone,
  type StoredProjectRule,
} from "./types";
import type {
  ProjectRulesChange,
  ProjectRulesChangeOutcome,
  ProjectRulesCommitGuard,
  ProjectRulesStore,
  ProjectRulesUnavailableCategory,
} from "./storage";

const DEFAULT_REVISION_RETRIES = 2;
const MAX_TOMBSTONES = PROJECT_RULES_LIMITS.maxTombstones;

/** Stable rejection reasons an in-transaction change returns for the service. */
const REJECT_NOT_FOUND = "not-found";
const REJECT_ALREADY_REVOKED = "already-revoked";
const REJECT_ALREADY_NEEDS_REVIEW = "already-needs-review";

const STATUS_ORDER: Readonly<Record<RuleStatus, number>> = {
  active: 0,
  needs_review: 1,
  revoked: 2,
};

// ---------------------------------------------------------------------------
// Public contracts
// ---------------------------------------------------------------------------

/**
 * Read-only view of the intent barrier (Phase 9 owns the implementation).
 * `holdsRevision` returns the currentness guard the store re-checks right
 * before it publishes a reconciliation transaction.
 */
export interface ProjectRulesIntentBarrier {
  readonly revision: number;
  needsReconciliation(): boolean;
  currentTaskPaused(): boolean;
  learningDisabled(): boolean;
  holdsRevision(revision: number): ProjectRulesCommitGuard;
}

/**
 * One audit fact. `rules-committed` is reserved for the learning transaction;
 * the service itself emits the other kinds.
 */
export type ProjectRulesAuditEvent = {
  readonly kind: "rules-committed" | "rules-revoked" | "needs-review-marked" | "write-failed" | "rules-unavailable";
  readonly ruleIds?: readonly string[];
  readonly revision?: number;
  readonly reason?: string;
};

export interface ProjectRulesServiceOptions {
  readonly store: ProjectRulesStore;
  readonly identity: ProjectIdentity;
  readonly barrier: ProjectRulesIntentBarrier;
  readonly now: () => Date;
  readonly audit?: (event: ProjectRulesAuditEvent) => void | Promise<void>;
  readonly revisionRetries?: number;
}

/** Why an active rule is currently not usable as a learned shortcut. */
export type ProjectRulesSuspension =
  | "write-failed"
  | "needs-reconciliation"
  | "current-task-paused"
  | "learning-disabled";

/** One list entry: stable facts plus the current suspension, never raw arguments. */
export interface ProjectRulesRuleSummary {
  readonly id: string;
  readonly effect: RuleEffect;
  readonly status: RuleStatus;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly provenance: {
    readonly quote: string;
    readonly confidence?: number;
    readonly judge?: string;
    readonly actor: string;
  };
  readonly tool: RuleToolIdentity;
  readonly cwd: string;
  readonly requiredScopes: readonly RuleScope[];
  readonly suspension?: ProjectRulesSuspension;
}

export type ProjectRulesListResult =
  | { readonly kind: "available"; readonly revision: number; readonly rules: readonly ProjectRulesRuleSummary[] }
  | { readonly kind: "missing"; readonly revision: 0; readonly rules: readonly ProjectRulesRuleSummary[] }
  | {
      readonly kind: "unavailable";
      readonly revision: 0;
      readonly category: ProjectRulesUnavailableCategory;
      readonly diagnostic?: string;
      readonly rules: readonly ProjectRulesRuleSummary[];
    };

export type ProjectRulesEvaluation =
  | {
      readonly kind: "defer";
      readonly revision: 0;
      readonly intentRevision: number;
      readonly category: ProjectRulesUnavailableCategory;
      readonly diagnostic?: string;
    }
  | { readonly kind: "none"; readonly revision: number; readonly intentRevision: number; readonly needsReviewRuleIds: readonly string[] }
  | { readonly kind: "needs-reconciliation"; readonly revision: number; readonly intentRevision: number }
  | {
      readonly kind: "allow";
      readonly revision: number;
      readonly intentRevision: number;
      readonly ruleIds: readonly string[];
      /** Current ask scope IDs already covered by learned allows, in action order. */
      readonly coveredScopeIds: readonly string[];
      /** Ask scope IDs that still need an independent allow. */
      readonly remainingAskScopeIds: readonly string[];
      readonly needsReviewRuleIds: readonly string[];
    }
  | { readonly kind: "deny"; readonly revision: number; readonly intentRevision: number; readonly ruleIds: readonly string[]; readonly needsReviewRuleIds: readonly string[] };

export interface ProjectRulesRevokeRequest {
  readonly ruleId: string;
  /** Persisted revocation actor; never model-supplied without host verification. */
  readonly actor: string;
  /** Sensitive reasons are replaced wholesale by a generic placeholder. */
  readonly reason?: string;
  /**
   * Present when this revoke is the reconciliation transaction for an intent
   * revision. The store then receives a guard so a stale intent can never be
   * published.
   */
  readonly reconciliationIntentRevision?: number;
}

export type ProjectRulesRevokeResult =
  | { readonly kind: "revoked"; readonly revision: number; readonly ruleIds: readonly string[]; readonly currentIntentValid?: boolean }
  | { readonly kind: "not-found"; readonly revision: number }
  | { readonly kind: "already-revoked"; readonly revision: number; readonly ruleIds: readonly string[] }
  | { readonly kind: "revision-conflict"; readonly expectedRevision: number; readonly revision: number }
  | { readonly kind: "stale-guard"; readonly revision: number }
  | { readonly kind: "unavailable"; readonly category: ProjectRulesUnavailableCategory; readonly diagnostic?: string }
  | { readonly kind: "failed"; readonly category: "lock" | "io"; readonly diagnostic?: string };

export interface ProjectRulesNeedsReviewRequest {
  readonly ruleId: string;
  /** Audit-only context; needs_review itself persists no reason. */
  readonly reason?: string;
}

export type ProjectRulesNeedsReviewResult =
  | { readonly kind: "marked"; readonly revision: number; readonly ruleIds: readonly string[] }
  | { readonly kind: "already-needs-review"; readonly revision: number; readonly ruleIds: readonly string[] }
  | { readonly kind: "not-found"; readonly revision: number }
  | { readonly kind: "revision-conflict"; readonly expectedRevision: number; readonly revision: number }
  | { readonly kind: "stale-guard"; readonly revision: number }
  | { readonly kind: "unavailable"; readonly category: ProjectRulesUnavailableCategory; readonly diagnostic?: string }
  | { readonly kind: "failed"; readonly category: "lock" | "io"; readonly diagnostic?: string };

/**
 * A review snapshot is served only when the caller's owner, its view owner and
 * its revision owner are the same project, and both revisions are current.
 */
export interface ProjectRulesSnapshotRequest {
  readonly owner: ProjectIdentity;
  readonly viewOwner: ProjectIdentity;
  readonly revisionOwner: ProjectIdentity;
  /** Revision of the project rules file the caller observed. */
  readonly projectRulesRevision: number;
  /** Intent revision the caller observed from the barrier. */
  readonly intentRevision: number;
}

export interface ProjectRulesSnapshotRule {
  readonly id: string;
  readonly effect: RuleEffect;
  readonly status: RuleStatus;
  /** Active, intent gate open and not write-failed suspended. */
  readonly applicable: boolean;
  /** Frozen match facts; the environment appears only as a digest. */
  readonly match: ExactActionMatch;
}

export interface ProjectRulesSnapshot {
  readonly revision: number;
  readonly intentRevision: number;
  readonly rules: readonly ProjectRulesSnapshotRule[];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface BarrierState {
  readonly intentRevision: number;
  readonly needsReconciliation: boolean;
  readonly currentTaskPaused: boolean;
  readonly learningDisabled: boolean;
  /** Learned shortcuts may apply at all right now. */
  readonly gateOpen: boolean;
}

function sameIdentity(left: ProjectIdentity, right: ProjectIdentity): boolean {
  return left.rootPath === right.rootPath && left.displayName === right.displayName &&
    left.slug === right.slug && left.identityHash === right.identityHash;
}

function compareSummaries(left: ProjectRulesRuleSummary, right: ProjectRulesRuleSummary): number {
  const byStatus = STATUS_ORDER[left.status] - STATUS_ORDER[right.status];
  if (byStatus !== 0) return byStatus;
  const leftCreated = Date.parse(left.createdAt);
  const rightCreated = Date.parse(right.createdAt);
  if (Number.isFinite(leftCreated) && Number.isFinite(rightCreated) && leftCreated !== rightCreated) {
    return leftCreated - rightCreated;
  }
  if (left.createdAt !== right.createdAt) return left.createdAt < right.createdAt ? -1 : 1;
  return left.id < right.id ? -1 : left.id > right.id ? 1 : 0;
}

function suspensionFor(
  rule: StoredProjectRule,
  suspended: ReadonlySet<string>,
  barrier: BarrierState,
): ProjectRulesSuspension | undefined {
  if (rule.status !== "active") return undefined;
  if (suspended.has(rule.id)) return "write-failed";
  if (barrier.needsReconciliation) return "needs-reconciliation";
  if (barrier.currentTaskPaused) return "current-task-paused";
  if (barrier.learningDisabled) return "learning-disabled";
  return undefined;
}

function summarizeRule(rule: StoredProjectRule, suspension: ProjectRulesSuspension | undefined): ProjectRulesRuleSummary {
  const provenance: ProjectRulesRuleSummary["provenance"] = {
    quote: rule.provenance.quote,
    actor: rule.provenance.actor,
    ...(rule.provenance.confidence === undefined ? {} : { confidence: rule.provenance.confidence }),
    ...(rule.provenance.judge === undefined ? {} : { judge: rule.provenance.judge }),
  };
  return {
    id: rule.id,
    effect: rule.effect,
    status: rule.status,
    createdAt: rule.createdAt,
    updatedAt: rule.updatedAt,
    provenance,
    tool: rule.match.tool,
    cwd: rule.match.cwd,
    requiredScopes: rule.match.requiredScopes,
    ...(suspension === undefined ? {} : { suspension }),
  };
}

type CloneResult = { readonly ok: true; readonly value: unknown } | { readonly ok: false };

/**
 * Clone one JSON value and freeze every container. Rules loaded from the store
 * are already validated; this only proves the snapshot itself can be frozen
 * without exposing a mutable alias of the stored match.
 */
function cloneJsonFreeze(value: unknown, ancestors: Set<object>): CloneResult {
  if (value === null) return { ok: true, value: null };
  switch (typeof value) {
    case "string":
    case "boolean":
      return { ok: true, value };
    case "number":
      return Number.isFinite(value) ? { ok: true, value } : { ok: false };
    case "object": {
      if (ancestors.has(value)) return { ok: false };
      ancestors.add(value);
      try {
        if (Array.isArray(value)) {
          const items: unknown[] = [];
          for (const item of value) {
            const cloned = cloneJsonFreeze(item, ancestors);
            if (!cloned.ok) return { ok: false };
            items.push(cloned.value);
          }
          return { ok: true, value: Object.freeze(items) };
        }
        const prototype: unknown = Object.getPrototypeOf(value);
        if (prototype !== Object.prototype && prototype !== null) return { ok: false };
        if (Object.getOwnPropertySymbols(value as object).length > 0) return { ok: false };
        const record = value as Record<string, unknown>;
        const entries: Record<string, unknown> = {};
        for (const key of Object.keys(record)) {
          const cloned = cloneJsonFreeze(record[key], ancestors);
          if (!cloned.ok) return { ok: false };
          entries[key] = cloned.value;
        }
        return { ok: true, value: Object.freeze(entries) };
      } finally {
        ancestors.delete(value);
      }
    }
    default:
      return { ok: false };
  }
}

function freezeSnapshotMatch(match: ExactActionMatch): ExactActionMatch | undefined {
  const argumentsResult = cloneJsonFreeze(match.arguments, new Set());
  if (!argumentsResult.ok) return undefined;
  if (!Array.isArray(match.requiredScopes)) return undefined;
  const requiredScopes: RuleScope[] = [];
  for (const scope of match.requiredScopes) {
    if (typeof scope !== "object" || scope === null) return undefined;
    requiredScopes.push(Object.freeze({ surface: scope.surface, target: scope.target, access: scope.access }));
  }
  const tool = match.tool;
  return Object.freeze({
    contractVersion: match.contractVersion,
    type: match.type,
    tool: Object.freeze({ name: tool.name, origin: tool.origin, definitionRevision: tool.definitionRevision }),
    definitionDigest: match.definitionDigest,
    arguments: argumentsResult.value,
    argumentsDigest: match.argumentsDigest,
    cwd: match.cwd,
    environmentDigest: match.environmentDigest,
    requiredScopes: Object.freeze(requiredScopes) as readonly RuleScope[],
  });
}

type RevokeTarget =
  | { readonly kind: "not-found" }
  | { readonly kind: "already-revoked" }
  | { readonly kind: "actionable"; readonly rule: StoredProjectRule };

function locateRevokeTarget(file: ProjectRulesFile, ruleId: string): RevokeTarget {
  const rule = file.rules.find((item) => item.id === ruleId);
  if (rule === undefined) return { kind: "not-found" };
  if (rule.status === "revoked") return { kind: "already-revoked" };
  return { kind: "actionable", rule };
}

type NeedsReviewTarget =
  | { readonly kind: "not-found" }
  | { readonly kind: "already-needs-review" }
  | { readonly kind: "actionable"; readonly rule: StoredProjectRule };

function locateNeedsReviewTarget(file: ProjectRulesFile, ruleId: string): NeedsReviewTarget {
  const rule = file.rules.find((item) => item.id === ruleId);
  if (rule === undefined || rule.status === "revoked") return { kind: "not-found" };
  if (rule.status === "needs_review") return { kind: "already-needs-review" };
  return { kind: "actionable", rule };
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export class ProjectRulesService {
  private readonly store: ProjectRulesStore;
  private readonly identity: ProjectIdentity;
  private readonly barrier: ProjectRulesIntentBarrier;
  private readonly now: () => Date;
  private readonly auditSink: ((event: ProjectRulesAuditEvent) => void | Promise<void>) | undefined;
  private readonly revisionRetries: number;
  private readonly suspended = new Set<string>();

  constructor(options: ProjectRulesServiceOptions) {
    this.store = options.store;
    this.identity = options.identity;
    this.barrier = options.barrier;
    this.now = options.now;
    this.auditSink = options.audit;
    const retries = options.revisionRetries;
    this.revisionRetries = typeof retries === "number" && Number.isSafeInteger(retries) && retries >= 0
      ? retries
      : DEFAULT_REVISION_RETRIES;
  }

  /** Add write-failed revoke targets to the in-memory suspension set. */
  suspendRuleIds(ids: readonly string[]): void {
    for (const id of ids) this.suspended.add(id);
  }

  /** Drop suspension for rules a durable transaction has settled. */
  clearRuleSuspension(ids: readonly string[]): void {
    for (const id of ids) this.suspended.delete(id);
  }

  isSuspended(ruleId: string): boolean {
    return this.suspended.has(ruleId);
  }

  /** Read and summarize the current file on every call (spec §5). */
  async list(): Promise<ProjectRulesListResult> {
    const loaded = await this.store.load();
    if (loaded.kind === "unavailable") {
      await this.emit({ kind: "rules-unavailable", reason: loaded.category });
      return {
        kind: "unavailable",
        revision: 0,
        category: loaded.category,
        ...(loaded.diagnostic === undefined ? {} : { diagnostic: loaded.diagnostic }),
        rules: [],
      };
    }
    if (loaded.kind === "missing") return { kind: "missing", revision: 0, rules: [] };

    const barrier = this.barrierState();
    const rules = loaded.file.rules
      .map((rule) => summarizeRule(rule, suspensionFor(rule, this.suspended, barrier)))
      .sort(compareSummaries);
    return { kind: "available", revision: loaded.file.revision, rules };
  }

  /** Exact-action evaluation in the order fixed by spec §6. */
  async evaluate(action: ExactAction): Promise<ProjectRulesEvaluation> {
    const loaded = await this.store.load();
    if (loaded.kind === "unavailable") {
      await this.emit({ kind: "rules-unavailable", reason: loaded.category });
      return { kind: "defer", revision: 0, intentRevision: this.barrier.revision, category: loaded.category };
    }

    const revision = loaded.kind === "missing" ? 0 : loaded.file.revision;
    const intentRevision = this.barrier.revision;
    if (action.hardDeny === true) {
      return { kind: "none", revision, intentRevision, needsReviewRuleIds: [] };
    }
    if (loaded.kind === "missing") {
      return { kind: "none", revision: 0, intentRevision, needsReviewRuleIds: [] };
    }
    if (this.barrier.needsReconciliation()) {
      return { kind: "needs-reconciliation", revision, intentRevision };
    }
    if (this.barrier.currentTaskPaused() || this.barrier.learningDisabled()) {
      return { kind: "none", revision, intentRevision, needsReviewRuleIds: [] };
    }
    if (action.scopes.length === 0) {
      return { kind: "none", revision, intentRevision, needsReviewRuleIds: [] };
    }

    const allowRuleIds: string[] = [];
    const denyRuleIds: string[] = [];
    const covered = new Set<string>();
    const needsReviewRuleIds: string[] = [];
    for (const rule of loaded.file.rules) {
      if (rule.status !== "active" || this.suspended.has(rule.id)) continue;
      const result = matchExactAction(rule, action);
      if (result.kind === "definition-changed" || result.kind === "environment-changed") {
        needsReviewRuleIds.push(rule.id);
        continue;
      }
      if (result.kind !== "match") continue;
      if (rule.effect === "deny") {
        denyRuleIds.push(rule.id);
        continue;
      }
      allowRuleIds.push(rule.id);
      for (const scopeId of result.coveredScopeIds) covered.add(scopeId);
    }

    if (denyRuleIds.length > 0) {
      return { kind: "deny", revision, intentRevision, ruleIds: denyRuleIds, needsReviewRuleIds };
    }
    if (allowRuleIds.length === 0) {
      return { kind: "none", revision, intentRevision, needsReviewRuleIds };
    }
    // Keep coverage in action order so callers see the same scope list they sent.
    const coveredScopeIds = action.scopes.map((scope) => scope.id).filter((id) => covered.has(id));
    const remainingAskScopeIds = action.scopes.map((scope) => scope.id).filter((id) => !covered.has(id));
    return { kind: "allow", revision, intentRevision, ruleIds: allowRuleIds, coveredScopeIds, remainingAskScopeIds, needsReviewRuleIds };
  }

  /** Durable revoke; the only operation that appends a tombstone (spec §7). */
  async revoke(request: ProjectRulesRevokeRequest): Promise<ProjectRulesRevokeResult> {
    const revokedAt = this.now().toISOString();
    const reason = request.reason === undefined ? undefined : redactSensitiveReason(request.reason);

    let loaded = await this.store.load();
    if (loaded.kind === "unavailable") {
      await this.emit({ kind: "rules-unavailable", reason: loaded.category });
      return { kind: "unavailable", category: loaded.category, diagnostic: loaded.diagnostic };
    }
    if (!isRuleId(request.ruleId)) {
      return { kind: "not-found", revision: loaded.kind === "missing" ? 0 : loaded.file.revision };
    }
    if (loaded.kind === "missing") return { kind: "not-found", revision: 0 };

    const initial = locateRevokeTarget(loaded.file, request.ruleId);
    if (initial.kind === "not-found") return { kind: "not-found", revision: loaded.file.revision };
    if (initial.kind === "already-revoked") {
      return { kind: "already-revoked", revision: loaded.file.revision, ruleIds: [request.ruleId] };
    }

    let expectedRevision = loaded.file.revision;
    for (let attempt = 0; ; attempt += 1) {
      const guard = request.reconciliationIntentRevision === undefined
        ? undefined
        : this.barrier.holdsRevision(request.reconciliationIntentRevision);
      const change: ProjectRulesChange = {
        apply: (input) => this.applyRevoke(input, request.ruleId, request.actor, revokedAt, reason),
      };
      const result = await this.store.commit(change, expectedRevision, guard);
      switch (result.kind) {
        case "committed": {
          this.suspended.delete(request.ruleId);
          await this.emit({ kind: "rules-revoked", ruleIds: [request.ruleId], revision: result.revision });
          if (request.reconciliationIntentRevision !== undefined) {
            const currentIntentValid = this.barrier.revision === request.reconciliationIntentRevision;
            return { kind: "revoked", revision: result.revision, ruleIds: [request.ruleId], currentIntentValid };
          }
          return { kind: "revoked", revision: result.revision, ruleIds: [request.ruleId] };
        }
        case "no-change":
          return { kind: "already-revoked", revision: result.revision, ruleIds: [request.ruleId] };
        case "rejected":
          return result.reason === REJECT_ALREADY_REVOKED
            ? { kind: "already-revoked", revision: result.revision, ruleIds: [request.ruleId] }
            : { kind: "not-found", revision: result.revision };
        case "revision-conflict": {
          if (attempt >= this.revisionRetries) {
            return { kind: "revision-conflict", expectedRevision, revision: result.revision };
          }
          loaded = await this.store.load();
          if (loaded.kind === "unavailable") {
            await this.emit({ kind: "rules-unavailable", reason: loaded.category });
            return { kind: "unavailable", category: loaded.category, diagnostic: loaded.diagnostic };
          }
          if (loaded.kind === "missing") return { kind: "not-found", revision: 0 };
          const retried = locateRevokeTarget(loaded.file, request.ruleId);
          if (retried.kind === "not-found") return { kind: "not-found", revision: loaded.file.revision };
          if (retried.kind === "already-revoked") {
            return { kind: "already-revoked", revision: loaded.file.revision, ruleIds: [request.ruleId] };
          }
          expectedRevision = loaded.file.revision;
          continue;
        }
        case "stale-guard":
          return { kind: "stale-guard", revision: result.revision };
        case "unavailable":
          await this.emit({ kind: "rules-unavailable", reason: result.category });
          return { kind: "unavailable", category: result.category, diagnostic: result.diagnostic };
        case "failed":
          this.suspended.add(request.ruleId);
          await this.emit({ kind: "write-failed", ruleIds: [request.ruleId], reason: result.category });
          return { kind: "failed", category: result.category, diagnostic: result.diagnostic };
      }
    }
  }

  /** Mark one active rule as needing review; duplicate calls are idempotent. */
  async markNeedsReview(request: ProjectRulesNeedsReviewRequest): Promise<ProjectRulesNeedsReviewResult> {
    const updatedAt = this.now().toISOString();
    let loaded = await this.store.load();
    if (loaded.kind === "unavailable") {
      await this.emit({ kind: "rules-unavailable", reason: loaded.category });
      return { kind: "unavailable", category: loaded.category, diagnostic: loaded.diagnostic };
    }
    if (!isRuleId(request.ruleId)) {
      return { kind: "not-found", revision: loaded.kind === "missing" ? 0 : loaded.file.revision };
    }
    if (loaded.kind === "missing") return { kind: "not-found", revision: 0 };

    const initial = locateNeedsReviewTarget(loaded.file, request.ruleId);
    if (initial.kind === "not-found") return { kind: "not-found", revision: loaded.file.revision };
    if (initial.kind === "already-needs-review") {
      return { kind: "already-needs-review", revision: loaded.file.revision, ruleIds: [request.ruleId] };
    }

    let expectedRevision = loaded.file.revision;
    for (let attempt = 0; ; attempt += 1) {
      const change: ProjectRulesChange = {
        apply: (input) => this.applyNeedsReview(input, request.ruleId, updatedAt),
      };
      const result = await this.store.commit(change, expectedRevision);
      switch (result.kind) {
        case "committed":
          await this.emit({
            kind: "needs-review-marked",
            ruleIds: [request.ruleId],
            revision: result.revision,
            ...(request.reason === undefined ? {} : { reason: request.reason }),
          });
          return { kind: "marked", revision: result.revision, ruleIds: [request.ruleId] };
        case "no-change":
          return { kind: "already-needs-review", revision: result.revision, ruleIds: [request.ruleId] };
        case "rejected":
          return result.reason === REJECT_ALREADY_NEEDS_REVIEW
            ? { kind: "already-needs-review", revision: result.revision, ruleIds: [request.ruleId] }
            : { kind: "not-found", revision: result.revision };
        case "revision-conflict": {
          if (attempt >= this.revisionRetries) {
            return { kind: "revision-conflict", expectedRevision, revision: result.revision };
          }
          loaded = await this.store.load();
          if (loaded.kind === "unavailable") {
            await this.emit({ kind: "rules-unavailable", reason: loaded.category });
            return { kind: "unavailable", category: loaded.category, diagnostic: loaded.diagnostic };
          }
          if (loaded.kind === "missing") return { kind: "not-found", revision: 0 };
          const retried = locateNeedsReviewTarget(loaded.file, request.ruleId);
          if (retried.kind === "not-found") return { kind: "not-found", revision: loaded.file.revision };
          if (retried.kind === "already-needs-review") {
            return { kind: "already-needs-review", revision: loaded.file.revision, ruleIds: [request.ruleId] };
          }
          expectedRevision = loaded.file.revision;
          continue;
        }
        case "stale-guard":
          return { kind: "stale-guard", revision: result.revision };
        case "unavailable":
          await this.emit({ kind: "rules-unavailable", reason: result.category });
          return { kind: "unavailable", category: result.category, diagnostic: result.diagnostic };
        case "failed":
          await this.emit({ kind: "write-failed", ruleIds: [request.ruleId], reason: result.category });
          return { kind: "failed", category: result.category, diagnostic: result.diagnostic };
      }
    }
  }

  /**
   * Frozen review snapshot (spec §8). Any owner/revision mismatch, an
   * unavailable file or one unfreezable rule suppresses the whole snapshot.
   */
  async snapshot(request: ProjectRulesSnapshotRequest): Promise<ProjectRulesSnapshot | undefined> {
    if (!sameIdentity(request.owner, this.identity)) return undefined;
    if (!sameIdentity(request.owner, request.viewOwner)) return undefined;
    if (!sameIdentity(request.owner, request.revisionOwner)) return undefined;

    const loaded = await this.store.load();
    if (loaded.kind === "unavailable") {
      await this.emit({ kind: "rules-unavailable", reason: loaded.category });
      return undefined;
    }
    const barrier = this.barrierState();
    if (request.intentRevision !== barrier.intentRevision) return undefined;

    if (loaded.kind === "missing") {
      if (request.projectRulesRevision !== 0) return undefined;
      return Object.freeze({ revision: 0, intentRevision: barrier.intentRevision, rules: Object.freeze([] as ProjectRulesSnapshotRule[]) });
    }
    if (request.projectRulesRevision !== loaded.file.revision) return undefined;

    const rules: ProjectRulesSnapshotRule[] = [];
    for (const rule of loaded.file.rules) {
      const match = freezeSnapshotMatch(rule.match);
      if (match === undefined) return undefined;
      const applicable = rule.status === "active" && barrier.gateOpen && !this.suspended.has(rule.id);
      rules.push(Object.freeze({ id: rule.id, effect: rule.effect, status: rule.status, applicable, match }));
    }
    return Object.freeze({ revision: loaded.file.revision, intentRevision: barrier.intentRevision, rules: Object.freeze(rules) });
  }

  // -------------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------------

  private barrierState(): BarrierState {
    const needsReconciliation = this.barrier.needsReconciliation();
    const currentTaskPaused = this.barrier.currentTaskPaused();
    const learningDisabled = this.barrier.learningDisabled();
    return {
      intentRevision: this.barrier.revision,
      needsReconciliation,
      currentTaskPaused,
      learningDisabled,
      gateOpen: !needsReconciliation && !currentTaskPaused && !learningDisabled,
    };
  }

  private applyRevoke(
    input: { readonly revision: number; readonly file: ProjectRulesFile },
    ruleId: string,
    actor: string,
    revokedAt: string,
    reason: string | undefined,
  ): ProjectRulesChangeOutcome {
    const index = input.file.rules.findIndex((rule) => rule.id === ruleId);
    if (index < 0) return { kind: "reject", reason: REJECT_NOT_FOUND };
    const rule = input.file.rules[index] as StoredProjectRule;
    if (rule.status === "revoked") return { kind: "reject", reason: REJECT_ALREADY_REVOKED };

    const revocation = reason === undefined
      ? { revokedAt, actor }
      : { revokedAt, actor, reason };
    const rules = [...input.file.rules];
    rules[index] = { ...rule, status: "revoked", updatedAt: revokedAt, revocation };
    const tombstone: RuleTombstone = {
      ruleId: rule.id,
      effect: rule.effect,
      matchDigest: exactMatchDigest(rule.match),
      revokedAt,
      // The store stamps this change as the next revision of the file.
      revision: input.revision + 1,
    };
    const tombstones = [...input.file.tombstones, tombstone].slice(-MAX_TOMBSTONES);
    return { kind: "apply", rules, tombstones };
  }

  private applyNeedsReview(
    input: { readonly revision: number; readonly file: ProjectRulesFile },
    ruleId: string,
    updatedAt: string,
  ): ProjectRulesChangeOutcome {
    const index = input.file.rules.findIndex((rule) => rule.id === ruleId);
    if (index < 0) return { kind: "reject", reason: REJECT_NOT_FOUND };
    const rule = input.file.rules[index] as StoredProjectRule;
    if (rule.status === "revoked") return { kind: "reject", reason: REJECT_NOT_FOUND };
    if (rule.status === "needs_review") return { kind: "reject", reason: REJECT_ALREADY_NEEDS_REVIEW };
    const rules = [...input.file.rules];
    rules[index] = { ...rule, status: "needs_review", updatedAt };
    // needs_review never adds a tombstone (spec §7).
    return { kind: "apply", rules, tombstones: input.file.tombstones };
  }

  private async emit(event: ProjectRulesAuditEvent): Promise<void> {
    if (this.auditSink === undefined) return;
    try {
      await this.auditSink(event);
    } catch {
      // Audit failures must never change the file, revision or approval result.
    }
  }
}
