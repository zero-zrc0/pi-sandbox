/**
 * Project rule learning transaction (specs/project-rule-learning.md §3-§9).
 *
 * This module is the only path that turns untrusted model output into durable
 * project rules. It has three seams:
 *
 * - {@link validateLearningAdmission}: a strict, pure capture seam. Only plain
 *   data-own properties cross it, every revision is re-checked, and the result
 *   is a deeply frozen admission.
 * - {@link ProjectRuleLearningService}: pre-commit checks (§4), one atomic store
 *   change with an in-lock re-check (§5), and durable/staleness reporting (§6).
 *   The model never supplies scopes, matches, rule IDs or persisted fields.
 * - {@link wrapLearningApprover}: freezes and validates the review input, calls
 *   the real approver, and commits staged candidates only for legal, model-backed
 *   outcomes (§7). A stale/durable failure never fabricates a verdict; a stale
 *   allow is downgraded to defer instead.
 *
 * The collector and intent barrier are consumed through structural ports so the
 * transaction can be tested with in-memory doubles and still accept the real
 * Phase 9 classes.
 */
import type { LearningCandidate, LearningCandidateCollector, LearningField, StagedLearningData } from "./candidates";
import type { LearningIntentBarrier } from "./barrier";
import { verifyCreateEvidence, verifyRevokeEvidence } from "./evidence";
import { buildExactMatch, exactMatchDigest } from "./match";
import { isSensitiveText, redactSensitiveReason } from "./sensitive";
import type { ProjectRulesService } from "./service";
import type { ProjectRulesChangeOutcome, ProjectRulesCommitGuard, ProjectRulesStore } from "./storage";
import {
  PROJECT_RULES_LIMITS,
  canonicalJson,
  isRuleId,
  ruleIdFor,
  sha256Hex,
  type ActionScope,
  type AuthorizationEntry,
  type EvidenceProposal,
  type ExactAction,
  type ExactActionMatch,
  type ProjectIdentity,
  type ProjectRulesFile,
  type RuleEffect,
  type RuleTombstone,
  type ScopeAccess,
  type StoredProjectRule,
} from "./types";

// ---------------------------------------------------------------------------
// Structural ports for the parallel Phase 9 modules
// ---------------------------------------------------------------------------

/** The collector surface the learning transaction needs. */
export type LearningCollectorPort = Pick<
  LearningCandidateCollector,
  "take" | "currentAttemptId" | "discardAttempt" | "hasStagedData"
>;

/** The barrier surface the learning transaction needs. */
export type LearningBarrierPort = Pick<
  LearningIntentBarrier,
  "revision" | "holdsRevision" | "recordOwnCommit" | "requireReconciliation"
>;

/** Lifecycle fact the restricted policy tools read before staging anything. */
export interface LearningLifecyclePort {
  readonly disposed: boolean;
}

// ---------------------------------------------------------------------------
// Public vocabulary
// ---------------------------------------------------------------------------

export type LearningVerdict = "allow" | "deny" | "defer";

export interface LearningOwners {
  readonly owner: string;
  readonly viewOwner: string;
  readonly revisionOwner: string;
}

export interface LearningMember {
  readonly requestId: string;
  readonly actionDigest: string;
  readonly action: ExactAction;
  readonly verdict: LearningVerdict;
}

/** Frozen, host-verified facts of one learning commit. */
export interface LearningAdmission {
  readonly identity: ProjectIdentity;
  readonly owners: LearningOwners;
  readonly mode: "auto-review";
  readonly judge: string;
  readonly session: string;
  readonly expectedRevision: number;
  readonly projectRulesRevision: number;
  readonly intentRevision: number;
  readonly viewHistoryRevision: number;
  readonly viewCaptureRevision: number;
  readonly dependenciesVerified: boolean;
  readonly members: readonly LearningMember[];
  readonly authorization: readonly AuthorizationEntry[];
  readonly signal: AbortSignal;
  readonly deadline: number;
  readonly batchId?: string;
}

export type LearningAdmissionResult =
  | { readonly ok: true; readonly admission: LearningAdmission }
  | { readonly ok: false; readonly reason: string };

/**
 * One model-proposed create candidate. `scope`/`actionRef` are host-checked
 * transport fields: the match itself is always rebuilt from the captured action.
 */
export interface LearningCreateCandidateValue {
  readonly effect: RuleEffect;
  readonly scope: "exact_action";
  /** `current-action` or the candidate's own request id. */
  readonly actionRef: string;
  readonly sourceEntryId: string;
  readonly quote: string;
  readonly confidence: number;
}

/** One model-proposed revoke candidate; the target rule is host-verified. */
export interface LearningRevokeCandidateValue {
  readonly ruleId: string;
  readonly sourceEntryId: string;
  readonly quote: string;
  readonly confidence: number;
  readonly reason?: string;
}

/** Every candidate/rule rejection and every idempotent duplicate, per attempt. */
export interface LearningRejectionDetail {
  readonly stage: "parse" | "candidate" | "rule" | "duplicate";
  readonly reason: string;
  readonly attemptId?: string;
  readonly requestId?: string;
  readonly field?: LearningField;
  readonly index?: number;
  readonly ruleId?: string;
}

export type LearningFailureCategory =
  | "invalid-admission"
  | "disabled"
  | "disposed"
  | "aborted"
  | "timeout"
  | "dependencies-unverified"
  | "identity-mismatch"
  | "owner-mismatch"
  | "sensitive"
  | "stale"
  | "unavailable"
  | "capacity"
  | "write-failed"
  | "commit-rejected";

export type LearningCommitResult =
  | {
      readonly kind: "committed";
      readonly durable: true;
      readonly revision: number;
      readonly previousRevision: number;
      readonly durableRuleIds: readonly string[];
      readonly revokedRuleIds: readonly string[];
      readonly rejections: readonly LearningRejectionDetail[];
      /** The intent revision and file revision were still current after publish. */
      readonly currentIntentValid: boolean;
      /** A broad create or an invalidated fact requires another reconciliation. */
      readonly needsReconciliation: boolean;
      /** The narrow transaction opened the barrier itself. */
      readonly ownCommitRecorded: boolean;
      readonly intentRevision: number;
    }
  | {
      readonly kind: "no-change";
      readonly durable: false;
      readonly revision: number;
      readonly previousRevision: number;
      readonly rejections: readonly LearningRejectionDetail[];
      readonly currentIntentValid: boolean;
      readonly needsReconciliation: false;
      readonly ownCommitRecorded: false;
      readonly intentRevision: number;
    }
  | {
      readonly kind: "failed";
      readonly durable: false;
      readonly category: LearningFailureCategory;
      readonly reason: string;
      readonly revision?: number;
      readonly currentIntentValid: boolean;
      readonly rejections: readonly LearningRejectionDetail[];
    };

export type LearningAuditEvent =
  | { readonly kind: "rules-committed"; readonly ruleIds: readonly string[]; readonly revision: number }
  | { readonly kind: "write-failed"; readonly ruleIds: readonly string[]; readonly reason: string }
  | { readonly kind: "learning-discarded"; readonly reason: string; readonly ruleIds?: readonly string[] }
  | { readonly kind: "learning-no-change" };

export interface ProjectRuleLearningServiceOptions {
  readonly store: ProjectRulesStore;
  readonly service: ProjectRulesService;
  readonly identity: ProjectIdentity;
  readonly collector: LearningCollectorPort;
  readonly barrier: LearningBarrierPort;
  readonly now: () => Date;
  readonly learningEnabled: () => boolean;
  readonly mode: () => string;
  readonly audit?: (event: LearningAuditEvent) => void | Promise<void>;
  readonly owners?: LearningOwners;
}

const MAX_MEMBERS = PROJECT_RULES_LIMITS.maxCandidates;
const MAX_AUTHORIZATION = PROJECT_RULES_LIMITS.maxCandidates;
const MAX_RULES = PROJECT_RULES_LIMITS.maxRules;
const MAX_TOMBSTONES = PROJECT_RULES_LIMITS.maxTombstones;
const MIN_CONFIDENCE = PROJECT_RULES_LIMITS.minConfidence;
const CURRENT_ACTION_REF = "current-action";
const SUPERSEDED_REASON = "superseded-by-deny";

const ACCESS_VALUES = new Set<ScopeAccess>(["read", "write", "execute", "network", "other"]);
const EVIDENCE_KEYS = ["sourceEntryId", "quote", "confidence"];
const VERDICTS = new Set<LearningVerdict>(["allow", "deny", "defer"]);

// ---------------------------------------------------------------------------
// Strict data readers (§3)
// ---------------------------------------------------------------------------

type DataRecord = Record<string, unknown>;

const NOT_OBJECT = "not-object";

interface ReadResult<T> {
  readonly ok: true;
  readonly value: T;
}
interface ReadFailure {
  readonly ok: false;
  readonly reason: string;
}

function readFailure(reason: string): ReadFailure {
  return { ok: false, reason };
}

function isPlainDataObject(value: unknown): value is DataRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/**
 * Closed-object reader: own data properties only, required keys present, no
 * unknown keys, no symbols and no accessors. Inherited fields never count.
 */
function readClosedObject(
  value: unknown,
  required: readonly string[],
  optional: readonly string[] = [],
): ReadResult<DataRecord> | ReadFailure {
  if (!isPlainDataObject(value)) return readFailure(NOT_OBJECT);
  if (Object.getOwnPropertySymbols(value).length > 0) return readFailure("symbol-property");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const names = Object.keys(descriptors);
  for (const name of names) {
    if (!required.includes(name) && !optional.includes(name)) return readFailure("unknown-field");
    const descriptor = descriptors[name] as PropertyDescriptor;
    if (!("value" in descriptor)) return readFailure("non-data-property");
  }
  for (const name of required) {
    if (!Object.prototype.hasOwnProperty.call(descriptors, name)) return readFailure("missing-field");
  }
  return { ok: true, value };
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function nonNegativeSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isJsonValue(value: unknown, ancestors: Set<object>): boolean {
  if (value === null) return true;
  switch (typeof value) {
    case "string":
    case "boolean":
      return true;
    case "number":
      return Number.isFinite(value);
    case "object": {
      if (ancestors.has(value)) return false;
      ancestors.add(value);
      try {
        if (Array.isArray(value)) return value.every((item) => isJsonValue(item, ancestors));
        if (!isPlainDataObject(value)) return false;
        if (Object.getOwnPropertySymbols(value).length > 0) return false;
        for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) {
          if (!("value" in descriptor)) return false;
          if (!isJsonValue(descriptor.value, ancestors)) return false;
        }
        return true;
      } finally {
        ancestors.delete(value);
      }
    }
    default:
      return false;
  }
}

function isJsonObject(value: unknown): value is DataRecord {
  return isPlainDataObject(value) && isJsonValue(value, new Set());
}

/** Deep copy + freeze of one JSON value; the caller already proved it is JSON. */
function freezeJson(value: unknown): unknown {
  if (value === null) return null;
  switch (typeof value) {
    case "string":
    case "boolean":
      return value;
    case "number":
      return value;
    case "object": {
      if (Array.isArray(value)) return Object.freeze(value.map((item) => freezeJson(item)));
      const record = value as DataRecord;
      const copy: DataRecord = {};
      for (const key of Object.keys(record)) copy[key] = freezeJson(record[key]);
      return Object.freeze(copy);
    }
    default:
      return null;
  }
}

function readToolIdentity(value: unknown): ReadResult<ExactActionMatch["tool"]> | ReadFailure {
  const closed = readClosedObject(value, ["name", "origin", "definitionRevision"]);
  if (!closed.ok) return closed;
  const record = closed.value;
  const name = record.name;
  const origin = record.origin;
  const definitionRevision = record.definitionRevision;
  if (!nonEmptyString(name) || !nonEmptyString(origin) || !nonEmptyString(definitionRevision)) {
    return readFailure("invalid-tool");
  }
  return { ok: true, value: Object.freeze({ name, origin, definitionRevision }) };
}

function readActionScope(value: unknown): ReadResult<ActionScope> | ReadFailure {
  const closed = readClosedObject(value, ["id", "surface", "target", "access"]);
  if (!closed.ok) return closed;
  const record = closed.value;
  const id = record.id;
  const surface = record.surface;
  const target = record.target;
  const access = record.access;
  if (!nonEmptyString(id) || !nonEmptyString(surface) || !nonEmptyString(target)) {
    return readFailure("invalid-action");
  }
  if (typeof access !== "string" || !ACCESS_VALUES.has(access as ScopeAccess)) {
    return readFailure("invalid-action");
  }
  return { ok: true, value: Object.freeze({ id, surface, target, access: access as ScopeAccess }) };
}

function readAction(value: unknown): ReadResult<ExactAction> | ReadFailure {
  const closed = readClosedObject(
    value,
    ["requestId", "tool", "definitionDigest", "arguments", "argumentsDigest", "cwd", "environmentDigest", "scopes"],
    ["hardDeny"],
  );
  if (!closed.ok) return closed;
  const record = closed.value;
  if (!nonEmptyString(record.requestId) || !nonEmptyString(record.definitionDigest) ||
    !nonEmptyString(record.argumentsDigest) || !nonEmptyString(record.cwd) ||
    !nonEmptyString(record.environmentDigest)) {
    return readFailure("invalid-action");
  }
  const tool = readToolIdentity(record.tool);
  if (!tool.ok) return tool;
  if (!isJsonObject(record.arguments)) return readFailure("invalid-action");
  if (!Array.isArray(record.scopes)) return readFailure("invalid-action");
  if (record.hardDeny !== undefined && typeof record.hardDeny !== "boolean") return readFailure("invalid-action");
  const scopes: ActionScope[] = [];
  for (const raw of record.scopes) {
    const parsed = readActionScope(raw);
    if (!parsed.ok) return parsed;
    scopes.push(parsed.value);
  }
  const action: ExactAction = Object.freeze({
    requestId: record.requestId,
    tool: tool.value,
    definitionDigest: record.definitionDigest,
    arguments: freezeJson(record.arguments),
    argumentsDigest: record.argumentsDigest,
    cwd: record.cwd,
    environmentDigest: record.environmentDigest,
    scopes: Object.freeze(scopes),
    ...(record.hardDeny === undefined ? {} : { hardDeny: record.hardDeny }),
  });
  return { ok: true, value: action };
}

export function actionDigestOf(action: ExactAction): string {
  return sha256Hex(canonicalJson(action));
}

function readMember(value: unknown): ReadResult<LearningMember> | ReadFailure {
  const closed = readClosedObject(value, ["requestId", "actionDigest", "action", "verdict"]);
  if (!closed.ok) return closed;
  const record = closed.value;
  if (!nonEmptyString(record.requestId) || !nonEmptyString(record.actionDigest)) {
    return readFailure("invalid-member");
  }
  const action = readAction(record.action);
  if (!action.ok) return action;
  if (action.value.requestId !== record.requestId) return readFailure("request-id-mismatch");
  if (record.actionDigest !== actionDigestOf(action.value)) return readFailure("action-digest-mismatch");
  const verdict = record.verdict;
  if (typeof verdict !== "string" || !VERDICTS.has(verdict as LearningVerdict)) return readFailure("invalid-verdict");
  return {
    ok: true,
    value: Object.freeze({
      requestId: record.requestId,
      actionDigest: record.actionDigest,
      action: action.value,
      verdict: verdict as LearningVerdict,
    }),
  };
}

function readOwners(value: unknown): ReadResult<LearningOwners> | ReadFailure {
  const closed = readClosedObject(value, ["owner", "viewOwner", "revisionOwner"]);
  if (!closed.ok) return closed;
  const record = closed.value;
  if (!nonEmptyString(record.owner) || !nonEmptyString(record.viewOwner) || !nonEmptyString(record.revisionOwner)) {
    return readFailure("invalid-owner");
  }
  return {
    ok: true,
    value: Object.freeze({ owner: record.owner, viewOwner: record.viewOwner, revisionOwner: record.revisionOwner }),
  };
}

function readIdentity(value: unknown): ReadResult<ProjectIdentity> | ReadFailure {
  const closed = readClosedObject(value, ["rootPath", "displayName", "slug", "identityHash"]);
  if (!closed.ok) return closed;
  const record = closed.value;
  if (!nonEmptyString(record.rootPath) || !nonEmptyString(record.displayName) ||
    !nonEmptyString(record.slug) || !nonEmptyString(record.identityHash)) {
    return readFailure("invalid-identity");
  }
  return {
    ok: true,
    value: Object.freeze({
      rootPath: record.rootPath,
      displayName: record.displayName,
      slug: record.slug,
      identityHash: record.identityHash,
    }),
  };
}

function readAuthorization(value: unknown): ReadResult<readonly AuthorizationEntry[]> | ReadFailure {
  if (!Array.isArray(value)) return readFailure("invalid-authorization");
  if (value.length > MAX_AUTHORIZATION) return readFailure("invalid-authorization");
  const entries: AuthorizationEntry[] = [];
  for (const raw of value) {
    const closed = readClosedObject(raw, ["id", "source", "text"]);
    if (!closed.ok) return readFailure("invalid-authorization");
    const record = closed.value;
    if (!nonEmptyString(record.id) || !nonEmptyString(record.text)) return readFailure("invalid-authorization");
    if (record.source !== "user") return readFailure("non-user-authorization");
    entries.push(Object.freeze({ id: record.id, source: "user" as const, text: record.text }));
  }
  return { ok: true, value: Object.freeze(entries) };
}

/**
 * The strict admission seam. Pure and total: every rejection is a stable
 * reason string and no input value is ever mutated, only copied and frozen.
 */
export function validateLearningAdmission(input: unknown): LearningAdmissionResult {
  const closed = readClosedObject(
    input,
    [
      "identity",
      "owners",
      "mode",
      "judge",
      "session",
      "expectedRevision",
      "projectRulesRevision",
      "intentRevision",
      "viewHistoryRevision",
      "viewCaptureRevision",
      "dependenciesVerified",
      "members",
      "authorization",
      "signal",
      "deadline",
    ],
    ["batchId"],
  );
  if (!closed.ok) return readFailure(closed.reason);
  const record = closed.value;

  const identity = readIdentity(record.identity);
  if (!identity.ok) return readFailure(identity.reason);
  const owners = readOwners(record.owners);
  if (!owners.ok) return readFailure(owners.reason);

  if (record.mode !== "auto-review") return readFailure("invalid-mode");
  if (!nonEmptyString(record.judge)) return readFailure("invalid-judge");
  if (!nonEmptyString(record.session)) return readFailure("invalid-session");

  const expectedRevision = record.expectedRevision;
  const projectRulesRevision = record.projectRulesRevision;
  const intentRevision = record.intentRevision;
  const viewHistoryRevision = record.viewHistoryRevision;
  const viewCaptureRevision = record.viewCaptureRevision;
  if (!nonNegativeSafeInteger(expectedRevision) || !nonNegativeSafeInteger(projectRulesRevision) ||
    !nonNegativeSafeInteger(intentRevision)) {
    return readFailure("invalid-revision");
  }
  if (!nonNegativeSafeInteger(viewHistoryRevision) || !nonNegativeSafeInteger(viewCaptureRevision)) {
    return readFailure("invalid-view-revision");
  }
  if (typeof record.dependenciesVerified !== "boolean") return readFailure("invalid-dependencies");

  if (!Array.isArray(record.members)) return readFailure("invalid-members");
  if (record.members.length === 0) return readFailure("invalid-members");
  if (record.members.length > MAX_MEMBERS) return readFailure("too-many-members");
  const members: LearningMember[] = [];
  const requestIds = new Set<string>();
  for (const raw of record.members) {
    const member = readMember(raw);
    if (!member.ok) return readFailure(`member:${member.reason}`);
    if (requestIds.has(member.value.requestId)) return readFailure("duplicate-request-id");
    requestIds.add(member.value.requestId);
    members.push(member.value);
  }

  const authorization = readAuthorization(record.authorization);
  if (!authorization.ok) return readFailure(authorization.reason);

  if (!(record.signal instanceof AbortSignal)) return readFailure("invalid-signal");
  if (typeof record.deadline !== "number" || !Number.isFinite(record.deadline)) {
    return readFailure("invalid-deadline");
  }

  if (record.batchId !== undefined && !nonEmptyString(record.batchId)) return readFailure("invalid-batch-id");

  const admission: LearningAdmission = Object.freeze({
    identity: identity.value,
    owners: owners.value,
    mode: "auto-review" as const,
    judge: record.judge,
    session: record.session,
    expectedRevision,
    projectRulesRevision,
    intentRevision,
    viewHistoryRevision,
    viewCaptureRevision,
    dependenciesVerified: record.dependenciesVerified,
    members: Object.freeze(members),
    authorization: authorization.value,
    signal: record.signal,
    deadline: record.deadline,
    ...(record.batchId === undefined ? {} : { batchId: record.batchId }),
  });
  return { ok: true, admission };
}

// ---------------------------------------------------------------------------
// Candidate readers (§5: every field is re-validated in the transaction)
// ---------------------------------------------------------------------------

function readConfidence(value: unknown): ReadResult<number> | ReadFailure {
  if (typeof value !== "number" || !Number.isFinite(value) || value < MIN_CONFIDENCE || value > 1) {
    return readFailure("invalid-evidence");
  }
  return { ok: true, value };
}

function readEvidenceFields(record: DataRecord): ReadResult<{ sourceEntryId: string; quote: string; confidence: number }> | ReadFailure {
  const sourceEntryId = record.sourceEntryId;
  const quote = record.quote;
  const confidence = readConfidence(record.confidence);
  if (!confidence.ok) return confidence;
  if (!nonEmptyString(sourceEntryId)) return readFailure("invalid-evidence");
  if (!nonEmptyString(quote)) return readFailure("invalid-evidence");
  if (quote.length > PROJECT_RULES_LIMITS.maxQuoteChars) return readFailure("invalid-evidence");
  if (isSensitiveText(quote)) return readFailure("sensitive");
  return { ok: true, value: { sourceEntryId, quote, confidence: confidence.value } };
}

function readCreateValue(value: unknown): ReadResult<LearningCreateCandidateValue> | ReadFailure {
  const closed = readClosedObject(value, ["effect", "scope", "actionRef", ...EVIDENCE_KEYS]);
  if (!closed.ok) return readFailure(closed.reason === NOT_OBJECT ? "invalid-candidate" : closed.reason);
  const record = closed.value;
  if (record.effect !== "allow" && record.effect !== "deny") return readFailure("invalid-effect");
  if (record.scope !== CURRENT_ACTION_REF && record.scope !== "exact_action") return readFailure("invalid-scope");
  if (!nonEmptyString(record.actionRef)) return readFailure("invalid-action-ref");
  const evidence = readEvidenceFields(record);
  if (!evidence.ok) return evidence;
  return {
    ok: true,
    value: {
      effect: record.effect,
      scope: "exact_action",
      actionRef: record.actionRef,
      ...evidence.value,
    },
  };
}

function readRevokeValue(value: unknown): ReadResult<LearningRevokeCandidateValue> | ReadFailure {
  const closed = readClosedObject(value, ["ruleId", ...EVIDENCE_KEYS], ["reason"]);
  if (!closed.ok) return readFailure(closed.reason === NOT_OBJECT ? "invalid-candidate" : closed.reason);
  const record = closed.value;
  if (!isRuleId(record.ruleId)) return readFailure("invalid-rule-id");
  if (record.reason !== undefined && typeof record.reason !== "string") return readFailure("invalid-candidate");
  const evidence = readEvidenceFields(record);
  if (!evidence.ok) return evidence;
  return {
    ok: true,
    value: {
      ruleId: record.ruleId,
      ...evidence.value,
      ...(record.reason === undefined ? {} : { reason: record.reason }),
    },
  };
}

function readRuleIdOf(value: unknown): string | undefined {
  if (!isPlainDataObject(value)) return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(value, "ruleId");
  if (descriptor === undefined || !("value" in descriptor)) return undefined;
  return isRuleId(descriptor.value) ? descriptor.value : undefined;
}

// ---------------------------------------------------------------------------
// Transaction (§5)
// ---------------------------------------------------------------------------

interface TransactionInput {
  readonly admission: LearningAdmission;
  readonly file: ProjectRulesFile;
  readonly candidates: readonly LearningCandidate[];
  readonly timestamp: string;
  /** Host-verified actor persisted on provenance and revocations. */
  readonly actor: string;
}

interface TransactionOutput {
  readonly applied: boolean;
  readonly failure?: "capacity";
  readonly rules: readonly StoredProjectRule[];
  readonly tombstones: readonly RuleTombstone[];
  readonly durableRuleIds: readonly string[];
  readonly revokedRuleIds: readonly string[];
  readonly broadCreate: boolean;
  readonly rejections: readonly LearningRejectionDetail[];
}

function rejection(
  stage: LearningRejectionDetail["stage"],
  reason: string,
  context: { readonly requestId?: string; readonly field?: LearningField; readonly index?: number; readonly ruleId?: string },
): LearningRejectionDetail {
  return {
    stage,
    reason,
    ...(context.requestId === undefined ? {} : { requestId: context.requestId }),
    ...(context.field === undefined ? {} : { field: context.field }),
    ...(context.index === undefined ? {} : { index: context.index }),
    ...(context.ruleId === undefined ? {} : { ruleId: context.ruleId }),
  };
}

function proposalFor(admission: LearningAdmission, value: { sourceEntryId: string; quote: string; confidence: number }): EvidenceProposal {
  return {
    sourceEntryId: value.sourceEntryId,
    quote: value.quote,
    confidence: value.confidence,
    judge: admission.judge,
    sessionId: admission.session,
    actor: admission.owners.owner,
  };
}

/**
 * Build the whole learning change against one loaded file. Pure: the file is
 * never mutated, revokes run before creates, deny candidates run before allow
 * candidates, and any capacity violation makes the whole change fail. Only
 * durable effects are reported; duplicates and rejections are diagnostics.
 */
function runTransaction(input: TransactionInput): TransactionOutput {
  const rejections: LearningRejectionDetail[] = [];
  const durableRuleIds: string[] = [];
  const revokedRuleIds: string[] = [];
  const nextRevision = input.file.revision + 1;
  const actor = input.actor;
  const admission = input.admission;
  const batch = admission.members.map((member) => member.action);
  let rules: StoredProjectRule[] = [...input.file.rules];
  let tombstones: RuleTombstone[] = [...input.file.tombstones];
  let broadCreate = false;

  const memberOf = (requestId: string): LearningMember | undefined =>
    admission.members.find((member) => member.requestId === requestId);

  /**
   * A revoke candidate may be staged by the restricted policy tool under its
   * own tool-call request id, which is not necessarily a reviewed action id. A
   * single-action review supplies the action (target proof and batch) for it;
   * a batch keeps the strict per-request binding.
   */
  const actionContextFor = (requestId: string): LearningMember | undefined =>
    memberOf(requestId) ?? (admission.members.length === 1 ? admission.members[0] : undefined);

  // 1. Revokes first so a same-transaction create can never be revoked at once.
  for (const candidate of input.candidates) {
    if (candidate.field !== "revoke") continue;
    const parsed = readRevokeValue(candidate.value);
    if (!parsed.ok) {
      rejections.push(rejection("candidate", parsed.reason, {
        requestId: candidate.requestId,
        field: "revoke",
        index: candidate.index,
      }));
      continue;
    }
    const value = parsed.value;
    const member = actionContextFor(candidate.requestId);
    if (member === undefined) {
      rejections.push(rejection("rule", "unknown-request-id", {
        requestId: candidate.requestId,
        field: "revoke",
        index: candidate.index,
        ruleId: value.ruleId,
      }));
      continue;
    }
    const target = rules.find((rule) => rule.id === value.ruleId);
    if (target === undefined) {
      rejections.push(rejection("rule", "unknown-rule", {
        requestId: candidate.requestId,
        field: "revoke",
        index: candidate.index,
        ruleId: value.ruleId,
      }));
      continue;
    }
    if (target.status === "revoked" || target.revocation !== undefined) {
      rejections.push(rejection("duplicate", "already-revoked", {
        requestId: candidate.requestId,
        field: "revoke",
        index: candidate.index,
        ruleId: value.ruleId,
      }));
      continue;
    }
    const verified = verifyRevokeEvidence({
      action: member.action,
      batch,
      authorization: admission.authorization,
      proposal: proposalFor(admission, value),
      rules,
      targetRuleId: value.ruleId,
    });
    if (!verified.ok) {
      rejections.push(rejection("rule", `evidence-${verified.reason}`, {
        requestId: candidate.requestId,
        field: "revoke",
        index: candidate.index,
        ruleId: value.ruleId,
      }));
      continue;
    }
    const targetRule = rules.find((rule) => rule.id === verified.targetRuleId);
    if (targetRule === undefined) continue;
    const reason = value.reason === undefined ? undefined : redactSensitiveReason(value.reason);
    const revocation = reason === undefined
      ? { revokedAt: input.timestamp, actor }
      : { revokedAt: input.timestamp, actor, reason };
    const targetId = targetRule.id;
    rules = rules.map((rule) => rule.id === targetId
      ? { ...rule, status: "revoked" as const, updatedAt: input.timestamp, revocation }
      : rule);
    tombstones = [
      ...tombstones,
      {
        ruleId: targetId,
        effect: targetRule.effect,
        matchDigest: exactMatchDigest(targetRule.match),
        revokedAt: input.timestamp,
        revision: nextRevision,
      },
    ];
    revokedRuleIds.push(targetId);
  }

  // 2. Creates: deny candidates first, then allow candidates.
  type CreateEntry = { readonly candidate: LearningCandidate; readonly parsed: ReadResult<LearningCreateCandidateValue> | ReadFailure };
  const createOrder: CreateEntry[] = [];
  for (const candidate of input.candidates) {
    if (candidate.field !== "create") continue;
    createOrder.push({ candidate, parsed: readCreateValue(candidate.value) });
  }
  const rank = (entry: CreateEntry): number => {
    if (!entry.parsed.ok) return 2;
    return entry.parsed.value.effect === "deny" ? 0 : 1;
  };
  createOrder.sort((left, right) => rank(left) - rank(right) ||
    left.candidate.index - right.candidate.index);

  for (const { candidate, parsed } of createOrder) {
    if (!parsed.ok) {
      rejections.push(rejection("candidate", parsed.reason, {
        requestId: candidate.requestId,
        field: "create",
        index: candidate.index,
      }));
      continue;
    }
    const value = parsed.value;
    const member = memberOf(candidate.requestId);
    if (member === undefined) {
      rejections.push(rejection("rule", "unknown-request-id", {
        requestId: candidate.requestId,
        field: "create",
        index: candidate.index,
      }));
      continue;
    }
    if (value.scope !== "exact_action") {
      rejections.push(rejection("candidate", "invalid-scope", {
        requestId: candidate.requestId,
        field: "create",
        index: candidate.index,
      }));
      continue;
    }
    if (value.actionRef !== CURRENT_ACTION_REF && value.actionRef !== member.requestId) {
      rejections.push(rejection("candidate", "invalid-action-ref", {
        requestId: candidate.requestId,
        field: "create",
        index: candidate.index,
      }));
      continue;
    }
    if (value.effect === "allow" && member.verdict !== "allow") {
      rejections.push(rejection("rule", "verdict-not-allow", {
        requestId: candidate.requestId,
        field: "create",
        index: candidate.index,
      }));
      continue;
    }
    if (value.effect === "deny" && member.verdict === "defer") {
      rejections.push(rejection("rule", "verdict-defer", {
        requestId: candidate.requestId,
        field: "create",
        index: candidate.index,
      }));
      continue;
    }
    const verified = verifyCreateEvidence({
      action: member.action,
      batch,
      authorization: admission.authorization,
      proposal: proposalFor(admission, value),
      effect: value.effect,
    });
    if (!verified.ok) {
      rejections.push(rejection("rule", `evidence-${verified.reason}`, {
        requestId: candidate.requestId,
        field: "create",
        index: candidate.index,
      }));
      continue;
    }
    // The match is always rebuilt from the host's current action.
    const match = buildExactMatch(member.action);
    if (match === undefined) {
      rejections.push(rejection("rule", "unlearnable", {
        requestId: candidate.requestId,
        field: "create",
        index: candidate.index,
      }));
      continue;
    }
    if (match.argumentsDigest !== sha256Hex(canonicalJson(match.arguments))) {
      rejections.push(rejection("rule", "invalid-action", {
        requestId: candidate.requestId,
        field: "create",
        index: candidate.index,
      }));
      continue;
    }
    const matchDigest = exactMatchDigest(match);
    const ruleId = ruleIdFor({
      effect: value.effect,
      matchDigest,
      sourceEntryId: value.sourceEntryId,
      sessionId: admission.session,
    });
    if (tombstones.some((item) => item.ruleId === ruleId)) {
      rejections.push(rejection("rule", "tombstoned", {
        requestId: candidate.requestId,
        field: "create",
        index: candidate.index,
        ruleId,
      }));
      continue;
    }
    const existing = rules.find((rule) => rule.id === ruleId);
    if (existing !== undefined) {
      if (existing.status === "active") {
        rejections.push(rejection("duplicate", "duplicate-rule", {
          requestId: candidate.requestId,
          field: "create",
          index: candidate.index,
          ruleId,
        }));
      } else if (existing.status === "needs_review") {
        rejections.push(rejection("rule", "needs-review", {
          requestId: candidate.requestId,
          field: "create",
          index: candidate.index,
          ruleId,
        }));
      } else {
        rejections.push(rejection("rule", "tombstoned", {
          requestId: candidate.requestId,
          field: "create",
          index: candidate.index,
          ruleId,
        }));
      }
      continue;
    }
    if (rules.some((rule) => rule.status === "active" && rule.effect === value.effect &&
      exactMatchDigest(rule.match) === matchDigest)) {
      rejections.push(rejection("duplicate", "duplicate-match", {
        requestId: candidate.requestId,
        field: "create",
        index: candidate.index,
        ruleId,
      }));
      continue;
    }
    if (value.effect === "allow") {
      const activeDeny = rules.some((rule) => rule.status === "active" && rule.effect === "deny" &&
        exactMatchDigest(rule.match) === matchDigest);
      if (activeDeny) {
        rejections.push(rejection("rule", "conflict-with-deny", {
          requestId: candidate.requestId,
          field: "create",
          index: candidate.index,
          ruleId,
        }));
        continue;
      }
    } else {
      // A new deny supersedes every active allow with the same match.
      for (const target of rules.filter((rule) => rule.status === "active" && rule.effect === "allow" &&
        exactMatchDigest(rule.match) === matchDigest)) {
        const revocation = { revokedAt: input.timestamp, actor, reason: SUPERSEDED_REASON };
        const targetId = target.id;
        rules = rules.map((rule) => rule.id === targetId
          ? { ...rule, status: "revoked" as const, updatedAt: input.timestamp, revocation }
          : rule);
        tombstones = [
          ...tombstones,
          {
            ruleId: targetId,
            effect: target.effect,
            matchDigest: exactMatchDigest(target.match),
            revokedAt: input.timestamp,
            revision: nextRevision,
          },
        ];
        revokedRuleIds.push(targetId);
      }
    }
    const rule: StoredProjectRule = {
      id: ruleId,
      effect: value.effect,
      status: "active",
      match,
      provenance: {
        sessionId: admission.session,
        sourceEntryId: value.sourceEntryId,
        quote: value.quote,
        confidence: value.confidence,
        judge: admission.judge,
        actor,
      },
      createdAt: input.timestamp,
      updatedAt: input.timestamp,
    };
    rules = [...rules, rule];
    durableRuleIds.push(ruleId);
    if (verified.classification.broad) broadCreate = true;
  }

  if (rules.length > MAX_RULES) {
    return {
      applied: false,
      failure: "capacity",
      rules: input.file.rules,
      tombstones: input.file.tombstones,
      durableRuleIds: [],
      revokedRuleIds: [],
      broadCreate: false,
      rejections,
    };
  }
  if (tombstones.length > MAX_TOMBSTONES) tombstones = tombstones.slice(-MAX_TOMBSTONES);
  if (durableRuleIds.length === 0 && revokedRuleIds.length === 0) {
    return {
      applied: false,
      rules: input.file.rules,
      tombstones: input.file.tombstones,
      durableRuleIds: [],
      revokedRuleIds: [],
      broadCreate: false,
      rejections,
    };
  }
  return {
    applied: true,
    rules: Object.freeze(rules),
    tombstones: Object.freeze(tombstones),
    durableRuleIds: Object.freeze(durableRuleIds),
    revokedRuleIds: Object.freeze(revokedRuleIds),
    broadCreate,
    rejections: Object.freeze(rejections),
  };
}

// ---------------------------------------------------------------------------
// Service (§4-§6)
// ---------------------------------------------------------------------------

interface PrecheckFailure {
  readonly kind: "fail";
  readonly category: LearningFailureCategory;
  readonly reason: string;
  readonly currentIntentValid: boolean;
}

interface PrecheckSuccess {
  readonly kind: "ok";
  readonly revision: number;
}

const REJECT_CATEGORIES: Readonly<Record<string, LearningFailureCategory>> = Object.freeze({
  "stale-intent": "stale",
  "stale-revision": "stale",
  disabled: "disabled",
  disposed: "disposed",
  aborted: "aborted",
  timeout: "timeout",
  sensitive: "sensitive",
  "dependencies-unverified": "dependencies-unverified",
  "identity-mismatch": "identity-mismatch",
  "owner-mismatch": "owner-mismatch",
  capacity: "capacity",
});

function sameIdentity(left: ProjectIdentity, right: ProjectIdentity): boolean {
  return left.rootPath === right.rootPath && left.displayName === right.displayName &&
    left.slug === right.slug && left.identityHash === right.identityHash;
}

function sameOwners(left: LearningOwners, right: LearningOwners): boolean {
  return left.owner === right.owner && left.viewOwner === right.viewOwner &&
    left.revisionOwner === right.revisionOwner;
}

function toRejectionDetails(rejections: readonly import("./candidates").LearningRejection[]): LearningRejectionDetail[] {
  return rejections.map((item) => ({
    stage: "parse" as const,
    reason: item.reason,
    attemptId: item.attemptId,
    requestId: item.requestId,
    ...(item.field === undefined ? {} : { field: item.field }),
    ...(item.index === undefined ? {} : { index: item.index }),
  }));
}

function stageFromOutcome(outcome: TransactionOutput): LearningCommitResult["rejections"] {
  return [...outcome.rejections];
}

/**
 * The learning transaction owner. One instance per project; `commit` is the
 * only durable entry point and every failure is reported as a stable category.
 */
export class ProjectRuleLearningService {
  private readonly store: ProjectRulesStore;
  private readonly rulesService: ProjectRulesService;
  private readonly identity: ProjectIdentity;
  private readonly collector: LearningCollectorPort;
  private readonly barrier: LearningBarrierPort;
  private readonly now: () => Date;
  private readonly learningEnabledSink: () => boolean;
  private readonly modeSink: () => string;
  private readonly auditSink: ((event: LearningAuditEvent) => void | Promise<void>) | undefined;
  private readonly owners: LearningOwners | undefined;
  private readonly lifecycle = new AbortController();
  private disposedState = false;

  constructor(options: ProjectRuleLearningServiceOptions) {
    this.store = options.store;
    this.rulesService = options.service;
    this.identity = options.identity;
    this.collector = options.collector;
    this.barrier = options.barrier;
    this.now = options.now;
    this.learningEnabledSink = options.learningEnabled;
    this.modeSink = options.mode;
    this.auditSink = options.audit;
    this.owners = options.owners;
  }

  get disposed(): boolean {
    return this.disposedState;
  }

  /** Idempotent shutdown: no later commit may start or publish. */
  dispose(): void {
    if (this.disposedState) return;
    this.disposedState = true;
    this.lifecycle.abort();
  }

  async commit(admissionInput: unknown, attemptId?: string): Promise<LearningCommitResult> {
    const validated = validateLearningAdmission(admissionInput);
    if (!validated.ok) {
      this.discardAttempt(attemptId ?? this.collector.currentAttemptId());
      await this.emit({ kind: "learning-discarded", reason: "invalid-admission" });
      return {
        kind: "failed",
        durable: false,
        category: "invalid-admission",
        reason: validated.reason,
        currentIntentValid: false,
        rejections: [],
      };
    }
    const admission = validated.admission;
    const attempt = attemptId ?? this.collector.currentAttemptId();

    const precheck = await this.precheck(admission);
    if (precheck.kind === "fail") {
      this.discardAttempt(attempt);
      await this.emit({ kind: "learning-discarded", reason: precheck.category });
      return {
        kind: "failed",
        durable: false,
        category: precheck.category,
        reason: precheck.reason,
        currentIntentValid: precheck.currentIntentValid,
        rejections: [],
      };
    }

    const requestIds = admission.members.map((member) => member.requestId);
    const staged: StagedLearningData = attempt === undefined
      ? { candidates: [], rejections: [] }
      : this.collector.take(attempt, requestIds);
    const parseRejections = toRejectionDetails(staged.rejections);

    if (staged.candidates.length === 0) {
      this.discardAttempt(attempt);
      await this.emit({ kind: "learning-no-change" });
      const intentRevision = this.barrier.revision;
      return {
        kind: "no-change",
        durable: false,
        revision: precheck.revision,
        previousRevision: precheck.revision,
        rejections: parseRejections,
        currentIntentValid: intentRevision === admission.intentRevision,
        needsReconciliation: false,
        ownCommitRecorded: false,
        intentRevision,
      };
    }

    const revokeTargets = staged.candidates
      .filter((candidate) => candidate.field === "revoke")
      .map((candidate) => readRuleIdOf(candidate.value))
      .filter((ruleId): ruleId is string => ruleId !== undefined);

    let transaction: TransactionOutput | undefined;
    const guard: ProjectRulesCommitGuard = this.barrier.holdsRevision(admission.intentRevision);
    const commitResult = await this.store.commit({
      apply: (changeInput): ProjectRulesChangeOutcome => {
        const rejected = this.recheckTransaction(admission, changeInput.revision);
        if (rejected !== undefined) return { kind: "reject", reason: rejected };
        const outcome = runTransaction({
          admission,
          file: changeInput.file,
          candidates: staged.candidates,
          timestamp: this.now().toISOString(),
          actor: admission.owners.owner,
        });
        transaction = outcome;
        if (outcome.failure !== undefined) return { kind: "reject", reason: outcome.failure };
        if (!outcome.applied) return { kind: "no-change" };
        return { kind: "apply", rules: outcome.rules, tombstones: outcome.tombstones };
      },
    }, admission.expectedRevision, guard);

    const rejections = [...parseRejections, ...(transaction === undefined ? [] : stageFromOutcome(transaction))];
    const intentRevision = this.barrier.revision;

    switch (commitResult.kind) {
      case "committed": {
        const durableRuleIds = transaction?.durableRuleIds ?? [];
        const revokedRuleIds = transaction?.revokedRuleIds ?? [];
        this.clearSuspensions(revokedRuleIds);
        await this.emit({
          kind: "rules-committed",
          ruleIds: [...durableRuleIds, ...revokedRuleIds],
          revision: commitResult.revision,
        });
        const reloaded = await this.store.load();
        const fileRevision = reloaded.kind === "available"
          ? reloaded.file.revision
          : reloaded.kind === "missing"
            ? 0
            : undefined;
        const currentIntentValid = fileRevision !== undefined &&
          fileRevision === commitResult.revision &&
          this.barrier.revision === admission.intentRevision;
        let needsReconciliation = (transaction?.broadCreate ?? false) || !currentIntentValid;
        let ownCommitRecorded = false;
        if (!needsReconciliation) {
          const activeIds = reloaded.kind === "available"
            ? reloaded.file.rules.filter((rule) => rule.status === "active").map((rule) => rule.id)
            : [];
          const created = new Set(durableRuleIds);
          const narrow = activeIds.every((id) => created.has(id));
          if (narrow) {
            ownCommitRecorded = this.barrier.recordOwnCommit();
            if (!ownCommitRecorded) needsReconciliation = true;
          } else {
            needsReconciliation = true;
          }
        }
        if (needsReconciliation) this.barrier.requireReconciliation();
        return {
          kind: "committed",
          durable: true,
          revision: commitResult.revision,
          previousRevision: commitResult.previousRevision,
          durableRuleIds,
          revokedRuleIds,
          rejections,
          currentIntentValid,
          needsReconciliation,
          ownCommitRecorded,
          intentRevision: this.barrier.revision,
        };
      }
      case "no-change":
        return {
          kind: "no-change",
          durable: false,
          revision: commitResult.revision,
          previousRevision: commitResult.revision,
          rejections,
          currentIntentValid: intentRevision === admission.intentRevision,
          needsReconciliation: false,
          ownCommitRecorded: false,
          intentRevision,
        };
      case "rejected": {
        const category = REJECT_CATEGORIES[commitResult.reason] ?? "commit-rejected";
        return this.failWith(category, commitResult.reason, revokeTargets, commitResult.revision, admission, rejections);
      }
      case "revision-conflict":
        return this.failWith("stale", "revision-changed", revokeTargets, commitResult.revision, admission, rejections);
      case "stale-guard":
        return this.failWith("stale", "intent-changed", revokeTargets, commitResult.revision, admission, rejections);
      case "unavailable":
        return this.failWith("unavailable", commitResult.category, revokeTargets, undefined, admission, rejections);
      case "failed":
        return this.failWith("write-failed", commitResult.category, revokeTargets, undefined, admission, rejections);
    }
  }

  // -------------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------------

  private async precheck(admission: LearningAdmission): Promise<PrecheckFailure | PrecheckSuccess> {
    const failure = (category: LearningFailureCategory, reason: string, currentIntentValid: boolean): PrecheckFailure =>
      ({ kind: "fail", category, reason, currentIntentValid });

    if (this.disposedState || this.lifecycle.signal.aborted) return failure("disposed", "disposed", false);
    if (admission.signal.aborted) return failure("aborted", "aborted", false);
    if (this.now().getTime() > admission.deadline) return failure("timeout", "deadline", false);
    if (!this.learningEnabledSink()) return failure("disabled", "learning-disabled", true);
    if (this.modeSink() !== "auto-review") return failure("disabled", "mode", true);
    if (!admission.dependenciesVerified) return failure("dependencies-unverified", "dependencies", true);
    if (!sameIdentity(admission.identity, this.identity)) return failure("identity-mismatch", "identity", false);
    if (this.owners !== undefined && !sameOwners(admission.owners, this.owners)) {
      return failure("owner-mismatch", "owners", false);
    }
    if (isSensitiveText(admission.judge) || isSensitiveText(admission.session)) {
      return failure("sensitive", "sensitive", true);
    }

    const loaded = await this.store.load();
    if (loaded.kind === "unavailable") return failure("unavailable", loaded.category, false);
    const revision = loaded.kind === "missing" ? 0 : loaded.file.revision;
    if (admission.expectedRevision !== revision || admission.projectRulesRevision !== revision) {
      return failure("stale", "revision-changed", false);
    }
    if (admission.intentRevision !== this.barrier.revision) return failure("stale", "intent-changed", false);
    return { kind: "ok", revision };
  }

  /** Re-checked inside the store's lock, right before the change is built. */
  private recheckTransaction(admission: LearningAdmission, currentRevision: number): string | undefined {
    if (this.disposedState || this.lifecycle.signal.aborted) return "disposed";
    if (admission.signal.aborted) return "aborted";
    if (this.now().getTime() > admission.deadline) return "timeout";
    if (!this.learningEnabledSink()) return "disabled";
    if (this.modeSink() !== "auto-review") return "disabled";
    if (!admission.dependenciesVerified) return "dependencies-unverified";
    if (!sameIdentity(admission.identity, this.identity)) return "identity-mismatch";
    if (this.owners !== undefined && !sameOwners(admission.owners, this.owners)) return "owner-mismatch";
    if (isSensitiveText(admission.judge) || isSensitiveText(admission.session)) return "sensitive";
    if (currentRevision !== admission.expectedRevision || currentRevision !== admission.projectRulesRevision) {
      return "stale-revision";
    }
    if (this.barrier.revision !== admission.intentRevision) return "stale-intent";
    return undefined;
  }

  private failureResult(
    category: LearningFailureCategory,
    reason: string,
    revision: number | undefined,
    admission: LearningAdmission,
    rejections: readonly LearningRejectionDetail[],
  ): LearningCommitResult {
    const intentRevision = this.barrier.revision;
    const currentIntentValid = category === "stale" || category === "disposed"
      ? false
      : intentRevision === admission.intentRevision;
    return {
      kind: "failed",
      durable: false,
      category,
      reason,
      ...(revision === undefined ? {} : { revision }),
      currentIntentValid,
      rejections,
    };
  }

  private async failWith(
    category: LearningFailureCategory,
    reason: string,
    revokeTargets: readonly string[],
    revision: number | undefined,
    admission: LearningAdmission,
    rejections: readonly LearningRejectionDetail[],
  ): Promise<LearningCommitResult> {
    // A failed revoke must never leave an old allow usable (spec §6).
    if (revokeTargets.length > 0) this.rulesService.suspendRuleIds(revokeTargets);
    const wroteNothing = category === "write-failed" || category === "unavailable" ||
      category === "commit-rejected";
    if (wroteNothing) {
      await this.emit({ kind: "write-failed", ruleIds: revokeTargets, reason: category });
    } else {
      await this.emit({ kind: "learning-discarded", reason: category, ruleIds: revokeTargets });
    }
    return this.failureResult(category, reason, revision, admission, rejections);
  }

  /**
   * The service exposes no public unsuspend seam today; a duck-typed optional
   * method keeps committed revokes from leaving stale write-failed suspensions.
   */
  private clearSuspensions(ruleIds: readonly string[]): void {
    if (ruleIds.length === 0) return;
    const port = this.rulesService as ProjectRulesService & {
      clearRuleSuspension?: (ids: readonly string[]) => void;
    };
    if (typeof port.clearRuleSuspension === "function") port.clearRuleSuspension(ruleIds);
  }

  private discardAttempt(attemptId: string | undefined): void {
    if (attemptId === undefined) return;
    this.collector.discardAttempt(attemptId);
  }

  private async emit(event: LearningAuditEvent): Promise<void> {
    if (this.auditSink === undefined) return;
    try {
      await this.auditSink(event);
    } catch {
      // Audit failures must never change the durable outcome.
    }
  }
}

// ---------------------------------------------------------------------------
// Learning approver wrapper (§7)
// ---------------------------------------------------------------------------

export interface LearningReviewMember {
  readonly requestId: string;
  readonly actionDigest: string;
  readonly action: ExactAction;
}

/** Admission facts minus the per-member verdicts, which only the approver knows. */
export type LearningAdmissionFacts = Omit<LearningAdmission, "members" | "mode">;

export interface LearningReviewInput {
  readonly members: readonly LearningReviewMember[];
  readonly admission: LearningAdmissionFacts;
  readonly attemptId?: string;
}

/** One verdict as the real approver reports it; only host verdicts may learn. */
export interface LearningApproverUnit {
  readonly requestId: string;
  readonly actionDigest: string;
  readonly verdict: string;
  readonly source?: string;
  readonly modelRequestCount?: number;
  /** Set on a defer: known technical categories are never learnable. */
  readonly deferCategory?: string;
}

export interface LearningApproverResult {
  readonly source?: string;
  readonly modelRequestCount?: number;
  readonly members: readonly LearningApproverUnit[];
}

export type LearningCommitPort = Pick<ProjectRuleLearningService, "commit">;

export interface LearningApproverWrapperOptions {
  readonly inner: (input: unknown) => Promise<unknown>;
  readonly learning: LearningCommitPort;
  readonly collector: LearningCollectorPort;
  readonly mode: () => string;
  readonly learningEnabled: () => boolean;
}

/** The wrapped approver also exposes an idempotent lifecycle cleanup. */
export interface WrappedLearningApprover {
  (input: unknown): Promise<unknown>;
  dispose(): void;
}

/** Technical defer categories: model non-answers that never prove user intent. */
export const LEARNING_TECHNICAL_DEFER_CATEGORIES: ReadonlySet<string> = Object.freeze(new Set([
  "transport",
  "capacity",
  "invalid-response",
  "identity-mismatch",
  "cancelled",
  "timeout",
  "queue",
  "model-unavailable",
  "project-rules-unavailable",
]));

interface NormalizedUnit {
  readonly requestId: string;
  readonly actionDigest: string;
  readonly verdict: string;
  readonly source: string | undefined;
  readonly modelRequestCount: number | undefined;
  readonly deferCategory: string | undefined;
}

function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function cloneFreeze(value: unknown, ancestors: Set<object>): unknown {
  if (value === null) return null;
  switch (typeof value) {
    case "string":
    case "boolean":
    case "number":
      return value;
    case "object": {
      if (ancestors.has(value)) throw new Error("cycle");
      ancestors.add(value);
      try {
        if (Array.isArray(value)) return Object.freeze(value.map((item) => cloneFreeze(item, ancestors)));
        if (!isPlainDataObject(value)) return value;
        const copy: DataRecord = {};
        for (const key of Object.keys(value)) copy[key] = cloneFreeze(value[key], ancestors);
        return Object.freeze(copy);
      } finally {
        ancestors.delete(value);
      }
    }
    default:
      return value;
  }
}

function freezeReviewInput(input: unknown): unknown {
  try {
    return cloneFreeze(input, new Set());
  } catch {
    return input;
  }
}

function peekAttemptId(input: unknown): string | undefined {
  if (!isPlainDataObject(input)) return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(input, "attemptId");
  if (descriptor === undefined || !("value" in descriptor)) return undefined;
  return nonEmptyString(descriptor.value) ? descriptor.value : undefined;
}

interface ReadReviewInputSuccess {
  readonly ok: true;
  readonly members: readonly LearningReviewMember[];
  readonly admission: LearningAdmissionFacts;
}

function readReviewInput(input: unknown): ReadReviewInputSuccess | { readonly ok: false } {
  const closed = readClosedObject(input, ["members", "admission"], ["attemptId"]);
  if (!closed.ok) return { ok: false };
  const record = closed.value;
  if (!Array.isArray(record.members) || record.members.length === 0) return { ok: false };
  const members: LearningReviewMember[] = [];
  for (const raw of record.members) {
    const member = readClosedObject(raw, ["requestId", "actionDigest", "action"]);
    if (!member.ok) return { ok: false };
    const value = member.value;
    if (!nonEmptyString(value.requestId) || !nonEmptyString(value.actionDigest)) return { ok: false };
    const action = readAction(value.action);
    if (!action.ok) return { ok: false };
    members.push({
      requestId: value.requestId,
      actionDigest: value.actionDigest,
      action: action.value,
    });
  }
  if (!isPlainDataObject(record.admission)) return { ok: false };
  const provisional = validateLearningAdmission({
    ...record.admission,
    mode: "auto-review",
    members: members.map((member) => ({ ...member, verdict: "defer" as const })),
  });
  if (!provisional.ok) return { ok: false };
  const { members: _members, mode: _mode, ...facts } = provisional.admission;
  return { ok: true, members: Object.freeze(members), admission: Object.freeze(facts) };
}

function readApproverUnit(value: unknown): LearningApproverUnit | undefined {
  if (!isPlainDataObject(value)) return undefined;
  const requestId = value.requestId;
  const actionDigest = value.actionDigest;
  const verdict = value.verdict;
  if (!nonEmptyString(requestId) || !nonEmptyString(actionDigest) || typeof verdict !== "string") return undefined;
  return {
    requestId,
    actionDigest,
    verdict,
    ...(nonEmptyString(value.source) ? { source: value.source } : {}),
    ...(typeof value.modelRequestCount === "number" ? { modelRequestCount: value.modelRequestCount } : {}),
    ...(nonEmptyString(value.deferCategory) ? { deferCategory: value.deferCategory } : {}),
  };
}

/**
 * Normalize the real approver's outcome. Both a batch envelope (`members`) and a
 * single top-level verdict are accepted so a single-request approver can stay
 * simple; anything else means the wrapper cannot learn.
 */
function normalizeApproverResult(result: unknown, members: readonly LearningReviewMember[]): NormalizedUnit[] | undefined {
  if (!isPlainDataObject(result)) return undefined;
  const topSource = nonEmptyString(result.source) ? result.source : undefined;
  const topCount = typeof result.modelRequestCount === "number" ? result.modelRequestCount : undefined;
  if (Array.isArray(result.members)) {
    const units: NormalizedUnit[] = [];
    for (const raw of result.members) {
      const unit = readApproverUnit(raw);
      if (unit === undefined) return undefined;
      units.push({
        requestId: unit.requestId,
        actionDigest: unit.actionDigest,
        verdict: unit.verdict,
        source: unit.source ?? topSource,
        modelRequestCount: unit.modelRequestCount ?? topCount,
        deferCategory: unit.deferCategory,
      });
    }
    return units;
  }
  if (typeof result.verdict === "string" && members.length === 1) {
    const only = members[0] as LearningReviewMember;
    return [{
      requestId: only.requestId,
      actionDigest: only.actionDigest,
      verdict: result.verdict,
      source: topSource,
      modelRequestCount: topCount,
      deferCategory: nonEmptyString(result.deferCategory) ? result.deferCategory : undefined,
    }];
  }
  return undefined;
}

function unitIsLearnable(unit: NormalizedUnit, collector: LearningCollectorPort, attempt: string | undefined): boolean {
  // Only a real model-backed verdict can prove user intent, for every outcome.
  if (unit.source !== "approver" || !isPositiveSafeInteger(unit.modelRequestCount)) return false;
  if (unit.verdict === "allow" || unit.verdict === "deny") return true;
  if (unit.verdict === "defer") {
    // A technical defer never proves intent; a non-technical one only counts
    // when candidates were actually staged.
    if (unit.deferCategory !== undefined) return false;
    return attempt !== undefined && collector.hasStagedData(attempt);
  }
  return false;
}

interface LearningPlan {
  readonly ok: true;
  readonly admission: Record<string, unknown>;
  readonly units: readonly NormalizedUnit[];
}

function planLearning(
  input: unknown,
  result: unknown,
  collector: LearningCollectorPort,
  attempt: string | undefined,
): LearningPlan | { readonly ok: false } {
  const review = readReviewInput(input);
  if (!review.ok) return { ok: false };
  const units = normalizeApproverResult(result, review.members);
  if (units === undefined || units.length !== review.members.length) return { ok: false };

  const byRequestId = new Map(units.map((unit) => [unit.requestId, unit]));
  if (byRequestId.size !== units.length) return { ok: false };
  for (const member of review.members) {
    const unit = byRequestId.get(member.requestId);
    if (unit === undefined || unit.actionDigest !== member.actionDigest) return { ok: false };
  }

  const isBatch = review.members.length > 1 || review.admission.batchId !== undefined;
  if (isBatch) {
    if (!nonEmptyString(review.admission.batchId)) return { ok: false };
    for (const unit of units) {
      if (unit.verdict !== "allow" && unit.verdict !== "deny" && unit.verdict !== "defer") return { ok: false };
      if (unit.verdict === "defer" && unit.deferCategory !== undefined &&
        LEARNING_TECHNICAL_DEFER_CATEGORIES.has(unit.deferCategory)) {
        return { ok: false };
      }
    }
    if (!units.some((unit) => unitIsLearnable(unit, collector, attempt))) return { ok: false };
  } else {
    const only = units[0] as NormalizedUnit;
    if (only.verdict !== "allow" && only.verdict !== "deny" && only.verdict !== "defer") return { ok: false };
    if (!unitIsLearnable(only, collector, attempt)) return { ok: false };
  }

  const members = review.members.map((member) => {
    const unit = byRequestId.get(member.requestId) as NormalizedUnit;
    return {
      requestId: member.requestId,
      actionDigest: member.actionDigest,
      action: member.action,
      verdict: unit.verdict as LearningVerdict,
    };
  });
  return {
    ok: true,
    admission: {
      ...review.admission,
      mode: "auto-review",
      members,
    },
    units,
  };
}

function downgradeAllowVerdicts(result: unknown, units: readonly NormalizedUnit[]): unknown {
  if (!isPlainDataObject(result)) return result;
  const allowRequestIds = new Set(units.filter((unit) => unit.verdict === "allow").map((unit) => unit.requestId));
  if (allowRequestIds.size === 0) return result;
  if (Array.isArray(result.members)) {
    const members = result.members.map((raw) => {
      if (!isPlainDataObject(raw)) return raw;
      if (typeof raw.requestId !== "string" || !allowRequestIds.has(raw.requestId)) return raw;
      return Object.freeze({ ...raw, verdict: "defer" });
    });
    return Object.freeze({ ...result, members: Object.freeze(members) });
  }
  if (typeof result.verdict === "string" && units.length === 1 && allowRequestIds.size === 1) {
    return Object.freeze({ ...result, verdict: "defer" });
  }
  return result;
}

function outcomeInvalidatesCurrentAllow(outcome: LearningCommitResult): boolean {
  if (outcome.kind === "committed") return !outcome.currentIntentValid;
  if (outcome.kind !== "failed") return false;
  return outcome.category === "stale" || outcome.category === "disposed" ||
    outcome.category === "timeout" || outcome.category === "aborted";
}

export function wrapLearningApprover(options: LearningApproverWrapperOptions): WrappedLearningApprover {
  const lifecycle = new AbortController();
  let disposed = false;

  const wrapped = async (input: unknown): Promise<unknown> => {
    const frozen = freezeReviewInput(input);
    const explicitAttempt = peekAttemptId(frozen);
    const attempt = explicitAttempt ?? options.collector.currentAttemptId();
    try {
      const result = await options.inner(frozen);
      // Disposed or not configured: the legal verdict stands, learning never starts.
      if (disposed || lifecycle.signal.aborted) return result;
      if (!options.learningEnabled() || options.mode() !== "auto-review") return result;
      const plan = planLearning(frozen, result, options.collector, attempt);
      if (!plan.ok) return result;
      const outcome = await options.learning.commit(plan.admission, attempt);
      if (outcomeInvalidatesCurrentAllow(outcome)) {
        return downgradeAllowVerdicts(result, plan.units);
      }
      return result;
    } finally {
      if (attempt !== undefined) options.collector.discardAttempt(attempt);
    }
  };

  const dispose = (): void => {
    if (disposed) return;
    disposed = true;
    lifecycle.abort();
    try {
      const inner = options.inner as ((input: unknown) => Promise<unknown>) & { dispose?: () => void };
      if (typeof inner.dispose === "function") inner.dispose();
    } catch {
      // Releasing the inner approver is best effort.
    }
  };

  return Object.assign(wrapped, { dispose });
}

// ---------------------------------------------------------------------------
// Deferred learning handoff (§9)
// ---------------------------------------------------------------------------

export interface DeferredLearningHandoffInput {
  readonly verdict: string;
  readonly mode: string;
  readonly learningEnabled: boolean;
  /** The action identity the review was made for. */
  readonly actionDigest: string;
  /** The action identity at handoff time; a change drops the candidates. */
  readonly expectedActionDigest: string;
  readonly units: readonly { readonly verdict: string }[];
  readonly candidateCount: number;
}

/**
 * Phase 10 predicate: candidates may only be handed to the deferred lifecycle
 * for a legal host allow under auto-review + learning, while the action identity
 * is unchanged and every unit of that action stayed allow.
 */
export function canHandOffDeferredLearning(input: DeferredLearningHandoffInput): boolean {
  if (input.verdict !== "allow") return false;
  if (input.mode !== "auto-review") return false;
  if (!input.learningEnabled) return false;
  if (input.actionDigest !== input.expectedActionDigest) return false;
  if (!Number.isSafeInteger(input.candidateCount) || input.candidateCount <= 0) return false;
  if (input.units.length === 0) return false;
  return input.units.every((unit) => unit.verdict === "allow");
}
