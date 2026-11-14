import type { ExecutionRequest } from "../../elevation";
/**
 * Reviewer context domain vocabulary (specs/reviewer-context.md).
 *
 * This module owns the frozen facts every reviewer-context consumer shares:
 * the session view, its revisions, projected evidence, the Full/Delta context
 * selection and the deferred-learning lifecycle ports. Artifact-level behavior
 * lives in the sibling modules; this file only fixes shapes and limits so the
 * host integration layer can join the session memory, the context store and
 * the approval nodes without re-deriving any of them.
 */
import type { LearningCommitResult } from "#approve-core/policy/project-rules/learning";
import { canonicalJson, sha256Hex } from "#approve-core/policy/project-rules/types";

// ---------------------------------------------------------------------------
// Resource limits (§1, §8, §9, §10)
// ---------------------------------------------------------------------------

/**
 * Session memory hard limits. Reaching one fails the capture explicitly; the
 * memory never silently drops an entry to stay underneath a limit.
 */
export const REVIEW_MEMORY_LIMITS = Object.freeze({
  /** Transcript entries kept in one view. */
  maxTranscriptEntries: 8_192,
  /** Immutable authorization entries kept in one view. */
  maxAuthorizationEntries: 2_048,
  /** Bytes of frozen views plus step manifests for one owner. */
  maxViewBytes: 16 * 1024 * 1024,
  /** Distinct tool call/result identities tracked for reconciliation. */
  maxToolEvents: 8_192,
  /** Entries walked from the old leaf to the new leaf before a full rebuild. */
  maxIncrementalEntries: 4_096,
});

/** Full/Delta context store limits; constructor overrides never exceed the hard caps. */
export const REVIEW_CONTEXT_LIMITS = Object.freeze({
  defaultOwners: 32,
  defaultConsumersPerOwner: 8,
  defaultRetentionMs: 30 * 60_000,
  maxOwners: 64,
  maxConsumersPerOwner: 32,
});

/** Deferred learning lifecycle limits (§10). */
export const REVIEW_LEARNING_LIMITS = Object.freeze({
  defaultPending: 128,
  defaultTtlMs: 5 * 60_000,
});

/** Token budget constants (§9). */
export const REVIEW_BUDGET_LIMITS = Object.freeze({
  decisionDefaultTokens: 32_768,
  decisionMinimumTargetTokens: 500,
  decisionPackingRatio: 0.8,
});

// ---------------------------------------------------------------------------
// Revisions and modes
// ---------------------------------------------------------------------------

/**
 * Permission mode string as the reviewer sees it. The host layer has its own
 * closed union with the same members; keeping the domain copy structural means
 * the two never need a cast at the join point.
 */
export type ReviewerMode = "read-only" | "default" | "auto-review" | "full-access";

/** Session-owned revision counters; a change makes earlier reviews stale. */
export interface ReviewSessionRevisions {
  readonly owner: number;
  readonly navigation: number;
  readonly authorization: number;
}

/**
 * Every revision a review was made against. Project-rule revisions are owned by
 * the project-rule service and joined by the host; the session counters are
 * owned by the session memory.
 */
export interface ReviewRevisions extends ReviewSessionRevisions {
  readonly projectRules: number;
  readonly intent: number;
}

// ---------------------------------------------------------------------------
// Session view (§1, §3)
// ---------------------------------------------------------------------------

export type ReviewTranscriptKind =
  | "user"
  | "assistant"
  | "tool_call"
  | "tool_result"
  | "parent_summary"
  | "branch_summary"
  | "extension"
  | "environment_checkpoint";

/** Tool identity and result facts carried by a tool transcript entry. */
export interface ReviewToolFacts {
  readonly name: string;
  readonly callId?: string;
  readonly parentCallId?: string;
  readonly part: "call" | "result";
  /** Present on results only when the host recorded an error result. */
  readonly isError?: boolean;
  /** Host-reported nested call status, when one exists. */
  readonly status?: string;
  /** Nested call duration the host recorded, when any. */
  readonly durationMs?: number;
  /** Nested call error text the host recorded, when any. */
  readonly error?: string;
  /** Nested call argument size the host recorded instead of the arguments. */
  readonly argumentsBytes?: number;
  /** The projection replaced omitted arguments with an explicit marker. */
  readonly omitted?: boolean;
}

/**
 * One model-visible contribution in the reviewed history. `content` is either
 * plain text or a frozen JSON object; `digest` covers the identity, source,
 * content and tool facts of the entry.
 */
export interface ReviewTranscriptEntry {
  readonly entryKey: string;
  readonly sourceEntryId?: string;
  readonly kind: ReviewTranscriptKind;
  readonly content: string | Readonly<Record<string, unknown>>;
  readonly tool?: ReviewToolFacts;
  readonly edited: boolean;
  readonly digest: string;
}

/** Immutable, user-sourced text; never rewritten by a projection or a budget. */
export interface ReviewAuthorizationEntry {
  readonly id: string;
  readonly sourceEntryId: string;
  readonly text: string;
}

/** One direct call of the latest step manifest. */
export interface ReviewManifestCall {
  readonly toolCallId: string;
  readonly toolName: string;
  readonly arguments: Readonly<Record<string, unknown>>;
  readonly argumentsDigest: string;
  readonly parentToolCallId?: string;
}

/**
 * The latest assistant step. `complete` is false when the host facts were
 * ambiguous (duplicate ids, missing fields, non-object arguments). An
 * incomplete manifest can never authorize a step capture.
 */
export interface ReviewStepManifest {
  readonly stepKey: string;
  readonly sourceEntryId: string;
  readonly revision: number;
  readonly complete: boolean;
  readonly directCalls: readonly ReviewManifestCall[];
}

/**
 * Frozen session view. Every capture publishes a new view with a new
 * `captureSeq`; older views are never mutated so in-flight reviews keep the
 * facts they resolved.
 */
export interface ReviewView {
  readonly owner: string;
  readonly sessionId: string;
  readonly historyVersion: number;
  readonly captureSeq: number;
  readonly leafId: string;
  readonly branchRootId: string;
  readonly manifest?: ReviewStepManifest;
  readonly transcript: readonly ReviewTranscriptEntry[];
  readonly authorization: readonly ReviewAuthorizationEntry[];
  /**
   * True when the host exposed no session projection and the view serves only
   * an empty session. Host events never enter the reviewed history in that
   * mode; the transcript carries an explicit environment notice instead.
   */
  readonly degraded: boolean;
}

/** Everything one model reviewer resolves per evaluation. */
export interface ReviewerSessionFacts {
  readonly view: ReviewView;
  readonly revisions: ReviewRevisions;
  readonly mode: ReviewerMode;
}

// ---------------------------------------------------------------------------
// Evidence projection (§6)
// ---------------------------------------------------------------------------

export type ApprovalEvidenceSource =
  | "user"
  | "assistant"
  | "tool"
  | "summary"
  | "environment"
  | "extension";

/**
 * One projected history item. User-sourced authorization is projected once and
 * the budgeted history region excludes it (the request renders authorization in
 * its own section instead).
 */
export interface ApprovalEvidence {
  readonly id: string;
  readonly source: ApprovalEvidenceSource;
  readonly text: string;
  readonly toolName?: string;
  readonly toolCallId?: string;
  readonly toolPart?: "call" | "result";
  readonly digest: string;
}

/** Authorization as a reviewer request renders it: original id plus verbatim text. */
export interface AuthorizationEvidence {
  readonly sourceEntryId: string;
  readonly text: string;
}

// ---------------------------------------------------------------------------
// Pending direct calls rendered into a reviewer request
// ---------------------------------------------------------------------------

export type ChainCallDecision = "allow" | "ask" | "deny" | "escalate";
export type ChainAskTarget = "allow" | "escalate";

export interface ChainCallHistoryRecord {
  readonly revision: number;
  readonly nodeId: string;
  readonly priority: number | null;
  readonly decision: ChainCallDecision;
  readonly askFor?: ChainAskTarget;
  readonly reason: string;
}

export interface ChainCallUnit {
  readonly unitId: string;
  readonly decision: ChainCallDecision;
  readonly reason: string;
  readonly source: string;
  readonly history: readonly ChainCallHistoryRecord[];
}

/**
 * One pending original call as the reviewer request shows it. The reviewer only
 * ever approves the fixed `askFor` target of this exact call.
 */
export interface ChainCallMaterial {
  readonly toolCallId: string;
  readonly parentToolCallId?: string;
  readonly toolName: string;
  readonly arguments: Readonly<Record<string, unknown>>;
  readonly argumentsDigest: string;
  readonly hostExecutionRequest?: ExecutionRequest;
  readonly askFor: ChainAskTarget;
  readonly digest: string;
  readonly units: readonly ChainCallUnit[];
  readonly pendingUnitIds: readonly string[];
}

// ---------------------------------------------------------------------------
// Full/Delta selection and store (§8)
// ---------------------------------------------------------------------------

/**
 * One context read handed to a reviewer. `readCount` is the number of
 * transcript entries the selection covers; `prefixDigest` digests the consumed
 * transcript prefix so a later Delta can prove the history was not rewritten.
 */
export interface ContextSelection {
  readonly owner: string;
  readonly consumer: string;
  readonly view: ReviewView;
  readonly revisions: ReviewRevisions;
  readonly mode: "full" | "delta";
  readonly generation: number;
  readonly historyVersion: number;
  readonly captureSeq: number;
  readonly readCount: number;
  readonly prefixDigest: string;
  readonly authorization: readonly AuthorizationEvidence[];
  readonly evidence: readonly ApprovalEvidence[];
  /** False for a readable-but-old snapshot; such a selection must not commit. */
  readonly installable: boolean;
}

export type ContextBeginFailure =
  | "disposed"
  | "cancelled"
  | "deadline"
  | "invalid-consumer"
  | "invalid-owner"
  | "invalid-view"
  | "invalid-revision"
  | "projection-failed";

export type ReviewerContextBeginResult =
  | { readonly ok: true; readonly selection: ContextSelection }
  | { readonly ok: false; readonly reason: ContextBeginFailure };

export type ContextCommitFailure =
  | "disposed"
  | "cancelled"
  | "deadline"
  | "stale"
  | "not-installable"
  | "invalid-selection"
  | "unknown-consumer";

export type ReviewerContextCommitResult =
  | { readonly ok: true; readonly generation: number }
  | { readonly ok: false; readonly reason: ContextCommitFailure };

export interface ReviewerContextStop {
  readonly signal?: AbortSignal;
  readonly deadline?: number | null;
}

/** One consumer cursor as exposed by the read-only store state. */
export interface ReviewerContextConsumerState {
  readonly owner: string;
  readonly consumer: string;
  readonly generation: number;
  readonly cursor: number;
  readonly prefixDigest: string | null;
  readonly historyVersion: number;
  readonly captureSeq: number;
  readonly revisionDigest: string;
  readonly forceFull: boolean;
  readonly lastUsedAt: number;
}

/**
 * The Full/Delta context store used by the reviewer nodes. `begin` never
 * advances a cursor; only an `installable` selection from the current snapshot
 * can commit.
 */
export interface ReviewerContextStore {
  readonly disposed: boolean;
  begin(input: {
    readonly facts: ReviewerSessionFacts;
    readonly consumer: string;
    readonly forceFull?: boolean;
    readonly signal?: AbortSignal;
    readonly deadline?: number | null;
  }): ReviewerContextBeginResult;
  commit(selection: ContextSelection, stop?: ReviewerContextStop): ReviewerContextCommitResult;
  invalidate(input?: { readonly owner?: string; readonly consumer?: string }): void;
  state(): readonly ReviewerContextConsumerState[];
  dispose(): void;
}

// ---------------------------------------------------------------------------
// Deferred learning lifecycle (§10)
// ---------------------------------------------------------------------------

/** The immutable call facts a deferred candidate is bound to. */
export interface LearningCallFacts {
  readonly toolCallId: string;
  readonly toolName: string;
  readonly parentToolCallId?: string;
  readonly arguments: Readonly<Record<string, unknown>>;
  readonly argumentsDigest: string;
  readonly digest: string;
  readonly units: readonly ChainCallUnit[];
}

/** One node accept: legal model allow plus the frozen facts it was made against. */
export interface LearningAcceptInput {
  readonly attemptId: string;
  readonly stepKey: string;
  readonly sessionId: string;
  readonly call: LearningCallFacts;
  readonly view: ReviewView;
  readonly revisions: ReviewRevisions;
  readonly mode: ReviewerMode;
  readonly verdict: "allow" | "deny" | "ask";
}

/** One call of a final host decision; `decision`/`units` are the final verdicts. */
export interface LearningFinalCall extends LearningCallFacts {
  readonly decision: ChainCallDecision;
}

/**
 * Final host decision for one step. Pending candidates are committed only when
 * the call and every one of its units finally ended allow.
 */
export interface LearningFinalizeInput {
  readonly stepKey: string;
  readonly sessionId: string;
  readonly owner: string;
  readonly calls: readonly LearningFinalCall[];
  /** Current mode at finalize time; when supplied it must still match the accept. */
  readonly mode?: ReviewerMode;
  /** Current revisions at finalize time; when supplied they must equal the accept. */
  readonly revisions?: ReviewRevisions;
  readonly signal?: AbortSignal;
  readonly deadline?: number | null;
}

/** Facts handed to the durable learning transaction when a pending candidate finalizes. */
export interface DeferredLearningCommitInput {
  readonly sessionId: string;
  readonly stepKey: string;
  readonly toolCallId: string;
  readonly attemptId: string;
  readonly call: LearningCallFacts;
  readonly view: ReviewView;
  readonly revisions: ReviewRevisions;
  readonly mode: ReviewerMode;
  readonly verdict: "allow";
}

/** Injected durable-commit seam; the host owns admission construction. */
export interface ReviewerLearningCommitPort {
  commit(input: DeferredLearningCommitInput): LearningCommitResult | Promise<LearningCommitResult>;
}

/** The accept-side surface a model node depends on. */
export interface ReviewerLearningLifecycle {
  beginAttempt(): string;
  stage(attemptId: string, toolCallId: string, learning: unknown): number;
  accept(input: LearningAcceptInput): void;
  discardAttempt(attemptId: string): void;
}

// ---------------------------------------------------------------------------
// Digest helpers
// ---------------------------------------------------------------------------

/** Canonical-JSON digest used by every reviewer-context identity. */
export function reviewDigest(value: unknown): string {
  return sha256Hex(canonicalJson(value));
}
