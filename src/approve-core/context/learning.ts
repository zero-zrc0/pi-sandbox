/**
 * Deferred learning lifecycle (specs/reviewer-context.md §10).
 *
 * A model review may propose project-rule candidates, but nothing becomes
 * durable until the host's final decision for the step still allows the call.
 * This module owns that gap: accepted candidates wait in a bounded, TTL-limited
 * pending table keyed by session/step/tool call, and only an agreeing final
 * decision hands the frozen facts to the durable commit port.
 *
 * All collaborators are injected through {@link ReviewerDeferredLearningOptions}:
 * the Phase 9 candidate collector (structural port), the durable commit port,
 * the learning switch and the clock. Observers are pure notification hooks:
 * neither a throwing observer nor a throwing commit port may change the state
 * machine or the result.
 */
import type { LearningCandidateCollector } from "#approve-core/policy/project-rules/candidates";
import type { LearningCommitResult } from "#approve-core/policy/project-rules/learning";
import {
  REVIEW_LEARNING_LIMITS,
  type ChainCallUnit,
  type DeferredLearningCommitInput,
  type LearningAcceptInput,
  type LearningCallFacts,
  type LearningFinalCall,
  type LearningFinalizeInput,
  type ReviewRevisions,
  type ReviewerLearningCommitPort,
  type ReviewerLearningLifecycle,
  type ReviewerMode,
  type ReviewView,
} from "#approve-core/context/types";

// ---------------------------------------------------------------------------
// Injected ports and public vocabulary
// ---------------------------------------------------------------------------

/**
 * Structural collector port. It is the intersection of the Phase 9
 * `LearningCandidateCollector` members this module needs with the loosest
 * possible `parse` result, so the real class and an in-memory double both
 * satisfy it without a cast.
 */
export type DeferredLearningCollectorPort = Pick<
  LearningCandidateCollector,
  "currentAttemptId" | "hasStagedData" | "discardAttempt"
> & {
  parse(
    input: unknown,
    context: { attemptId?: string; requestId: string },
  ): { candidates: readonly unknown[]; rejections: readonly unknown[] };
};

/** Stable accept rejection reasons (§10). */
export type DeferredLearningAcceptFailure =
  | "disposed"
  | "invalid-input"
  | "invalid-verdict"
  | "not-auto-review"
  | "learning-disabled"
  | "no-candidates"
  | "capacity";

/** Stable pending-discard reasons carried by observer events. */
export type DeferredLearningDiscardReason =
  | "discard"
  | "discard-attempt"
  | "replaced"
  | "disposed"
  | "cancelled"
  | "deadline"
  | "expired"
  | "learning-disabled"
  | "identity-mismatch"
  | "not-final-allow";

/** Stable finalize failure reasons (§10). */
export type DeferredLearningFinalizeFailure =
  | "disposed"
  | "cancelled"
  | "deadline"
  | "no-pending"
  | "duplicate-finalize"
  | "not-final-allow"
  | "identity-mismatch"
  | "expired"
  | "learning-disabled"
  | "commit-failed"
  | "commit-threw";

/** Read-only notification emitted to the injected observers. */
export type DeferredLearningEvent =
  | { readonly kind: "attempt-begun"; readonly attemptId: string }
  | {
      readonly kind: "candidates-staged";
      readonly attemptId: string;
      readonly toolCallId: string;
      readonly candidates: number;
    }
  | {
      readonly kind: "accept-rejected";
      readonly reason: DeferredLearningAcceptFailure;
      readonly attemptId?: string;
      readonly toolCallId?: string;
    }
  | {
      readonly kind: "accepted";
      readonly sessionId: string;
      readonly stepKey: string;
      readonly toolCallId: string;
      readonly attemptId: string;
    }
  | {
      readonly kind: "pending-discarded";
      readonly reason: DeferredLearningDiscardReason;
      readonly attemptId?: string;
      readonly toolCallId?: string;
    }
  | {
      readonly kind: "finalize-rejected";
      readonly reason: DeferredLearningFinalizeFailure;
      readonly toolCallId?: string;
    }
  | { readonly kind: "commit-started"; readonly toolCallId: string; readonly attemptId: string }
  | {
      readonly kind: "committed";
      readonly toolCallId: string;
      readonly attemptId: string;
      readonly revision: number;
    }
  | {
      readonly kind: "commit-failed";
      readonly reason: "commit-failed" | "commit-threw";
      readonly toolCallId: string;
      readonly attemptId: string;
    }
  | { readonly kind: "disposed" };

/** One candidate that was not (or could no longer be) committed. */
export interface DeferredLearningFinalizeRejection {
  readonly toolCallId: string;
  readonly attemptId: string;
  readonly reason: DeferredLearningFinalizeFailure;
}

/** One successful durable commit of a finalized pending candidate. */
export interface DeferredLearningCommittedEntry {
  readonly toolCallId: string;
  readonly attemptId: string;
  readonly result: LearningCommitResult;
}

export type DeferredLearningFinalizeResult =
  | {
      readonly ok: true;
      readonly committed: true;
      readonly sessionId: string;
      readonly stepKey: string;
      readonly commits: readonly DeferredLearningCommittedEntry[];
      readonly rejections: readonly DeferredLearningFinalizeRejection[];
    }
  | {
      readonly ok: false;
      readonly committed: false;
      readonly reason: DeferredLearningFinalizeFailure;
      readonly sessionId: string;
      readonly stepKey: string;
      readonly rejections: readonly DeferredLearningFinalizeRejection[];
    };

/** Read-only snapshot of the pending table. */
export interface DeferredLearningPendingState {
  readonly sessionId: string;
  readonly stepKey: string;
  readonly toolCallId: string;
  readonly attemptId: string;
  readonly acceptedAt: number;
}

export interface DeferredLearningState {
  readonly disposed: boolean;
  readonly pendingCount: number;
  readonly pending: readonly DeferredLearningPendingState[];
}

export interface ReviewerDeferredLearningOptions {
  readonly collector: DeferredLearningCollectorPort;
  readonly commit: ReviewerLearningCommitPort;
  readonly learningEnabled?: () => boolean;
  readonly now?: () => number;
  readonly maxPending?: number;
  readonly ttlMs?: number;
  readonly observers?: readonly ((event: DeferredLearningEvent) => void)[];
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

interface PendingEntry {
  readonly key: string;
  readonly sessionId: string;
  readonly stepKey: string;
  readonly call: LearningCallFacts;
  readonly view: ReviewView;
  readonly revisions: ReviewRevisions;
  readonly mode: ReviewerMode;
  readonly attemptId: string;
  readonly acceptedAt: number;
}

const KEY_SEPARATOR = "\u0000";
const ATTEMPT_COUNTER_WIDTH = 12;
const MAX_REMEMBERED_FINALIZATIONS = 4_096;

function nonEmptyString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function boundedLimit(value: unknown, fallback: number, minimum: number): number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= minimum
    ? value
    : fallback;
}

function pendingKey(sessionId: string, stepKey: string, toolCallId: string): string {
  return `${sessionId}${KEY_SEPARATOR}${stepKey}${KEY_SEPARATOR}${toolCallId}`;
}

function finalizePrefix(sessionId: string, stepKey: string): string {
  return `${sessionId}${KEY_SEPARATOR}${stepKey}${KEY_SEPARATOR}`;
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const REVISION_FIELDS = ["owner", "navigation", "authorization", "projectRules", "intent"] as const;

/** True when the host-supplied current revisions differ from the accepted ones. */
function revisionsMismatch(current: unknown, accepted: ReviewRevisions): boolean {
  if (!isRecord(current)) return true;
  return REVISION_FIELDS.some((field) => current[field] !== accepted[field]);
}

/** Freeze the accepted call facts so later host mutation cannot rewrite identity. */
function freezeCallFacts(call: Partial<LearningCallFacts>): LearningCallFacts {
  return Object.freeze({
    toolCallId: nonEmptyString(call.toolCallId) ?? "",
    toolName: typeof call.toolName === "string" ? call.toolName : "",
    parentToolCallId:
      typeof call.parentToolCallId === "string" ? call.parentToolCallId : undefined,
    arguments: isRecord(call.arguments) ? call.arguments : Object.freeze({}),
    argumentsDigest: typeof call.argumentsDigest === "string" ? call.argumentsDigest : "",
    digest: typeof call.digest === "string" ? call.digest : "",
    units: Array.isArray(call.units)
      ? Object.freeze([...call.units])
      : (Object.freeze([]) as readonly ChainCallUnit[]),
  });
}

function isCommittedResult(value: unknown): value is LearningCommitResult {
  return typeof value === "object" && value !== null && (value as { kind?: unknown }).kind === "committed";
}

function normalizedParentId(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function discardReasonFor(reason: DeferredLearningFinalizeFailure): DeferredLearningDiscardReason {
  switch (reason) {
    case "expired":
    case "learning-disabled":
    case "identity-mismatch":
    case "not-final-allow":
    case "cancelled":
    case "deadline":
      return reason;
    default:
      return "discard";
  }
}

export class ReviewerDeferredLearning implements ReviewerLearningLifecycle {
  readonly #collector: DeferredLearningCollectorPort;
  readonly #commit: ReviewerLearningCommitPort;
  readonly #learningEnabledHook: () => boolean;
  readonly #nowHook: () => number;
  readonly #maxPending: number;
  readonly #ttlMs: number;
  readonly #observers: readonly ((event: DeferredLearningEvent) => void)[];

  readonly #pending = new Map<string, PendingEntry>();
  readonly #attempts = new Set<string>();
  readonly #finalized = new Set<string>();
  #attemptCounter = 0;
  #disposedState = false;

  constructor(options: ReviewerDeferredLearningOptions) {
    this.#collector = options.collector;
    this.#commit = options.commit;
    this.#learningEnabledHook =
      typeof options.learningEnabled === "function" ? options.learningEnabled : () => true;
    this.#nowHook = typeof options.now === "function" ? options.now : () => Date.now();
    this.#maxPending = boundedLimit(
      options.maxPending,
      REVIEW_LEARNING_LIMITS.defaultPending,
      1,
    );
    this.#ttlMs = boundedLimit(options.ttlMs, REVIEW_LEARNING_LIMITS.defaultTtlMs, 0);
    this.#observers = Array.isArray(options.observers)
      ? Object.freeze(options.observers.filter((observer) => typeof observer === "function"))
      : Object.freeze([]);
  }

  get disposed(): boolean {
    return this.#disposedState;
  }

  get pendingCount(): number {
    return this.#pending.size;
  }

  /** Allocate a unique, monotonically increasing attempt id. */
  beginAttempt(): string {
    this.#attemptCounter += 1;
    const sequence = String(this.#attemptCounter).padStart(ATTEMPT_COUNTER_WIDTH, "0");
    const attemptId = `learning-attempt-${sequence}-${this.#readNow()}`;
    if (!this.#disposedState) this.#attempts.add(attemptId);
    this.#emit({ kind: "attempt-begun", attemptId });
    return attemptId;
  }

  /**
   * Stage one model learning payload under the attempt. The collector owns all
   * parsing; this method only reports how many candidates became visible and
   * never throws.
   */
  stage(attemptId: string, toolCallId: string, learning: unknown): number {
    if (this.#disposedState) return 0;
    const attempt = nonEmptyString(attemptId);
    const request = nonEmptyString(toolCallId);
    if (attempt === undefined || request === undefined) return 0;

    let staged = 0;
    try {
      const result = this.#collector.parse(learning, { attemptId: attempt, requestId: request });
      const candidates = (result as { candidates?: unknown } | undefined)?.candidates;
      staged = Array.isArray(candidates) ? candidates.length : 0;
    } catch {
      staged = 0;
    }
    if (staged > 0) {
      this.#attempts.add(attempt);
      this.#emit({
        kind: "candidates-staged",
        attemptId: attempt,
        toolCallId: request,
        candidates: staged,
      });
    }
    return staged;
  }

  /**
   * Admit one staged candidate into the pending table (§10).
   *
   * Capacity is checked before same-key replacement: a full table rejects even
   * a new accept for an existing key and keeps the old pending untouched. Every
   * rejection discards only the new attempt so staged data never leaks.
   */
  accept(input: LearningAcceptInput): void {
    if (this.#disposedState) {
      const attemptId = nonEmptyString((input as Partial<LearningAcceptInput> | null)?.attemptId);
      this.#rejectAccept(attemptId, undefined, "disposed");
      return;
    }

    const source = input as Partial<LearningAcceptInput> | null | undefined;
    const attemptId = nonEmptyString(source?.attemptId);
    const sessionId = nonEmptyString(source?.sessionId);
    const stepKey = nonEmptyString(source?.stepKey);
    const call = source?.call as Partial<LearningCallFacts> | undefined;
    const toolCallId = nonEmptyString(call?.toolCallId);
    if (
      attemptId === undefined ||
      sessionId === undefined ||
      stepKey === undefined ||
      toolCallId === undefined
    ) {
      this.#rejectAccept(attemptId, toolCallId, "invalid-input");
      return;
    }

    if (source?.verdict !== "allow") {
      this.#rejectAccept(attemptId, toolCallId, "invalid-verdict");
      return;
    }
    if (source.mode !== "auto-review") {
      this.#rejectAccept(attemptId, toolCallId, "not-auto-review");
      return;
    }
    if (!this.#learningEnabled()) {
      this.#rejectAccept(attemptId, toolCallId, "learning-disabled");
      return;
    }
    if (!this.#hasStagedData(attemptId)) {
      this.#rejectAccept(attemptId, toolCallId, "no-candidates");
      return;
    }

    const key = pendingKey(sessionId, stepKey, toolCallId);
    // §10: capacity comes first, so a full table never replaces a same-key pending.
    if (this.#pending.size >= this.#maxPending) {
      this.#rejectAccept(attemptId, toolCallId, "capacity");
      return;
    }

    const acceptedAt = this.#readNow();
    const entry: PendingEntry = Object.freeze({
      key,
      sessionId,
      stepKey,
      call: freezeCallFacts(call as LearningCallFacts),
      view: source.view as ReviewView,
      revisions: source.revisions as ReviewRevisions,
      mode: source.mode,
      attemptId,
      acceptedAt,
    });

    const replaced = this.#pending.get(key);
    if (replaced !== undefined) {
      this.#pending.delete(key);
      this.#discardCollectorAttempt(replaced.attemptId);
      this.#emit({
        kind: "pending-discarded",
        reason: "replaced",
        attemptId: replaced.attemptId,
        toolCallId: replaced.call.toolCallId,
      });
    }
    this.#pending.set(key, entry);
    this.#finalized.delete(key);
    this.#rememberFinalizationBound();
    this.#emit({
      kind: "accepted",
      sessionId,
      stepKey,
      toolCallId,
      attemptId,
    });
  }

  /**
   * Settle one step's final host decision (§10).
   *
   * Pending candidates are re-validated against the accepted frozen facts,
   * then marked finalized and removed from the table *before* the durable
   * commit is awaited, so a re-entrant finalize can never double-commit. The
   * collector attempt is released on every outcome and a throwing commit port
   * is reported, never propagated.
   */
  async finalize(input: LearningFinalizeInput): Promise<DeferredLearningFinalizeResult> {
    const source = input as Partial<LearningFinalizeInput> | null | undefined;
    const sessionId = nonEmptyString(source?.sessionId);
    const stepKey = nonEmptyString(source?.stepKey);

    if (this.#disposedState) {
      return this.#finalizeFailure(sessionId, stepKey, "disposed", []);
    }

    const signal = source?.signal;
    if (signal !== undefined && signal !== null && signal.aborted === true) {
      this.#discardStepEntries(sessionId, stepKey, "cancelled");
      return this.#finalizeFailure(sessionId, stepKey, "cancelled", []);
    }
    const deadline = source?.deadline;
    if (typeof deadline === "number" && Number.isFinite(deadline) && this.#readNow() >= deadline) {
      this.#discardStepEntries(sessionId, stepKey, "deadline");
      return this.#finalizeFailure(sessionId, stepKey, "deadline", []);
    }
    if (sessionId === undefined || stepKey === undefined) {
      return this.#finalizeFailure(sessionId, stepKey, "no-pending", []);
    }

    const relevant = this.#pendingEntries(sessionId, stepKey);
    if (relevant.length === 0) {
      const reason = this.#hasFinalizedPrefix(finalizePrefix(sessionId, stepKey))
        ? "duplicate-finalize"
        : "no-pending";
      return this.#finalizeFailure(sessionId, stepKey, reason, []);
    }

    const owner = nonEmptyString(source?.owner);
    const enabled = this.#learningEnabled();
    const now = this.#readNow();
    const finalInput: Partial<LearningFinalizeInput> = source ?? {};
    const commitEntries: PendingEntry[] = [];
    const rejections: DeferredLearningFinalizeRejection[] = [];

    // Classify synchronously so state can be captured before the first await.
    const discardReasons = new Map<string, DeferredLearningDiscardReason>();
    for (const entry of relevant) {
      const reason = this.#validateFinalize(entry, finalInput, owner, enabled, now);
      if (reason === undefined) {
        commitEntries.push(entry);
        continue;
      }
      rejections.push(
        Object.freeze({ toolCallId: entry.call.toolCallId, attemptId: entry.attemptId, reason }),
      );
      discardReasons.set(entry.key, discardReasonFor(reason));
    }

    // Rejected candidates are consumed by this finalize; drop them before any await.
    for (const entry of relevant) {
      const discardReason = discardReasons.get(entry.key);
      if (discardReason === undefined) continue;
      this.#pending.delete(entry.key);
      this.#finalized.add(entry.key);
      this.#discardCollectorAttempt(entry.attemptId);
      this.#emit({
        kind: "pending-discarded",
        reason: discardReason,
        attemptId: entry.attemptId,
        toolCallId: entry.call.toolCallId,
      });
    }
    // §10: mark finalized and remove pending before awaiting the commit.
    for (const entry of commitEntries) {
      this.#pending.delete(entry.key);
      this.#finalized.add(entry.key);
    }
    this.#rememberFinalizationBound();

    if (commitEntries.length === 0) {
      const reason = rejections[0]?.reason ?? "no-pending";
      return this.#finalizeFailure(sessionId, stepKey, reason, rejections);
    }

    const commits: DeferredLearningCommittedEntry[] = [];
    for (const entry of commitEntries) {
      this.#emit({
        kind: "commit-started",
        toolCallId: entry.call.toolCallId,
        attemptId: entry.attemptId,
      });
      try {
        const result = await this.#commit.commit(this.#commitInput(entry));
        if (isCommittedResult(result)) {
          commits.push(
            Object.freeze({
              toolCallId: entry.call.toolCallId,
              attemptId: entry.attemptId,
              result,
            }),
          );
          this.#emit({
            kind: "committed",
            toolCallId: entry.call.toolCallId,
            attemptId: entry.attemptId,
            revision: typeof result.revision === "number" ? result.revision : 0,
          });
        } else {
          rejections.push(
            Object.freeze({
              toolCallId: entry.call.toolCallId,
              attemptId: entry.attemptId,
              reason: "commit-failed",
            }),
          );
          this.#emit({
            kind: "commit-failed",
            reason: "commit-failed",
            toolCallId: entry.call.toolCallId,
            attemptId: entry.attemptId,
          });
        }
      } catch {
        rejections.push(
          Object.freeze({
            toolCallId: entry.call.toolCallId,
            attemptId: entry.attemptId,
            reason: "commit-threw",
          }),
        );
        this.#emit({
          kind: "commit-failed",
          reason: "commit-threw",
          toolCallId: entry.call.toolCallId,
          attemptId: entry.attemptId,
        });
      } finally {
        // §10: whatever the durable transaction did, the attempt is released.
        this.#discardCollectorAttempt(entry.attemptId);
      }
    }

    if (commits.length > 0) {
      return Object.freeze({
        ok: true,
        committed: true,
        sessionId,
        stepKey,
        commits: Object.freeze(commits),
        rejections: Object.freeze(rejections),
      });
    }
    const reason = rejections.some((item) => item.reason === "commit-threw")
      ? "commit-threw"
      : "commit-failed";
    return this.#finalizeFailure(sessionId, stepKey, reason, rejections);
  }

  /** Drop every pending candidate registered for one tool call (§10). */
  discard(toolCallId: string): void {
    const target = nonEmptyString(toolCallId);
    if (target === undefined) return;
    this.#discardPending(
      (entry) => entry.call.toolCallId === target,
      (entry) => ({
        kind: "pending-discarded",
        reason: "discard",
        attemptId: entry.attemptId,
        toolCallId: entry.call.toolCallId,
      }),
      true,
    );
  }

  /**
   * Drop the pending candidates of one attempt and always release its staged
   * collector bucket, even when no pending was registered.
   */
  discardAttempt(attemptId: string): void {
    const target = nonEmptyString(attemptId);
    if (target === undefined) return;
    this.#discardPending(
      (entry) => entry.attemptId === target,
      (entry) => ({
        kind: "pending-discarded",
        reason: "discard-attempt",
        attemptId: entry.attemptId,
        toolCallId: entry.call.toolCallId,
      }),
      false,
    );
    this.#discardCollectorAttempt(target);
  }

  /** Idempotent shutdown: no later call may stage, accept, discard or commit. */
  dispose(): void {
    if (this.#disposedState) return;
    this.#disposedState = true;

    const pending = [...this.#pending.values()];
    const attempts = new Set<string>(this.#attempts);
    for (const entry of pending) attempts.add(entry.attemptId);
    this.#pending.clear();
    this.#attempts.clear();
    this.#finalized.clear();

    for (const entry of pending) {
      this.#emit({
        kind: "pending-discarded",
        reason: "disposed",
        attemptId: entry.attemptId,
        toolCallId: entry.call.toolCallId,
      });
    }
    for (const attemptId of attempts) this.#discardCollectorAttempt(attemptId);
    this.#emit({ kind: "disposed" });
  }

  state(): DeferredLearningState {
    return Object.freeze({
      disposed: this.#disposedState,
      pendingCount: this.#pending.size,
      pending: Object.freeze(
        [...this.#pending.values()].map((entry) =>
          Object.freeze({
            sessionId: entry.sessionId,
            stepKey: entry.stepKey,
            toolCallId: entry.call.toolCallId,
            attemptId: entry.attemptId,
            acceptedAt: entry.acceptedAt,
          }),
        ),
      ),
    });
  }

  // -------------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------------

  #readNow(): number {
    try {
      const value = this.#nowHook();
      return typeof value === "number" && Number.isFinite(value) ? value : 0;
    } catch {
      return 0;
    }
  }

  #learningEnabled(): boolean {
    try {
      return this.#learningEnabledHook() === true;
    } catch {
      return false;
    }
  }

  #hasStagedData(attemptId: string): boolean {
    try {
      return this.#collector.hasStagedData(attemptId) === true;
    } catch {
      return false;
    }
  }

  #discardCollectorAttempt(attemptId: string): void {
    this.#attempts.delete(attemptId);
    try {
      this.#collector.discardAttempt(attemptId);
    } catch {
      // The collector is a safety seam; a failure must not corrupt the lifecycle.
    }
  }

  #discardPending(
    predicate: (entry: PendingEntry) => boolean,
    eventFor: (entry: PendingEntry) => DeferredLearningEvent,
    discardAttempts: boolean,
  ): void {
    for (const [key, entry] of [...this.#pending]) {
      if (!predicate(entry)) continue;
      this.#pending.delete(key);
      if (discardAttempts) this.#discardCollectorAttempt(entry.attemptId);
      this.#emit(eventFor(entry));
    }
  }

  #pendingEntries(sessionId: string, stepKey: string): PendingEntry[] {
    const entries: PendingEntry[] = [];
    for (const entry of this.#pending.values()) {
      if (entry.sessionId === sessionId && entry.stepKey === stepKey) entries.push(entry);
    }
    return entries;
  }

  #hasFinalizedPrefix(prefix: string): boolean {
    for (const key of this.#finalized) {
      if (key.startsWith(prefix)) return true;
    }
    return false;
  }

  /**
   * Re-verify one pending candidate against the final host decision (§10).
   *
   * Only an allow call whose final unit verdicts are all allow, found under the
   * same session/step/tool call, may reach the durable transaction. Expiry,
   * the learning switch and the accepted identity are re-checked first.
   */
  #validateFinalize(
    entry: PendingEntry,
    source: Partial<LearningFinalizeInput>,
    owner: string | undefined,
    enabled: boolean,
    now: number,
  ): DeferredLearningFinalizeFailure | undefined {
    if (now - entry.acceptedAt >= this.#ttlMs) return "expired";
    if (!enabled) return "learning-disabled";
    if (entry.view?.owner !== owner) return "identity-mismatch";
    if (entry.view?.sessionId !== entry.sessionId) return "identity-mismatch";
    // State identity re-checked against the accept when the host supplies it.
    if (source.mode !== undefined && source.mode !== entry.mode) return "identity-mismatch";
    if (source.revisions !== undefined && revisionsMismatch(source.revisions, entry.revisions)) {
      return "identity-mismatch";
    }

    const calls = Array.isArray(source.calls) ? source.calls : [];
    const match = calls.find(
      (candidate) => isRecord(candidate) && candidate.toolCallId === entry.call.toolCallId,
    ) as Partial<LearningFinalCall> | undefined;
    if (match === undefined) return "not-final-allow";
    if (match.decision !== "allow") return "not-final-allow";

    const units = Array.isArray(match.units) ? match.units : [];
    for (const unit of units) {
      if (!isRecord(unit) || unit.decision !== "allow") return "not-final-allow";
    }

    if (match.digest !== entry.call.digest) return "identity-mismatch";
    if (match.argumentsDigest !== entry.call.argumentsDigest) return "identity-mismatch";
    if (match.toolName !== entry.call.toolName) return "identity-mismatch";
    if (normalizedParentId(match.parentToolCallId) !== normalizedParentId(entry.call.parentToolCallId)) {
      return "identity-mismatch";
    }
    return undefined;
  }

  #discardStepEntries(
    sessionId: string | undefined,
    stepKey: string | undefined,
    reason: DeferredLearningDiscardReason,
  ): void {
    if (sessionId === undefined || stepKey === undefined) return;
    for (const [key, entry] of [...this.#pending]) {
      if (entry.sessionId !== sessionId || entry.stepKey !== stepKey) continue;
      this.#pending.delete(key);
      this.#finalized.add(key);
      this.#discardCollectorAttempt(entry.attemptId);
      this.#emit({
        kind: "pending-discarded",
        reason,
        attemptId: entry.attemptId,
        toolCallId: entry.call.toolCallId,
      });
    }
    this.#rememberFinalizationBound();
  }

  #commitInput(entry: PendingEntry): DeferredLearningCommitInput {
    return Object.freeze({
      sessionId: entry.sessionId,
      stepKey: entry.stepKey,
      toolCallId: entry.call.toolCallId,
      attemptId: entry.attemptId,
      call: entry.call,
      view: entry.view,
      revisions: entry.revisions,
      mode: entry.mode,
      verdict: "allow" as const,
    });
  }

  #finalizeFailure(
    sessionId: string | undefined,
    stepKey: string | undefined,
    reason: DeferredLearningFinalizeFailure,
    rejections: readonly DeferredLearningFinalizeRejection[],
  ): DeferredLearningFinalizeResult {
    this.#emit({ kind: "finalize-rejected", reason });
    return Object.freeze({
      ok: false,
      committed: false,
      reason,
      sessionId: sessionId ?? "",
      stepKey: stepKey ?? "",
      rejections: Object.freeze([...rejections]),
    });
  }

  #rejectAccept(
    attemptId: string | undefined,
    toolCallId: string | undefined,
    reason: DeferredLearningAcceptFailure,
  ): void {
    if (attemptId !== undefined) this.#discardCollectorAttempt(attemptId);
    this.#emit({ kind: "accept-rejected", reason, attemptId, toolCallId });
  }

  #rememberFinalizationBound(): void {
    if (this.#finalized.size <= MAX_REMEMBERED_FINALIZATIONS) return;
    const excess = this.#finalized.size - MAX_REMEMBERED_FINALIZATIONS;
    let removed = 0;
    for (const key of this.#finalized) {
      if (removed >= excess) break;
      this.#finalized.delete(key);
      removed += 1;
    }
  }

  #emit(event: DeferredLearningEvent): void {
    const frozen = Object.freeze(event);
    for (const observer of this.#observers) {
      try {
        const result = observer(frozen) as unknown;
        if (
          result !== undefined &&
          result !== null &&
          typeof (result as PromiseLike<unknown>).then === "function"
        ) {
          void Promise.resolve(result).catch(() => undefined);
        }
      } catch {
        // Observers are notification only; their failure never changes behavior.
      }
    }
  }
}
