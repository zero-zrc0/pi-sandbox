/**
 * Full/Delta reviewer context store (specs/reviewer-context.md §8).
 *
 * The store owns the per-owner/consumer evidence cursor shared by the reviewer
 * nodes. `begin` resolves one Full or Delta read from a frozen session view and
 * never advances the shared cursor; only an installable selection resolved from
 * the current snapshot may `commit`, and it commits the cursor exactly once.
 *
 * Identity is generation + revision digest + history version + capture
 * sequence: a revision or history change forces the next read to Full, an older
 * capture stays readable but is never installable, and a revised prefix digest
 * proves the consumed history was rewritten so it must not be resumed.
 */
import { projectDeltaEvidence, projectFullEvidence, transcriptPrefixDigest } from "./projection";
import {
  REVIEW_CONTEXT_LIMITS,
  reviewDigest,
  type ContextSelection,
  type ReviewerContextBeginResult,
  type ReviewerContextCommitResult,
  type ReviewerContextConsumerState,
  type ReviewerContextStop,
  type ReviewerContextStore,
  type ReviewerSessionFacts,
  type ReviewRevisions,
  type ReviewView,
} from "./types";

export interface ReviewerContextStoreOptions {
  readonly now?: () => number;
  readonly maxOwners?: number;
  readonly maxConsumersPerOwner?: number;
  readonly retentionMs?: number;
}

/** One consumer cursor plus the bookkeeping the store keeps private. */
interface ConsumerEntry {
  generation: number;
  cursor: number;
  prefixDigest: string | null;
  historyVersion: number;
  captureSeq: number;
  revisionDigest: string;
  forceFull: boolean;
  lastUsedAt: number;
  /** Recency rank used for deterministic LRU ties; never exposed. */
  accessSeq: number;
  /** Cursor an installable selection started from; null when no commit is pending. */
  pendingCursor: number | null;
}

interface OwnerGroup {
  readonly consumers: Map<string, ConsumerEntry>;
  accessSeq: number;
}

// ---------------------------------------------------------------------------
// Narrowing and option normalization
// ---------------------------------------------------------------------------

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function nonNegativeSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function validRevisions(value: unknown): value is ReviewRevisions {
  if (!isPlainObject(value)) return false;
  return (
    nonNegativeSafeInteger(value.owner) &&
    nonNegativeSafeInteger(value.navigation) &&
    nonNegativeSafeInteger(value.authorization) &&
    nonNegativeSafeInteger(value.projectRules) &&
    nonNegativeSafeInteger(value.intent)
  );
}

function positiveSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 1;
}

/** A capacity override; unusable values fall back to the default and none exceed the hard cap. */
function capacityOption(value: unknown, fallback: number, hardCap: number): number {
  return positiveSafeInteger(value) ? Math.min(value, hardCap) : fallback;
}

function retentionOption(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0
    ? value
    : REVIEW_CONTEXT_LIMITS.defaultRetentionMs;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createReviewerContextStore(
  options?: ReviewerContextStoreOptions,
): ReviewerContextStore {
  const input = isPlainObject(options) ? options : {};
  const clock = typeof input.now === "function" ? input.now : () => Date.now();
  const maxOwners = capacityOption(
    input.maxOwners,
    REVIEW_CONTEXT_LIMITS.defaultOwners,
    REVIEW_CONTEXT_LIMITS.maxOwners,
  );
  const maxConsumersPerOwner = capacityOption(
    input.maxConsumersPerOwner,
    REVIEW_CONTEXT_LIMITS.defaultConsumersPerOwner,
    REVIEW_CONTEXT_LIMITS.maxConsumersPerOwner,
  );
  const retentionMs = retentionOption(input.retentionMs);

  const owners = new Map<string, OwnerGroup>();
  let accessSeq = 0;
  let disposed = false;

  function touch(group: OwnerGroup, entry: ConsumerEntry, instant: number): void {
    entry.lastUsedAt = instant;
    entry.accessSeq = ++accessSeq;
    group.accessSeq = accessSeq;
  }

  function evictIdle(instant: number): void {
    for (const [owner, group] of owners) {
      for (const [consumer, entry] of group.consumers) {
        if (instant - entry.lastUsedAt >= retentionMs) group.consumers.delete(consumer);
      }
      if (group.consumers.size === 0) owners.delete(owner);
    }
  }

  function evictLruOwner(): void {
    let victim: string | undefined;
    let oldest = Number.POSITIVE_INFINITY;
    for (const [owner, group] of owners) {
      if (group.accessSeq < oldest) {
        oldest = group.accessSeq;
        victim = owner;
      }
    }
    if (victim !== undefined) owners.delete(victim);
  }

  function evictLruConsumer(group: OwnerGroup): void {
    let victim: string | undefined;
    let oldest = Number.POSITIVE_INFINITY;
    for (const [consumer, entry] of group.consumers) {
      if (entry.accessSeq < oldest) {
        oldest = entry.accessSeq;
        victim = consumer;
      }
    }
    if (victim !== undefined) group.consumers.delete(victim);
  }

  /** Make room for one owner/consumer pair, evicting the least-recently-used entries. */
  function reserve(owner: string, consumer: string): OwnerGroup {
    const existing = owners.get(owner);
    if (existing !== undefined) {
      if (!existing.consumers.has(consumer) && existing.consumers.size >= maxConsumersPerOwner) {
        evictLruConsumer(existing);
      }
      return existing;
    }
    while (owners.size >= maxOwners) evictLruOwner();
    const group: OwnerGroup = { consumers: new Map(), accessSeq: 0 };
    owners.set(owner, group);
    return group;
  }

  function makeSelection(fields: {
    readonly consumer: string;
    readonly view: ReviewView;
    readonly revisions: ReviewRevisions;
    readonly mode: "full" | "delta";
    readonly generation: number;
    readonly readCount: number;
    readonly prefixDigest: string;
    readonly installable: boolean;
    readonly evidence: ContextSelection["evidence"];
    readonly authorization: ContextSelection["authorization"];
  }): ContextSelection {
    return Object.freeze({
      owner: fields.view.owner,
      consumer: fields.consumer,
      view: fields.view,
      revisions: fields.revisions,
      mode: fields.mode,
      generation: fields.generation,
      historyVersion: fields.view.historyVersion,
      captureSeq: fields.view.captureSeq,
      readCount: fields.readCount,
      prefixDigest: fields.prefixDigest,
      authorization: fields.authorization,
      evidence: fields.evidence,
      installable: fields.installable,
    });
  }

  function begin(input: {
    readonly facts: ReviewerSessionFacts;
    readonly consumer: string;
    readonly forceFull?: boolean;
    readonly signal?: AbortSignal;
    readonly deadline?: number | null;
  }): ReviewerContextBeginResult {
    if (disposed) return { ok: false, reason: "disposed" };
    const instant = clock();
    if (input?.signal?.aborted) return { ok: false, reason: "cancelled" };
    const deadline = input?.deadline;
    if (
      deadline !== undefined &&
      deadline !== null &&
      (!Number.isFinite(deadline) || instant >= deadline)
    ) {
      return { ok: false, reason: "deadline" };
    }

    const consumer = input?.consumer;
    if (!nonEmptyString(consumer)) return { ok: false, reason: "invalid-consumer" };
    const facts: unknown = input?.facts;
    if (!isPlainObject(facts)) return { ok: false, reason: "invalid-view" };
    const view = facts.view;
    if (!isPlainObject(view)) return { ok: false, reason: "invalid-view" };
    if (!nonEmptyString(view.owner)) return { ok: false, reason: "invalid-owner" };
    if (!nonNegativeSafeInteger(view.historyVersion)) return { ok: false, reason: "invalid-view" };
    if (!nonNegativeSafeInteger(view.captureSeq)) return { ok: false, reason: "invalid-view" };
    if (!Array.isArray(view.transcript)) return { ok: false, reason: "invalid-view" };
    if (!Array.isArray(view.authorization)) return { ok: false, reason: "invalid-view" };
    const revisions = facts.revisions;
    if (!validRevisions(revisions)) return { ok: false, reason: "invalid-revision" };

    const reviewView = view as unknown as ReviewView;
    const revisionDigest = reviewDigest(revisions);

    evictIdle(instant);
    const group = reserve(reviewView.owner, consumer);
    let entry = group.consumers.get(consumer);
    let fresh = false;
    if (entry === undefined) {
      entry = {
        generation: 0,
        cursor: 0,
        prefixDigest: null,
        historyVersion: reviewView.historyVersion,
        captureSeq: reviewView.captureSeq,
        revisionDigest,
        forceFull: false,
        lastUsedAt: instant,
        accessSeq: 0,
        pendingCursor: null,
      };
      group.consumers.set(consumer, entry);
      fresh = true;
    }

    // A snapshot older than the stored state stays readable, but it can never
    // advance the shared cursor: the consumer already installed newer facts.
    if (!fresh && (reviewView.historyVersion < entry.historyVersion || reviewView.captureSeq < entry.captureSeq)) {
      touch(group, entry, instant);
      entry.pendingCursor = null;
      const projection = projectFullEvidence(reviewView);
      return {
        ok: true,
        selection: makeSelection({
          consumer,
          view: reviewView,
          revisions,
          mode: "full",
          generation: entry.generation,
          readCount: reviewView.transcript.length,
          prefixDigest: transcriptPrefixDigest(reviewView, reviewView.transcript.length),
          installable: false,
          evidence: projection.evidence,
          authorization: projection.authorization,
        }),
      };
    }

    // A revision or history change invalidates the installed context: the next
    // read restarts from the beginning of a new generation.
    if (!fresh && (revisionDigest !== entry.revisionDigest || reviewView.historyVersion !== entry.historyVersion)) {
      entry.generation += 1;
      entry.cursor = 0;
      entry.forceFull = true;
      entry.revisionDigest = revisionDigest;
      entry.historyVersion = reviewView.historyVersion;
    }

    const forced = input?.forceFull === true || entry.forceFull;
    let mode: "full" | "delta" = "delta";
    let installable = true;
    if (fresh || forced || entry.cursor > reviewView.transcript.length || entry.prefixDigest === null) {
      mode = "full";
    } else if (entry.prefixDigest !== transcriptPrefixDigest(reviewView, entry.cursor)) {
      // Same identity but the consumed prefix digest changed: the history was
      // rewritten, so the cursor no longer describes a provable continuation.
      mode = "full";
      installable = false;
    }

    touch(group, entry, instant);

    if (mode === "full") {
      const projection = projectFullEvidence(reviewView);
      const selection = makeSelection({
        consumer,
        view: reviewView,
        revisions,
        mode: "full",
        generation: entry.generation,
        readCount: reviewView.transcript.length,
        prefixDigest: transcriptPrefixDigest(reviewView, reviewView.transcript.length),
        installable,
        evidence: projection.evidence,
        authorization: projection.authorization,
      });
      if (installable) {
        // An installable read adopts the capture it was resolved against.
        entry.captureSeq = reviewView.captureSeq;
        entry.pendingCursor = entry.cursor;
      } else {
        entry.pendingCursor = null;
      }
      return { ok: true, selection };
    }

    // A newer capture of the same history is now the identity an install proves.
    entry.captureSeq = reviewView.captureSeq;
    const evidenceProjection = projectDeltaEvidence(reviewView, entry.cursor);
    const selection = makeSelection({
      consumer,
      view: reviewView,
      revisions,
      mode: "delta",
      generation: entry.generation,
      readCount: reviewView.transcript.length - entry.cursor,
      prefixDigest: transcriptPrefixDigest(reviewView, reviewView.transcript.length),
      installable: true,
      evidence: evidenceProjection.evidence,
      authorization: evidenceProjection.authorization,
    });
    entry.pendingCursor = entry.cursor;
    return { ok: true, selection };
  }

  function commit(
    selection: ContextSelection,
    stop?: ReviewerContextStop,
  ): ReviewerContextCommitResult {
    if (disposed) return { ok: false, reason: "disposed" };
    const instant = clock();
    if (stop?.signal?.aborted) return { ok: false, reason: "cancelled" };
    const deadline = stop?.deadline;
    if (
      deadline !== undefined &&
      deadline !== null &&
      (!Number.isFinite(deadline) || instant >= deadline)
    ) {
      return { ok: false, reason: "deadline" };
    }

    // The selection itself can be forged by a caller, so every field the
    // install uses is validated before it can touch stored state.
    if (!isPlainObject(selection)) return { ok: false, reason: "invalid-selection" };
    const candidate = selection as unknown as Record<string, unknown>;
    const owner = candidate.owner;
    const consumer = candidate.consumer;
    if (!nonEmptyString(owner) || !nonEmptyString(consumer)) {
      return { ok: false, reason: "invalid-selection" };
    }
    const group = owners.get(owner);
    const entry = group?.consumers.get(consumer);
    if (group === undefined || entry === undefined) return { ok: false, reason: "unknown-consumer" };

    const view = candidate.view;
    if (!isPlainObject(view) || !Array.isArray(view.transcript)) {
      return { ok: false, reason: "invalid-selection" };
    }
    const reviewView = view as unknown as ReviewView;
    if (reviewView.owner !== owner) return { ok: false, reason: "invalid-selection" };
    const revisions = candidate.revisions;
    if (!validRevisions(revisions)) return { ok: false, reason: "invalid-selection" };
    const mode = candidate.mode;
    if (mode !== "full" && mode !== "delta") return { ok: false, reason: "invalid-selection" };
    if (
      !nonNegativeSafeInteger(candidate.generation) ||
      !nonNegativeSafeInteger(candidate.historyVersion) ||
      !nonNegativeSafeInteger(candidate.captureSeq) ||
      !nonNegativeSafeInteger(candidate.readCount)
    ) {
      return { ok: false, reason: "invalid-selection" };
    }
    if (typeof candidate.prefixDigest !== "string") return { ok: false, reason: "invalid-selection" };
    if (typeof candidate.installable !== "boolean") return { ok: false, reason: "invalid-selection" };
    if (!Array.isArray(candidate.authorization) || !Array.isArray(candidate.evidence)) {
      return { ok: false, reason: "invalid-selection" };
    }
    const transcriptLength = reviewView.transcript.length;
    if (candidate.prefixDigest !== transcriptPrefixDigest(reviewView, transcriptLength)) {
      return { ok: false, reason: "invalid-selection" };
    }
    if (candidate.installable === false) return { ok: false, reason: "not-installable" };

    // Identity must still describe the installed state and the exact cursor the
    // selection started from; any concurrent install makes it stale.
    if (entry.generation !== candidate.generation) return { ok: false, reason: "stale" };
    if (entry.revisionDigest !== reviewDigest(revisions)) return { ok: false, reason: "stale" };
    if (entry.historyVersion !== candidate.historyVersion) return { ok: false, reason: "stale" };
    if (entry.captureSeq !== candidate.captureSeq) return { ok: false, reason: "stale" };
    if (entry.pendingCursor === null || entry.cursor !== entry.pendingCursor) {
      return { ok: false, reason: "stale" };
    }
    const readCount = candidate.readCount as number;
    if (mode === "full") {
      if (readCount !== transcriptLength) return { ok: false, reason: "stale" };
    } else if (transcriptLength - readCount !== entry.pendingCursor) {
      return { ok: false, reason: "stale" };
    }

    entry.cursor = transcriptLength;
    entry.prefixDigest = candidate.prefixDigest;
    entry.historyVersion = candidate.historyVersion as number;
    entry.captureSeq = candidate.captureSeq as number;
    entry.revisionDigest = reviewDigest(revisions);
    entry.forceFull = false;
    entry.pendingCursor = null;
    if (mode === "full") entry.generation += 1;
    touch(group, entry, instant);
    return { ok: true, generation: entry.generation };
  }

  function invalidate(input?: { readonly owner?: string; readonly consumer?: string }): void {
    if (disposed) return;
    const ownerFilter = isPlainObject(input) ? input.owner : undefined;
    const consumerFilter = isPlainObject(input) ? input.consumer : undefined;
    for (const [owner, group] of owners) {
      if (ownerFilter !== undefined && owner !== ownerFilter) continue;
      for (const [consumer, entry] of group.consumers) {
        if (consumerFilter !== undefined && consumer !== consumerFilter) continue;
        entry.forceFull = true;
      }
    }
  }

  function state(): readonly ReviewerContextConsumerState[] {
    const snapshots: ReviewerContextConsumerState[] = [];
    for (const [owner, group] of owners) {
      for (const [consumer, entry] of group.consumers) {
        snapshots.push(Object.freeze({
          owner,
          consumer,
          generation: entry.generation,
          cursor: entry.cursor,
          prefixDigest: entry.prefixDigest,
          historyVersion: entry.historyVersion,
          captureSeq: entry.captureSeq,
          revisionDigest: entry.revisionDigest,
          forceFull: entry.forceFull,
          lastUsedAt: entry.lastUsedAt,
        }));
      }
    }
    return Object.freeze(snapshots);
  }

  function dispose(): void {
    if (disposed) return;
    disposed = true;
    owners.clear();
  }

  return {
    get disposed(): boolean {
      return disposed;
    },
    begin,
    commit,
    invalidate,
    state,
    dispose,
  };
}
