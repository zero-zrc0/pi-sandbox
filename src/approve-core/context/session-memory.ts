/**
 * Reviewer session memory (specs/reviewer-context.md §1, §2, §4, §5).
 *
 * The memory is the only reader of the host session for the reviewer: it turns
 * one append-only host session into a sequence of frozen {@link ReviewView}
 * snapshots, synchronizes them incrementally from the previous leaf, and folds
 * live tool events into the view without ever rewriting evidence the host has
 * already persisted.
 *
 * Everything external is injected: the host reader
 * ({@link ReviewerHostSession}) and the clock. The memory never touches disk,
 * never mutates a published view, and fails every capture explicitly
 * (`invalid-owner`, `sync-failed`, `projection-unavailable`,
 * `capacity-exceeded`, `fatal`, `uninitialized`, `disposed`) instead of
 * silently serving a partial history.
 */
import type { SessionEntry, SessionProjection } from "@earendil-works/pi-coding-agent";
import { canonicalJson } from "#approve-core/policy/project-rules/types";
import {
  buildAuthorization,
  buildReviewView,
  buildStepManifest,
  degradedView,
  projectEntryTranscript,
} from "./projection";
import {
  REVIEW_MEMORY_LIMITS,
  reviewDigest,
  type ReviewAuthorizationEntry,
  type ReviewManifestCall,
  type ReviewSessionRevisions,
  type ReviewStepManifest,
  type ReviewToolFacts,
  type ReviewTranscriptEntry,
  type ReviewView,
} from "./types";

export { REVIEW_MEMORY_LIMITS } from "./types";

// ---------------------------------------------------------------------------
// Injected host reader
// ---------------------------------------------------------------------------

/**
 * The subset of `SessionManager` the memory reads. A fake without
 * `buildSessionProjection` models a projection-less host; its session may only
 * be served while it is empty (declared degraded mode, §2).
 */
export interface ReviewerHostSession {
  getSessionId(): string;
  getLeafId(): string | null;
  getEntry(id: string): SessionEntry | undefined;
  getBranch(fromId?: string): SessionEntry[];
  getEntries(): SessionEntry[];
  buildSessionProjection?(): SessionProjection;
}

// ---------------------------------------------------------------------------
// Public vocabulary
// ---------------------------------------------------------------------------

/** One live tool event handed to the memory between captures (§5). */
export type ReviewToolEvent =
  | {
      readonly kind: "call";
      readonly sessionId: string;
      readonly toolCallId: string;
      readonly parentToolCallId?: string;
      readonly toolName: string;
      readonly input: unknown;
    }
  | {
      readonly kind: "result";
      readonly sessionId: string;
      readonly toolCallId: string;
      readonly toolName: string;
      readonly text: string;
      readonly isError: boolean;
    };

/** Stable reasons a capture may fail; every one is explicit and fail-closed. */
export type ReviewMemoryFailure =
  | "uninitialized"
  | "disposed"
  | "fatal"
  | "sync-failed"
  | "projection-unavailable"
  | "capacity-exceeded"
  | "invalid-owner";

/** Result of one capture: either a published frozen view or a stable failure. */
export type ReviewCaptureResult =
  | { readonly ok: true; readonly view: ReviewView; readonly revisions: ReviewSessionRevisions }
  | { readonly ok: false; readonly reason: ReviewMemoryFailure };

/** Read-only memory snapshot; never mutates the memory. */
interface ReviewerMemoryState {
  readonly initialized: boolean;
  readonly disposed: boolean;
  readonly degraded: boolean;
  readonly failure: ReviewMemoryFailure | undefined;
  readonly view: ReviewView | undefined;
  readonly historyVersion: number;
  readonly captureSeq: number;
  readonly pendingEvents: number;
}

/** The seam every reviewer-context consumer resolves a view through. */
export interface ReviewerSessionMemory {
  readonly initialized: boolean;
  readonly disposed: boolean;
  readonly degraded: boolean;
  state(): ReviewerMemoryState;
  capture(owner: string): ReviewCaptureResult;
  noteUserInput(text: string): void;
  noteNavigation(): void;
  requestHistoryRebuild(): void;
  recordToolEvent(event: ReviewToolEvent): void;
  dispose(): void;
}

interface ReviewerSessionMemoryOptions {
  readonly host: ReviewerHostSession;
  readonly now?: () => number;
  readonly limits?: Partial<typeof REVIEW_MEMORY_LIMITS>;
}

// ---------------------------------------------------------------------------
// Narrowing, freezing and capacity helpers
// ---------------------------------------------------------------------------

type JsonObject = Readonly<Record<string, unknown>>;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

/** Recursively freeze a value without copying or aliasing it. */
function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const item of Object.values(value as Record<string, unknown>)) deepFreeze(item);
  return value;
}

/** True only for values that survive a JSON round trip without loss. */
function isJsonValue(value: unknown, depth = 0): boolean {
  if (depth > 64) return false;
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (Array.isArray(value)) return value.every((item: unknown) => isJsonValue(item, depth + 1));
  if (isPlainObject(value)) {
    return Object.values(value).every((item) => item !== undefined && isJsonValue(item, depth + 1));
  }
  return false;
}

/** Deep-copy and freeze one JSON object; anything else yields `undefined`. */
function frozenJsonObject(value: unknown): JsonObject | undefined {
  if (!isPlainObject(value) || !isJsonValue(value)) return undefined;
  const copy = (input: unknown): unknown => {
    if (Array.isArray(input)) return input.map(copy);
    if (isPlainObject(input)) {
      const result: Record<string, unknown> = {};
      for (const [key, item] of Object.entries(input)) result[key] = copy(item);
      return result;
    }
    return input;
  };
  return deepFreeze(copy(value)) as JsonObject;
}

/** Canonical identity of an arbitrary event input; `undefined` when unrepresentable. */
function canonicalIdentity(value: unknown): string | undefined {
  try {
    return canonicalJson(value);
  } catch {
    return undefined;
  }
}

/** UTF-8 size of a frozen view exactly as a consumer receives it. */
function viewBytes(view: ReviewView): number {
  try {
    return Buffer.byteLength(JSON.stringify(view), "utf8");
  } catch {
    return Number.MAX_SAFE_INTEGER;
  }
}

/** A capacity override wins only as a non-negative finite number. */
function limitOption(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : fallback;
}

/** The concrete limits the memory works with (the shared object stays frozen). */
interface ReviewMemoryLimits {
  readonly maxTranscriptEntries: number;
  readonly maxAuthorizationEntries: number;
  readonly maxViewBytes: number;
  readonly maxToolEvents: number;
  readonly maxIncrementalEntries: number;
}

function mergedLimits(
  overrides: Partial<typeof REVIEW_MEMORY_LIMITS> | undefined,
): ReviewMemoryLimits {
  const input = isPlainObject(overrides) ? overrides : {};
  return Object.freeze({
    maxTranscriptEntries: limitOption(
      input.maxTranscriptEntries,
      REVIEW_MEMORY_LIMITS.maxTranscriptEntries,
    ),
    maxAuthorizationEntries: limitOption(
      input.maxAuthorizationEntries,
      REVIEW_MEMORY_LIMITS.maxAuthorizationEntries,
    ),
    maxViewBytes: limitOption(input.maxViewBytes, REVIEW_MEMORY_LIMITS.maxViewBytes),
    maxToolEvents: limitOption(input.maxToolEvents, REVIEW_MEMORY_LIMITS.maxToolEvents),
    maxIncrementalEntries: limitOption(
      input.maxIncrementalEntries,
      REVIEW_MEMORY_LIMITS.maxIncrementalEntries,
    ),
  });
}

// ---------------------------------------------------------------------------
// Host entry validation (§4: unknown entry types/roles fail explicitly)
// ---------------------------------------------------------------------------

/** How one raw host entry contributes to an incrementally synchronized view. */
type EntryDisposition = "rebuild" | "fatal" | "ignore" | "transcript" | "authorization";

/**
 * Known message roles. Evidence roles contribute transcript text (except user,
 * whose text contributes authorization); `bashExecution` is a known host
 * message that never participates in the reviewed history.
 */
const TRANSCRIPT_ROLES = new Set([
  "assistant",
  "toolResult",
  "system",
  "custom",
  "compactionSummary",
  "branchSummary",
]);

const KNOWN_ENTRY_TYPES = new Set([
  "message",
  "thinking_level_change",
  "model_change",
  "usage",
  "compaction",
  "branch_summary",
  "custom",
  "custom_message",
  "context_edit",
  "label",
  "session_info",
]);

/** Classify one raw entry; an unknown message role or entry type is fatal (§4). */
function classifyEntry(entry: SessionEntry): EntryDisposition {
  const type: unknown = entry.type;
  if (typeof type !== "string" || !KNOWN_ENTRY_TYPES.has(type)) return "fatal";
  switch (type) {
    case "message": {
      const message: unknown = (entry as { message?: unknown }).message;
      if (!isPlainObject(message)) return "fatal";
      const role: unknown = message.role;
      if (typeof role !== "string") return "fatal";
      if (role === "user") return "authorization";
      if (role === "bashExecution") return "ignore";
      return TRANSCRIPT_ROLES.has(role) ? "transcript" : "fatal";
    }
    case "custom_message":
      return "transcript";
    case "compaction":
    case "branch_summary":
    case "context_edit":
      return "rebuild";
    default:
      return "ignore";
  }
}

/** True when every entry of a full branch is one the memory can project. */
function branchIsReadable(branch: readonly SessionEntry[]): boolean {
  return branch.every((entry) => classifyEntry(entry) !== "fatal");
}

/**
 * Decide what an append-only suffix allows (§4): plain evidence can be appended,
 * a compaction/branch summary/context edit rewrites earlier history and forces a
 * rebuild, and an unknown entry or role is fatal.
 */
function suffixDisposition(branch: readonly SessionEntry[]): "append" | "rebuild" | "fatal" {
  let rebuild = false;
  for (const entry of branch) {
    const disposition = classifyEntry(entry);
    if (disposition === "fatal") return "fatal";
    if (disposition === "rebuild") rebuild = true;
  }
  return rebuild ? "rebuild" : "append";
}

/** Two authorization lists describe the same immutable user text. */
function authorizationEqual(
  left: readonly ReviewAuthorizationEntry[],
  right: readonly ReviewAuthorizationEntry[],
): boolean {
  return left.length === right.length && left.every((entry, index) => {
    const other = right[index];
    return other !== undefined && entry.id === other.id && entry.text === other.text;
  });
}

// ---------------------------------------------------------------------------
// Live tool-event records (§5)
// ---------------------------------------------------------------------------

interface CallEventRecord {
  readonly key: string;
  readonly direct: boolean;
  readonly toolCallId: string;
  readonly toolName: string;
  readonly parentToolCallId: string | undefined;
  readonly inputJson: string;
  readonly input: JsonObject | undefined;
  readonly sequence: number;
  readonly recordedAt: number;
  /** Relational validation against the view completed. */
  resolved: boolean;
  placeholder: ReviewTranscriptEntry | undefined;
}

interface ResultEventRecord {
  readonly key: string;
  readonly toolCallId: string;
  readonly toolName: string;
  readonly text: string;
  readonly isError: boolean;
  readonly sequence: number;
  readonly recordedAt: number;
  resolved: boolean;
  placeholder: ReviewTranscriptEntry | undefined;
}

type PendingEvent =
  | { readonly kind: "call"; readonly record: CallEventRecord }
  | { readonly kind: "result"; readonly record: ResultEventRecord };

/** The immutable facts one publish needs. */
interface PublishFacts {
  readonly owner: string;
  readonly sessionId: string;
  readonly leafId: string;
  readonly branchRootId: string;
  readonly historyVersion: number;
  readonly captureSeq: number;
  readonly manifest: ReviewStepManifest | undefined;
  readonly transcript: readonly ReviewTranscriptEntry[];
  readonly authorization: readonly ReviewAuthorizationEntry[];
  readonly degraded: boolean;
}

// ---------------------------------------------------------------------------
// Live-event placeholders (§5)
// ---------------------------------------------------------------------------

type EventRecord = CallEventRecord | ResultEventRecord;

function isCallRecord(record: EventRecord): record is CallEventRecord {
  return "direct" in record;
}

/** Deterministic live-event order: the injected clock first, record order second. */
function compareEventRecords(left: EventRecord, right: EventRecord): number {
  if (left.recordedAt !== right.recordedAt) return left.recordedAt - right.recordedAt;
  return left.sequence - right.sequence;
}

/**
 * Live placeholder for one registered nested call. It carries the same logical
 * entryKey (`call:<id>`) as the projection entry the host will persist later, so
 * the persisted entry replaces the placeholder without duplication.
 */
function makeCallPlaceholder(record: CallEventRecord): ReviewTranscriptEntry {
  const tool: ReviewToolFacts = {
    name: record.toolName,
    callId: record.toolCallId,
    parentCallId: record.parentToolCallId,
    part: "call",
  };
  const content = record.input ?? deepFreeze({ omitted: true });
  return deepFreeze({
    entryKey: record.key,
    kind: "tool_call",
    content,
    tool,
    edited: false,
    digest: reviewDigest({
      entryKey: record.key,
      kind: "tool_call",
      content,
      tool,
      edited: false,
    }),
  }) satisfies ReviewTranscriptEntry;
}

/**
 * Live placeholder for one tool result the host has not persisted yet. It uses
 * `result:<id>`, the same logical key as the projected result entry (§5).
 */
function makeResultPlaceholder(record: ResultEventRecord): ReviewTranscriptEntry {
  const tool: ReviewToolFacts = {
    name: record.toolName,
    callId: record.toolCallId,
    part: "result",
    ...(record.isError ? { isError: true } : {}),
  };
  return deepFreeze({
    entryKey: record.key,
    kind: "tool_result",
    content: record.text,
    tool,
    edited: false,
    digest: reviewDigest({
      entryKey: record.key,
      kind: "tool_result",
      content: record.text,
      tool,
      edited: false,
    }),
  }) satisfies ReviewTranscriptEntry;
}

// ---------------------------------------------------------------------------
// The memory
// ---------------------------------------------------------------------------

class ReviewerSessionMemoryImpl implements ReviewerSessionMemory {
  #host: ReviewerHostSession | undefined;
  readonly #nowHook: () => number;
  readonly #limits: ReviewMemoryLimits;

  #viewState: ReviewView | undefined;
  #placeholderEntries: readonly ReviewTranscriptEntry[] = Object.freeze([]);
  #placeholderKeys: ReadonlySet<string> = new Set<string>();
  #failure: ReviewMemoryFailure | undefined;
  #disposedState = false;
  #pendingRebuild = false;

  #ownerRevision = 0;
  #navigationRevision = 0;
  #authorizationRevision = 0;
  #userNoticePending = false;
  #navigationNoticePending = false;

  readonly #calls = new Map<string, CallEventRecord>();
  readonly #results = new Map<string, ResultEventRecord>();
  #pending: PendingEvent[] = [];
  #eventSequence = 0;

  constructor(options: ReviewerSessionMemoryOptions) {
    this.#host = options.host;
    this.#nowHook = typeof options.now === "function" ? options.now : () => Date.now();
    this.#limits = mergedLimits(options.limits);
  }

  get initialized(): boolean {
    return this.#viewState !== undefined;
  }

  get disposed(): boolean {
    return this.#disposedState;
  }

  get degraded(): boolean {
    return this.#viewState?.degraded === true;
  }

  state(): ReviewerMemoryState {
    return Object.freeze({
      initialized: this.#viewState !== undefined,
      disposed: this.#disposedState,
      degraded: this.#viewState?.degraded === true,
      failure: this.#failure,
      view: this.#viewState,
      historyVersion: this.#viewState?.historyVersion ?? 0,
      captureSeq: this.#viewState?.captureSeq ?? 0,
      pendingEvents: this.#pending.length,
    });
  }

  // -------------------------------------------------------------------------
  // Capture (§1, §2, §4, §5)
  // -------------------------------------------------------------------------

  capture(owner: string): ReviewCaptureResult {
    if (this.#disposedState) return { ok: false, reason: "disposed" };
    if (!nonEmptyString(owner)) return { ok: false, reason: "invalid-owner" };
    if (this.#failure !== undefined) return { ok: false, reason: this.#failure };
    if (this.#viewState === undefined) return this.#initialize(owner);
    if (this.#viewState.owner !== owner) return { ok: false, reason: "invalid-owner" };
    return this.#synchronize();
  }

  /** First capture: prefer the host projection, otherwise serve only an empty session (§2). */
  #initialize(owner: string): ReviewCaptureResult {
    const host = this.#host;
    if (host === undefined) return { ok: false, reason: "disposed" };

    let sessionId: string;
    let leafId: string | null;
    let branch: SessionEntry[];
    try {
      sessionId = host.getSessionId();
      leafId = host.getLeafId();
      branch = host.getBranch();
    } catch {
      return this.#fail("sync-failed");
    }
    if (!nonEmptyString(sessionId) || !Array.isArray(branch)) return this.#fail("sync-failed");
    if (!branchIsReadable(branch)) return this.#fail("fatal");

    const branchRootId = branch.length > 0 && typeof branch[0]?.id === "string" ? branch[0].id : null;
    const projection = this.#readProjection();
    if (projection === "sync-failed") return this.#fail("sync-failed");

    let view: ReviewView;
    try {
      if (projection === undefined) {
        if (leafId !== null || branch.length > 0) return this.#fail("projection-unavailable");
        view = degradedView({
          owner,
          sessionId,
          leafId: null,
          branchRootId: null,
          historyVersion: 0,
          captureSeq: 1,
        });
      } else {
        view = buildReviewView({
          owner,
          sessionId,
          leafId,
          branchRootId,
          historyVersion: 0,
          captureSeq: 1,
          branch,
          projection,
        });
      }
    } catch {
      return this.#fail("sync-failed");
    }

    const published = this.#publish({
      owner: view.owner,
      sessionId: view.sessionId,
      leafId: view.leafId,
      branchRootId: view.branchRootId,
      historyVersion: view.historyVersion,
      captureSeq: view.captureSeq,
      manifest: view.manifest,
      transcript: view.transcript,
      authorization: view.authorization,
      degraded: view.degraded,
    }, []);
    if (published === undefined) return { ok: false, reason: this.#failure ?? "fatal" };
    return { ok: true, view: published, revisions: this.#revisions() };
  }

  /**
   * Read the host projection when the host exposes it. `undefined` means the
   * host has no projection capability at all; `"sync-failed"` means the
   * capability exists but did not produce a usable projection.
   */
  #readProjection(): SessionProjection | undefined | "sync-failed" {
    const host = this.#host;
    if (host === undefined) return "sync-failed";
    if (typeof host.buildSessionProjection !== "function") return undefined;
    try {
      const projection: unknown = host.buildSessionProjection();
      if (!isPlainObject(projection) || !Array.isArray(projection.entries)) return "sync-failed";
      return projection as unknown as SessionProjection;
    } catch {
      return "sync-failed";
    }
  }

  /** Capture after initialization; the host state is synchronized first (§2, §4). */
  #synchronize(): ReviewCaptureResult {
    const current = this.#viewState;
    if (current === undefined) return { ok: false, reason: "uninitialized" };

    let sessionId: string;
    let leafId: string | null;
    try {
      sessionId = this.#requireHost().getSessionId();
      leafId = this.#requireHost().getLeafId();
    } catch {
      return this.#fail("sync-failed");
    }
    if (!nonEmptyString(sessionId)) return this.#fail("sync-failed");
    if (sessionId !== current.sessionId) return this.#fail("fatal");

    let candidate: PublishFacts | undefined;
    let observedUsers = 0;
    let observedNavigation = false;

    if (current.degraded) {
      // §2: a projection-less host may only serve an empty session.
      let branch: SessionEntry[];
      try {
        branch = this.#requireHost().getBranch();
      } catch {
        return this.#fail("sync-failed");
      }
      if (!Array.isArray(branch)) return this.#fail("sync-failed");
      if (leafId !== null || branch.length > 0) return this.#fail("projection-unavailable");
      if (this.#pendingRebuild) {
        const view = degradedView({
          owner: current.owner,
          sessionId: current.sessionId,
          leafId: null,
          branchRootId: null,
          historyVersion: current.historyVersion + 1,
          captureSeq: current.captureSeq + 1,
        });
        candidate = {
          owner: view.owner,
          sessionId: view.sessionId,
          leafId: view.leafId,
          branchRootId: view.branchRootId,
          historyVersion: view.historyVersion,
          captureSeq: view.captureSeq,
          manifest: view.manifest,
          transcript: view.transcript,
          authorization: view.authorization,
          degraded: view.degraded,
        };
      }
    } else if (this.#pendingRebuild) {
      const rebuilt = this.#rebuild(leafId);
      if ("failure" in rebuilt) return this.#fail(rebuilt.failure);
      candidate = rebuilt.facts;
      observedUsers = rebuilt.observedUsers;
    } else if ((leafId ?? "") !== current.leafId) {
      const walked = this.#walkSuffix(current.leafId, leafId);
      if (walked.kind === "ok") {
        const disposition = suffixDisposition(walked.entries);
        if (disposition === "fatal") return this.#fail("fatal");
        if (disposition === "append") {
          const appended = this.#appendIncremental(current, walked.entries, leafId);
          if ("failure" in appended) return this.#fail(appended.failure);
          candidate = appended.facts;
          observedUsers = appended.observedUsers;
        } else {
          const rebuilt = this.#rebuild(leafId);
          if ("failure" in rebuilt) return this.#fail(rebuilt.failure);
          candidate = rebuilt.facts;
          observedUsers = rebuilt.observedUsers;
        }
      } else {
        if (walked.kind === "disconnected") observedNavigation = true;
        const rebuilt = this.#rebuild(leafId);
        if ("failure" in rebuilt) return this.#fail(rebuilt.failure);
        candidate = rebuilt.facts;
        observedUsers = rebuilt.observedUsers;
      }
    }

    // §5: pending tool events are reconciled on every capture, including a
    // capture that would otherwise reuse the current view unchanged.
    const base = candidate ?? {
      owner: current.owner,
      sessionId: current.sessionId,
      leafId: current.leafId,
      branchRootId: current.branchRootId,
      historyVersion: current.historyVersion,
      captureSeq: current.captureSeq + 1,
      manifest: current.manifest,
      transcript: this.#stripPlaceholders(current.transcript),
      authorization: current.authorization,
      degraded: current.degraded,
    };
    const reconciled = this.#reconcileEvents(base.transcript, base.manifest, current.degraded);
    if ("failure" in reconciled) return this.#fail("fatal");

    if (candidate === undefined && this.#placeholdersEqual(reconciled.placeholders)) {
      this.#pending = [];
      this.#pendingRebuild = false;
      this.#applyObservations(0, false);
      return { ok: true, view: current, revisions: this.#revisions() };
    }

    const published = this.#publish({
      ...base,
      transcript: [...base.transcript, ...reconciled.placeholders],
    }, reconciled.placeholders);
    if (published === undefined) return { ok: false, reason: this.#failure ?? "fatal" };
    this.#applyObservations(observedUsers, observedNavigation);
    return { ok: true, view: published, revisions: this.#revisions() };
  }

  /**
   * Walk from the previous leaf along `parentId` to the new leaf (§4). A walk
   * that leaves the old path, hits a missing entry or exceeds
   * `maxIncrementalEntries` forces a full rebuild.
   */
  #walkSuffix(
    fromLeafId: string,
    toLeafId: string | null,
  ):
    | { readonly kind: "ok"; readonly entries: SessionEntry[] }
    | { readonly kind: "too-long" }
    | { readonly kind: "disconnected" } {
    if (toLeafId === null || fromLeafId.length === 0) return { kind: "disconnected" };
    const host = this.#requireHost();
    const collected: SessionEntry[] = [];
    let cursor: string | null = toLeafId;
    for (;;) {
      if (cursor === fromLeafId) return { kind: "ok", entries: collected.reverse() };
      if (collected.length >= this.#limits.maxIncrementalEntries) return { kind: "too-long" };
      if (cursor === null) return { kind: "disconnected" };
      let entry: SessionEntry | undefined;
      try {
        entry = host.getEntry(cursor);
      } catch {
        return { kind: "disconnected" };
      }
      if (entry === undefined || entry.id !== cursor) return { kind: "disconnected" };
      collected.push(entry);
      cursor = typeof entry.parentId === "string" ? entry.parentId : null;
    }
  }

  /** Extend the current view with a validated append-only suffix (§4). */
  #appendIncremental(
    current: ReviewView,
    suffix: readonly SessionEntry[],
    leafId: string | null,
  ): { readonly facts: PublishFacts; readonly observedUsers: number } | {
    readonly failure: ReviewMemoryFailure;
  } {
    const transcript = this.#stripPlaceholders(current.transcript);
    const authorization: ReviewAuthorizationEntry[] = [...current.authorization];
    let observedUsers = 0;
    try {
      for (const entry of suffix) {
        const disposition = classifyEntry(entry);
        if (disposition === "fatal") return { failure: "fatal" };
        if (disposition === "transcript") transcript.push(...projectEntryTranscript(entry));
        if (disposition === "authorization") {
          // §4: suffix user text contributes authorization, not transcript entries.
          const added = buildAuthorization([entry]);
          authorization.push(...added);
          if (added.length > 0) observedUsers += added.length;
        }
      }
      const suffixManifest = buildStepManifest({ branch: suffix, editedTargets: new Map() });
      return {
        observedUsers,
        facts: {
          owner: current.owner,
          sessionId: current.sessionId,
          leafId: leafId ?? "",
          branchRootId: current.branchRootId,
          historyVersion: current.historyVersion,
          captureSeq: current.captureSeq + 1,
          manifest: suffixManifest ?? current.manifest,
          transcript,
          authorization,
          degraded: false,
        },
      };
    } catch {
      return { failure: "sync-failed" };
    }
  }

  /** Full rebuild of the frozen view from the current host branch (§2, §3). */
  #rebuild(leafId: string | null): {
    readonly facts: PublishFacts;
    readonly observedUsers: number;
  } | { readonly failure: ReviewMemoryFailure } {
    const current = this.#viewState;
    const host = this.#host;
    if (current === undefined || host === undefined) return { failure: "uninitialized" };

    let branch: SessionEntry[];
    try {
      branch = host.getBranch();
    } catch {
      return { failure: "sync-failed" };
    }
    if (!Array.isArray(branch)) return { failure: "sync-failed" };
    if (!branchIsReadable(branch)) return { failure: "fatal" };

    const projection = this.#readProjection();
    if (projection === "sync-failed") return { failure: "sync-failed" };
    if (projection === undefined) {
      // The host advertised no projection after a projection-backed view existed.
      return { failure: "sync-failed" };
    }
    const branchRootId = branch.length > 0 && typeof branch[0]?.id === "string" ? branch[0].id : null;
    try {
      const rebuilt = buildReviewView({
        owner: current.owner,
        sessionId: current.sessionId,
        leafId,
        branchRootId,
        historyVersion: current.historyVersion + 1,
        captureSeq: current.captureSeq + 1,
        branch,
        projection,
      });
      return {
        observedUsers: authorizationEqual(current.authorization, rebuilt.authorization) ? 0 : 1,
        facts: {
          owner: rebuilt.owner,
          sessionId: rebuilt.sessionId,
          leafId: rebuilt.leafId,
          branchRootId: rebuilt.branchRootId,
          historyVersion: rebuilt.historyVersion,
          captureSeq: rebuilt.captureSeq,
          manifest: rebuilt.manifest,
          transcript: rebuilt.transcript,
          authorization: rebuilt.authorization,
          degraded: rebuilt.degraded,
        },
      };
    } catch {
      return { failure: "sync-failed" };
    }
  }

  /**
   * Reconcile live tool events with the persisted history (§5).
   *
   * Only events not yet validated against a view are checked; once a fact is
   * registered it keeps its identity for the life of the memory. Validation is
   * explicit and fail-closed: a direct event must belong to a complete manifest
   * with a matching tool name, a nested event needs a known parent and JSON
   * object input, and a result needs a known call whose tool name agrees. An
   * authoritative persisted entry is never replaced or duplicated by an event.
   * In projection-less degraded mode only the already-validated finite event
   * state is kept; events never enter the reviewed history.
   */
  #reconcileEvents(
    baseTranscript: readonly ReviewTranscriptEntry[],
    manifest: ReviewStepManifest | undefined,
    degraded: boolean,
  ): { readonly placeholders: readonly ReviewTranscriptEntry[] } | { readonly failure: "fatal" } {
    const baseByKey = new Map<string, ReviewTranscriptEntry>();
    const baseCalls = new Map<string, ReviewTranscriptEntry>();
    for (const entry of baseTranscript) {
      baseByKey.set(entry.entryKey, entry);
      const callId = entry.tool?.callId;
      if (entry.kind === "tool_call" && callId !== undefined) baseCalls.set(callId, entry);
    }
    const manifestCalls = new Map<string, ReviewManifestCall>();
    if (manifest !== undefined) {
      for (const call of manifest.directCalls) manifestCalls.set(call.toolCallId, call);
    }

    if (degraded) {
      for (const pending of this.#pending) pending.record.resolved = true;
      return { placeholders: [] };
    }

    for (const pending of this.#pending) {
      const record = pending.record;
      if (record.resolved) continue;
      const valid = isCallRecord(record)
        ? this.#validateCallRecord(record, baseByKey, baseCalls, manifest)
        : this.#validateResultRecord(record, baseByKey, baseCalls, manifestCalls);
      if (!valid) return { failure: "fatal" };
      record.resolved = true;
    }

    const records: EventRecord[] = [...this.#calls.values(), ...this.#results.values()];
    records.sort(compareEventRecords);
    const placeholders: ReviewTranscriptEntry[] = [];
    for (const record of records) {
      if (!record.resolved) return { failure: "fatal" };
      // §5: an authoritative persisted/projected entry is never replaced by an
      // earlier event, and it replaces an event placeholder without duplication.
      if (baseByKey.has(record.key)) continue;
      if (isCallRecord(record)) {
        if (record.direct) continue;
        record.placeholder ??= makeCallPlaceholder(record);
        placeholders.push(record.placeholder);
        continue;
      }
      record.placeholder ??= makeResultPlaceholder(record);
      placeholders.push(record.placeholder);
    }
    return { placeholders };
  }

  /** §5: a direct call must belong to the complete manifest and match its tool name. */
  #validateCallRecord(
    record: CallEventRecord,
    baseByKey: ReadonlyMap<string, ReviewTranscriptEntry>,
    baseCalls: ReadonlyMap<string, ReviewTranscriptEntry>,
    manifest: ReviewStepManifest | undefined,
  ): boolean {
    if (record.direct) {
      if (manifest === undefined || manifest.complete !== true) return false;
      const call = manifest.directCalls.find((candidate) => candidate.toolCallId === record.toolCallId);
      if (call === undefined || call.toolName !== record.toolName) return false;
    } else {
      const parent = record.parentToolCallId;
      if (parent === undefined) return false;
      const inManifest = manifest?.directCalls.some((candidate) => candidate.toolCallId === parent) === true;
      if (!inManifest && !this.#calls.has(parent) && !baseCalls.has(parent)) return false;
    }
    const authoritative = baseByKey.get(record.key);
    if (authoritative === undefined) return true;
    if (authoritative.kind !== "tool_call" || authoritative.tool?.name !== record.toolName) return false;
    return (authoritative.tool?.parentCallId ?? undefined) === record.parentToolCallId;
  }

  /** §5: a result must match a known call and must not contradict its tool name. */
  #validateResultRecord(
    record: ResultEventRecord,
    baseByKey: ReadonlyMap<string, ReviewTranscriptEntry>,
    baseCalls: ReadonlyMap<string, ReviewTranscriptEntry>,
    manifestCalls: ReadonlyMap<string, ReviewManifestCall>,
  ): boolean {
    const callRecord = this.#calls.get(record.toolCallId);
    const manifestCall = manifestCalls.get(record.toolCallId);
    const baseCall = baseCalls.get(record.toolCallId);
    const knownName = callRecord?.toolName ?? manifestCall?.toolName ?? baseCall?.tool?.name;
    if (knownName === undefined || knownName !== record.toolName) return false;
    const authoritative = baseByKey.get(record.key);
    if (authoritative === undefined) return true;
    return authoritative.kind === "tool_result" && authoritative.tool?.name === record.toolName;
  }

  #placeholdersEqual(next: readonly ReviewTranscriptEntry[]): boolean {
    if (next.length !== this.#placeholderEntries.length) return false;
    return next.every((entry, index) => entry === this.#placeholderEntries[index]);
  }

  #stripPlaceholders(
    transcript: readonly ReviewTranscriptEntry[],
  ): ReviewTranscriptEntry[] {
    if (this.#placeholderKeys.size === 0) return [...transcript];
    return transcript.filter((entry) => !this.#placeholderKeys.has(entry.entryKey));
  }

  // -------------------------------------------------------------------------
  // Publication and capacity (§1)
  // -------------------------------------------------------------------------

  /** Publish one frozen view; `undefined` means capacity would be exceeded. */
  #publish(
    facts: PublishFacts,
    placeholderEntries: readonly ReviewTranscriptEntry[],
  ): ReviewView | undefined {
    if (facts.transcript.length > this.#limits.maxTranscriptEntries) {
      this.#failure = "capacity-exceeded";
      return undefined;
    }
    if (facts.authorization.length > this.#limits.maxAuthorizationEntries) {
      this.#failure = "capacity-exceeded";
      return undefined;
    }
    const view = deepFreeze({
      owner: facts.owner,
      sessionId: facts.sessionId,
      historyVersion: facts.historyVersion,
      captureSeq: facts.captureSeq,
      leafId: facts.leafId,
      branchRootId: facts.branchRootId,
      ...(facts.manifest === undefined ? {} : { manifest: facts.manifest }),
      transcript: [...facts.transcript],
      authorization: [...facts.authorization],
      degraded: facts.degraded,
    }) satisfies ReviewView;
    const bytes = viewBytes(view);
    // The byte budget covers the frozen view the memory currently retains
    // (transcript, authorization and the step manifest). Earlier snapshots are
    // released by the memory once a new view is published, so publishing a
    // small view many times must not exhaust the budget.
    if (bytes > this.#limits.maxViewBytes) {
      this.#failure = "capacity-exceeded";
      return undefined;
    }
    this.#viewState = view;
    this.#placeholderEntries = Object.freeze([...placeholderEntries]);
    this.#placeholderKeys = new Set(placeholderEntries.map((entry) => entry.entryKey));
    this.#pending = [];
    this.#pendingRebuild = false;
    return view;
  }

  // -------------------------------------------------------------------------
  // Notifications (§4)
  // -------------------------------------------------------------------------

  noteUserInput(text: string): void {
    if (this.#disposedState) return;
    if (typeof text !== "string") return;
    this.#authorizationRevision += 1;
    this.#userNoticePending = true;
  }

  noteNavigation(): void {
    if (this.#disposedState) return;
    this.#navigationRevision += 1;
    this.#navigationNoticePending = true;
  }

  requestHistoryRebuild(): void {
    if (this.#disposedState) return;
    this.#pendingRebuild = true;
  }

  /**
   * Fold observed branch changes into the revision counters. An explicit host
   * notification already advanced the matching counter, so the observed entry
   * must not be counted twice.
   */
  #applyObservations(observedUsers: number, observedNavigation: boolean): void {
    if (observedUsers > 0 && !this.#userNoticePending) {
      this.#authorizationRevision += observedUsers;
    }
    this.#userNoticePending = false;
    if (observedNavigation && !this.#navigationNoticePending) {
      this.#navigationRevision += 1;
    }
    this.#navigationNoticePending = false;
  }

  // -------------------------------------------------------------------------
  // Tool events (§5)
  // -------------------------------------------------------------------------

  recordToolEvent(event: ReviewToolEvent): void {
    if (this.#disposedState) return;
    const view = this.#viewState;
    // §5: a record while the view is unusable or the memory already failed is
    // fatal; the event is never silently dropped into a healthy-looking state.
    if (view === undefined || this.#failure !== undefined) {
      this.#failure = "fatal";
      return;
    }
    const source: Record<string, unknown> = event as unknown as Record<string, unknown>;
    if (!isPlainObject(source)) {
      this.#failure = "fatal";
      return;
    }
    const kind = source.kind;
    const sessionId = source.sessionId;
    const toolCallId = source.toolCallId;
    const toolName = source.toolName;
    if (
      (kind !== "call" && kind !== "result") ||
      !nonEmptyString(sessionId) ||
      sessionId !== view.sessionId ||
      !nonEmptyString(toolCallId) ||
      !nonEmptyString(toolName)
    ) {
      this.#failure = "fatal";
      return;
    }
    const recordedAt = this.#readNow();
    const sequence = ++this.#eventSequence;
    if (kind === "call") {
      const parentValue = source.parentToolCallId;
      let parentToolCallId: string | undefined;
      if (parentValue !== undefined) {
        if (!nonEmptyString(parentValue)) {
          this.#failure = "fatal";
          return;
        }
        parentToolCallId = parentValue;
      }
      const inputJson = canonicalIdentity(source.input);
      if (inputJson === undefined) {
        this.#failure = "fatal";
        return;
      }
      const existing = this.#calls.get(toolCallId);
      if (existing !== undefined) {
        if (
          existing.toolName !== toolName ||
          existing.parentToolCallId !== parentToolCallId ||
          existing.inputJson !== inputJson
        ) {
          this.#failure = "fatal";
          return;
        }
        this.#pending.push({ kind: "call", record: existing });
        return;
      }
      if (this.#calls.size + this.#results.size >= this.#limits.maxToolEvents) {
        this.#failure = "capacity-exceeded";
        return;
      }
      const input = parentToolCallId === undefined ? undefined : frozenJsonObject(source.input);
      if (parentToolCallId !== undefined && input === undefined) {
        this.#failure = "fatal";
        return;
      }
      const record: CallEventRecord = {
        key: `call:${toolCallId}`,
        direct: parentToolCallId === undefined,
        toolCallId,
        toolName,
        parentToolCallId,
        inputJson,
        input,
        sequence,
        recordedAt,
        resolved: false,
        placeholder: undefined,
      };
      this.#calls.set(toolCallId, record);
      this.#pending.push({ kind: "call", record });
      return;
    }

    const text = source.text;
    const isError = source.isError;
    if (typeof text !== "string" || typeof isError !== "boolean") {
      this.#failure = "fatal";
      return;
    }
    const existing = this.#results.get(toolCallId);
    if (existing !== undefined) {
      if (existing.toolName !== toolName || existing.text !== text || existing.isError !== isError) {
        this.#failure = "fatal";
        return;
      }
      this.#pending.push({ kind: "result", record: existing });
      return;
    }
    if (this.#calls.size + this.#results.size >= this.#limits.maxToolEvents) {
      this.#failure = "capacity-exceeded";
      return;
    }
    const result: ResultEventRecord = {
      key: `result:${toolCallId}`,
      toolCallId,
      toolName,
      text,
      isError,
      sequence,
      recordedAt,
      resolved: false,
      placeholder: undefined,
    };
    this.#results.set(toolCallId, result);
    this.#pending.push({ kind: "result", record: result });
  }

  // -------------------------------------------------------------------------
  // Disposal (§5)
  // -------------------------------------------------------------------------

  dispose(): void {
    if (this.#disposedState) return;
    this.#disposedState = true;
    this.#host = undefined;
    this.#viewState = undefined;
    this.#placeholderEntries = Object.freeze([]);
    this.#placeholderKeys = new Set<string>();
    this.#failure = undefined;
    this.#pendingRebuild = false;
    this.#ownerRevision = 0;
    this.#navigationRevision = 0;
    this.#authorizationRevision = 0;
    this.#userNoticePending = false;
    this.#navigationNoticePending = false;
    this.#calls.clear();
    this.#results.clear();
    this.#pending = [];
    this.#eventSequence = 0;
  }

  // -------------------------------------------------------------------------
  // Internal helpers
  // -------------------------------------------------------------------------

  #requireHost(): ReviewerHostSession {
    const host = this.#host;
    if (host === undefined) throw new Error("disposed");
    return host;
  }

  #readNow(): number {
    try {
      const value = this.#nowHook();
      return typeof value === "number" && Number.isFinite(value) ? value : 0;
    } catch {
      return 0;
    }
  }

  #fail(reason: ReviewMemoryFailure): ReviewCaptureResult {
    this.#failure = reason;
    return { ok: false, reason };
  }

  #revisions(): ReviewSessionRevisions {
    return Object.freeze({
      owner: this.#ownerRevision,
      navigation: this.#navigationRevision,
      authorization: this.#authorizationRevision,
    });
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createReviewerSessionMemory(options: {
  readonly host: ReviewerHostSession;
  readonly now?: () => number;
  readonly limits?: Partial<typeof REVIEW_MEMORY_LIMITS>;
}): ReviewerSessionMemory {
  return new ReviewerSessionMemoryImpl(options);
}
