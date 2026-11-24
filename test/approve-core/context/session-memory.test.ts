/**
 * Phase 11 reviewer session memory (specs/reviewer-context.md §1, §2, §4, §5).
 *
 * Every fixture is a real host entry shape (`SessionEntry`, `SessionProjection`,
 * `AssistantMessage`, `ToolResultMessage`, ...). The host reader and the clock
 * are injected fakes; no module internals are mocked. Expected values are
 * worked examples written from the spec, never recomputed from the
 * implementation.
 */
import { describe, expect, it, vi } from "vitest";
import type {
  BranchSummaryEntry,
  CompactionEntry,
  CustomEntry,
  CustomMessageEntry,
  ModelChangeEntry,
  ProjectedSessionEntry,
  SessionEntry,
  SessionInfoEntry,
  SessionMessageEntry,
  SessionProjection,
  ThinkingLevelChangeEntry,
} from "@earendil-works/pi-coding-agent";
import type {
  AssistantMessage,
  SystemMessage,
  TextContent,
  ToolCall,
  ToolResultMessage,
  UserMessage,
} from "@earendil-works/pi-ai";
import {
  REVIEW_MEMORY_LIMITS as SHARED_LIMITS,
  reviewDigest,
  type ReviewTranscriptEntry,
  type ReviewView,
} from "#approve-core/context/types";
import {
  createReviewerSessionMemory,
  REVIEW_MEMORY_LIMITS,
  type ReviewerHostSession,
  type ReviewerSessionMemory,
  type ReviewToolEvent,
} from "#approve-core/context/session-memory";

// ---------------------------------------------------------------------------
// Real host fixture helpers
// ---------------------------------------------------------------------------

const ENTRY_STAMP = "2026-01-01T00:00:00.000Z";
const MESSAGE_STAMP = 1_000;

function messageEntry(
  id: string,
  message: SessionMessageEntry["message"],
  parentId: string | null = null,
): SessionMessageEntry {
  return { type: "message", id, parentId, timestamp: ENTRY_STAMP, message };
}

function userMessage(content: UserMessage["content"]): UserMessage {
  return { role: "user", content, timestamp: MESSAGE_STAMP };
}

function messageUsage(): AssistantMessage["usage"] {
  return {
    input: 10,
    output: 5,
    cacheRead: 0,
    cacheWrite: 0,
    totalTokens: 15,
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
  };
}

function assistantMessage(
  content: AssistantMessage["content"],
  overrides: Partial<AssistantMessage> = {},
): AssistantMessage {
  return {
    role: "assistant",
    content,
    api: "anthropic-messages",
    provider: "anthropic",
    model: "test-model",
    usage: messageUsage(),
    stopReason: "toolUse",
    timestamp: MESSAGE_STAMP,
    ...overrides,
  };
}

function toolCall(id: string, name: string, args: unknown): ToolCall {
  return { type: "toolCall", id, name, arguments: args as ToolCall["arguments"] };
}

function toolResultMessage(
  toolCallId: string,
  toolName: string,
  text: string,
  overrides: Partial<ToolResultMessage> = {},
): ToolResultMessage {
  return {
    role: "toolResult",
    toolCallId,
    toolName,
    content: [{ type: "text", text }],
    isError: false,
    timestamp: MESSAGE_STAMP,
    ...overrides,
  };
}

function systemMessage(content: string | TextContent[]): SystemMessage {
  return { role: "system", content, timestamp: MESSAGE_STAMP };
}

function compactionEntry(
  id: string,
  summary: string,
  overrides: Partial<CompactionEntry> = {},
): CompactionEntry {
  return {
    type: "compaction",
    id,
    parentId: null,
    timestamp: ENTRY_STAMP,
    summary,
    firstKeptEntryId: "kept-1",
    tokensBefore: 1_234,
    ...overrides,
  };
}

function branchSummaryEntry(id: string, summary: string): BranchSummaryEntry {
  return {
    type: "branch_summary",
    id,
    parentId: null,
    timestamp: ENTRY_STAMP,
    fromId: "abandoned-leaf",
    summary,
  };
}

function customMessageEntry(id: string, content: CustomMessageEntry["content"]): CustomMessageEntry {
  return {
    type: "custom_message",
    id,
    parentId: null,
    timestamp: ENTRY_STAMP,
    customType: "test-extension",
    content,
    display: true,
  };
}

type UsageEntryFixture = Extract<SessionEntry, { type: "usage" }>;
type LabelEntryFixture = Extract<SessionEntry, { type: "label" }>;

function usageEntry(id: string): UsageEntryFixture {
  return {
    type: "usage",
    id,
    parentId: null,
    timestamp: ENTRY_STAMP,
    kind: "cache_warm",
    provider: "anthropic",
    model: "test-model",
    usage: messageUsage(),
  };
}

function modelChangeEntry(id: string): ModelChangeEntry {
  return {
    type: "model_change",
    id,
    parentId: null,
    timestamp: ENTRY_STAMP,
    provider: "anthropic",
    modelId: "other-model",
  };
}

function thinkingLevelChangeEntry(id: string): ThinkingLevelChangeEntry {
  return {
    type: "thinking_level_change",
    id,
    parentId: null,
    timestamp: ENTRY_STAMP,
    thinkingLevel: "high",
  };
}

function labelEntry(id: string, targetId: string): LabelEntryFixture {
  return { type: "label", id, parentId: null, timestamp: ENTRY_STAMP, targetId, label: "bookmark" };
}

function sessionInfoEntry(id: string): SessionInfoEntry {
  return { type: "session_info", id, parentId: null, timestamp: ENTRY_STAMP, name: "named session" };
}

function customEntry(id: string): CustomEntry {
  return {
    type: "custom",
    id,
    parentId: null,
    timestamp: ENTRY_STAMP,
    customType: "test-extension",
    data: { hidden: true },
  };
}

// ---------------------------------------------------------------------------
// Injected host reader
// ---------------------------------------------------------------------------

type ProjectedMessage = SessionProjection["entries"][number]["messages"][number];

function projectedMessages(entry: SessionEntry): ProjectedMessage[] {
  switch (entry.type) {
    case "message":
      return [entry.message];
    case "custom_message":
      return [{
        role: "custom",
        customType: entry.customType,
        content: entry.content,
        display: entry.display,
        timestamp: MESSAGE_STAMP,
      }];
    case "compaction":
      return [{
        role: "compactionSummary",
        summary: entry.summary,
        tokensBefore: entry.tokensBefore,
        timestamp: MESSAGE_STAMP,
      }];
    case "branch_summary":
      return [{
        role: "branchSummary",
        summary: entry.summary,
        fromId: entry.fromId,
        timestamp: MESSAGE_STAMP,
      }];
    default:
      return [];
  }
}

/** Identity projection: every branch entry keeps its raw contribution. */
function identityProjection(branch: readonly SessionEntry[]): SessionProjection {
  const entries: ProjectedSessionEntry[] = branch.map((entry) => ({
    sourceEntry: entry,
    messages: projectedMessages(entry),
  }));
  return {
    entries,
    messages: entries.flatMap((entry) => entry.messages),
    thinkingLevel: "off",
    model: { provider: "anthropic", modelId: "test-model" },
  };
}

class FakeHostState {
  sessionId: string;
  leafId: string | null = null;
  readonly byId = new Map<string, SessionEntry>();
  readonly reads: string[] = [];
  projectionMode: "identity" | "none" | "throw";
  fixedProjection: SessionProjection | undefined;
  readonly throwing = new Set<string>();

  constructor(options: { sessionId?: string; projection?: "identity" | "none" | "throw" } = {}) {
    this.sessionId = options.sessionId ?? "session-1";
    this.projectionMode = options.projection ?? "identity";
  }

  /** Append a child of the current leaf and advance the leaf. */
  append<T extends SessionEntry>(entry: T): T {
    const next = { ...entry, parentId: this.leafId } as T;
    this.byId.set(next.id, next);
    this.leafId = next.id;
    return next;
  }

  /** Insert an entry without moving the leaf (broken chain / branch fixtures). */
  insert(entry: SessionEntry): void {
    this.byId.set(entry.id, entry);
  }

  setLeaf(leafId: string | null): void {
    this.leafId = leafId;
  }

  /** Root-to-leaf path of the current (or given) leaf. */
  branch(fromId?: string | null): SessionEntry[] {
    let cursor = fromId === undefined ? this.leafId : fromId;
    const path: SessionEntry[] = [];
    const seen = new Set<string>();
    while (cursor !== null && cursor !== undefined) {
      const entry = this.byId.get(cursor);
      if (entry === undefined || seen.has(entry.id)) break;
      seen.add(entry.id);
      path.push(entry);
      cursor = entry.parentId;
    }
    return path.reverse();
  }

  projection(): SessionProjection {
    return this.fixedProjection ?? identityProjection(this.branch());
  }
}

function reader(state: FakeHostState): ReviewerHostSession {
  const guard = (name: string): void => {
    state.reads.push(name);
    if (state.throwing.has(name)) throw new Error(`host ${name} failed`);
  };
  const base: ReviewerHostSession = {
    getSessionId: () => {
      guard("getSessionId");
      return state.sessionId;
    },
    getLeafId: () => {
      guard("getLeafId");
      return state.leafId;
    },
    getEntry: (id) => {
      guard("getEntry");
      return state.byId.get(id);
    },
    getBranch: (fromId) => {
      guard("getBranch");
      return state.branch(fromId);
    },
    getEntries: () => {
      guard("getEntries");
      return [...state.byId.values()];
    },
  };
  if (state.projectionMode === "none") return base;
  return {
    ...base,
    buildSessionProjection: () => {
      guard("buildSessionProjection");
      if (state.projectionMode === "throw") throw new Error("host projection failed");
      return state.projection();
    },
  };
}

function createMemory(
  state: FakeHostState,
  options: { now?: () => number; limits?: Record<string, number> } = {},
): ReviewerSessionMemory {
  return createReviewerSessionMemory({
    host: reader(state),
    now: options.now ?? (() => 1),
    ...(options.limits === undefined ? {} : { limits: options.limits }),
  });
}

function captureView(memory: ReviewerSessionMemory, owner = "owner-1") {
  const result = memory.capture(owner);
  if (!result.ok) throw new Error(`capture failed: ${result.reason}`);
  return result;
}

function failureOf(memory: ReviewerSessionMemory, owner = "owner-1"): string {
  const result = memory.capture(owner);
  return result.ok ? "ok" : result.reason;
}

// ---------------------------------------------------------------------------
// §1/§2 initialization
// ---------------------------------------------------------------------------

describe("session memory initialization", () => {
  it("initializes from the host projection and publishes a frozen view with manifest and authorization", () => {
    const state = new FakeHostState({ projection: "identity" });
    state.append(messageEntry("u1", userMessage("please list the files")));
    state.append(messageEntry("a1", assistantMessage([
      { type: "text", text: "listing" },
      toolCall("call-1", "bash", { command: "ls" }),
    ])));
    const memory = createMemory(state);
    const result = captureView(memory);

    expect(result.view.owner).toBe("owner-1");
    expect(result.view.sessionId).toBe("session-1");
    expect(result.view.leafId).toBe("a1");
    expect(result.view.branchRootId).toBe("u1");
    expect(result.view.historyVersion).toBe(0);
    expect(result.view.captureSeq).toBe(1);
    expect(result.view.degraded).toBe(false);
    expect(result.view.transcript.map((entry) => [entry.entryKey, entry.kind, entry.content])).toEqual([
      ["u1:user:0", "user", "please list the files"],
      ["a1:assistant:0", "assistant", "listing"],
      ["call:call-1", "tool_call", { command: "ls" }],
    ]);
    expect(result.view.manifest).toEqual({
      stepKey: "step-a1",
      sourceEntryId: "a1",
      revision: 0,
      complete: true,
      directCalls: [{
        toolCallId: "call-1",
        toolName: "bash",
        arguments: { command: "ls" },
        argumentsDigest: reviewDigest({ command: "ls" }),
      }],
    });
    expect(result.view.authorization).toEqual([
      { id: "auth:u1", sourceEntryId: "u1", text: "please list the files" },
    ]);
    expect(result.revisions).toEqual({ owner: 0, navigation: 0, authorization: 0 });
  });

  it("freezes the view, its transcript entries, authorization and manifest", () => {
    const state = new FakeHostState();
    state.append(messageEntry("u1", userMessage("go")));
    state.append(messageEntry("a1", assistantMessage([toolCall("call-1", "bash", { command: "ls" })])));
    const { view } = captureView(createMemory(state));

    expect(Object.isFrozen(view)).toBe(true);
    expect(Object.isFrozen(view.transcript)).toBe(true);
    expect(Object.isFrozen(view.transcript[0])).toBe(true);
    expect(Object.isFrozen(view.authorization)).toBe(true);
    expect(Object.isFrozen(view.authorization[0])).toBe(true);
    expect(Object.isFrozen(view.manifest)).toBe(true);
    expect(Object.isFrozen(view.manifest?.directCalls)).toBe(true);
    expect(Object.isFrozen(view.manifest?.directCalls[0]?.arguments)).toBe(true);
  });

  it("publishes an empty, non-degraded view for an empty session when the host has a projection", () => {
    const state = new FakeHostState({ projection: "identity" });
    const { view } = captureView(createMemory(state));

    expect(view.transcript).toEqual([]);
    expect(view.authorization).toEqual([]);
    expect(view.manifest).toBeUndefined();
    expect(view.degraded).toBe(false);
    expect(view.leafId).toBe("");
    expect(view.branchRootId).toBe("");
  });

  it("initializes a projection-less empty session in declared degraded mode", () => {
    const state = new FakeHostState({ projection: "none" });
    const memory = createMemory(state);
    const { view } = captureView(memory);

    expect(view.degraded).toBe(true);
    expect(memory.degraded).toBe(true);
    expect(view.historyVersion).toBe(0);
    expect(view.captureSeq).toBe(1);
    expect(view.leafId).toBe("");
    expect(view.branchRootId).toBe("");
    expect(view.manifest).toBeUndefined();
    expect(view.authorization).toEqual([]);
    expect(view.transcript).toHaveLength(1);
    expect(view.transcript[0]?.entryKey).toBe("environment:degraded");
    expect(view.transcript[0]?.kind).toBe("environment_checkpoint");
    expect(view.transcript[0]?.content).toContain("not part of the reviewed history");
  });

  it("fails initialization with projection-unavailable for a non-empty projection-less session", () => {
    const state = new FakeHostState({ projection: "none" });
    state.append(messageEntry("u1", userMessage("hello")));
    const memory = createMemory(state);

    expect(memory.capture("owner-1")).toEqual({ ok: false, reason: "projection-unavailable" });
    expect(memory.initialized).toBe(false);
    expect(memory.state().failure).toBe("projection-unavailable");
    expect(memory.capture("owner-1")).toEqual({ ok: false, reason: "projection-unavailable" });
  });

  it("fails initialization with projection-unavailable when an empty branch still has a leaf", () => {
    const state = new FakeHostState({ projection: "none" });
    state.setLeaf("ghost-leaf");
    const memory = createMemory(state);
    expect(memory.capture("owner-1")).toEqual({ ok: false, reason: "projection-unavailable" });
  });

  it("fails with sync-failed when the host branch reader throws", () => {
    const state = new FakeHostState();
    state.append(messageEntry("u1", userMessage("hello")));
    state.throwing.add("getBranch");
    const memory = createMemory(state);

    expect(memory.capture("owner-1")).toEqual({ ok: false, reason: "sync-failed" });
    expect(memory.state().failure).toBe("sync-failed");
    expect(failureOf(memory)).toBe("sync-failed");
  });

  it("fails with sync-failed when the host projection throws", () => {
    const state = new FakeHostState({ projection: "throw" });
    state.append(messageEntry("u1", userMessage("hello")));
    const memory = createMemory(state);
    expect(memory.capture("owner-1")).toEqual({ ok: false, reason: "sync-failed" });
  });

  it("fails with sync-failed when the host reports an empty session id", () => {
    const state = new FakeHostState({ sessionId: "" });
    const memory = createMemory(state);
    expect(memory.capture("owner-1")).toEqual({ ok: false, reason: "sync-failed" });
  });

  it("rejects an empty owner without poisoning the memory", () => {
    const state = new FakeHostState();
    state.append(messageEntry("u1", userMessage("hi")));
    const memory = createMemory(state);

    expect(memory.capture("")).toEqual({ ok: false, reason: "invalid-owner" });
    expect(memory.capture("   ")).toEqual({ ok: false, reason: "invalid-owner" });
    expect(memory.state().failure).toBeUndefined();
    expect(memory.initialized).toBe(false);
    expect(memory.capture("owner-1").ok).toBe(true);
  });

  it("rejects a different owner after initialization without publishing", () => {
    const state = new FakeHostState();
    state.append(messageEntry("u1", userMessage("hi")));
    const memory = createMemory(state);
    const first = captureView(memory);

    expect(memory.capture("owner-2")).toEqual({ ok: false, reason: "invalid-owner" });
    expect(memory.state().view).toBe(first.view);
    expect(memory.state().failure).toBeUndefined();
  });

  it("state() before the first capture is uninitialized", () => {
    const memory = createMemory(new FakeHostState());
    expect(memory.initialized).toBe(false);
    expect(memory.disposed).toBe(false);
    expect(memory.degraded).toBe(false);
    expect(memory.state()).toEqual({
      initialized: false,
      disposed: false,
      degraded: false,
      failure: undefined,
      view: undefined,
      historyVersion: 0,
      captureSeq: 0,
      pendingEvents: 0,
    });
  });

  it("state() reports the published view, counters and no pending events", () => {
    const state = new FakeHostState();
    state.append(messageEntry("u1", userMessage("hi")));
    const memory = createMemory(state);
    const { view } = captureView(memory);
    const snapshot = memory.state();

    expect(snapshot.initialized).toBe(true);
    expect(snapshot.failure).toBeUndefined();
    expect(snapshot.view).toBe(view);
    expect(snapshot.historyVersion).toBe(0);
    expect(snapshot.captureSeq).toBe(1);
    expect(snapshot.pendingEvents).toBe(0);
    expect(Object.isFrozen(snapshot)).toBe(true);
  });

  it("reuses the exact same view object while the host leaf is unchanged", () => {
    const state = new FakeHostState();
    state.append(messageEntry("u1", userMessage("hi")));
    const memory = createMemory(state);
    const first = captureView(memory);
    const second = captureView(memory);

    expect(second.view).toBe(first.view);
    expect(second.revisions).toEqual(first.revisions);
    expect(memory.state().captureSeq).toBe(1);
  });

  it("re-exports the shared REVIEW_MEMORY_LIMITS object", () => {
    expect(REVIEW_MEMORY_LIMITS).toBe(SHARED_LIMITS);
    expect(REVIEW_MEMORY_LIMITS.maxTranscriptEntries).toBe(8_192);
    expect(REVIEW_MEMORY_LIMITS.maxAuthorizationEntries).toBe(2_048);
    expect(REVIEW_MEMORY_LIMITS.maxViewBytes).toBe(16 * 1024 * 1024);
    expect(REVIEW_MEMORY_LIMITS.maxToolEvents).toBe(8_192);
    expect(REVIEW_MEMORY_LIMITS.maxIncrementalEntries).toBe(4_096);
  });
});

// ---------------------------------------------------------------------------
// Lifecycle: dispose
// ---------------------------------------------------------------------------

describe("session memory dispose", () => {
  it("dispose clears the view, counters, pending events and host reader", () => {
    const state = new FakeHostState();
    state.append(messageEntry("u1", userMessage("hi")));
    const memory = createMemory(state);
    captureView(memory);
    memory.noteUserInput("next");
    memory.requestHistoryRebuild();

    memory.dispose();
    expect(memory.disposed).toBe(true);
    expect(memory.initialized).toBe(false);
    expect(memory.degraded).toBe(false);
    expect(memory.state()).toEqual({
      initialized: false,
      disposed: true,
      degraded: false,
      failure: undefined,
      view: undefined,
      historyVersion: 0,
      captureSeq: 0,
      pendingEvents: 0,
    });
  });

  it("fails every capture after dispose with disposed", () => {
    const memory = createMemory(new FakeHostState());
    memory.dispose();
    expect(memory.capture("owner-1")).toEqual({ ok: false, reason: "disposed" });
    expect(memory.capture("")).toEqual({ ok: false, reason: "disposed" });
  });

  it("is idempotent and ignores notes and tool events after dispose", () => {
    const memory = createMemory(new FakeHostState());
    memory.dispose();
    memory.dispose();
    memory.noteUserInput("ignored");
    memory.noteNavigation();
    memory.requestHistoryRebuild();
    memory.recordToolEvent({
      kind: "call",
      sessionId: "session-1",
      toolCallId: "call-1",
      toolName: "bash",
      input: { command: "ls" },
    });
    expect(memory.state().pendingEvents).toBe(0);
    expect(memory.capture("owner-1")).toEqual({ ok: false, reason: "disposed" });
  });

  it("never consults the host reader after dispose", () => {
    const state = new FakeHostState();
    state.append(messageEntry("u1", userMessage("hi")));
    const memory = createMemory(state);
    captureView(memory);
    memory.dispose();
    state.reads.length = 0;
    expect(memory.capture("owner-1")).toEqual({ ok: false, reason: "disposed" });
    expect(state.reads).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// §4 revisions
// ---------------------------------------------------------------------------

function seededMemory(
  state: FakeHostState,
  options: { now?: () => number; limits?: Record<string, number> } = {},
): ReviewerSessionMemory {
  state.append(messageEntry("u1", userMessage("first request")));
  state.append(messageEntry("a1", assistantMessage([{ type: "text", text: "first answer" }])));
  return createMemory(state, options);
}

describe("session revisions", () => {
  it("advances the authorization revision on user input and reports it from the next capture", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    const first = captureView(memory);
    memory.noteUserInput("second request");
    const second = captureView(memory);

    expect(second.revisions).toEqual({ owner: 0, navigation: 0, authorization: 1 });
    expect(second.view).toBe(first.view);
  });

  it("advances the authorization revision once per notified input", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    captureView(memory);
    memory.noteUserInput("one");
    memory.noteUserInput("two");
    expect(captureView(memory).revisions.authorization).toBe(2);
  });

  it("advances the navigation revision on navigation", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    captureView(memory);
    memory.noteNavigation();
    expect(captureView(memory).revisions).toEqual({ owner: 0, navigation: 1, authorization: 0 });
  });

  it("applies notifications made before the first capture to the initial revisions", () => {
    const state = new FakeHostState();
    state.append(messageEntry("u1", userMessage("first request")));
    const memory = createMemory(state);
    memory.noteUserInput("queued");
    memory.noteNavigation();
    expect(captureView(memory).revisions).toEqual({ owner: 0, navigation: 1, authorization: 1 });
  });

  it("does not infer a notified user entry twice: it advances the authorization revision once", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    captureView(memory);
    memory.noteUserInput("second request");
    state.append(messageEntry("u2", userMessage("second request")));
    const second = captureView(memory);

    expect(second.revisions.authorization).toBe(1);
    expect(second.view.authorization.map((entry) => entry.id)).toEqual(["auth:u1", "auth:u2"]);
  });

  it("advances the authorization revision when an unnotified user entry joins the branch", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    captureView(memory);
    state.append(messageEntry("u2", userMessage("second request")));
    expect(captureView(memory).revisions.authorization).toBe(1);
  });

  it("advances the navigation revision when the leaf moves to a different branch without a notification", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    captureView(memory);
    state.setLeaf("u1");
    state.append(messageEntry("a1b", assistantMessage([{ type: "text", text: "other branch" }])));
    const second = captureView(memory);

    expect(second.view.historyVersion).toBe(1);
    expect(second.revisions).toEqual({ owner: 0, navigation: 1, authorization: 0 });
  });

  it("does not treat a notified branch switch as an extra navigation revision", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    captureView(memory);
    memory.noteNavigation();
    state.setLeaf("u1");
    state.append(messageEntry("a1b", assistantMessage([{ type: "text", text: "other branch" }])));
    expect(captureView(memory).revisions.navigation).toBe(1);
  });

  it("does not treat a descendant rebuild as navigation", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    captureView(memory);
    state.append(compactionEntry("cp1", "compacted history"));
    const second = captureView(memory);

    expect(second.view.historyVersion).toBe(1);
    expect(second.revisions.navigation).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// §4 requested rebuilds and capture sequencing
// ---------------------------------------------------------------------------

describe("history rebuild requests", () => {
  it("defers a requested rebuild until the next capture", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    const first = captureView(memory);
    memory.requestHistoryRebuild();

    expect(memory.state().historyVersion).toBe(0);
    expect(memory.state().captureSeq).toBe(1);
    const second = captureView(memory);
    expect(second.view).not.toBe(first.view);
    expect(second.view.historyVersion).toBe(1);
    expect(second.view.captureSeq).toBe(2);
    expect(second.view.transcript).toEqual(first.view.transcript);
    expect(second.view.authorization).toEqual(first.view.authorization);
  });

  it("performs exactly one rebuild for repeated requests before a capture", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    captureView(memory);
    memory.requestHistoryRebuild();
    memory.requestHistoryRebuild();
    expect(captureView(memory).view.historyVersion).toBe(1);
  });

  it("consumes the rebuild request once", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    captureView(memory);
    memory.requestHistoryRebuild();
    const rebuilt = captureView(memory);
    const third = captureView(memory);
    expect(third.view).toBe(rebuilt.view);
    expect(third.view.historyVersion).toBe(1);
  });

  it("increments captureSeq on every publish and historyVersion only on a rebuild", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);

    expect(captureView(memory).view.captureSeq).toBe(1);
    state.append(messageEntry("a2", assistantMessage([{ type: "text", text: "next" }])));
    const appended = captureView(memory);
    expect(appended.view.captureSeq).toBe(2);
    expect(appended.view.historyVersion).toBe(0);
    memory.requestHistoryRebuild();
    const rebuilt = captureView(memory);
    expect(rebuilt.view.captureSeq).toBe(3);
    expect(rebuilt.view.historyVersion).toBe(1);
    state.append(messageEntry("a3", assistantMessage([{ type: "text", text: "again" }])));
    const appendedAgain = captureView(memory);
    expect(appendedAgain.view.captureSeq).toBe(4);
    expect(appendedAgain.view.historyVersion).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// §4 incremental suffix synchronization
// ---------------------------------------------------------------------------

describe("incremental suffix synchronization", () => {
  it("appends a user message: authorization only, no transcript entry", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    const first = captureView(memory);
    state.append(messageEntry("u2", userMessage("second request")));
    const second = captureView(memory);

    expect(second.view).not.toBe(first.view);
    expect(second.view.captureSeq).toBe(2);
    expect(second.view.historyVersion).toBe(0);
    expect(second.view.leafId).toBe("u2");
    expect(second.view.authorization).toEqual([
      { id: "auth:u1", sourceEntryId: "u1", text: "first request" },
      { id: "auth:u2", sourceEntryId: "u2", text: "second request" },
    ]);
    expect(second.view.transcript.map((entry) => entry.entryKey))
      .toEqual(first.view.transcript.map((entry) => entry.entryKey));
  });

  it("appends an assistant message and refreshes the step manifest", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    const first = captureView(memory);
    state.append(messageEntry("a2", assistantMessage([
      { type: "text", text: "second answer" },
      toolCall("call-2", "read", { path: "a.txt" }),
    ])));
    const second = captureView(memory);

    expect(second.view.transcript.map((entry) => entry.entryKey)).toEqual([
      ...first.view.transcript.map((entry) => entry.entryKey),
      "a2:assistant:0",
      "call:call-2",
    ]);
    expect(second.view.manifest).toEqual({
      stepKey: "step-a2",
      sourceEntryId: "a2",
      revision: 0,
      complete: true,
      directCalls: [{
        toolCallId: "call-2",
        toolName: "read",
        arguments: { path: "a.txt" },
        argumentsDigest: reviewDigest({ path: "a.txt" }),
      }],
    });
    expect(second.view.historyVersion).toBe(0);
  });

  it("appends a tool result without changing the step manifest", () => {
    const state = new FakeHostState();
    state.append(messageEntry("u1", userMessage("read it")));
    state.append(messageEntry("a1", assistantMessage([toolCall("call-1", "read", { path: "a.txt" })])));
    const memory = createMemory(state);
    const first = captureView(memory);
    state.append(messageEntry("r1", toolResultMessage("call-1", "read", "file contents")));
    const second = captureView(memory);

    expect(second.view.transcript.map((entry) => [entry.entryKey, entry.kind, entry.content])).toEqual([
      ...first.view.transcript.map((entry) => [entry.entryKey, entry.kind, entry.content]),
      ["result:call-1", "tool_result", "file contents"],
    ]);
    expect(second.view.manifest).toEqual(first.view.manifest);
  });

  it("appends a system message as an environment checkpoint", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    captureView(memory);
    state.append(messageEntry("s1", systemMessage("tools changed")));
    const entries = captureView(memory).view.transcript;
    expect(entries[entries.length - 1]).toMatchObject({
      entryKey: "s1:environment_checkpoint:0",
      kind: "environment_checkpoint",
      content: "tools changed",
    });
  });

  it("appends a custom message as an extension entry", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    captureView(memory);
    state.append(customMessageEntry("cm1", [{ type: "text", text: "extension says" }]));
    const entries = captureView(memory).view.transcript;
    expect(entries[entries.length - 1]).toMatchObject({
      entryKey: "cm1:extension:0",
      kind: "extension",
      content: "extension says",
    });
  });

  it("appends a batch of suffix entries in branch order", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    captureView(memory);
    state.append(messageEntry("u2", userMessage("second request")));
    state.append(messageEntry("a2", assistantMessage([{ type: "text", text: "second answer" }])));
    state.append(messageEntry("r2", toolResultMessage("call-9", "bash", "done")));
    const second = captureView(memory);

    expect(second.view.authorization.map((entry) => entry.id)).toEqual(["auth:u1", "auth:u2"]);
    expect(second.view.transcript.slice(2).map((entry) => entry.entryKey)).toEqual([
      "a2:assistant:0",
      "result:call-9",
    ]);
  });

  it("publishes a new view for state-only suffix entries without changing the history", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    const first = captureView(memory);
    state.append(usageEntry("us1"));
    state.append(modelChangeEntry("mc1"));
    state.append(thinkingLevelChangeEntry("tl1"));
    state.append(labelEntry("lb1", "u1"));
    state.append(sessionInfoEntry("si1"));
    state.append(customEntry("cu1"));
    const second = captureView(memory);

    expect(second.view).not.toBe(first.view);
    expect(second.view.captureSeq).toBe(2);
    expect(second.view.historyVersion).toBe(0);
    expect(second.view.leafId).toBe("cu1");
    expect(second.view.transcript).toEqual(first.view.transcript);
    expect(second.view.authorization).toEqual(first.view.authorization);
  });

  it("produces the same history as a full rebuild for an append-only branch", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    captureView(memory);
    state.append(messageEntry("a2", assistantMessage([
      { type: "text", text: "second answer" },
      toolCall("call-2", "read", { path: "a.txt" }),
    ])));
    state.append(messageEntry("r2", toolResultMessage("call-2", "read", "contents")));
    state.append(messageEntry("s2", systemMessage("environment note")));
    const incremental = captureView(memory).view;

    const fresh = new FakeHostState();
    for (const entry of state.branch()) fresh.append(entry);
    const rebuilt = captureView(createMemory(fresh)).view;

    expect(incremental.transcript).toEqual(rebuilt.transcript);
    expect(incremental.authorization).toEqual(rebuilt.authorization);
    expect(incremental.manifest).toEqual(rebuilt.manifest);
    expect(incremental.leafId).toBe(rebuilt.leafId);
    expect(incremental.branchRootId).toBe(rebuilt.branchRootId);
  });

  it("keeps an empty user message out of authorization but still publishes the new leaf", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    const first = captureView(memory);
    state.append(messageEntry("u2", userMessage("   ")));
    const second = captureView(memory);

    expect(second.view.captureSeq).toBe(2);
    expect(second.view.leafId).toBe("u2");
    expect(second.view.authorization).toEqual(first.view.authorization);
  });

  it("falls back to a full rebuild when the parent chain is broken", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    captureView(memory);
    state.insert({
      type: "message",
      id: "x1",
      parentId: "missing-parent",
      timestamp: ENTRY_STAMP,
      message: userMessage("orphan"),
    });
    state.setLeaf("x1");
    const second = captureView(memory);

    expect(second.view.historyVersion).toBe(1);
    expect(second.view.leafId).toBe("x1");
    expect(second.view.branchRootId).toBe("x1");
    expect(second.view.transcript.map((entry) => entry.entryKey)).toEqual(["x1:user:0"]);
  });

  it("falls back to a full rebuild when the leaf moves to a different branch", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    captureView(memory);
    state.setLeaf("u1");
    state.append(messageEntry("a1b", assistantMessage([{ type: "text", text: "other branch" }])));
    const second = captureView(memory);

    expect(second.view.historyVersion).toBe(1);
    expect(second.view.transcript.map((entry) => entry.entryKey)).toEqual([
      "u1:user:0",
      "a1b:assistant:0",
    ]);
  });

  it("rebuilds when the appended suffix exceeds maxIncrementalEntries", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state, { limits: { maxIncrementalEntries: 2 } });
    captureView(memory);
    state.append(usageEntry("us1"));
    state.append(usageEntry("us2"));
    state.append(usageEntry("us3"));
    const second = captureView(memory);

    expect(second.view.historyVersion).toBe(1);
    expect(second.view.leafId).toBe("us3");
  });

  it("appends incrementally when the suffix exactly reaches maxIncrementalEntries", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state, { limits: { maxIncrementalEntries: 2 } });
    captureView(memory);
    state.append(usageEntry("us1"));
    state.append(usageEntry("us2"));
    const second = captureView(memory);

    expect(second.view.historyVersion).toBe(0);
    expect(second.view.captureSeq).toBe(2);
    expect(second.view.leafId).toBe("us2");
  });

  it("rebuilds when a compaction entry joins the suffix and maps it to a parent summary", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    captureView(memory);
    state.append(compactionEntry("cp1", "compacted history"));
    const second = captureView(memory);

    expect(second.view.historyVersion).toBe(1);
    expect(second.view.transcript.map((entry) => [entry.entryKey, entry.kind, entry.content])).toEqual([
      ["u1:user:0", "user", "first request"],
      ["a1:assistant:0", "assistant", "first answer"],
      ["cp1:parent_summary:0", "parent_summary", "compacted history"],
    ]);
  });

  it("rebuilds when a branch summary joins the suffix", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    captureView(memory);
    state.append(branchSummaryEntry("bs1", "abandoned branch summary"));
    const second = captureView(memory);

    expect(second.view.historyVersion).toBe(1);
    expect(second.view.transcript[second.view.transcript.length - 1]).toMatchObject({
      entryKey: "bs1:branch_summary:0",
      kind: "branch_summary",
      content: "abandoned branch summary",
    });
  });

  it("rebuilds when a context edit joins the suffix and marks the edited entry", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    captureView(memory);
    state.append({
      type: "context_edit",
      id: "ce1",
      parentId: null,
      timestamp: ENTRY_STAMP,
      targetId: "u1",
      replacement: { content: "edited wording" },
    });
    const second = captureView(memory);

    expect(second.view.historyVersion).toBe(1);
    const userEntry = second.view.transcript[0];
    expect(userEntry).toMatchObject({
      entryKey: "u1:user:0",
      kind: "user",
      content: "first request",
      edited: true,
    });
  });

  it("fails fatal for an unknown entry type in the suffix", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    captureView(memory);
    state.append({ type: "future_entry", id: "f1", parentId: null, timestamp: ENTRY_STAMP } as unknown as SessionEntry);
    expect(failureOf(memory)).toBe("fatal");
    expect(memory.state().failure).toBe("fatal");
  });

  it("fails fatal for an unknown message role in the suffix", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    captureView(memory);
    state.append(messageEntry("m1", { role: "bogus" } as unknown as UserMessage));
    expect(failureOf(memory)).toBe("fatal");
  });

  it("fails fatal for an unknown entry type during a full rebuild", () => {
    const state = new FakeHostState();
    state.append({ type: "future_entry", id: "f1", parentId: null, timestamp: ENTRY_STAMP } as unknown as SessionEntry);
    const memory = createMemory(state);
    expect(failureOf(memory)).toBe("fatal");
    expect(memory.initialized).toBe(false);
  });

  it("fails fatal for an unknown message role during a full rebuild", () => {
    const state = new FakeHostState();
    state.append(messageEntry("m1", { role: "bogus" } as unknown as UserMessage));
    const memory = createMemory(state);
    expect(failureOf(memory)).toBe("fatal");
  });

  it("keeps a pending rebuild request across a rejected capture", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    captureView(memory);
    memory.requestHistoryRebuild();
    expect(memory.capture("someone-else")).toEqual({ ok: false, reason: "invalid-owner" });
    expect(captureView(memory, "owner-1").view.historyVersion).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// §1 capacity limits
// ---------------------------------------------------------------------------

describe("snapshot validity", () => {
  it("reuses an unchanged view without sorting tool events again", () => {
    const state = new FakeHostState();
    state.append(messageEntry("a1", assistantMessage([{ type: "text", text: "first" }])));
    const memory = createMemory(state);
    const first = captureView(memory);
    const sort = vi.spyOn(Array.prototype, "sort");
    try {
      expect(captureView(memory).view).toBe(first.view);
      expect(sort).not.toHaveBeenCalled();
    } finally {
      sort.mockRestore();
    }
  });

  it("accepts appended messages but rejects a changed branch or authorization", () => {
    const state = new FakeHostState();
    state.append(messageEntry("a1", assistantMessage([{ type: "text", text: "first" }])));
    const memory = createMemory(state);
    const snapshot = captureView(memory);
    state.append(messageEntry("a2", assistantMessage([{ type: "text", text: "queued" }])));
    expect(memory.isCurrent("owner-1", snapshot.view, snapshot.revisions)).toBe(true);
    state.insert(messageEntry("other", assistantMessage([{ type: "text", text: "other branch" }])));
    state.setLeaf("other");
    expect(memory.isCurrent("owner-1", snapshot.view, snapshot.revisions)).toBe(false);
    state.setLeaf("a2");
    memory.noteUserInput("new authorization");
    expect(memory.isCurrent("owner-1", snapshot.view, snapshot.revisions)).toBe(false);
  });
});

describe("capacity limits", () => {
  it("truncates the oldest transcript entries at the transcript limit", () => {
    const state = new FakeHostState();
    state.append(messageEntry("u1", userMessage("first")));
    state.append(messageEntry("a1", assistantMessage([{ type: "text", text: "answer" }])));
    const memory = createMemory(state, { limits: { maxTranscriptEntries: 1 } });

    const view = captureView(memory).view;
    expect(view.transcript.map((entry) => entry.entryKey)).toEqual(["a1:assistant:0"]);
    expect(memory.state().failure).toBeUndefined();
    expect(memory.initialized).toBe(true);
  });

  it("publishes a transcript exactly at the transcript limit", () => {
    const state = new FakeHostState();
    state.append(messageEntry("u1", userMessage("first")));
    state.append(messageEntry("a1", assistantMessage([{ type: "text", text: "answer" }])));
    const memory = createMemory(state, { limits: { maxTranscriptEntries: 2 } });
    expect(captureView(memory).view.transcript).toHaveLength(2);
  });

  it("truncates completed tool pairs as one unit when results settle out of order", () => {
    const state = new FakeHostState();
    state.append(messageEntry("a1", assistantMessage([
      toolCall("call-a", "bash", { command: "first" }),
      toolCall("call-b", "grep", { pattern: "needle" }),
    ])));
    state.append(messageEntry("r-b", toolResultMessage("call-b", "grep", "denied", { isError: true })));
    state.append(messageEntry("r-a", toolResultMessage("call-a", "bash", "done")));
    const memory = createMemory(state, { limits: { maxTranscriptEntries: 1 } });

    const transcript = captureView(memory).view.transcript;
    expect(transcript.map((entry) => entry.entryKey)).toEqual(["call:call-b", "result:call-b"]);
    expect(transcript[1]?.tool).toMatchObject({ callId: "call-b", isError: true });
  });

  it("removes a complete tool pair when the byte budget cannot retain it", () => {
    const state = new FakeHostState();
    state.append(messageEntry("a1", assistantMessage([toolCall("call-1", "bash", { command: "run" })])));
    state.append(messageEntry("r1", toolResultMessage("call-1", "bash", "done")));
    const memory = createMemory(state, { limits: { maxViewBytes: 16 } });

    const transcript = captureView(memory).view.transcript;
    expect(transcript).toEqual([]);
    expect(transcript.some((entry) => entry.tool?.callId === "call-1")).toBe(false);
  });

  it("limits a large UTF-8 transcript without repeatedly serializing the full view", () => {
    const state = new FakeHostState();
    for (let index = 0; index < 80; index += 1) {
      state.append(messageEntry(`a${index}`, assistantMessage([{ type: "text", text: `内容-${index}-${"字".repeat(40)}` }])));
    }
    const memory = createMemory(state, { limits: { maxViewBytes: 2_500 } });
    const original = JSON.stringify;
    let wholeViews = 0;
    const spy = vi.spyOn(JSON, "stringify").mockImplementation(((value: unknown, ...rest: unknown[]) => {
      if (typeof value === "object" && value !== null && "captureSeq" in value && "transcript" in value) wholeViews += 1;
      return Reflect.apply(original, JSON, [value, ...rest]);
    }) as typeof JSON.stringify);
    try {
      const view = captureView(memory).view;
      expect(view.transcript.length).toBeGreaterThan(0);
      expect(view.transcript.at(-1)?.content).toContain("内容-79-");
      expect(Buffer.byteLength(original(view), "utf8")).toBeLessThanOrEqual(2_500);
      expect(wholeViews).toBeLessThanOrEqual(2);
    } finally {
      spy.mockRestore();
    }
  });

  it("truncates the oldest authorization entries at the authorization limit", () => {
    const state = new FakeHostState();
    state.append(messageEntry("u1", userMessage("first")));
    state.append(messageEntry("a1", assistantMessage([{ type: "text", text: "answer" }])));
    state.append(messageEntry("u2", userMessage("second")));
    const memory = createMemory(state, { limits: { maxAuthorizationEntries: 1 } });
    const view = captureView(memory).view;
    expect(view.authorization.map((entry) => entry.id)).toEqual(["auth:u2"]);
  });

  it("publishes authorization exactly at the authorization limit", () => {
    const state = new FakeHostState();
    state.append(messageEntry("u1", userMessage("first")));
    state.append(messageEntry("a1", assistantMessage([{ type: "text", text: "answer" }])));
    const memory = createMemory(state, { limits: { maxAuthorizationEntries: 1 } });
    expect(captureView(memory).view.authorization).toHaveLength(1);
  });

  it("drops the oldest evidence until the frozen view fits the byte budget", () => {
    const state = new FakeHostState();
    const prepared = seededMemory(state);
    const measured = captureView(prepared);
    const oneViewBytes = Buffer.byteLength(JSON.stringify(measured.view), "utf8") + 8;

    const fresh = new FakeHostState();
    const memory = seededMemory(fresh, { limits: { maxViewBytes: oneViewBytes } });
    expect(captureView(memory).view.captureSeq).toBe(1);
    memory.requestHistoryRebuild();
    // Repeated publications each fit the budget on their own.
    expect(captureView(memory).view.captureSeq).toBe(2);
    memory.requestHistoryRebuild();
    expect(captureView(memory).view.captureSeq).toBe(3);
  });

  it("never fails a capture just because the byte budget is smaller than one view", () => {
    const state = new FakeHostState();
    state.append(messageEntry("u1", userMessage("first")));
    const memory = createMemory(state, { limits: { maxViewBytes: 16 } });
    const view = captureView(memory).view;
    expect(view.transcript).toEqual([]);
    expect(memory.state().failure).toBeUndefined();
  });

  it("truncates an incremental publish at the transcript limit", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state, { limits: { maxTranscriptEntries: 2 } });
    captureView(memory);
    state.append(messageEntry("a2", assistantMessage([{ type: "text", text: "extra" }])));
    const view = captureView(memory).view;
    expect(view.transcript).toHaveLength(2);
    expect(view.transcript[1]?.entryKey).toBe("a2:assistant:0");
  });
});

// ---------------------------------------------------------------------------
// §5 tool-event reconciliation
// ---------------------------------------------------------------------------

/** A published view whose latest step manifest owns the direct call `call-1`. */
function manifestMemory(
  state: FakeHostState,
  options: { now?: () => number; limits?: Record<string, number> } = {},
): ReviewerSessionMemory {
  state.append(messageEntry("u1", userMessage("run it")));
  state.append(messageEntry("a1", assistantMessage([
    { type: "text", text: "running" },
    toolCall("call-1", "bash", { command: "ls" }),
  ])));
  return createMemory(state, options);
}

function callEvent(overrides: Partial<{
  sessionId: string;
  toolCallId: string;
  parentToolCallId: string | undefined;
  toolName: string;
  input: unknown;
}> = {}): ReviewToolEvent {
  return {
    kind: "call",
    sessionId: overrides.sessionId ?? "session-1",
    toolCallId: overrides.toolCallId ?? "call-1",
    ...(overrides.parentToolCallId === undefined
      ? {}
      : { parentToolCallId: overrides.parentToolCallId }),
    toolName: overrides.toolName ?? "bash",
    input: "input" in overrides ? overrides.input : { command: "ls" },
  };
}

function resultEvent(overrides: Partial<{
  sessionId: string;
  toolCallId: string;
  toolName: string;
  text: string;
  isError: boolean;
}> = {}): ReviewToolEvent {
  return {
    kind: "result",
    sessionId: overrides.sessionId ?? "session-1",
    toolCallId: overrides.toolCallId ?? "call-1",
    toolName: overrides.toolName ?? "bash",
    text: overrides.text ?? "output",
    isError: overrides.isError ?? false,
  };
}

function lastEntry(view: ReviewView): ReviewTranscriptEntry {
  return view.transcript[view.transcript.length - 1]!;
}

describe("tool event recording", () => {
  it("folds an event recorded before the first capture into that baseline", () => {
    const state = new FakeHostState();
    const memory = manifestMemory(state);
    memory.recordToolEvent(callEvent({
      toolCallId: "nested-1",
      parentToolCallId: "call-1",
      toolName: "grep",
      input: { pattern: "needle" },
    }));
    const view = captureView(memory).view;

    expect(view.transcript[view.transcript.length - 1]?.entryKey).toBe("call:nested-1");
    expect(memory.state().pendingEvents).toBe(0);
  });

  it("drops an event from a different session", () => {
    const state = new FakeHostState();
    const memory = manifestMemory(state);
    const first = captureView(memory);
    memory.recordToolEvent(resultEvent({ sessionId: "other-session" }));
    const second = captureView(memory);

    expect(second.view).toBe(first.view);
    expect(memory.state().pendingEvents).toBe(0);
    expect(memory.state().failure).toBeUndefined();
  });

  it("drops a malformed event", () => {
    const state = new FakeHostState();
    const memory = manifestMemory(state);
    const first = captureView(memory);
    memory.recordToolEvent({
      kind: "call",
      sessionId: "session-1",
      toolCallId: "",
      toolName: "bash",
      input: {},
    });
    const second = captureView(memory);

    expect(second.view).toBe(first.view);
    expect(memory.state().failure).toBeUndefined();
  });

  it("keeps collecting after a failed capture", () => {
    const state = new FakeHostState();
    state.append(messageEntry("u1", userMessage("go")));
    state.throwing.add("getBranch");
    const memory = createMemory(state);
    expect(failureOf(memory)).toBe("sync-failed");

    state.throwing.delete("getBranch");
    state.append(messageEntry("a1", assistantMessage([
      { type: "text", text: "running" },
      toolCall("call-1", "bash", { command: "ls" }),
    ])));
    memory.recordToolEvent(resultEvent());
    const view = captureView(memory).view;

    expect(view.transcript.some((entry) => entry.entryKey === "result:call-1")).toBe(true);
    expect(memory.state().failure).toBeUndefined();
  });

  it("stays usable when the very first tool result arrives before any snapshot", () => {
    // Regression: a gate-rejected first call emits only `tool_execution_end`.
    const state = new FakeHostState();
    state.append(messageEntry("u1", userMessage("run the watchdog")));
    const memory = createMemory(state);
    memory.recordToolEvent(resultEvent({
      toolCallId: "denied-1",
      toolName: "watchdog_diff",
      text: "permission:denied",
      isError: true,
    }));

    const view = captureView(memory).view;
    expect(view.transcript.some((entry) => entry.entryKey === "result:denied-1")).toBe(false);
    expect(memory.state().failure).toBeUndefined();

    // The next call in the same session still works.
    memory.recordToolEvent(callEvent({ toolCallId: "call-2", toolName: "ls", input: {} }));
    expect(captureView(memory).ok).toBe(true);
  });

  it("counts pending events until the next capture and consumes them", () => {
    const state = new FakeHostState();
    const memory = manifestMemory(state);
    const first = captureView(memory);
    memory.recordToolEvent(callEvent());
    memory.recordToolEvent(resultEvent());
    expect(memory.state().pendingEvents).toBe(1);
    const second = captureView(memory);
    expect(memory.state().pendingEvents).toBe(0);
    expect(second.view.captureSeq).toBe(2);
    expect(second.view).not.toBe(first.view);
  });

  it("stamps each recorded event with the injected clock", () => {
    let ticks = 0;
    const clock = (): number => {
      ticks += 1;
      return ticks;
    };
    const state = new FakeHostState();
    const memory = manifestMemory(state, { now: clock });
    captureView(memory);
    const before = ticks;
    memory.recordToolEvent(resultEvent());
    memory.recordToolEvent(resultEvent({ toolCallId: "call-1", text: "again" }));
    expect(ticks - before).toBe(2);
  });

  it("treats the tool-event identity budget as a budget, not a failure", () => {
    const state = new FakeHostState();
    const memory = manifestMemory(state, { limits: { maxToolEvents: 1 } });
    captureView(memory);
    memory.recordToolEvent(resultEvent());
    memory.recordToolEvent(resultEvent({ toolCallId: "call-2" }));
    const view = captureView(memory).view;

    expect(view.transcript.filter((entry) => entry.entryKey === "result:call-1")).toHaveLength(1);
    expect(view.transcript.some((entry) => entry.entryKey === "result:call-2")).toBe(false);
    expect(memory.state().failure).toBeUndefined();
  });
});

describe("direct tool call reconciliation", () => {
  it("accepts a direct call event that belongs to the complete manifest and reuses the view", () => {
    const state = new FakeHostState();
    const memory = manifestMemory(state);
    const first = captureView(memory);
    memory.recordToolEvent(callEvent());

    const second = captureView(memory);
    expect(second.view).toBe(first.view);
    expect(second.view.captureSeq).toBe(1);
    expect(memory.state().pendingEvents).toBe(0);
  });

  it("ignores a direct call event that is not in the manifest", () => {
    const state = new FakeHostState();
    const memory = manifestMemory(state);
    const first = captureView(memory);
    memory.recordToolEvent(callEvent({ toolCallId: "call-other" }));
    const second = captureView(memory);

    expect(second.view).toBe(first.view);
    expect(memory.state().failure).toBeUndefined();
  });

  it("ignores a direct call event whose tool name conflicts with the manifest", () => {
    const state = new FakeHostState();
    const memory = manifestMemory(state);
    const first = captureView(memory);
    memory.recordToolEvent(callEvent({ toolName: "read" }));
    expect(captureView(memory).view).toBe(first.view);
  });

  it("ignores a direct call event when there is no step manifest", () => {
    const state = new FakeHostState();
    state.append(messageEntry("u1", userMessage("hello")));
    const memory = createMemory(state);
    const first = captureView(memory);
    memory.recordToolEvent(callEvent());
    expect(captureView(memory).view).toBe(first.view);
  });

  it("ignores a direct call event when the manifest is incomplete", () => {
    const state = new FakeHostState();
    state.append(messageEntry("u1", userMessage("go")));
    state.append(messageEntry("a1", assistantMessage([
      toolCall("call-1", "bash", { command: "ls" }),
      toolCall("call-1", "bash", { command: "pwd" }),
    ])));
    const memory = createMemory(state);
    expect(captureView(memory).view.manifest?.complete).toBe(false);
    memory.recordToolEvent(callEvent());
    expect(memory.state().failure).toBeUndefined();
    expect(memory.capture("owner-1").ok).toBe(true);
  });

  it("accepts duplicate identical direct call events idempotently", () => {
    const state = new FakeHostState();
    const memory = manifestMemory(state);
    captureView(memory);
    memory.recordToolEvent(callEvent());
    memory.recordToolEvent(callEvent());
    expect(failureOf(memory)).toBe("ok");
  });

  it("keeps the first identity when duplicate call events conflict on input", () => {
    const state = new FakeHostState();
    const memory = manifestMemory(state);
    captureView(memory);
    memory.recordToolEvent(callEvent({ input: { command: "ls" } }));
    memory.recordToolEvent(callEvent({ input: { command: "pwd" } }));
    expect(memory.state().failure).toBeUndefined();
    expect(memory.capture("owner-1").ok).toBe(true);
  });

  it("keeps the first identity when duplicate call events conflict on parent", () => {
    const state = new FakeHostState();
    const memory = manifestMemory(state);
    captureView(memory);
    memory.recordToolEvent(callEvent({ toolCallId: "nested-1", parentToolCallId: "call-1", toolName: "grep", input: { pattern: "a" } }));
    memory.recordToolEvent(callEvent({ toolCallId: "nested-1", parentToolCallId: "nested-2", toolName: "grep", input: { pattern: "a" } }));
    const view = captureView(memory).view;
    const nested = view.transcript.filter((entry) => entry.entryKey === "call:nested-1");
    expect(nested).toHaveLength(1);
    expect(nested[0]?.tool?.parentCallId).toBe("call-1");
  });
});

describe("nested tool call reconciliation", () => {
  it("appends a frozen nested tool_call placeholder for a known direct parent", () => {
    const state = new FakeHostState();
    const memory = manifestMemory(state);
    const first = captureView(memory);
    memory.recordToolEvent(callEvent({
      toolCallId: "nested-1",
      parentToolCallId: "call-1",
      toolName: "grep",
      input: { pattern: "needle" },
    }));
    const second = captureView(memory);

    expect(second.view.captureSeq).toBe(2);
    expect(second.view.historyVersion).toBe(0);
    expect(second.view.transcript.slice(0, -1)).toEqual(first.view.transcript);
    const placeholder = lastEntry(second.view);
    expect(placeholder).toEqual({
      entryKey: "call:nested-1",
      kind: "tool_call",
      content: { pattern: "needle" },
      tool: {
        name: "grep",
        callId: "nested-1",
        parentCallId: "call-1",
        part: "call",
      },
      edited: false,
      digest: reviewDigest({
        entryKey: "call:nested-1",
        kind: "tool_call",
        content: { pattern: "needle" },
        tool: { name: "grep", callId: "nested-1", parentCallId: "call-1", part: "call" },
        edited: false,
      }),
    });
    expect(Object.isFrozen(placeholder)).toBe(true);
    expect(Object.isFrozen(placeholder.content)).toBe(true);
    expect(second.view.manifest).toEqual(first.view.manifest);
  });

  it("reuses the same view on a capture after the nested call placeholder was published", () => {
    const state = new FakeHostState();
    const memory = manifestMemory(state);
    captureView(memory);
    memory.recordToolEvent(callEvent({
      toolCallId: "nested-1",
      parentToolCallId: "call-1",
      toolName: "grep",
      input: { pattern: "needle" },
    }));
    const published = captureView(memory);
    const again = captureView(memory);
    expect(again.view).toBe(published.view);
    expect(again.view.captureSeq).toBe(2);
  });

  it("accepts a nested call under another registered nested call", () => {
    const state = new FakeHostState();
    const memory = manifestMemory(state);
    captureView(memory);
    memory.recordToolEvent(callEvent({
      toolCallId: "nested-1",
      parentToolCallId: "call-1",
      toolName: "grep",
      input: { pattern: "a" },
    }));
    memory.recordToolEvent(callEvent({
      toolCallId: "nested-2",
      parentToolCallId: "nested-1",
      toolName: "read",
      input: { path: "a.txt" },
    }));
    const view = captureView(memory).view;
    expect(view.transcript.slice(-2).map((entry) => entry.entryKey)).toEqual([
      "call:nested-1",
      "call:nested-2",
    ]);
    expect(view.transcript[view.transcript.length - 1]?.tool).toEqual({
      name: "read",
      callId: "nested-2",
      parentCallId: "nested-1",
      part: "call",
    });
  });

  it("renders a nested call whose parent is unknown", () => {
    const state = new FakeHostState();
    const memory = manifestMemory(state);
    captureView(memory);
    memory.recordToolEvent(callEvent({
      toolCallId: "nested-1",
      parentToolCallId: "unknown-parent",
      toolName: "grep",
      input: { pattern: "a" },
    }));
    const view = captureView(memory).view;
    expect(lastEntry(view).entryKey).toBe("call:nested-1");
    expect(lastEntry(view).tool?.parentCallId).toBe("unknown-parent");
  });

  it("renders a nested call without a JSON object input with omitted content", () => {
    const state = new FakeHostState();
    const memory = manifestMemory(state);
    captureView(memory);
    memory.recordToolEvent(callEvent({
      toolCallId: "nested-1",
      parentToolCallId: "call-1",
      toolName: "grep",
      input: ["not", "an", "object"],
    }));
    const view = captureView(memory).view;
    expect(lastEntry(view).entryKey).toBe("call:nested-1");
    expect(lastEntry(view).content).toEqual({ omitted: true });
    expect(Object.isFrozen(lastEntry(view).content)).toBe(true);
  });
});

describe("tool result reconciliation", () => {
  it("admits new nested events after the default 8192-ID budget is filled", () => {
    const state = new FakeHostState();
    state.append(messageEntry("a1", assistantMessage([toolCall("parent", "bash", { command: "run" })])));
    const memory = createMemory(state);
    captureView(memory);
    for (let index = 0; index < 8_194; index += 1) {
      const id = `nested-${index}`;
      memory.recordToolEvent(callEvent({ toolCallId: id, parentToolCallId: "parent", input: { index } }));
      memory.recordToolEvent(resultEvent({ toolCallId: id, text: `result-${index}` }));
    }
    const transcript = captureView(memory).view.transcript;
    expect(transcript.some(entry => entry.tool?.callId === "nested-0")).toBe(false);
    expect(transcript.filter(entry => entry.tool?.callId === "nested-8193").map(entry => entry.content)).toEqual([
      { index: 8193 }, "result-8193",
    ]);
    expect(memory.state().failure).toBeUndefined();
  }, 30_000);

  it("preserves in-flight calls while completed event slots are reused", () => {
    const state = new FakeHostState();
    state.append(messageEntry("a1", assistantMessage([toolCall("parent", "bash", { command: "run" })])));
    const memory = createMemory(state, { limits: { maxToolEvents: 2, maxTranscriptEntries: 10 } });
    captureView(memory);
    for (const id of ["a", "b"]) memory.recordToolEvent(callEvent({ toolCallId: id, parentToolCallId: "parent", input: { id } }));
    memory.recordToolEvent(resultEvent({ toolCallId: "b", text: "finished-b" }));
    memory.recordToolEvent(callEvent({ toolCallId: "c", parentToolCallId: "parent", input: { id: "c" } }));
    memory.recordToolEvent(resultEvent({ toolCallId: "c", text: "finished-c" }));
    memory.recordToolEvent(resultEvent({ toolCallId: "b", text: "finished-b" }));
    const entries = captureView(memory).view.transcript.filter(entry => ["a", "b", "c"].includes(entry.tool?.callId ?? ""));
    expect(entries.map(entry => entry.entryKey)).toEqual(["call:a", "call:b", "result:b", "call:c", "result:c"]);
    expect(entries.find(entry => entry.tool?.callId === "a")?.content).toEqual({ id: "a" });
  });

  it("retains completed nested calls in the bounded view when live event slots are reused", () => {
    const state = new FakeHostState();
    state.append(messageEntry("a1", assistantMessage([toolCall("parent", "bash", { command: "run" })])));
    const memory = createMemory(state, { limits: { maxToolEvents: 2, maxTranscriptEntries: 10 } });
    captureView(memory);
    for (const id of ["nested-a", "nested-b", "nested-c"]) {
      memory.recordToolEvent(callEvent({ toolCallId: id, parentToolCallId: "parent", input: { id } }));
      memory.recordToolEvent(resultEvent({ toolCallId: id, text: `result-${id}` }));
    }
    const view = captureView(memory).view;
    expect(view.transcript.filter(entry => entry.tool?.callId?.startsWith("nested-")).map(entry => entry.entryKey)).toEqual([
      "call:nested-a", "result:nested-a", "call:nested-b", "result:nested-b", "call:nested-c", "result:nested-c",
    ]);
  });

  it("appends a result placeholder for a known direct call", () => {
    const state = new FakeHostState();
    const memory = manifestMemory(state);
    const first = captureView(memory);
    memory.recordToolEvent(resultEvent({ text: "file.txt" }));
    const second = captureView(memory);

    expect(second.view.captureSeq).toBe(2);
    expect(second.view.transcript.slice(0, -1)).toEqual(first.view.transcript);
    expect(lastEntry(second.view)).toEqual({
      entryKey: "result:call-1",
      kind: "tool_result",
      content: "file.txt",
      tool: { name: "bash", callId: "call-1", part: "result" },
      edited: false,
      digest: reviewDigest({
        entryKey: "result:call-1",
        kind: "tool_result",
        content: "file.txt",
        tool: { name: "bash", callId: "call-1", part: "result" },
        edited: false,
      }),
    });
  });

  it("keeps the error fact of an error result placeholder", () => {
    const state = new FakeHostState();
    const memory = manifestMemory(state);
    captureView(memory);
    memory.recordToolEvent(resultEvent({ text: "boom", isError: true }));
    expect(lastEntry(captureView(memory).view).tool).toEqual({
      name: "bash",
      callId: "call-1",
      part: "result",
      isError: true,
    });
  });

  it("drops a result event whose call is unknown", () => {
    const state = new FakeHostState();
    const memory = manifestMemory(state);
    const first = captureView(memory);
    memory.recordToolEvent(resultEvent({ toolCallId: "unknown-call" }));
    const second = captureView(memory);
    expect(second.view).toBe(first.view);
    expect(memory.state().failure).toBeUndefined();
  });

  it("drops a result event whose tool name conflicts with the call", () => {
    const state = new FakeHostState();
    const memory = manifestMemory(state);
    const first = captureView(memory);
    memory.recordToolEvent(resultEvent({ toolName: "read" }));
    expect(captureView(memory).view).toBe(first.view);
  });

  it("accepts duplicate identical result events", () => {
    const state = new FakeHostState();
    const memory = manifestMemory(state);
    captureView(memory);
    memory.recordToolEvent(resultEvent({ text: "output" }));
    memory.recordToolEvent(resultEvent({ text: "output" }));
    const view = captureView(memory).view;
    expect(view.transcript.filter((entry) => entry.entryKey === "result:call-1")).toHaveLength(1);
  });

  it("keeps the first result when duplicate result events conflict on text", () => {
    const state = new FakeHostState();
    const memory = manifestMemory(state);
    captureView(memory);
    memory.recordToolEvent(resultEvent({ text: "one" }));
    memory.recordToolEvent(resultEvent({ text: "two" }));
    const view = captureView(memory).view;
    expect(view.transcript.find((entry) => entry.entryKey === "result:call-1")?.content).toBe("one");
  });

  it("keeps the first result when duplicate result events conflict on the error identity", () => {
    const state = new FakeHostState();
    const memory = manifestMemory(state);
    captureView(memory);
    memory.recordToolEvent(resultEvent({ isError: false }));
    memory.recordToolEvent(resultEvent({ isError: true }));
    const view = captureView(memory).view;
    expect(view.transcript.find((entry) => entry.entryKey === "result:call-1")?.tool).toEqual({
      name: "bash",
      callId: "call-1",
      part: "result",
    });
  });

  it("lets a persisted result replace the event placeholder without duplication", () => {
    const state = new FakeHostState();
    const memory = manifestMemory(state);
    captureView(memory);
    memory.recordToolEvent(resultEvent({ text: "output" }));
    expect(lastEntry(captureView(memory).view).entryKey).toBe("result:call-1");

    state.append(messageEntry("r1", toolResultMessage("call-1", "bash", "output")));
    const replaced = captureView(memory).view;
    const results = replaced.transcript.filter((entry) => entry.entryKey === "result:call-1");
    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({
      entryKey: "result:call-1",
      sourceEntryId: "r1",
      content: "output",
    });
    expect(replaced.transcript[replaced.transcript.length - 1]?.entryKey).toBe("result:call-1");
    expect(memory.state().pendingEvents).toBe(0);
  });

  it("never overwrites a persisted authoritative nested call with an event placeholder", () => {
    const state = new FakeHostState();
    state.append(messageEntry("u1", userMessage("run it")));
    state.append(messageEntry("a1", assistantMessage([toolCall("call-1", "bash", { command: "ls" })])));
    state.append(messageEntry("r1", toolResultMessage("call-1", "bash", "done", {
      nestedCalls: {
        calls: [{ id: "nested-1", name: "grep", arguments: { pattern: "needle" }, status: "ok" }],
        complete: true,
      },
    })));
    const memory = createMemory(state);
    const first = captureView(memory);
    expect(first.view.transcript.some((entry) => entry.entryKey === "call:nested-1")).toBe(true);

    memory.recordToolEvent(callEvent({
      toolCallId: "nested-1",
      parentToolCallId: "call-1",
      toolName: "grep",
      input: { pattern: "needle" },
    }));
    const second = captureView(memory);
    expect(second.view).toBe(first.view);
    expect(second.view.transcript.filter((entry) => entry.entryKey === "call:nested-1")).toHaveLength(1);
    expect(second.view.transcript.find((entry) => entry.entryKey === "call:nested-1")?.sourceEntryId).toBe("r1");
  });

  it("drops a result placeholder when the host persists the result in the same capture", () => {
    const state = new FakeHostState();
    const memory = manifestMemory(state);
    captureView(memory);
    memory.recordToolEvent(resultEvent({ text: "output" }));
    state.append(messageEntry("r1", toolResultMessage("call-1", "bash", "output")));
    const view = captureView(memory).view;
    expect(view.transcript.filter((entry) => entry.entryKey === "result:call-1")).toHaveLength(1);
    expect(view.transcript.find((entry) => entry.entryKey === "result:call-1")?.sourceEntryId).toBe("r1");
  });
});

describe("tool events in degraded mode", () => {
  it("validates and consumes events without adding them to the reviewed history", () => {
    const state = new FakeHostState({ projection: "none" });
    const memory = createMemory(state);
    const first = captureView(memory);
    memory.recordToolEvent(callEvent());
    memory.recordToolEvent(resultEvent());
    const second = captureView(memory);

    expect(second.view).toBe(first.view);
    expect(second.view.degraded).toBe(true);
    expect(second.view.transcript).toHaveLength(1);
    expect(memory.state().pendingEvents).toBe(0);
  });

  it("keeps the first of conflicting duplicate events in degraded mode", () => {
    const state = new FakeHostState({ projection: "none" });
    const memory = createMemory(state);
    const first = captureView(memory);
    memory.recordToolEvent(resultEvent({ text: "one" }));
    memory.recordToolEvent(resultEvent({ text: "two" }));
    const second = captureView(memory);
    expect(second.view).toBe(first.view);
    expect(memory.state().failure).toBeUndefined();
  });

  it("fails with projection-unavailable when the degraded session becomes non-empty", () => {
    const state = new FakeHostState({ projection: "none" });
    const memory = createMemory(state);
    captureView(memory);
    state.append(messageEntry("u1", userMessage("hello")));
    expect(memory.capture("owner-1")).toEqual({ ok: false, reason: "projection-unavailable" });
  });
});

describe("tool event ordering", () => {
  it("orders a nested call placeholder before its result placeholder by event order", () => {
    const state = new FakeHostState();
    const memory = manifestMemory(state);
    captureView(memory);
    memory.recordToolEvent(callEvent({
      toolCallId: "nested-1",
      parentToolCallId: "call-1",
      toolName: "grep",
      input: { pattern: "needle" },
    }));
    memory.recordToolEvent(resultEvent({ toolCallId: "nested-1", toolName: "grep", text: "matched" }));
    const view = captureView(memory).view;

    expect(view.transcript.slice(-2).map((entry) => [entry.entryKey, entry.kind])).toEqual([
      ["call:nested-1", "tool_call"],
      ["result:nested-1", "tool_result"],
    ]);
  });
});

// ---------------------------------------------------------------------------
// Identity changes and old-view immutability
// ---------------------------------------------------------------------------

describe("session identity changes", () => {
  it("fails the capture when the host reports a different session id, then recovers", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    const first = captureView(memory);
    state.sessionId = "session-2";
    expect(memory.capture("owner-1")).toEqual({ ok: false, reason: "fatal" });
    expect(memory.state().failure).toBe("fatal");

    state.sessionId = first.view.sessionId;
    const recovered = captureView(memory);
    expect(recovered.view.sessionId).toBe("session-1");
    expect(memory.state().failure).toBeUndefined();
  });

  it("reports a broken projection during a rebuild and retries on the next capture", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    const first = captureView(memory);
    state.throwing.add("buildSessionProjection");
    memory.requestHistoryRebuild();
    expect(memory.capture("owner-1")).toEqual({ ok: false, reason: "rebuild-failed" });
    expect(memory.state().view).toBe(first.view);

    state.throwing.delete("buildSessionProjection");
    const rebuilt = captureView(memory);
    expect(rebuilt.view.historyVersion).toBe(first.view.historyVersion + 1);
    expect(memory.state().failure).toBeUndefined();
  });

  it("never mutates or unfreezes an earlier published view", () => {
    const state = new FakeHostState();
    const memory = seededMemory(state);
    const first = captureView(memory);
    const frozenTranscript = first.view.transcript;
    const serialized = JSON.stringify(first.view);

    state.append(messageEntry("u2", userMessage("second request")));
    state.append(messageEntry("a2", assistantMessage([{ type: "text", text: "second answer" }])));
    const second = captureView(memory);

    expect(second.view).not.toBe(first.view);
    expect(JSON.stringify(first.view)).toBe(serialized);
    expect(first.view.transcript).toBe(frozenTranscript);
    expect(Object.isFrozen(first.view)).toBe(true);
    expect(first.view.captureSeq).toBe(1);
  });
});
