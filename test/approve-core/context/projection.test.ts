/**
 * Phase 11 session/evidence projection (specs/reviewer-context.md §2, §3, §6).
 *
 * Every fixture is a real host entry/message shape (`SessionEntry`,
 * `AssistantMessage`, `ToolResultMessage`, `SessionProjection`); every expected
 * value is a worked example written from the spec, never recomputed from the
 * implementation. No filesystem, network or clock access is involved.
 */
import { describe, expect, it } from "vitest";
import type {
  CompactionEntry,
  CustomMessageEntry,
  ProjectedSessionEntry,
  SessionEntry,
  SessionMessageEntry,
  SessionProjection,
} from "@earendil-works/pi-coding-agent";
import type {
  AssistantMessage,
  ImageContent,
  NestedToolCallRecord,
  NestedToolCalls,
  SystemMessage,
  TextContent,
  ToolCall,
  ToolResultMessage,
  UserMessage,
} from "@earendil-works/pi-ai";
import {
  buildAuthorization,
  buildReviewView,
  buildStepManifest,
  degradedView,
  projectDeltaEvidence,
  projectEntryTranscript,
  projectFullEvidence,
  renderEvidence,
  transcriptPrefixDigest,
  type ReviewProjectionInput,
} from "#approve-core/context/projection";
import { reviewDigest, type ApprovalEvidence, type ReviewView } from "#approve-core/context/types";
import { canonicalJson } from "#approve-core/policy/project-rules/types";

const ENTRY_STAMP = "2026-01-01T00:00:00.000Z";
const MESSAGE_STAMP = 1_000;

const IMAGE: ImageContent = { type: "image", data: "aGVsbG8=", mimeType: "image/png" };

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

function usage(): AssistantMessage["usage"] {
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
    usage: usage(),
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
  content: (TextContent | ImageContent)[],
  overrides: Partial<ToolResultMessage> = {},
): ToolResultMessage {
  return {
    role: "toolResult",
    toolCallId,
    toolName,
    content,
    isError: false,
    timestamp: MESSAGE_STAMP,
    ...overrides,
  };
}

function systemMessage(content: SystemMessage["content"]): SystemMessage {
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

function customMessageEntry(
  id: string,
  content: CustomMessageEntry["content"],
  customType = "test-extension",
): CustomMessageEntry {
  return {
    type: "custom_message",
    id,
    parentId: null,
    timestamp: ENTRY_STAMP,
    customType,
    content,
    display: true,
  };
}

describe("projectEntryTranscript: user text", () => {
  it("maps a user string message to one frozen user entry with a stable key and digest", () => {
    const transcript = projectEntryTranscript(messageEntry("u1", userMessage("hello world")));
    expect(transcript).toHaveLength(1);
    const entry = transcript[0]!;
    expect(entry).toEqual({
      entryKey: "u1:user:0",
      sourceEntryId: "u1",
      kind: "user",
      content: "hello world",
      edited: false,
      digest: reviewDigest({
        entryKey: "u1:user:0",
        sourceEntryId: "u1",
        kind: "user",
        content: "hello world",
        edited: false,
      }),
    });
    expect(Object.isFrozen(transcript)).toBe(true);
    expect(Object.isFrozen(entry)).toBe(true);
  });

  it("maps one entry per text block using the content-block position and ignores images", () => {
    const content: (TextContent | ImageContent)[] = [
      { type: "text", text: "first" },
      IMAGE,
      { type: "text", text: "second" },
    ];
    const transcript = projectEntryTranscript(messageEntry("u2", userMessage(content)));
    expect(transcript.map((entry) => [entry.entryKey, entry.content])).toEqual([
      ["u2:user:0", "first"],
      ["u2:user:2", "second"],
    ]);
  });

  it("returns an empty list for a user message with no text blocks", () => {
    expect(projectEntryTranscript(messageEntry("u3", userMessage([IMAGE])))).toEqual([]);
    expect(projectEntryTranscript(messageEntry("u4", userMessage([])))).toEqual([]);
  });

  it("ignores entries that are not evidence", () => {
    const custom: SessionEntry = {
      type: "custom",
      id: "c1",
      parentId: null,
      timestamp: ENTRY_STAMP,
      customType: "test",
      data: { hidden: true },
    };
    expect(projectEntryTranscript(custom)).toEqual([]);
  });
});

describe("projectEntryTranscript: assistant content", () => {
  it("maps assistant text blocks by content-block position and ignores thinking blocks", () => {
    const transcript = projectEntryTranscript(
      messageEntry("a1", assistantMessage([
        { type: "thinking", thinking: "secret reasoning", thinkingSignature: "sig" },
        { type: "text", text: "the answer" },
      ])),
    );
    expect(transcript).toHaveLength(1);
    expect(transcript[0]).toEqual({
      entryKey: "a1:assistant:1",
      sourceEntryId: "a1",
      kind: "assistant",
      content: "the answer",
      edited: false,
      digest: reviewDigest({
        entryKey: "a1:assistant:1",
        sourceEntryId: "a1",
        kind: "assistant",
        content: "the answer",
        edited: false,
      }),
    });
  });

  it("maps an assistant tool call to a call-keyed entry with frozen arguments and tool facts", () => {
    const argumentsValue = { command: "npm test", timeoutMs: 5_000 };
    const transcript = projectEntryTranscript(
      messageEntry("a2", assistantMessage([
        { type: "text", text: "running the tests" },
        toolCall("call-1", "bash", argumentsValue),
      ])),
    );
    expect(transcript.map((entry) => entry.entryKey)).toEqual(["a2:assistant:0", "call:call-1"]);
    const call = transcript[1]!;
    expect(call.kind).toBe("tool_call");
    expect(call.content).toEqual(argumentsValue);
    expect(call.tool).toEqual({ name: "bash", callId: "call-1", part: "call" });
    expect(Object.isFrozen(call.content)).toBe(true);
    expect(call.content).not.toBe(argumentsValue);
    expect(Object.isFrozen(argumentsValue)).toBe(false);
    expect(call.digest).toBe(reviewDigest({
      entryKey: "call:call-1",
      sourceEntryId: "a2",
      kind: "tool_call",
      content: argumentsValue,
      tool: { name: "bash", callId: "call-1", part: "call" },
      edited: false,
    }));
  });

  it("defaults missing or non-object tool arguments to a frozen empty object", () => {
    const noArguments = projectEntryTranscript(
      messageEntry("a3", assistantMessage([toolCall("call-2", "bash", undefined)])),
    );
    expect(noArguments[0]!.content).toEqual({});
    expect(Object.isFrozen(noArguments[0]!.content)).toBe(true);

    const arrayArguments = projectEntryTranscript(
      messageEntry("a4", assistantMessage([toolCall("call-3", "bash", ["not", "an", "object"])])),
    );
    expect(arrayArguments[0]!.content).toEqual({});
  });

  it("uses a content-block position key when a tool call has no id and keeps no callId fact", () => {
    const transcript = projectEntryTranscript(
      messageEntry("a5", assistantMessage([
        { type: "text", text: "prefix" },
        toolCall("", "bash", { command: "ls" }),
      ])),
    );
    expect(transcript[1]).toMatchObject({
      entryKey: "a5:tool:1",
      sourceEntryId: "a5",
      kind: "tool_call",
      content: { command: "ls" },
      tool: { name: "bash", part: "call" },
      edited: false,
    });
    expect(transcript[1]!.tool?.callId).toBeUndefined();
  });
});

describe("projectEntryTranscript: tool results and system messages", () => {
  it("maps a tool result under its call identity with concatenated text and result tool facts", () => {
    const transcript = projectEntryTranscript(messageEntry("r1", toolResultMessage(
      "call-1",
      "bash",
      [{ type: "text", text: "line one" }, { type: "text", text: "line two" }],
    )));
    expect(transcript).toHaveLength(1);
    expect(transcript[0]).toEqual({
      entryKey: "result:call-1",
      sourceEntryId: "r1",
      kind: "tool_result",
      content: "line one\nline two",
      tool: { name: "bash", callId: "call-1", part: "result" },
      edited: false,
      digest: reviewDigest({
        entryKey: "result:call-1",
        sourceEntryId: "r1",
        kind: "tool_result",
        content: "line one\nline two",
        tool: { name: "bash", callId: "call-1", part: "result" },
        edited: false,
      }),
    });
  });

  it("records isError only for error results", () => {
    const failed = projectEntryTranscript(messageEntry("r2", toolResultMessage(
      "call-2",
      "bash",
      [{ type: "text", text: "boom" }],
      { isError: true },
    )));
    expect(failed[0]!.tool?.isError).toBe(true);

    const succeeded = projectEntryTranscript(messageEntry("r3", toolResultMessage(
      "call-3",
      "bash",
      [{ type: "text", text: "ok" }],
    )));
    expect(succeeded[0]!.tool?.isError).toBeUndefined();
  });

  it("uses a stable fallback key when the tool result has no call id", () => {
    const transcript = projectEntryTranscript(messageEntry("r4", toolResultMessage(
      "",
      "bash",
      [{ type: "text", text: "output" }],
    )));
    expect(transcript[0]).toMatchObject({
      entryKey: "r4:tool_result:0",
      tool: { name: "bash", part: "result" },
    });
    expect(transcript[0]!.tool?.callId).toBeUndefined();
  });

  it("maps a system message to an environment checkpoint", () => {
    const transcript = projectEntryTranscript(messageEntry("s1", systemMessage([
      { type: "text", text: "system prompt" },
      { type: "text", text: "tools changed" },
    ] as TextContent[])));
    expect(transcript).toHaveLength(1);
    expect(transcript[0]).toMatchObject({
      entryKey: "s1:environment_checkpoint:0",
      sourceEntryId: "s1",
      kind: "environment_checkpoint",
      content: "system prompt\ntools changed",
      edited: false,
    });
  });
});

describe("projectEntryTranscript: summaries, extensions and state-only entries", () => {  it("maps a compaction to a parent summary", () => {
    const transcript = projectEntryTranscript(compactionEntry("cp1", "compacted history"));
    expect(transcript).toHaveLength(1);
    expect(transcript[0]).toMatchObject({
      entryKey: "cp1:parent_summary:0",
      sourceEntryId: "cp1",
      kind: "parent_summary",
      content: "compacted history",
      edited: false,
    });
  });

  it("keeps the compaction system prompt as a preceding environment checkpoint", () => {
    const transcript = projectEntryTranscript(compactionEntry("cp2", "summary text", {
      systemMessage: systemMessage("prompt at compaction"),
    }));
    expect(transcript.map((entry) => [entry.entryKey, entry.kind, entry.content])).toEqual([
      ["cp2:environment_checkpoint:0", "environment_checkpoint", "prompt at compaction"],
      ["cp2:parent_summary:0", "parent_summary", "summary text"],
    ]);
  });

  it("maps a branch summary to a branch summary entry", () => {
    const entry: SessionEntry = {
      type: "branch_summary",
      id: "bs1",
      parentId: null,
      timestamp: ENTRY_STAMP,
      fromId: "abandoned-leaf",
      summary: "abandoned branch summary",
    };
    expect(projectEntryTranscript(entry)).toMatchObject([{
      entryKey: "bs1:branch_summary:0",
      sourceEntryId: "bs1",
      kind: "branch_summary",
      content: "abandoned branch summary",
    }]);
  });

  it("maps a custom message to an extension entry using its text and ignoring images", () => {
    const transcript = projectEntryTranscript(customMessageEntry("cm1", [
      { type: "text", text: "extension says" },
      IMAGE,
    ]));
    expect(transcript).toHaveLength(1);
    expect(transcript[0]).toMatchObject({
      entryKey: "cm1:extension:0",
      sourceEntryId: "cm1",
      kind: "extension",
      content: "extension says",
      edited: false,
    });

    const stringContent = projectEntryTranscript(customMessageEntry("cm2", "plain extension text"));
    expect(stringContent[0]!.content).toBe("plain extension text");
  });

  it("returns an empty list for every state-only entry type", () => {
    const stateOnly: SessionEntry[] = [
      { type: "usage", id: "us1", parentId: null, timestamp: ENTRY_STAMP, kind: "cache_warm", provider: "anthropic", model: "m", usage: usage() },
      { type: "model_change", id: "mc1", parentId: null, timestamp: ENTRY_STAMP, provider: "anthropic", modelId: "m" },
      { type: "thinking_level_change", id: "tl1", parentId: null, timestamp: ENTRY_STAMP, thinkingLevel: "high" },
      { type: "label", id: "lb1", parentId: null, timestamp: ENTRY_STAMP, targetId: "u1", label: "after" },
      { type: "session_info", id: "si1", parentId: null, timestamp: ENTRY_STAMP, name: "session name" },
      { type: "context_edit", id: "ce1", parentId: null, timestamp: ENTRY_STAMP, targetId: "u1", replacement: { content: "replacement" } },
      { type: "custom", id: "cu1", parentId: null, timestamp: ENTRY_STAMP, customType: "state", data: { any: "data" } },
    ];
    for (const entry of stateOnly) expect(projectEntryTranscript(entry)).toEqual([]);
  });
});

describe("projectEntryTranscript: nested tool calls", () => {
  function nestedResult(nestedCalls: NestedToolCalls): ToolResultMessage {
    return toolResultMessage("call-1", "bash", [{ type: "text", text: "done" }], { nestedCalls });
  }

  function record(overrides: Partial<NestedToolCallRecord> = {}): NestedToolCallRecord {
    return { id: "nested-1", name: "grep", arguments: { pattern: "needle" }, status: "ok", ...overrides };
  }

  it("maps nested call records before the result with a parent call id and host facts", () => {
    const transcript = projectEntryTranscript(messageEntry("r10", nestedResult({
      calls: [record({ durationMs: 12 })],
      complete: true,
    })));
    expect(transcript.map((entry) => entry.entryKey)).toEqual(["call:nested-1", "result:call-1"]);
    expect(transcript[0]).toEqual({
      entryKey: "call:nested-1",
      sourceEntryId: "r10",
      kind: "tool_call",
      content: { pattern: "needle" },
      tool: {
        name: "grep",
        callId: "nested-1",
        parentCallId: "call-1",
        part: "call",
        status: "ok",
        durationMs: 12,
      },
      edited: false,
      digest: reviewDigest({
        entryKey: "call:nested-1",
        sourceEntryId: "r10",
        kind: "tool_call",
        content: { pattern: "needle" },
        tool: { name: "grep", callId: "nested-1", parentCallId: "call-1", part: "call", status: "ok", durationMs: 12 },
        edited: false,
      }),
    });
    expect(transcript[1]!.tool).toEqual({ name: "bash", callId: "call-1", part: "result" });
  });

  it("uses an explicit frozen omitted marker when the host omitted nested arguments", () => {
    const transcript = projectEntryTranscript(messageEntry("r11", nestedResult({
      calls: [record({ id: "nested-2", arguments: undefined, argumentsBytes: 2_048, status: "error", error: "grep failed" })],
      complete: true,
    })));
    const nested = transcript[0]!;
    expect(nested.content).toEqual({ omitted: true });
    expect(Object.isFrozen(nested.content)).toBe(true);
    expect(nested.tool).toEqual({
      name: "grep",
      callId: "nested-2",
      parentCallId: "call-1",
      part: "call",
      status: "error",
      error: "grep failed",
      argumentsBytes: 2_048,
      omitted: true,
    });
  });

  it("appends an environment checkpoint when nested calls were not complete", () => {
    const transcript = projectEntryTranscript(messageEntry("r12", nestedResult({
      calls: [record({ status: "unfinished" })],
      complete: false,
    })));
    expect(transcript.map((entry) => entry.kind)).toEqual(["tool_call", "tool_result", "environment_checkpoint"]);
    expect(transcript[2]).toMatchObject({
      entryKey: "r12:environment_checkpoint:2",
      sourceEntryId: "r12",
      kind: "environment_checkpoint",
      content: "The host recorded incomplete nested tool calls for this tool result; nested call results are not part of the reviewed history.",
      edited: false,
    });
  });

  it("skips invalid nested records, notes them and never crashes", () => {
    const transcript = projectEntryTranscript(messageEntry("r13", nestedResult({
      calls: [
        record({ id: "" }),
        record({ id: "nested-3", name: "" }),
        record({ id: "nested-4", status: "bogus" as NestedToolCallRecord["status"] }),
        record({ id: "nested-5", durationMs: -1 }),
        record({ id: "nested-6", arguments: ["not", "object"] as unknown as NestedToolCallRecord["arguments"] }),
      ],
      complete: true,
    })));
    expect(transcript.map((entry) => entry.entryKey)).toEqual([
      "result:call-1",
      "r13:environment_checkpoint:1",
    ]);
    expect(transcript[1]!.content).toBe(
      "The host recorded nested tool call records with invalid identity or status; they were omitted from the reviewed history.",
    );
  });

  it("notes a malformed nested call envelope instead of throwing", () => {
    const transcript = projectEntryTranscript(messageEntry("r14", toolResultMessage(
      "call-1",
      "bash",
      [{ type: "text", text: "done" }],
      { nestedCalls: { calls: "not-an-array", complete: false } as unknown as NestedToolCalls },
    )));
    expect(transcript.map((entry) => entry.kind)).toEqual(["tool_result", "environment_checkpoint"]);
    expect(transcript[1]!.content).toBe(
      "The host recorded nested tool call records with invalid identity or status; they were omitted from the reviewed history.",
    );
  });
});

describe("buildAuthorization", () => {
  it("builds one immutable entry per raw user message with non-empty text", () => {
    const branch: SessionEntry[] = [
      messageEntry("u1", userMessage("please allow this")),
      messageEntry("a1", assistantMessage([{ type: "text", text: "ok" }])),
      messageEntry("u2", userMessage([
        { type: "text", text: "first line" },
        IMAGE,
        { type: "text", text: "second line" },
      ] as (TextContent | ImageContent)[])),
      messageEntry("u3", userMessage([IMAGE])),
      messageEntry("u4", userMessage("   ")),
    ];
    expect(buildAuthorization(branch)).toEqual([
      { id: "auth:u1", sourceEntryId: "u1", text: "please allow this" },
      { id: "auth:u2", sourceEntryId: "u2", text: "first line\nsecond line" },
    ]);
  });

  it("drops empty text blocks and keeps the remaining raw text verbatim", () => {
    const branch: SessionEntry[] = [
      messageEntry("u5", userMessage([
        { type: "text", text: "" },
        { type: "text", text: "  padded  " },
        { type: "text", text: "" },
      ] as TextContent[])),
    ];
    expect(buildAuthorization(branch)).toEqual([
      { id: "auth:u5", sourceEntryId: "u5", text: "  padded  " },
    ]);
  });

  it("ignores every non-user message and entry", () => {
    const branch: SessionEntry[] = [
      messageEntry("a2", assistantMessage([{ type: "text", text: "assistant text" }])),
      messageEntry("s2", systemMessage("system text")),
      messageEntry("r2", toolResultMessage("call-9", "bash", [{ type: "text", text: "tool text" }])),
      compactionEntry("cp9", "summary text"),
      customMessageEntry("cm9", "extension text"),
    ];
    expect(buildAuthorization(branch)).toEqual([]);
  });

  it("keeps the original user text even when the branch later edits that entry", () => {
    const branch: SessionEntry[] = [
      messageEntry("u6", userMessage("original wording")),
      { type: "context_edit", id: "ce1", parentId: "u6", timestamp: ENTRY_STAMP, targetId: "u6", replacement: { content: "edited wording" } },
    ];
    expect(buildAuthorization(branch)).toEqual([
      { id: "auth:u6", sourceEntryId: "u6", text: "original wording" },
    ]);
  });

  it("returns a deeply frozen list", () => {
    const authorization = buildAuthorization([messageEntry("u7", userMessage("frozen"))]);
    expect(Object.isFrozen(authorization)).toBe(true);
    expect(Object.isFrozen(authorization[0])).toBe(true);
  });
});

function viewInput(overrides: Partial<ReviewProjectionInput> = {}): ReviewProjectionInput {
  return {
    owner: "owner-1",
    sessionId: "session-1",
    leafId: "leaf-1",
    branchRootId: "root-1",
    historyVersion: 3,
    captureSeq: 7,
    branch: [],
    ...overrides,
  };
}

describe("buildReviewView: branch rebuild", () => {
  it("builds a frozen view from identity facts, transcript, authorization and no manifest", () => {
    const view = buildReviewView(viewInput({
      branch: [
        messageEntry("u1", userMessage("hello there")),
        customMessageEntry("cm1", "extension text"),
        compactionEntry("cp1", "compacted history"),
      ],
    }));
    expect(view.owner).toBe("owner-1");
    expect(view.sessionId).toBe("session-1");
    expect(view.leafId).toBe("leaf-1");
    expect(view.branchRootId).toBe("root-1");
    expect(view.historyVersion).toBe(3);
    expect(view.captureSeq).toBe(7);
    expect(view.degraded).toBe(false);
    expect(view.manifest).toBeUndefined();
    expect(view.transcript.map((entry) => entry.entryKey)).toEqual([
      "u1:user:0",
      "cm1:extension:0",
      "cp1:parent_summary:0",
    ]);
    expect(view.authorization).toEqual([
      { id: "auth:u1", sourceEntryId: "u1", text: "hello there" },
    ]);
    expect(Object.isFrozen(view)).toBe(true);
    expect(Object.isFrozen(view.transcript)).toBe(true);
    expect(Object.isFrozen(view.transcript[0])).toBe(true);
    expect(Object.isFrozen(view.authorization)).toBe(true);
    expect(Object.isFrozen(view.authorization[0])).toBe(true);
  });

  it("maps null leaf and branch-root ids to empty strings", () => {
    const view = buildReviewView(viewInput({ leafId: null, branchRootId: null }));
    expect(view.leafId).toBe("");
    expect(view.branchRootId).toBe("");
  });

  it("returns an empty frozen history for an empty branch", () => {
    const view = buildReviewView(viewInput());
    expect(view.transcript).toEqual([]);
    expect(view.authorization).toEqual([]);
    expect(view.manifest).toBeUndefined();
    expect(Object.isFrozen(view.transcript)).toBe(true);
  });

  it("marks every entry of an edited source entry and covers the flag in the digest", () => {
    const view = buildReviewView(viewInput({
      branch: [
        messageEntry("u1", userMessage("original wording")),
        messageEntry("a1", assistantMessage([{ type: "text", text: "reply" }])),
        { type: "context_edit", id: "ce1", parentId: "a1", timestamp: ENTRY_STAMP, targetId: "u1", replacement: { content: "edited wording" } },
      ],
    }));
    const userEntry = view.transcript[0]!;
    expect(userEntry).toMatchObject({ entryKey: "u1:user:0", content: "original wording", edited: true });
    expect(view.transcript[1]!.edited).toBe(false);
    expect(userEntry.digest).toBe(reviewDigest({
      entryKey: "u1:user:0",
      sourceEntryId: "u1",
      kind: "user",
      content: "original wording",
      edited: true,
    }));
    expect(userEntry.digest).not.toBe(reviewDigest({
      entryKey: "u1:user:0",
      sourceEntryId: "u1",
      kind: "user",
      content: "original wording",
      edited: false,
    }));
    expect(view.authorization).toEqual([
      { id: "auth:u1", sourceEntryId: "u1", text: "original wording" },
    ]);
  });
});

type ProjectedMessage = SessionProjection["entries"][number]["messages"][number];

function projected(sourceEntry: SessionEntry, messages: ProjectedMessage[]): ProjectedSessionEntry {
  return { sourceEntry, messages };
}

function projectionOf(entries: ProjectedSessionEntry[]): SessionProjection {
  return {
    entries,
    messages: entries.flatMap((entry) => entry.messages),
    thinkingLevel: "off",
    model: { provider: "anthropic", modelId: "test-model" },
  };
}

function entryMessages(entry: SessionEntry): ProjectedMessage[] {
  return entry.type === "message" ? [entry.message] : [];
}

describe("buildReviewView: host projection", () => {
  it("uses effective projected content for edited entries and still keeps the raw authorization", () => {
    const user = messageEntry("u1", userMessage("original wording"));
    const edit: SessionEntry = {
      type: "context_edit",
      id: "ce1",
      parentId: "u1",
      timestamp: ENTRY_STAMP,
      targetId: "u1",
      replacement: { content: "edited wording" },
    };
    const view = buildReviewView(viewInput({
      branch: [user, edit],
      projection: projectionOf([
        projected(user, [userMessage("edited wording")]),
        projected(edit, []),
      ]),
    }));
    expect(view.transcript).toHaveLength(1);
    expect(view.transcript[0]).toMatchObject({
      entryKey: "u1:user:0",
      sourceEntryId: "u1",
      kind: "user",
      content: "edited wording",
      edited: true,
    });
    expect(view.authorization).toEqual([
      { id: "auth:u1", sourceEntryId: "u1", text: "original wording" },
    ]);
  });

  it("agrees with the branch rebuild when nothing was edited", () => {
    const entries: SessionEntry[] = [
      messageEntry("u1", userMessage("hello")),
      messageEntry("a1", assistantMessage([{ type: "text", text: "hi" }, toolCall("call-1", "bash", { command: "ls" })])),
      messageEntry("r1", toolResultMessage("call-1", "bash", [{ type: "text", text: "file.txt" }])),
      messageEntry("s1", systemMessage("system prompt")),
    ];
    const viaBranch = buildReviewView(viewInput({ branch: entries }));
    const viaProjection = buildReviewView(viewInput({
      branch: entries,
      projection: projectionOf(entries.map((entry) => projected(entry, entryMessages(entry)))),
    }));
    expect(viaProjection.transcript).toEqual(viaBranch.transcript);
    expect(viaProjection.authorization).toEqual(viaBranch.authorization);
    expect(viaProjection.manifest).toEqual(viaBranch.manifest);
  });

  it("maps projected extension, summary and system messages by their agent-message roles", () => {
    const user = messageEntry("u1", userMessage("go"));
    const custom = customMessageEntry("cm1", "ignored raw content");
    const compaction = compactionEntry("cp1", "ignored raw summary");
    const branchSummary: SessionEntry = {
      type: "branch_summary",
      id: "bs1",
      parentId: "u1",
      timestamp: ENTRY_STAMP,
      fromId: "old-leaf",
      summary: "ignored raw branch summary",
    };
    const system = messageEntry("s1", systemMessage("ignored raw prompt"));
    const view = buildReviewView(viewInput({
      branch: [user, custom, compaction, branchSummary, system],
      projection: projectionOf([
        projected(user, [userMessage("go")]),
        projected(custom, [{
          role: "custom",
          customType: "test-extension",
          content: "projected extension text",
          display: true,
          timestamp: MESSAGE_STAMP,
        }]),
        projected(compaction, [{
          role: "compactionSummary",
          summary: "projected compaction summary",
          tokensBefore: 900,
          timestamp: MESSAGE_STAMP,
        }]),
        projected(branchSummary, [{
          role: "branchSummary",
          summary: "projected branch summary",
          fromId: "old-leaf",
          timestamp: MESSAGE_STAMP,
        }]),
        projected(system, [systemMessage("projected system prompt")]),
      ]),
    }));
    expect(view.transcript.map((entry) => [entry.entryKey, entry.kind, entry.content])).toEqual([
      ["u1:user:0", "user", "go"],
      ["cm1:extension:0", "extension", "projected extension text"],
      ["cp1:parent_summary:0", "parent_summary", "projected compaction summary"],
      ["bs1:branch_summary:0", "branch_summary", "projected branch summary"],
      ["s1:environment_checkpoint:0", "environment_checkpoint", "projected system prompt"],
    ]);
  });

  it("lets state-only projected entries contribute nothing", () => {
    const usageEntry: SessionEntry = {
      type: "usage",
      id: "us1",
      parentId: null,
      timestamp: ENTRY_STAMP,
      kind: "cache_warm",
      provider: "anthropic",
      model: "m",
      usage: usage(),
    };
    const view = buildReviewView(viewInput({
      branch: [usageEntry],
      projection: projectionOf([projected(usageEntry, [])]),
    }));
    expect(view.transcript).toEqual([]);
  });
});

function manifestInput(overrides: {
  projection?: SessionProjection;
  branch?: SessionEntry[];
  editedTargets?: ReadonlyMap<string, number>;
} = {}): {
  projection?: SessionProjection;
  branch: readonly SessionEntry[];
  editedTargets: ReadonlyMap<string, number>;
} {
  return {
    projection: overrides.projection,
    branch: overrides.branch ?? [],
    editedTargets: overrides.editedTargets ?? new Map<string, number>(),
  };
}

describe("buildStepManifest", () => {
  it("builds a complete manifest from the latest assistant message", () => {
    const argumentsOne = { command: "ls" };
    const argumentsTwo = { path: "src", recursive: true };
    const input = manifestInput({
      branch: [
        messageEntry("u1", userMessage("go")),
        messageEntry("a1", assistantMessage([
          { type: "text", text: "checking" },
          toolCall("call-1", "bash", argumentsOne),
          toolCall("call-2", "read", argumentsTwo),
        ])),
      ],
    });
    const manifest = buildStepManifest(input);
    expect(manifest).toEqual({
      stepKey: "step-a1",
      sourceEntryId: "a1",
      revision: 0,
      complete: true,
      directCalls: [
        {
          toolCallId: "call-1",
          toolName: "bash",
          arguments: argumentsOne,
          argumentsDigest: reviewDigest({ command: "ls" }),
        },
        {
          toolCallId: "call-2",
          toolName: "read",
          arguments: argumentsTwo,
          argumentsDigest: reviewDigest({ path: "src", recursive: true }),
        },
      ],
    });
    expect(Object.isFrozen(manifest)).toBe(true);
    expect(Object.isFrozen(manifest!.directCalls)).toBe(true);
    expect(Object.isFrozen(manifest!.directCalls[0])).toBe(true);
    expect(Object.isFrozen(manifest!.directCalls[0]!.arguments)).toBe(true);
    expect(manifest!.directCalls[0]!.arguments).not.toBe(argumentsOne);
    expect(Object.isFrozen(argumentsOne)).toBe(false);
  });

  it("uses the latest assistant message and tolerates an assistant with no tool calls", () => {
    const input = manifestInput({
      branch: [
        messageEntry("a1", assistantMessage([toolCall("call-old", "bash", { command: "old" })])),
        messageEntry("a2", assistantMessage([{ type: "text", text: "final answer" }])),
      ],
    });
    expect(buildStepManifest(input)).toMatchObject({
      stepKey: "step-a2",
      sourceEntryId: "a2",
      complete: true,
      directCalls: [],
    });
    expect(buildStepManifest(manifestInput())).toBeUndefined();
  });

  it("applies the edit count of the assistant source entry as the manifest revision", () => {
    const branch = [messageEntry("a1", assistantMessage([toolCall("call-1", "bash", { command: "ls" })]))];
    const manifest = buildStepManifest(manifestInput({ branch, editedTargets: new Map([["a1", 2]]) }));
    expect(manifest).toMatchObject({ stepKey: "step-a1", revision: 2, complete: true });
  });

  it("marks duplicate tool call ids incomplete without dropping either call", () => {
    const manifest = buildStepManifest(manifestInput({
      branch: [messageEntry("a1", assistantMessage([
        toolCall("call-1", "bash", { command: "ls" }),
        toolCall("call-1", "bash", { command: "pwd" }),
      ]))],
    }));
    expect(manifest!.complete).toBe(false);
    expect(manifest!.directCalls.map((call) => call.toolCallId)).toEqual(["call-1", "call-1"]);
  });

  it("marks missing ids and names incomplete and keeps a stable positional id", () => {
    const missingId = buildStepManifest(manifestInput({
      branch: [messageEntry("a1", assistantMessage([toolCall("", "bash", { command: "ls" })]))],
    }));
    expect(missingId!.complete).toBe(false);
    expect(missingId!.directCalls[0]).toMatchObject({
      toolCallId: "a1:tool:0",
      toolName: "bash",
      arguments: { command: "ls" },
    });

    const missingName = buildStepManifest(manifestInput({
      branch: [messageEntry("a1", assistantMessage([toolCall("call-1", "", { command: "ls" })]))],
    }));
    expect(missingName!.complete).toBe(false);
    expect(missingName!.directCalls[0]).toMatchObject({ toolCallId: "call-1", toolName: "" });
  });

  it("marks arguments errors and non-object arguments incomplete with empty arguments", () => {
    const errored = buildStepManifest(manifestInput({
      branch: [messageEntry("a1", assistantMessage([{
        type: "toolCall",
        id: "call-1",
        name: "bash",
        arguments: {},
        argumentsError: "model produced invalid JSON",
      }]))],
    }));
    expect(errored!.complete).toBe(false);
    expect(errored!.directCalls[0]).toMatchObject({ arguments: {}, argumentsDigest: reviewDigest({}) });

    const nonObject = buildStepManifest(manifestInput({
      branch: [messageEntry("a1", assistantMessage([
        toolCall("call-2", "bash", ["not", "an", "object"]),
      ]))],
    }));
    expect(nonObject!.complete).toBe(false);
    expect(nonObject!.directCalls[0]).toMatchObject({ arguments: {} });
  });

  it("marks unknown assistant content-block types incomplete", () => {
    const manifest = buildStepManifest(manifestInput({
      branch: [messageEntry("a1", assistantMessage([
        { type: "text", text: "known" },
        { type: "futureBlock", payload: 1 } as unknown as TextContent,
      ]))],
    }));
    expect(manifest!.complete).toBe(false);
    expect(manifest!.directCalls).toEqual([]);
  });

  it("reads direct calls from the effective projected assistant content", () => {
    const raw = messageEntry("a1", assistantMessage([toolCall("call-old", "bash", { command: "old" })]));
    const projection = projectionOf([
      projected(raw, [assistantMessage([toolCall("call-new", "bash", { command: "new" })])]),
    ]);
    const manifest = buildStepManifest(manifestInput({ branch: [raw], projection }));
    expect(manifest).toMatchObject({
      sourceEntryId: "a1",
      complete: true,
      directCalls: [{ toolCallId: "call-new", toolName: "bash", arguments: { command: "new" } }],
    });
  });

  it("returns undefined when the projection has no effective assistant message", () => {
    const raw = messageEntry("a1", assistantMessage([{ type: "text", text: "gone" }]));
    const projection = projectionOf([projected(raw, [])]);
    expect(buildStepManifest(manifestInput({ branch: [raw], projection }))).toBeUndefined();
  });
});

describe("degradedView", () => {
  it("declares the projection-less mode with a single environment checkpoint and no manifest or authorization", () => {
    const view = degradedView({
      owner: "owner-1",
      sessionId: "session-1",
      leafId: null,
      branchRootId: null,
      historyVersion: 0,
      captureSeq: 1,
    });
    expect(view.owner).toBe("owner-1");
    expect(view.sessionId).toBe("session-1");
    expect(view.historyVersion).toBe(0);
    expect(view.captureSeq).toBe(1);
    expect(view.leafId).toBe("");
    expect(view.branchRootId).toBe("");
    expect(view.degraded).toBe(true);
    expect(view.manifest).toBeUndefined();
    expect(view.authorization).toEqual([]);
    expect(view.transcript).toHaveLength(1);
    expect(view.transcript[0]).toMatchObject({
      entryKey: "environment:degraded",
      kind: "environment_checkpoint",
      edited: false,
    });
    expect(view.transcript[0]!.sourceEntryId).toBeUndefined();
    const notice = view.transcript[0]!.content;
    expect(typeof notice).toBe("string");
    expect(notice).toContain("not part of the reviewed history");
    expect(view.transcript[0]!.digest).toBe(reviewDigest({
      entryKey: "environment:degraded",
      kind: "environment_checkpoint",
      content: notice,
      edited: false,
    }));
  });

  it("is deterministic and frozen", () => {
    const input = {
      owner: "owner-1",
      sessionId: "session-1",
      leafId: null,
      branchRootId: null,
      historyVersion: 0,
      captureSeq: 1,
    } as const;
    const first = degradedView(input);
    const second = degradedView(input);
    expect(second).toEqual(first);
    expect(Object.isFrozen(first)).toBe(true);
    expect(Object.isFrozen(first.transcript)).toBe(true);
    expect(Object.isFrozen(first.transcript[0])).toBe(true);
    expect(Object.isFrozen(first.authorization)).toBe(true);
  });

  it("keeps host facts out of the reviewed history: the transcript is exactly one notice", () => {
    const view = degradedView({
      owner: "owner-2",
      sessionId: "session-2",
      leafId: "leaf-x",
      branchRootId: "root-x",
      historyVersion: 4,
      captureSeq: 9,
    });
    expect(view.leafId).toBe("leaf-x");
    expect(view.branchRootId).toBe("root-x");
    expect(view.historyVersion).toBe(4);
    expect(view.captureSeq).toBe(9);
    expect(view.transcript).toHaveLength(1);
    expect(view.transcript[0]!.kind).toBe("environment_checkpoint");
  });
});

describe("projectFullEvidence", () => {
  it("emits a matching authorization once in place and never duplicates the user transcript entry", () => {
    const view = buildReviewView(viewInput({
      branch: [
        messageEntry("u1", userMessage("allow this")),
        messageEntry("a1", assistantMessage([{ type: "text", text: "ok" }])),
      ],
    }));
    const projection = projectFullEvidence(view);
    expect(projection.authorization).toEqual([
      { sourceEntryId: "u1", text: "allow this" },
    ]);
    expect(projection.evidence).toEqual([
      {
        id: "auth:u1",
        source: "user",
        text: "allow this",
        digest: reviewDigest({ id: "auth:u1", source: "user", text: "allow this" }),
      },
      {
        id: "a1:assistant:0",
        source: "assistant",
        text: "ok",
        digest: reviewDigest({ id: "a1:assistant:0", source: "assistant", text: "ok" }),
      },
    ]);
  });

  it("emits one authorization evidence for a user message with several text blocks", () => {
    const view = buildReviewView(viewInput({
      branch: [
        messageEntry("u1", userMessage([
          { type: "text", text: "first block" },
          { type: "text", text: "second block" },
        ])),
        messageEntry("a1", assistantMessage([{ type: "text", text: "ok" }])),
      ],
    }));
    expect(view.transcript.map((entry) => entry.entryKey)).toEqual([
      "u1:user:0",
      "u1:user:1",
      "a1:assistant:0",
    ]);
    const projection = projectFullEvidence(view);
    expect(projection.authorization).toEqual([
      { sourceEntryId: "u1", text: "first block\nsecond block" },
    ]);
    expect(projection.evidence.map((entry) => [entry.id, entry.source])).toEqual([
      ["auth:u1", "user"],
      ["a1:assistant:0", "assistant"],
    ]);
  });

  it("emits an edited user entry as extension evidence with its effective content and prepends its raw authorization", () => {
    const user = messageEntry("u1", userMessage("original wording"));
    const edit: SessionEntry = {
      type: "context_edit",
      id: "ce1",
      parentId: "u1",
      timestamp: ENTRY_STAMP,
      targetId: "u1",
      replacement: { content: "edited wording" },
    };
    const view = buildReviewView(viewInput({
      branch: [user, edit],
      projection: projectionOf([
        projected(user, [userMessage("edited wording")]),
        projected(edit, []),
      ]),
    }));
    const projection = projectFullEvidence(view);
    expect(projection.evidence.map((entry) => [entry.id, entry.source, entry.text])).toEqual([
      ["auth:u1", "user", "original wording"],
      ["u1:user:0", "extension", "edited wording"],
    ]);
    expect(projection.authorization).toEqual([{ sourceEntryId: "u1", text: "original wording" }]);
  });

  it("prepends authorization entries that the transcript projection no longer contains", () => {
    const first = messageEntry("u1", userMessage("first"));
    const compaction = compactionEntry("cp1", "summary text");
    const second = messageEntry("u2", userMessage("second"));
    const view = buildReviewView(viewInput({
      branch: [first, compaction, second],
      projection: projectionOf([
        projected(compaction, [{
          role: "compactionSummary",
          summary: "summary text",
          tokensBefore: 100,
          timestamp: MESSAGE_STAMP,
        }]),
        projected(second, [userMessage("second")]),
      ]),
    }));
    const projection = projectFullEvidence(view);
    expect(projection.evidence.map((entry) => [entry.id, entry.source])).toEqual([
      ["auth:u1", "user"],
      ["cp1:parent_summary:0", "summary"],
      ["auth:u2", "user"],
    ]);
    expect(projection.evidence[1]!.text).toBe("summary text");
  });

  it("maps assistant and tool transcript entries to tool evidence with tool facts and canonical argument text", () => {
    const view = buildReviewView(viewInput({
      branch: [
        messageEntry("u1", userMessage("run it")),
        messageEntry("a1", assistantMessage([
          { type: "text", text: "running" },
          toolCall("call-1", "bash", { command: "ls" }),
        ])),
        messageEntry("r1", toolResultMessage("call-1", "bash", [{ type: "text", text: "file.txt" }])),
      ],
    }));
    const evidence = projectFullEvidence(view).evidence;
    expect(evidence.map((entry) => [entry.id, entry.source, entry.text])).toEqual([
      ["auth:u1", "user", "run it"],
      ["a1:assistant:0", "assistant", "running"],
      ["call:call-1", "tool", canonicalJson({ command: "ls" })],
      ["result:call-1", "tool", "file.txt"],
    ]);
    expect(evidence[2]).toEqual({
      id: "call:call-1",
      source: "tool",
      text: '{"command":"ls"}',
      toolName: "bash",
      toolCallId: "call-1",
      toolPart: "call",
      digest: reviewDigest({
        id: "call:call-1",
        source: "tool",
        text: '{"command":"ls"}',
        toolName: "bash",
        toolCallId: "call-1",
        toolPart: "call",
      }),
    });
    expect(evidence[3]).toMatchObject({
      id: "result:call-1",
      source: "tool",
      text: "file.txt",
      toolName: "bash",
      toolCallId: "call-1",
      toolPart: "result",
    });
  });

  it("maps summaries, extensions and environment checkpoints to their evidence sources", () => {
    const view = buildReviewView(viewInput({
      branch: [
        messageEntry("s1", systemMessage("system prompt")),
        customMessageEntry("cm1", "extension text"),
        compactionEntry("cp1", "compaction summary"),
        {
          type: "branch_summary",
          id: "bs1",
          parentId: "cp1",
          timestamp: ENTRY_STAMP,
          fromId: "old-leaf",
          summary: "branch summary",
        },
      ],
    }));
    const evidence = projectFullEvidence(view).evidence;
    expect(evidence.map((entry) => [entry.id, entry.source, entry.text])).toEqual([
      ["s1:environment_checkpoint:0", "environment", "system prompt"],
      ["cm1:extension:0", "extension", "extension text"],
      ["cp1:parent_summary:0", "summary", "compaction summary"],
      ["bs1:branch_summary:0", "summary", "branch summary"],
    ]);
  });

  it("returns deeply frozen evidence and full authorization", () => {
    const view = buildReviewView(viewInput({
      branch: [messageEntry("u1", userMessage("allow"))],
    }));
    const projection = projectFullEvidence(view);
    expect(Object.isFrozen(projection)).toBe(true);
    expect(Object.isFrozen(projection.evidence)).toBe(true);
    expect(Object.isFrozen(projection.evidence[0])).toBe(true);
    expect(Object.isFrozen(projection.authorization)).toBe(true);
    expect(Object.isFrozen(projection.authorization[0])).toBe(true);
  });
});

describe("projectDeltaEvidence", () => {
  const branch: SessionEntry[] = [
    messageEntry("u1", userMessage("allow this")),
    messageEntry("a1", assistantMessage([{ type: "text", text: "running" }, toolCall("call-1", "bash", { command: "ls" })])),
    messageEntry("r1", toolResultMessage("call-1", "bash", [{ type: "text", text: "file.txt" }])),
  ];

  it("projects only the transcript entries after the cursor", () => {
    const view = buildReviewView(viewInput({ branch }));
    expect(projectDeltaEvidence(view, 3).evidence.map((entry) => [entry.id, entry.source])).toEqual([
      ["result:call-1", "tool"],
    ]);
    expect(projectDeltaEvidence(view, 2).evidence.map((entry) => entry.id)).toEqual(["call:call-1", "result:call-1"]);
  });

  it("never repeats user-sourced entries in the delta region but still returns full authorization", () => {
    const view = buildReviewView(viewInput({ branch }));
    const projection = projectDeltaEvidence(view, 0);
    expect(projection.evidence.map((entry) => [entry.id, entry.source])).toEqual([
      ["a1:assistant:0", "assistant"],
      ["call:call-1", "tool"],
      ["result:call-1", "tool"],
    ]);
    expect(projection.evidence.some((entry) => entry.source === "user")).toBe(false);
    expect(projection.authorization).toEqual([{ sourceEntryId: "u1", text: "allow this" }]);
  });

  it("emits an edited user entry as extension evidence in the delta region", () => {
    const user = messageEntry("u1", userMessage("original wording"));
    const edit: SessionEntry = {
      type: "context_edit",
      id: "ce1",
      parentId: "u1",
      timestamp: ENTRY_STAMP,
      targetId: "u1",
      replacement: { content: "edited wording" },
    };
    const view = buildReviewView(viewInput({
      branch: [user, edit],
      projection: projectionOf([
        projected(user, [userMessage("edited wording")]),
        projected(edit, []),
      ]),
    }));
    const projection = projectDeltaEvidence(view, 0);
    expect(projection.evidence.map((entry) => [entry.id, entry.source, entry.text])).toEqual([
      ["u1:user:0", "extension", "edited wording"],
    ]);
    expect(projection.authorization).toEqual([{ sourceEntryId: "u1", text: "original wording" }]);
  });

  it("clamps cursors outside the transcript bounds", () => {
    const view = buildReviewView(viewInput({ branch }));
    const past = projectDeltaEvidence(view, 99);
    expect(past.evidence).toEqual([]);
    expect(past.authorization).toHaveLength(1);
    const negative = projectDeltaEvidence(view, -5);
    expect(negative.evidence.map((entry) => entry.id)).toEqual([
      "a1:assistant:0",
      "call:call-1",
      "result:call-1",
    ]);
  });

  it("returns deeply frozen evidence", () => {
    const view = buildReviewView(viewInput({ branch }));
    const projection = projectDeltaEvidence(view, 1);
    expect(Object.isFrozen(projection)).toBe(true);
    expect(Object.isFrozen(projection.evidence)).toBe(true);
    expect(Object.isFrozen(projection.evidence[0])).toBe(true);
    expect(Object.isFrozen(projection.authorization)).toBe(true);
  });
});

describe("transcriptPrefixDigest", () => {
  const branch: SessionEntry[] = [
    messageEntry("u1", userMessage("allow this")),
    messageEntry("a1", assistantMessage([{ type: "text", text: "running" }] )),
    messageEntry("r1", toolResultMessage("call-1", "bash", [{ type: "text", text: "file.txt" }])),
  ];

  it("digests the digests of the first count transcript entries", () => {
    const view = buildReviewView(viewInput({ branch }));
    expect(transcriptPrefixDigest(view, 2)).toBe(reviewDigest([
      view.transcript[0]!.digest,
      view.transcript[1]!.digest,
    ]));
    expect(transcriptPrefixDigest(view, 1)).toBe(reviewDigest([view.transcript[0]!.digest]));
  });

  it("clamps count to the transcript bounds", () => {
    const view = buildReviewView(viewInput({ branch }));
    expect(transcriptPrefixDigest(view, 0)).toBe(reviewDigest([]));
    expect(transcriptPrefixDigest(view, -3)).toBe(reviewDigest([]));
    expect(transcriptPrefixDigest(view, 99)).toBe(reviewDigest(view.transcript.map((entry) => entry.digest)));
    expect(transcriptPrefixDigest(view, 99)).not.toBe(transcriptPrefixDigest(view, 0));
  });

  it("digests an empty prefix for an empty transcript", () => {
    const view = buildReviewView(viewInput());
    expect(transcriptPrefixDigest(view, 5)).toBe(reviewDigest([]));
  });
});

describe("renderEvidence", () => {
  function evidence(partial: Partial<ApprovalEvidence> & Pick<ApprovalEvidence, "id" | "source" | "text">): ApprovalEvidence {
    return {
      ...partial,
      digest: reviewDigest({ id: partial.id, source: partial.source, text: partial.text }),
    };
  }

  it("renders an empty list as an empty string", () => {
    expect(renderEvidence([])).toBe("");
  });

  it("renders one deterministic line per non-tool entry", () => {
    expect(renderEvidence([
      evidence({ id: "auth:u1", source: "user", text: "allow this" }),
      evidence({ id: "a1:assistant:0", source: "assistant", text: "ok" }),
      evidence({ id: "cp1:parent_summary:0", source: "summary", text: "earlier summary" }),
      evidence({ id: "cm1:extension:0", source: "extension", text: "extension text" }),
      evidence({ id: "s1:environment_checkpoint:0", source: "environment", text: "prompt" }),
    ])).toBe([
      "- user auth:u1: allow this",
      "- assistant a1:assistant:0: ok",
      "- summary cp1:parent_summary:0: earlier summary",
      "- extension cm1:extension:0: extension text",
      "- environment s1:environment_checkpoint:0: prompt",
    ].join("\n"));
  });

  it("renders tool entries with part, name and call id", () => {
    expect(renderEvidence([
      evidence({ id: "call:call-1", source: "tool", text: '{"command":"ls"}', toolName: "bash", toolCallId: "call-1", toolPart: "call" }),
      evidence({ id: "result:call-1", source: "tool", text: "file.txt", toolName: "bash", toolCallId: "call-1", toolPart: "result" }),
    ])).toBe([
      '- tool call bash call-1: {"command":"ls"}',
      "- tool result bash call-1: file.txt",
    ].join("\n"));
  });

  it("flattens embedded newlines so every entry stays on one line", () => {
    expect(renderEvidence([
      evidence({ id: "a1:assistant:0", source: "assistant", text: "line one\nline two\r\nline three" }),
    ])).toBe("- assistant a1:assistant:0: line one\\nline two\\nline three");
  });

  it("renders a projected full evidence list in transcript order", () => {
    const view = buildReviewView(viewInput({
      branch: [
        messageEntry("u1", userMessage("allow this")),
        messageEntry("a1", assistantMessage([{ type: "text", text: "ok" }])),
      ],
    }));
    expect(renderEvidence(projectFullEvidence(view).evidence)).toBe([
      "- user auth:u1: allow this",
      "- assistant a1:assistant:0: ok",
    ].join("\n"));
  });
});

describe("determinism between rebuild and suffix mapping", () => {
  function diverseBranch(): SessionEntry[] {
    return [
      messageEntry("u1", userMessage("hello")),
      messageEntry("a1", assistantMessage([{ type: "text", text: "working" }, toolCall("call-1", "bash", { command: "ls" })])),
      messageEntry("r1", toolResultMessage("call-1", "bash", [{ type: "text", text: "out" }], {
        nestedCalls: { calls: [{ id: "nested-1", name: "grep", arguments: { pattern: "x" }, status: "ok" }], complete: true },
      })),
      messageEntry("s1", systemMessage("system prompt")),
      customMessageEntry("cm1", "extension text"),
      compactionEntry("cp1", "compaction summary", { systemMessage: systemMessage("prompt at compaction") }),
      {
        type: "branch_summary",
        id: "bs1",
        parentId: "cp1",
        timestamp: ENTRY_STAMP,
        fromId: "old-leaf",
        summary: "branch summary",
      },
      { type: "usage", id: "us1", parentId: "bs1", timestamp: ENTRY_STAMP, kind: "cache_warm", provider: "anthropic", model: "m", usage: usage() },
    ];
  }

  it("concatenating per-entry suffix projections reproduces the branch rebuild exactly", () => {
    const branch = diverseBranch();
    const view = buildReviewView(viewInput({ branch }));
    const suffix = branch.flatMap((entry) => projectEntryTranscript(entry));
    expect(view.transcript).toEqual(suffix);
  });

  it("concatenating per-entry suffix projections reproduces the projection rebuild for unedited entries", () => {
    const branch = diverseBranch();
    const projectedEntries = branch.map((entry) => {
      if (entry.type === "message") return projected(entry, [entry.message]);
      if (entry.type === "custom_message") {
        return projected(entry, [{
          role: "custom",
          customType: entry.customType,
          content: entry.content,
          display: entry.display,
          timestamp: MESSAGE_STAMP,
        }]);
      }
      if (entry.type === "compaction") {
        const summary = {
          role: "compactionSummary" as const,
          summary: entry.summary,
          tokensBefore: entry.tokensBefore,
          timestamp: MESSAGE_STAMP,
        };
        return projected(entry, entry.systemMessage === undefined ? [summary] : [entry.systemMessage, summary]);
      }
      if (entry.type === "branch_summary") {
        return projected(entry, [{
          role: "branchSummary" as const,
          summary: entry.summary,
          fromId: entry.fromId,
          timestamp: MESSAGE_STAMP,
        }]);
      }
      return projected(entry, []);
    });
    const view = buildReviewView(viewInput({ branch, projection: projectionOf(projectedEntries) }));
    const suffix = branch.flatMap((entry) => projectEntryTranscript(entry));
    expect(view.transcript).toEqual(suffix);
  });

  it("never mutates or freezes the raw branch inputs", () => {
    const argumentsValue = { command: "ls", nested: { flags: ["-la"] } };
    const assistant = messageEntry("a1", assistantMessage([toolCall("call-1", "bash", argumentsValue)]));
    const branch: SessionEntry[] = [messageEntry("u1", userMessage("go")), assistant];
    const before = JSON.stringify(branch);
    buildReviewView(viewInput({ branch }));
    expect(JSON.stringify(branch)).toBe(before);
    expect(Object.isFrozen(branch)).toBe(false);
    expect(Object.isFrozen(assistant)).toBe(false);
    expect(Object.isFrozen(argumentsValue)).toBe(false);
    expect(Object.isFrozen(argumentsValue.nested.flags)).toBe(false);
  });

  it("produces identical frozen views on repeated rebuilds and carries the manifest revision", () => {
    const assistant = messageEntry("a1", assistantMessage([{ type: "text", text: "ready" }, toolCall("call-1", "bash", { command: "ls" })]));
    const branch: SessionEntry[] = [
      assistant,
      { type: "context_edit", id: "ce1", parentId: "a1", timestamp: ENTRY_STAMP, targetId: "a1", replacement: { content: "first edit" } },
      { type: "context_edit", id: "ce2", parentId: "ce1", timestamp: ENTRY_STAMP, targetId: "a1", replacement: { content: "second edit" } },
    ];
    const first = buildReviewView(viewInput({ branch, historyVersion: 8, captureSeq: 12 }));
    const second = buildReviewView(viewInput({ branch, historyVersion: 8, captureSeq: 12 }));
    expect(second).toEqual(first);
    expect(first.manifest).toMatchObject({
      stepKey: "step-a1",
      sourceEntryId: "a1",
      revision: 2,
      complete: true,
      directCalls: [{ toolCallId: "call-1", toolName: "bash", arguments: { command: "ls" } }],
    });
    expect(Object.isFrozen(first.manifest)).toBe(true);
    expect(Object.isFrozen(first.manifest!.directCalls[0]!.arguments)).toBe(true);
    expect(first.transcript[0]!.edited).toBe(true);
  });
});
