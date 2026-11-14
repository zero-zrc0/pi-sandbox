/**
 * Session/evidence projection (specs/reviewer-context.md §2, §3, §6).
 *
 * This module owns the pure mapping from host session facts to the frozen
 * reviewer view: transcript entries, immutable authorization, the latest step
 * manifest, the projection-less degraded view and the Full/Delta evidence
 * projections. It never reads the session itself, never reads a clock and never
 * mutates its inputs; every returned entry, array and view is frozen.
 *
 * The host supplies a compaction-aware `SessionProjection` whose entries keep
 * the raw `sourceEntry` plus the model-visible `messages` after context edits.
 * The same mapping is exposed per raw entry so an incremental suffix append and
 * a full rebuild produce identical transcript entries for the same raw entry.
 */
import type { SessionEntry, SessionProjection } from "@earendil-works/pi-coding-agent";
import { canonicalJson } from "../policy/project-rules/types";
import {
  reviewDigest,
  type ApprovalEvidence,
  type ApprovalEvidenceSource,
  type AuthorizationEvidence,
  type ReviewAuthorizationEntry,
  type ReviewManifestCall,
  type ReviewStepManifest,
  type ReviewToolFacts,
  type ReviewTranscriptEntry,
  type ReviewTranscriptKind,
  type ReviewView,
} from "./types";

// ---------------------------------------------------------------------------
// JSON, freezing and digest helpers
// ---------------------------------------------------------------------------

type JsonObject = Readonly<Record<string, unknown>>;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Narrow to a plain object without intersecting the value with the caller's
 * declared union; host session files can hold shapes the static types rule out.
 */
function plainObject(value: unknown): Record<string, unknown> | undefined {
  return isPlainObject(value) ? value : undefined;
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const item of Object.values(value as Record<string, unknown>)) deepFreeze(item);
  return value;
}

/** Digest of one transcript entry: identity, source, content, tool facts, edited. */
function transcriptDigest(fields: {
  readonly entryKey: string;
  readonly sourceEntryId: string;
  readonly kind: ReviewTranscriptKind;
  readonly content: string | JsonObject;
  readonly tool?: ReviewToolFacts;
  readonly edited: boolean;
}): string {
  return reviewDigest({
    entryKey: fields.entryKey,
    sourceEntryId: fields.sourceEntryId,
    kind: fields.kind,
    content: fields.content,
    tool: fields.tool,
    edited: fields.edited,
  });
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

/**
 * Deep-copy and freeze a JSON object. The copy keeps the returned view from
 * freezing or aliasing the caller's host objects; a non-object or non-JSON
 * value yields `undefined` so the caller can substitute its own default.
 */
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

const EMPTY_ARGUMENTS: JsonObject = deepFreeze({});
const OMITTED_ARGUMENTS: JsonObject = deepFreeze({ omitted: true });

const INCOMPLETE_NESTED_NOTE =
  "The host recorded incomplete nested tool calls for this tool result; nested call results are not part of the reviewed history.";
const INVALID_NESTED_NOTE =
  "The host recorded nested tool call records with invalid identity or status; they were omitted from the reviewed history.";

/** Build one entry and freeze its digest in place. */
function makeEntry(fields: {
  readonly entryKey: string;
  readonly sourceEntryId: string;
  readonly kind: ReviewTranscriptKind;
  readonly content: string | JsonObject;
  readonly tool?: ReviewToolFacts;
  readonly edited: boolean;
}): ReviewTranscriptEntry {
  return {
    entryKey: fields.entryKey,
    sourceEntryId: fields.sourceEntryId,
    kind: fields.kind,
    content: fields.content,
    edited: fields.edited,
    ...(fields.tool === undefined ? {} : { tool: fields.tool }),
    digest: transcriptDigest(fields),
  };
}

/**
 * Map one text-bearing content value to transcript entries. A string is one
 * block; an array keeps one entry per text block using the content-block
 * position, so an ignored image or thinking block never shifts a key.
 */
function textBlockEntries(
  sourceEntryId: string,
  kind: "user" | "assistant",
  content: unknown,
  edited: boolean,
): ReviewTranscriptEntry[] {
  const entries: ReviewTranscriptEntry[] = [];
  if (typeof content === "string") {
    entries.push(makeEntry({ entryKey: `${sourceEntryId}:${kind}:0`, sourceEntryId, kind, content, edited }));
    return entries;
  }
  if (!Array.isArray(content)) return entries;
  content.forEach((block: unknown, index) => {
    if (isPlainObject(block) && block.type === "text" && typeof block.text === "string") {
      entries.push(makeEntry({ entryKey: `${sourceEntryId}:${kind}:${index}`, sourceEntryId, kind, content: block.text, edited }));
    }
  });
  return entries;
}

// ---------------------------------------------------------------------------
// Message mapping
// ---------------------------------------------------------------------------

/** Text of a string-or-block-array content value; images are ignored. */
function textContentText(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  const parts: string[] = [];
  for (const block of content) {
    if (isPlainObject(block) && block.type === "text" && typeof block.text === "string") parts.push(block.text);
  }
  return parts.join("\n");
}

function mapUserMessage(sourceEntryId: string, content: unknown, edited: boolean): ReviewTranscriptEntry[] {
  return textBlockEntries(sourceEntryId, "user", content, edited);
}

function mapAssistantMessage(sourceEntryId: string, content: unknown, edited: boolean): ReviewTranscriptEntry[] {
  const entries: ReviewTranscriptEntry[] = [];
  if (!Array.isArray(content)) return entries;
  content.forEach((block: unknown, index) => {
    if (!isPlainObject(block)) return;
    if (block.type === "text" && typeof block.text === "string") {
      entries.push(makeEntry({
        entryKey: `${sourceEntryId}:assistant:${index}`,
        sourceEntryId,
        kind: "assistant",
        content: block.text,
        edited,
      }));
      return;
    }
    if (block.type !== "toolCall") return;
    const callId = typeof block.id === "string" && block.id.length > 0 ? block.id : undefined;
    const name = typeof block.name === "string" ? block.name : "";
    const tool: ReviewToolFacts = { name, ...(callId === undefined ? {} : { callId }), part: "call" };
    entries.push(makeEntry({
      entryKey: callId === undefined ? `${sourceEntryId}:tool:${index}` : `call:${callId}`,
      sourceEntryId,
      kind: "tool_call",
      content: frozenJsonObject(block.arguments) ?? EMPTY_ARGUMENTS,
      tool,
      edited,
    }));
  });
  return entries;
}

interface NestedCallFacts {
  readonly id: string;
  readonly content: JsonObject;
  readonly tool: ReviewToolFacts;
}

function nonNegativeNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function nonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

/**
 * Validate one nested call record and normalize it. A record with invalid
 * identity, status or optional numeric facts yields `undefined`; the projections
 * then skip it and record an explicit environment note instead of crashing.
 */
function readNestedCall(record: unknown, parentCallId: string | undefined): NestedCallFacts | undefined {
  if (!isPlainObject(record)) return undefined;
  const { id, name, status } = record;
  if (typeof id !== "string" || id.length === 0) return undefined;
  if (typeof name !== "string" || name.length === 0) return undefined;
  if (status !== "ok" && status !== "error" && status !== "unfinished") return undefined;
  if (record.durationMs !== undefined && !nonNegativeNumber(record.durationMs)) return undefined;
  if (record.argumentsBytes !== undefined && !nonNegativeInteger(record.argumentsBytes)) return undefined;
  if (record.error !== undefined && typeof record.error !== "string") return undefined;
  const argumentsValue = frozenJsonObject(record.arguments);
  if (record.arguments !== undefined && argumentsValue === undefined) return undefined;
  const omitted = record.arguments === undefined;
  const tool: ReviewToolFacts = {
    name,
    callId: id,
    ...(parentCallId === undefined ? {} : { parentCallId }),
    part: "call",
    status,
    ...(typeof record.durationMs === "number" ? { durationMs: record.durationMs } : {}),
    ...(typeof record.error === "string" ? { error: record.error } : {}),
    ...(typeof record.argumentsBytes === "number" ? { argumentsBytes: record.argumentsBytes } : {}),
    ...(omitted ? { omitted: true } : {}),
  };
  return { id, content: argumentsValue ?? OMITTED_ARGUMENTS, tool };
}

/** Nested call records become tool_call entries ahead of the owning result. */
function nestedCallEntries(
  sourceEntryId: string,
  nestedCalls: unknown,
  parentCallId: string | undefined,
  edited: boolean,
  notes: string[],
): ReviewTranscriptEntry[] {
  if (nestedCalls === undefined) return [];
  if (!isPlainObject(nestedCalls) || !Array.isArray(nestedCalls.calls) || typeof nestedCalls.complete !== "boolean") {
    notes.push(INVALID_NESTED_NOTE);
    return [];
  }
  const entries: ReviewTranscriptEntry[] = [];
  let invalidRecords = 0;
  for (const record of nestedCalls.calls) {
    const facts = readNestedCall(record, parentCallId);
    if (facts === undefined) {
      invalidRecords += 1;
      continue;
    }
    entries.push(makeEntry({
      entryKey: `call:${facts.id}`,
      sourceEntryId,
      kind: "tool_call",
      content: facts.content,
      tool: facts.tool,
      edited,
    }));
  }
  if (invalidRecords > 0) notes.push(INVALID_NESTED_NOTE);
  if (nestedCalls.complete === false) notes.push(INCOMPLETE_NESTED_NOTE);
  return entries;
}

function mapToolResult(sourceEntryId: string, message: Record<string, unknown>, edited: boolean): ReviewTranscriptEntry[] {
  const toolCallId = typeof message.toolCallId === "string" && message.toolCallId.length > 0
    ? message.toolCallId
    : undefined;
  const toolName = typeof message.toolName === "string" ? message.toolName : "";
  const tool: ReviewToolFacts = {
    name: toolName,
    ...(toolCallId === undefined ? {} : { callId: toolCallId }),
    part: "result",
    ...(message.isError === true ? { isError: true } : {}),
  };
  const notes: string[] = [];
  const entries = nestedCallEntries(sourceEntryId, message.nestedCalls, toolCallId, edited, notes);
  entries.push(makeEntry({
    entryKey: toolCallId === undefined ? `${sourceEntryId}:tool_result:0` : `result:${toolCallId}`,
    sourceEntryId,
    kind: "tool_result",
    content: textContentText(message.content),
    tool,
    edited,
  }));
  for (const note of notes) {
    entries.push(makeEntry({
      entryKey: `${sourceEntryId}:environment_checkpoint:${entries.length}`,
      sourceEntryId,
      kind: "environment_checkpoint",
      content: note,
      edited,
    }));
  }
  return entries;
}

function mapMessage(sourceEntryId: string, message: unknown, edited: boolean): ReviewTranscriptEntry[] {
  if (!isPlainObject(message)) return [];
  if (message.role === "user") return mapUserMessage(sourceEntryId, message.content, edited);
  if (message.role === "assistant") return mapAssistantMessage(sourceEntryId, message.content, edited);
  if (message.role === "toolResult") return mapToolResult(sourceEntryId, message, edited);
  if (message.role === "system") {
    return [makeEntry({
      entryKey: `${sourceEntryId}:environment_checkpoint:0`,
      sourceEntryId,
      kind: "environment_checkpoint",
      content: textContentText(message.content),
      edited,
    })];
  }
  if (message.role === "custom") {
    return [makeEntry({
      entryKey: `${sourceEntryId}:extension:0`,
      sourceEntryId,
      kind: "extension",
      content: textContentText(message.content),
      edited,
    })];
  }
  if (message.role === "compactionSummary") {
    return [makeEntry({
      entryKey: `${sourceEntryId}:parent_summary:0`,
      sourceEntryId,
      kind: "parent_summary",
      content: typeof message.summary === "string" ? message.summary : "",
      edited,
    })];
  }
  if (message.role === "branchSummary") {
    return [makeEntry({
      entryKey: `${sourceEntryId}:branch_summary:0`,
      sourceEntryId,
      kind: "branch_summary",
      content: typeof message.summary === "string" ? message.summary : "",
      edited,
    })];
  }
  return [];
}

// ---------------------------------------------------------------------------
// Raw entry mapping (incremental suffix and full rebuild share this)
// ---------------------------------------------------------------------------

function mapRawEntry(entry: SessionEntry, edited: boolean): ReviewTranscriptEntry[] {
  switch (entry.type) {
    case "message":
      return mapMessage(entry.id, entry.message, edited);
    case "custom_message":
      return [makeEntry({
        entryKey: `${entry.id}:extension:0`,
        sourceEntryId: entry.id,
        kind: "extension",
        content: textContentText(entry.content),
        edited,
      })];
    case "compaction": {
      const entries: ReviewTranscriptEntry[] = [];
      if (entry.systemMessage !== undefined) {
        entries.push(makeEntry({
          entryKey: `${entry.id}:environment_checkpoint:0`,
          sourceEntryId: entry.id,
          kind: "environment_checkpoint",
          content: textContentText(entry.systemMessage.content),
          edited,
        }));
      }
      entries.push(makeEntry({
        entryKey: `${entry.id}:parent_summary:0`,
        sourceEntryId: entry.id,
        kind: "parent_summary",
        content: entry.summary,
        edited,
      }));
      return entries;
    }
    case "branch_summary":
      return [makeEntry({
        entryKey: `${entry.id}:branch_summary:0`,
        sourceEntryId: entry.id,
        kind: "branch_summary",
        content: entry.summary,
        edited,
      })];
    default:
      return [];
  }
}

/** Non-empty text blocks of one user message, kept verbatim and in order. */
function nonEmptyTextBlocks(content: unknown): string[] {
  const blocks: string[] = [];
  if (typeof content === "string") {
    if (content.trim().length > 0) blocks.push(content);
    return blocks;
  }
  if (!Array.isArray(content)) return blocks;
  for (const block of content) {
    if (isPlainObject(block) && block.type === "text" && typeof block.text === "string" && block.text.trim().length > 0) {
      blocks.push(block.text);
    }
  }
  return blocks;
}

/**
 * Immutable authorization is generated from the raw branch's user messages
 * only. It is never derived from projected or edited content, so an edit can
 * change what the model sees but can never rewrite what the user authorized.
 */
export function buildAuthorization(entries: readonly SessionEntry[]): readonly ReviewAuthorizationEntry[] {
  const authorization: ReviewAuthorizationEntry[] = [];
  for (const entry of entries) {
    if (entry.type !== "message") continue;
    const message = plainObject(entry.message);
    if (message === undefined || message.role !== "user") continue;
    const text = nonEmptyTextBlocks(message.content).join("\n");
    if (text.length === 0) continue;
    authorization.push({ id: `auth:${entry.id}`, sourceEntryId: entry.id, text });
  }
  return deepFreeze(authorization);
}

/** Every host fact a full review-view rebuild needs. */
export interface ReviewProjectionInput {
  readonly owner: string;
  readonly sessionId: string;
  readonly leafId: string | null;
  readonly branchRootId: string | null;
  readonly historyVersion: number;
  readonly captureSeq: number;
  readonly branch: readonly SessionEntry[];
  readonly projection?: SessionProjection;
}

/** Append-only context edits observed on the raw branch, by target entry id. */
function collectEditedTargets(entries: readonly SessionEntry[]): Map<string, number> {
  const targets = new Map<string, number>();
  for (const entry of entries) {
    if (entry.type !== "context_edit") continue;
    targets.set(entry.targetId, (targets.get(entry.targetId) ?? 0) + 1);
  }
  return targets;
}

/** Read the direct tool calls of one assistant content list. */
function readDirectCalls(sourceEntryId: string, content: unknown): {
  readonly complete: boolean;
  readonly directCalls: readonly ReviewManifestCall[];
} {
  if (!Array.isArray(content)) return { complete: false, directCalls: [] };
  let complete = true;
  const seenIds = new Set<string>();
  const directCalls: ReviewManifestCall[] = [];
  content.forEach((block: unknown, index) => {
    if (!isPlainObject(block)) {
      complete = false;
      return;
    }
    if (block.type === "text" || block.type === "thinking") return;
    if (block.type !== "toolCall") {
      complete = false;
      return;
    }
    const validId = typeof block.id === "string" && block.id.length > 0;
    const validName = typeof block.name === "string" && block.name.length > 0;
    const toolCallId = validId ? block.id as string : `${sourceEntryId}:tool:${index}`;
    if (!validId) complete = false;
    if (!validName) complete = false;
    if (block.argumentsError !== undefined) complete = false;
    const argumentValue = frozenJsonObject(block.arguments);
    if (argumentValue === undefined) complete = false;
    const argumentsValue = argumentValue ?? EMPTY_ARGUMENTS;
    if (validId) {
      if (seenIds.has(toolCallId)) complete = false;
      seenIds.add(toolCallId);
    }
    directCalls.push({
      toolCallId,
      toolName: validName ? block.name as string : "",
      arguments: argumentsValue,
      argumentsDigest: reviewDigest(argumentsValue),
    });
  });
  return { complete, directCalls };
}

/** Latest effective assistant message, in projection or raw-branch order. */
function latestAssistantMessage(input: {
  readonly projection?: SessionProjection;
  readonly branch: readonly SessionEntry[];
}): { readonly sourceEntryId: string; readonly message: Record<string, unknown> } | undefined {
  let latest: { sourceEntryId: string; message: Record<string, unknown> } | undefined;
  if (input.projection !== undefined) {
    for (const projected of input.projection.entries) {
      for (const candidate of projected.messages) {
        const message = plainObject(candidate);
        if (message !== undefined && message.role === "assistant") {
          latest = { sourceEntryId: projected.sourceEntry.id, message };
        }
      }
    }
    return latest;
  }
  for (const entry of input.branch) {
    if (entry.type !== "message") continue;
    const message = plainObject(entry.message);
    if (message === undefined || message.role !== "assistant") continue;
    latest = { sourceEntryId: entry.id, message };
  }
  return latest;
}

/**
 * Manifest of the latest assistant step. Any fact the host recorded
 * ambiguously (duplicate ids, missing identity, non-object arguments, an
 * argument error or an unknown content block) makes the manifest incomplete;
 * callers must not capture a step against an incomplete manifest.
 */
export function buildStepManifest(input: {
  readonly projection?: SessionProjection;
  readonly branch: readonly SessionEntry[];
  readonly editedTargets: ReadonlyMap<string, number>;
}): ReviewStepManifest | undefined {
  const latest = latestAssistantMessage(input);
  if (latest === undefined) return undefined;
  const { complete, directCalls } = readDirectCalls(latest.sourceEntryId, latest.message.content);
  const manifest: ReviewStepManifest = {
    stepKey: `step-${latest.sourceEntryId}`,
    sourceEntryId: latest.sourceEntryId,
    revision: input.editedTargets.get(latest.sourceEntryId) ?? 0,
    complete,
    directCalls,
  };
  return deepFreeze(manifest);
}

/**
 * Full rebuild of the frozen session view. The host projection is authoritative
 * when present because it carries the effective content after compaction and
 * context edits; without it the raw branch entries are mapped one by one.
 */
export function buildReviewView(input: ReviewProjectionInput): ReviewView {
  const editedTargets = collectEditedTargets(input.branch);
  const transcript: ReviewTranscriptEntry[] = [];
  if (input.projection === undefined) {
    for (const entry of input.branch) {
      transcript.push(...mapRawEntry(entry, (editedTargets.get(entry.id) ?? 0) > 0));
    }
  } else {
    for (const projected of input.projection.entries) {
      const sourceEntryId = projected.sourceEntry.id;
      const edited = (editedTargets.get(sourceEntryId) ?? 0) > 0;
      for (const message of projected.messages) {
        transcript.push(...mapMessage(sourceEntryId, message, edited));
      }
    }
  }
  const manifest = buildStepManifest({ ...input, editedTargets });
  const view: ReviewView = {
    owner: input.owner,
    sessionId: input.sessionId,
    historyVersion: input.historyVersion,
    captureSeq: input.captureSeq,
    leafId: input.leafId ?? "",
    branchRootId: input.branchRootId ?? "",
    ...(manifest === undefined ? {} : { manifest }),
    transcript,
    authorization: buildAuthorization(input.branch),
    degraded: false,
  };
  return deepFreeze(view);
}

const DEGRADED_NOTICE =
  "This session is served without a host session projection, so it starts empty. " +
  "Host transcript, tool results and session events are not part of the reviewed history; " +
  "only events captured after this environment checkpoint are reviewed live.";

/**
 * Projection-less degraded view (§2). The host offered no session projection
 * and the session is empty, so the view serves an explicit notice instead of a
 * history: host events observed later must never be presented as reviewed
 * history, and no step manifest or authorization exists.
 */
export function degradedView(input: {
  readonly owner: string;
  readonly sessionId: string;
  readonly leafId: string | null;
  readonly branchRootId: string | null;
  readonly historyVersion: number;
  readonly captureSeq: number;
}): ReviewView {
  const notice: ReviewTranscriptEntry = {
    entryKey: "environment:degraded",
    kind: "environment_checkpoint",
    content: DEGRADED_NOTICE,
    edited: false,
    digest: reviewDigest({
      entryKey: "environment:degraded",
      kind: "environment_checkpoint",
      content: DEGRADED_NOTICE,
      edited: false,
    }),
  };
  const view: ReviewView = {
    owner: input.owner,
    sessionId: input.sessionId,
    historyVersion: input.historyVersion,
    captureSeq: input.captureSeq,
    leafId: input.leafId ?? "",
    branchRootId: input.branchRootId ?? "",
    transcript: [notice],
    authorization: [],
    degraded: true,
  };
  return deepFreeze(view);
}

/**
 * Map one raw host entry to transcript entries. State-only entries (usage,
 * model changes, thinking-level changes, labels, session info, custom data and
 * context edits) contribute nothing to the model-visible history.
 */
export function projectEntryTranscript(entry: SessionEntry): readonly ReviewTranscriptEntry[] {
  return deepFreeze(mapRawEntry(entry, false));
}

// ---------------------------------------------------------------------------
// Evidence projection (§6)
// ---------------------------------------------------------------------------

/** Evidence sources mapped from the transcript kinds of a projected view. */
const SOURCE_BY_KIND: Readonly<Record<ReviewTranscriptKind, ApprovalEvidenceSource>> = {
  user: "user",
  assistant: "assistant",
  tool_call: "tool",
  tool_result: "tool",
  parent_summary: "summary",
  branch_summary: "summary",
  extension: "extension",
  environment_checkpoint: "environment",
};

export interface EvidenceProjection {
  readonly evidence: readonly ApprovalEvidence[];
  readonly authorization: readonly AuthorizationEvidence[];
}

/** One transcript entry's content as evidence text (objects use canonical JSON). */
function evidenceText(content: ReviewTranscriptEntry["content"]): string {
  return typeof content === "string" ? content : canonicalJson(content);
}

/** Evidence digest covers id, source, text and the tool facts. */
function evidenceDigest(fields: {
  readonly id: string;
  readonly source: ApprovalEvidenceSource;
  readonly text: string;
  readonly toolName?: string;
  readonly toolCallId?: string;
  readonly toolPart?: "call" | "result";
}): string {
  return reviewDigest({
    id: fields.id,
    source: fields.source,
    text: fields.text,
    toolName: fields.toolName,
    toolCallId: fields.toolCallId,
    toolPart: fields.toolPart,
  });
}

function transcriptEvidence(entry: ReviewTranscriptEntry, source: ApprovalEvidenceSource): ApprovalEvidence {
  const text = evidenceText(entry.content);
  const toolName = entry.tool?.name;
  const toolCallId = entry.tool?.callId;
  const toolPart = entry.tool?.part;
  return {
    id: entry.entryKey,
    source,
    text,
    ...(toolName === undefined ? {} : { toolName }),
    ...(toolCallId === undefined ? {} : { toolCallId }),
    ...(toolPart === undefined ? {} : { toolPart }),
    digest: evidenceDigest({ id: entry.entryKey, source, text, toolName, toolCallId, toolPart }),
  };
}

function authorizationEvidence(entry: ReviewAuthorizationEntry): ApprovalEvidence {
  return {
    id: entry.id,
    source: "user",
    text: entry.text,
    digest: evidenceDigest({ id: entry.id, source: "user", text: entry.text }),
  };
}

function freezeEvidence(evidence: ApprovalEvidence[], authorization: AuthorizationEvidence[]): EvidenceProjection {
  return deepFreeze({ evidence, authorization });
}

/** Full authorization is always returned separately from the evidence region. */
function projectedAuthorization(view: ReviewView): AuthorizationEvidence[] {
  return view.authorization.map((entry) => ({ sourceEntryId: entry.sourceEntryId, text: entry.text }));
}

/**
 * Full evidence projection (§6). Authorization is emitted once as user evidence
 * in its transcript position; an edited user entry is emitted as extension and
 * the original authorization is prepended instead, so edited text is never
 * disguised as user authorization.
 */
export function projectFullEvidence(view: ReviewView): EvidenceProjection {
  const authorization = projectedAuthorization(view);
  const authorizationBySourceEntry = new Map(view.authorization.map((entry) => [entry.sourceEntryId, entry]));
  const consumedAuthorization = new Set<string>();
  const evidence: ApprovalEvidence[] = [];
  for (const entry of view.transcript) {
    if (entry.kind === "user") {
      const authorizationEntry = entry.sourceEntryId === undefined
        ? undefined
        : authorizationBySourceEntry.get(entry.sourceEntryId);
      if (authorizationEntry !== undefined && !entry.edited) {
        // One user message can project several text-block entries; its
        // authorization is emitted once and the later blocks add nothing.
        if (!consumedAuthorization.has(authorizationEntry.sourceEntryId)) {
          consumedAuthorization.add(authorizationEntry.sourceEntryId);
          evidence.push(authorizationEvidence(authorizationEntry));
        }
        continue;
      }
      if (entry.edited) {
        evidence.push(transcriptEvidence(entry, "extension"));
        continue;
      }
      evidence.push(transcriptEvidence(entry, "user"));
      continue;
    }
    evidence.push(transcriptEvidence(entry, SOURCE_BY_KIND[entry.kind]));
  }
  const prepended = view.authorization
    .filter((entry) => !consumedAuthorization.has(entry.sourceEntryId))
    .map(authorizationEvidence);
  return freezeEvidence([...prepended, ...evidence], authorization);
}

/**
 * Delta evidence projection (§6). Only transcript entries after the cursor are
 * projected; user-sourced entries are never repeated in the delta region
 * because the full authorization list is returned separately. An edited user
 * entry keeps its effective text as extension evidence.
 */
export function projectDeltaEvidence(view: ReviewView, cursor: number): EvidenceProjection {
  const authorization = projectedAuthorization(view);
  const start = Math.min(Math.max(0, Math.trunc(cursor)), view.transcript.length);
  const evidence: ApprovalEvidence[] = [];
  for (const entry of view.transcript.slice(start)) {
    if (entry.kind === "user") {
      if (entry.edited) evidence.push(transcriptEvidence(entry, "extension"));
      continue;
    }
    evidence.push(transcriptEvidence(entry, SOURCE_BY_KIND[entry.kind]));
  }
  return freezeEvidence(evidence, authorization);
}

/** Digest of the first `count` transcript entry digests; count is clamped to [0, length]. */
export function transcriptPrefixDigest(view: ReviewView, count: number): string {
  const clamped = Math.min(Math.max(0, Math.trunc(count)), view.transcript.length);
  return reviewDigest(view.transcript.slice(0, clamped).map((entry) => entry.digest));
}

/** Deterministic text rendering of evidence: one flattened line per entry. */
export function renderEvidence(evidence: readonly ApprovalEvidence[]): string {
  return evidence.map((entry) => {
    const text = entry.text.replace(/\r\n|\r|\n/g, "\\n");
    if (entry.source === "tool") {
      return `- tool ${entry.toolPart ?? ""} ${entry.toolName ?? ""} ${entry.toolCallId ?? ""}: ${text}`;
    }
    return `- ${entry.source} ${entry.id}: ${text}`;
  }).join("\n");
}
