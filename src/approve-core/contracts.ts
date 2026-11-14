import type { ExecutionRequest } from "../elevation";
/** Maximum direct calls accepted for one complete step. */
const MAX_STEP_CALLS = 1_024;
/** Maximum analysis units accepted for one complete step. */
export const MAX_STEP_UNITS = 4_096;
/** Maximum analysis units accepted for one original tool call. */
export const MAX_UNITS_PER_CALL = 256;
/** Maximum decisions accepted from one node submission. */
export const MAX_NODE_DECISIONS = 256;
/** Maximum characters accepted in one decision reason. */
export const MAX_REASON_LENGTH = 2_000;
/** Maximum canonical size of one node result. */
export const MAX_RESULT_BYTES = 256 * 1024;
export type Decision = "allow" | "ask" | "deny";
export type CallDecision = Decision | "escalate";
export type AskTarget = "allow" | "escalate";
export type ReviewDecision = "approve" | "deny" | "defer";

const CAPTURES = new WeakSet<object>();
const STATES = new WeakSet<object>();

function nonEmptyString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value : undefined;
}

function isSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value);
}

function isDecision(value: unknown): value is Decision {
  return value === "allow" || value === "ask" || value === "deny";
}

function isCallDecision(value: unknown): value is CallDecision {
  return isDecision(value) || value === "escalate";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const own = Object.keys(value);
  return own.length === keys.length && keys.every((key) =>
    Object.prototype.hasOwnProperty.call(value, key));
}

function freezeTree<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freezeTree(child);
    Object.freeze(value);
  }
  return value;
}

function jsonBytes(value: JsonValue): number {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}

function summaryReason(unit: UnitState): CallReason {
  return freezeTree({
    unitId: unit.unitId,
    decision: unit.decision,
    ...(unit.askFor === undefined ? {} : { askFor: unit.askFor }),
    reason: unit.reason,
    ...(unit.review === undefined ? {} : {
      review: {
        decision: unit.review.decision,
        nodeId: unit.review.nodeId,
        reason: unit.review.reason,
      },
    }),
  });
}

function callDenied(call: CallState): boolean {
  return call.units.some((unit) => unit.decision === "deny" || unit.review?.decision === "deny");
}

/* ------------------------------------------------------------------ */
/* Capture                                                             */
/* ------------------------------------------------------------------ */

export interface StepCaptureInput {
  readonly stepKey: string;
  readonly sessionId: string;
  readonly sourceEntryId: string;
  readonly manifestRevision: number;
  readonly complete: boolean;
  readonly directCalls: readonly {
    readonly toolCallId?: string;
    readonly parentToolCallId?: string;
    readonly toolName?: string;
    readonly arguments?: unknown;
    readonly argumentsDigest?: string;
    readonly hostExecutionRequest?: ExecutionRequest;
  }[];
}

export interface CapturedDirectCall {
  readonly toolCallId: string;
  readonly parentToolCallId?: string;
  readonly toolName: string;
  readonly arguments: JsonObject;
  readonly argumentsDigest: string;
  readonly hostExecutionRequest?: ExecutionRequest;
  /** Digest over the frozen original call facts; units bind to this value. */
  readonly digest: string;
}

export interface StepCapture {
  readonly stepKey: string;
  readonly sessionId: string;
  readonly sourceEntryId: string;
  readonly manifestRevision: number;
  readonly complete: true;
  readonly directCalls: readonly CapturedDirectCall[];
  readonly digest: string;
}

export type CaptureFailure =
  | "invalid-capture"
  | "incomplete-step"
  | "empty-step"
  | "missing-call-identity"
  | "invalid-call-facts"
  | "invalid-arguments"
  | "missing-arguments-digest"
  | "arguments-digest-mismatch"
  | "duplicate-tool-call-id"
  | "call-limit-exceeded";

export type CaptureStepResult =
  | { readonly ok: true; readonly capture: StepCapture }
  | { readonly ok: false; readonly reason: CaptureFailure };

/**
 * Copy and validate the host's complete step manifest. Missing facts are
 * rejected rather than completed from a later hook or from another registry.
 */
export function captureStep(input: StepCaptureInput): CaptureStepResult {
  let data: JsonValue;
  try {
    data = freezeJson(input);
  } catch {
    return { ok: false, reason: "invalid-capture" };
  }
  if (!isRecord(data)) return { ok: false, reason: "invalid-capture" };

  const stepKey = nonEmptyString(data.stepKey);
  const sessionId = nonEmptyString(data.sessionId);
  const sourceEntryId = nonEmptyString(data.sourceEntryId);
  if (
    !stepKey ||
    !sessionId ||
    !sourceEntryId ||
    !isSafeInteger(data.manifestRevision) ||
    data.manifestRevision < 0
  ) {
    return { ok: false, reason: "invalid-capture" };
  }
  if (data.complete !== true) return { ok: false, reason: "incomplete-step" };
  if (!Array.isArray(data.directCalls)) return { ok: false, reason: "invalid-capture" };
  if (data.directCalls.length === 0) return { ok: false, reason: "empty-step" };
  if (data.directCalls.length > MAX_STEP_CALLS) {
    return { ok: false, reason: "call-limit-exceeded" };
  }

  const seen = new Set<string>();
  const directCalls: CapturedDirectCall[] = [];
  for (const candidate of data.directCalls) {
    if (!isRecord(candidate)) return { ok: false, reason: "missing-call-identity" };
    const toolCallId = nonEmptyString(candidate.toolCallId);
    const toolName = nonEmptyString(candidate.toolName);
    if (!toolCallId || !toolName) {
      return { ok: false, reason: "missing-call-identity" };
    }
    if (seen.has(toolCallId)) {
      return { ok: false, reason: "duplicate-tool-call-id" };
    }
    const parentToolCallId = candidate.parentToolCallId;
    const parent = nonEmptyString(parentToolCallId);
    if (parentToolCallId !== undefined && (!parent || parent === toolCallId)) {
      return { ok: false, reason: "invalid-call-facts" };
    }
    if (!isRecord(candidate.arguments)) {
      return { ok: false, reason: "invalid-arguments" };
    }
    const argumentsDigest = nonEmptyString(candidate.argumentsDigest);
    if (!argumentsDigest) {
      return { ok: false, reason: "missing-arguments-digest" };
    }
    if (!/^[0-9a-f]{64}$/.test(argumentsDigest)) {
      return { ok: false, reason: "arguments-digest-mismatch" };
    }
    const args = candidate.arguments as JsonObject;
    if (jsonDigest(args) !== argumentsDigest) {
      return { ok: false, reason: "arguments-digest-mismatch" };
    }

    const facts: Record<string, JsonValue> = {
      toolCallId,
      toolName,
      arguments: args,
      argumentsDigest,
    };
    if (isRecord(candidate.hostExecutionRequest)) {
      const reason = nonEmptyString(candidate.hostExecutionRequest.reason);
      if (!reason) return { ok: false, reason: "invalid-call-facts" };
      const elevation = candidate.hostExecutionRequest.elevation;
      if (elevation !== undefined && (!isRecord(elevation) ||
        (elevation.tier !== "default" && elevation.tier !== "host") ||
        !Array.isArray(elevation.scope) || elevation.scope.length === 0 ||
        elevation.scope.some((entry) => !isRecord(entry) || !nonEmptyString(entry.path) ||
          (entry.access !== "read" && entry.access !== "write")))) {
        return { ok: false, reason: "invalid-call-facts" };
      }
      facts.hostExecutionRequest = { reason, ...(elevation === undefined ? {} : { elevation: elevation as JsonValue }) };
    } else if (candidate.hostExecutionRequest !== undefined) {
      return { ok: false, reason: "invalid-call-facts" };
    }
    if (parent !== undefined) {
      facts.parentToolCallId = parent;
    }
    seen.add(toolCallId);
    directCalls.push(freezeTree({
      ...facts,
      digest: jsonDigest(facts),
    }) as unknown as CapturedDirectCall);
  }

  const facts = {
    stepKey,
    sessionId,
    sourceEntryId,
    manifestRevision: data.manifestRevision,
    complete: true as const,
    directCalls,
  };
  const capture = freezeTree({ ...facts, digest: jsonDigest(facts) });
  CAPTURES.add(capture);
  return { ok: true, capture };
}

/* ------------------------------------------------------------------ */
/* Prepared step state                                                 */
/* ------------------------------------------------------------------ */

export interface UnitPreparation {
  readonly toolCallId: string;
  readonly unitId: string;
  readonly actionDigest: string;
  readonly reason: string;
}

export interface UnitDecisionRecord {
  readonly revision: number;
  readonly nodeId: string;
  readonly priority: number | null;
  readonly decision: CallDecision;
  readonly askFor?: AskTarget;
  readonly reason: string;
}

export interface UnitState {
  readonly unitId: string;
  readonly decision: CallDecision;
  readonly askFor?: AskTarget;
  readonly reason: string;
  readonly source: string;
  readonly history: readonly UnitDecisionRecord[];
  readonly review?: UnitReviewRecord;
}

export interface UnitReviewRecord {
  readonly revision: number;
  readonly nodeId: string;
  readonly decision: "approve" | "deny";
  readonly reason: string;
}

export interface CallState {
  readonly toolCallId: string;
  readonly parentToolCallId?: string;
  readonly toolName: string;
  readonly arguments: JsonObject;
  readonly argumentsDigest: string;
  readonly hostExecutionRequest?: ExecutionRequest;
  readonly askFor?: AskTarget;
  readonly digest: string;
  readonly units: readonly UnitState[];
}

export interface StepState {
  readonly stepKey: string;
  readonly sessionId: string;
  readonly sourceEntryId: string;
  readonly captureDigest: string;
  readonly revision: number;
  readonly calls: readonly CallState[];
  readonly digest: string;
}

export type PrepareFailure =
  | "invalid-capture"
  | "invalid-unit"
  | "unit-limit-exceeded"
  | "unknown-tool-call-id"
  | "duplicate-unit"
  | "action-without-unit"
  | "unit-action-mismatch"
  | "initial-state-not-ask";

export type PrepareStepResult =
  | { readonly ok: true; readonly state: StepState }
  | { readonly ok: false; readonly reason: PrepareFailure };

/**
 * Freeze the analysis result. Every unit starts at ask; the analysis node
 * cannot decide a unit, rewrite the original call or create a new tool call.
 */
export function prepareStep(
  capture: StepCapture,
  units: readonly UnitPreparation[],
): PrepareStepResult {
  if (!CAPTURES.has(capture)) return { ok: false, reason: "invalid-capture" };

  let data: JsonValue;
  try {
    data = freezeJson(units);
  } catch {
    return { ok: false, reason: "invalid-unit" };
  }
  if (!Array.isArray(data)) return { ok: false, reason: "invalid-unit" };
  if (data.length === 0) return { ok: false, reason: "action-without-unit" };
  if (data.length > MAX_STEP_UNITS) return { ok: false, reason: "unit-limit-exceeded" };

  const callsById = new Map(capture.directCalls.map((call) => [call.toolCallId, call]));
  const seenUnits = new Set<string>();
  const grouped = new Map<string, UnitPreparation[]>();

  for (const candidate of data) {
    if (!isRecord(candidate)) return { ok: false, reason: "invalid-unit" };
    if (Object.prototype.hasOwnProperty.call(candidate, "decision")) {
      return { ok: false, reason: "initial-state-not-ask" };
    }
    if (!hasExactKeys(candidate, ["toolCallId", "unitId", "actionDigest", "reason"])) {
      return { ok: false, reason: "invalid-unit" };
    }
    const toolCallId = nonEmptyString(candidate.toolCallId);
    const unitId = nonEmptyString(candidate.unitId);
    const actionDigest = nonEmptyString(candidate.actionDigest);
    const reason = nonEmptyString(candidate.reason);
    if (!toolCallId || !unitId || !actionDigest || !reason) {
      return { ok: false, reason: "invalid-unit" };
    }
    if (reason.length > MAX_REASON_LENGTH) return { ok: false, reason: "invalid-unit" };
    const call = callsById.get(toolCallId);
    if (!call) return { ok: false, reason: "unknown-tool-call-id" };
    if (actionDigest !== call.digest) {
      return { ok: false, reason: "unit-action-mismatch" };
    }
    if (seenUnits.has(unitId)) return { ok: false, reason: "duplicate-unit" };
    seenUnits.add(unitId);
    const list = grouped.get(toolCallId) ?? [];
    list.push(freezeTree({ toolCallId, unitId, actionDigest, reason }));
    grouped.set(toolCallId, list);
  }

  for (const call of capture.directCalls) {
    const callUnits = grouped.get(call.toolCallId);
    if (!callUnits || callUnits.length === 0) {
      return { ok: false, reason: "action-without-unit" };
    }
    if (callUnits.length > MAX_UNITS_PER_CALL) {
      return { ok: false, reason: "unit-limit-exceeded" };
    }
  }

  const calls: CallState[] = capture.directCalls.map((call) => {
    const callUnits = grouped.get(call.toolCallId)!;
    const unitStates = callUnits.map((unit) => freezeTree({
      unitId: unit.unitId,
      decision: "ask" as const,
      reason: unit.reason,
      source: "structure-analysis",
      history: [{
        revision: 1,
        nodeId: "structure-analysis",
        priority: null,
        decision: "ask" as const,
        reason: unit.reason,
      }],
    }));
    return freezeTree({
      toolCallId: call.toolCallId,
      ...(call.parentToolCallId === undefined
        ? {}
        : { parentToolCallId: call.parentToolCallId }),
      toolName: call.toolName,
      arguments: call.arguments,
      argumentsDigest: call.argumentsDigest,
      ...(call.hostExecutionRequest === undefined
        ? {}
        : { hostExecutionRequest: call.hostExecutionRequest }),
      ...(call.hostExecutionRequest === undefined ? {} : { askFor: "escalate" as const }),
      digest: call.digest,
      units: unitStates,
    });
  });

  const facts = {
    stepKey: capture.stepKey,
    sessionId: capture.sessionId,
    sourceEntryId: capture.sourceEntryId,
    captureDigest: capture.digest,
    revision: 1,
    calls,
  };
  const state = freezeTree({ ...facts, digest: jsonDigest(facts) });
  STATES.add(state);
  return { ok: true, state };
}

/* ------------------------------------------------------------------ */
/* Node results                                                        */
/* ------------------------------------------------------------------ */

export interface NodeIdentity {
  readonly id: string;
  readonly priority: number | null;
}

export interface UnitDecision {
  readonly toolCallId: string;
  readonly unitId: string;
  readonly decision: CallDecision;
  readonly askFor?: AskTarget;
  readonly reason: string;
}

export interface UnitReview {
  readonly toolCallId: string;
  readonly unitId: string;
  readonly decision: "approve" | "deny";
  readonly reason: string;
}

/**
 * The reserved built-in keys of one call's fact view. Their
 * values are projected from the BashProgram output the host already holds.
 * This is a reserved base set, not a closed enumeration of allowed keys.
 */
export const BASH_PROGRAM_BUILTIN_KEYS = [
  "commandText",
  "commands",
  "programCalls",
  "pathRuleCandidates",
  "externalAccesses",
] as const;

export type BashProgramBuiltinKey = (typeof BASH_PROGRAM_BUILTIN_KEYS)[number];

/**
 * The per-call fact view a node reads through `bashProgram["key"]`
 * It is an ordinary frozen dictionary with own data
 * properties: it inherits nothing from Object.prototype, reads unknown keys
 * as `undefined`, never recomputes on a read and exposes no getters. The
 * built-in keys keep their value shapes — `commandText` is the source
 * command, the three arrays hold the BashProgram output entries — while
 * every other key, the user-published extension keys, reads as `unknown` for
 * the consumer to confirm the structure before use. The view types stay free
 * of internal alias imports: the SDK ships this contract as source and a
 * packed user project must be able to typecheck it, while the built-in
 * consumers keep reading the fully typed facts through their existing
 * BashProgram getters. A call without a parsed program has no entry at all.
 */
export interface BashProgramFactsView {
  /** The source command text this call's parsed program was built from. */
  readonly commandText: string;
  /** The parsed command units (`BashProgram.commands()`), in source order. */
  readonly commands: readonly object[];
  /** Literal program-name and argv candidates aligned with `commands`. */
  readonly programCalls: readonly object[];
  /** Effective working directory used by this BashProgram. */
  readonly workingDirectory: string;
  /** The path-rule candidates with their policy lookup values and effects. */
  readonly pathRuleCandidates: readonly object[];
  /** The deduplicated accesses that resolve outside the working directory. */
  readonly externalAccesses: readonly object[];
  readonly [key: string]: unknown;
}

/**
 * One call's fact supplement inside a {@link NodeResult}. The
 * values are plain JSON data under new keys; a supplement may never overwrite
 * a built-in or already published key.
 */
export interface BashProgramFactsEntry {
  readonly toolCallId: string;
  readonly values: Readonly<Record<string, JsonValue>>;
}

export interface NodeResult {
  readonly decisions: readonly UnitDecision[];
  /** Review outcomes authorize or reject this frozen call without changing its rule result. */
  readonly reviews?: readonly UnitReview[];
  /**
   * Optional per-call fact supplements. They are validated
   * together with `decisions` as one formal acceptance: either both sides of
   * the result are published or neither is.
   */
  readonly bashProgramFacts?: readonly BashProgramFactsEntry[];
}

export interface NodeSubmission {
  readonly node: NodeIdentity;
  readonly evaluatedRevision: number;
  readonly result: NodeResult;
}

/**
 * The host-side context a fact supplement is accepted against: the per-call
 * views the host currently holds for this step. A call without an entry here
 * has no Bash program, so supplementing it is an invalid node result.
 */
export interface ApplyNodeResultOptions {
  readonly bashPrograms?: Readonly<Record<string, BashProgramFactsView>>;
}

export type ApplyFailure =
  | "invalid-state"
  | "invalid-node"
  | "invalid-result"
  | "invalid-decision"
  | "stale-revision"
  | "unknown-tool-call-id"
  | "unknown-unit"
  | "cross-call-identity"
  | "duplicate-decision"
  | "conflicting-decision"
  | "ask-cannot-be-allowed"
  | "invalid-review"
  | "duplicate-review"
  | "conflicting-review"
  | "unit-not-pending-review"
  | "unit-already-reviewed"
  | "call-already-denied"
  | "reason-too-long"
  | "result-too-large"
  | "invalid-bash-facts"
  | "unknown-bash-program"
  | "bash-fact-key-exists"
  | "duplicate-bash-fact-key";

export type ApplyNodeResultResult =
  | {
      readonly ok: true;
      readonly state: StepState;
      readonly applied: readonly UnitDecision[];
      readonly appliedReviews?: readonly UnitReview[];
      /** The accepted fact supplements, present when the result carried any. */
      readonly acceptedFacts?: readonly BashProgramFactsEntry[];
    }
  | { readonly ok: false; readonly reason: ApplyFailure };

function validNode(value: unknown): NodeIdentity | undefined {
  if (!isRecord(value) || !hasExactKeys(value, ["id", "priority"])) return undefined;
  const id = nonEmptyString(value.id);
  if (!id || id.length > MAX_NODE_ID_LENGTH) return undefined;
  if (value.priority !== null && !isSafeInteger(value.priority)) return undefined;
  return freezeTree({ id, priority: value.priority as number | null });
}

const RESULT_KEYS = new Set(["decisions", "reviews", "bashProgramFacts"]);
const ESCALATION_APPROVER_IDS = new Set([
  "builtin/human",
  "builtin/llm-approver",
  "builtin/decision-approver",
]);
const REVIEWER_NODE_IDS = new Set([
  "builtin/decision",
  "builtin/human",
  "builtin/llm-approver",
  "builtin/decision-approver",
]);

type BashFactsValidation =
  | { readonly ok: true; readonly accepted?: readonly BashProgramFactsEntry[] }
  | { readonly ok: false; readonly reason: ApplyFailure };

/**
 * Validate the optional fact supplements of one result. Every
 * check is pure: nothing is adopted, published or observed here. A supplement
 * must target a captured call that the host holds a fact view for, carry
 * plain JSON values under new keys only, and never overwrite a built-in or
 * already published key — neither within one entry nor across the entries of
 * the same submission.
 */
function validateBashProgramFacts(
  state: StepState,
  result: Record<string, unknown>,
  options: ApplyNodeResultOptions | undefined,
): BashFactsValidation {
  const contributions = result.bashProgramFacts;
  if (contributions === undefined || (Array.isArray(contributions) && contributions.length === 0)) {
    return { ok: true };
  }
  if (!Array.isArray(contributions)) return { ok: false, reason: "invalid-bash-facts" };
  const views = options?.bashPrograms;
  const accepted: BashProgramFactsEntry[] = [];
  const claimed = new Map<string, Set<string>>();
  for (const candidate of contributions) {
    if (!isRecord(candidate) || !hasExactKeys(candidate, ["toolCallId", "values"])) {
      return { ok: false, reason: "invalid-bash-facts" };
    }
    const toolCallId = nonEmptyString(candidate.toolCallId);
    if (!toolCallId) return { ok: false, reason: "invalid-bash-facts" };
    const call = state.calls.find((entry) => entry.toolCallId === toolCallId);
    if (!call) return { ok: false, reason: "unknown-tool-call-id" };
    const view = views === undefined || !Object.hasOwn(views, toolCallId)
      ? undefined
      : views[toolCallId];
    if (view === undefined) return { ok: false, reason: "unknown-bash-program" };
    if (!isRecord(candidate.values)) return { ok: false, reason: "invalid-bash-facts" };
    const seen = claimed.get(toolCallId) ?? new Set<string>();
    claimed.set(toolCallId, seen);
    for (const key of Object.keys(candidate.values)) {
      if (
        (BASH_PROGRAM_BUILTIN_KEYS as readonly string[]).includes(key) ||
        Object.hasOwn(view, key)
      ) {
        return { ok: false, reason: "bash-fact-key-exists" };
      }
      if (seen.has(key)) return { ok: false, reason: "duplicate-bash-fact-key" };
      seen.add(key);
    }
    // The values already passed freezeJson with the whole submission, so they
    // are plain JSON; the entry reuses that frozen object instead of copying.
    accepted.push(freezeTree({
      toolCallId,
      values: candidate.values,
    }) as unknown as BashProgramFactsEntry);
  }
  return { ok: true, accepted: Object.freeze(accepted) };
}

/**
 * Validate one node batch before applying any of it. A malformed batch leaves
 * the input snapshot untouched; a valid batch advances exactly one revision.
 * Fact supplements are validated as part of the same batch: when any side of
 * the result fails, no decision and no fact is published.
 */
export function applyNodeResult(
  state: StepState,
  submission: NodeSubmission,
  options: ApplyNodeResultOptions = {},
): ApplyNodeResultResult {
  if (!STATES.has(state)) return { ok: false, reason: "invalid-state" };

  let data: JsonValue;
  try {
    data = freezeJson(submission);
  } catch {
    return { ok: false, reason: "invalid-result" };
  }
  if (!isRecord(data) || !hasExactKeys(data, ["node", "evaluatedRevision", "result"])) {
    return { ok: false, reason: "invalid-result" };
  }
  const node = validNode(data.node);
  if (!node) return { ok: false, reason: "invalid-node" };
  if (!isSafeInteger(data.evaluatedRevision)) {
    return { ok: false, reason: "invalid-result" };
  }
  if (data.evaluatedRevision !== state.revision) {
    return { ok: false, reason: "stale-revision" };
  }
  if (!isRecord(data.result)) return { ok: false, reason: "invalid-result" };
  const resultKeys = Object.keys(data.result);
  if (
    resultKeys.length > RESULT_KEYS.size ||
    !Object.hasOwn(data.result, "decisions") ||
    !resultKeys.every((key) => RESULT_KEYS.has(key))
  ) {
    return { ok: false, reason: "invalid-result" };
  }
  const supplements = validateBashProgramFacts(state, data.result, options);
  if (!supplements.ok) return supplements;
  const decisions = data.result.decisions;
  if (!Array.isArray(decisions)) return { ok: false, reason: "invalid-result" };
  if (decisions.length > MAX_NODE_DECISIONS) {
    return { ok: false, reason: "result-too-large" };
  }
  try {
    if (jsonBytes(data.result as JsonValue) > MAX_RESULT_BYTES) {
      return { ok: false, reason: "result-too-large" };
    }
  } catch {
    return { ok: false, reason: "invalid-result" };
  }
  const reviewsValue = data.result.reviews;
  if (reviewsValue !== undefined && !Array.isArray(reviewsValue)) {
    return { ok: false, reason: "invalid-result" };
  }
  const reviews = (reviewsValue ?? []) as unknown[];
  if (reviews.length > MAX_NODE_DECISIONS) return { ok: false, reason: "result-too-large" };
  if (reviews.length > 0 && !REVIEWER_NODE_IDS.has(node.id)) {
    return { ok: false, reason: "invalid-review" };
  }

  const validated: UnitDecision[] = [];
  const seen = new Map<string, UnitDecision>();
  for (const candidate of decisions) {
    if (!isRecord(candidate) ||
        !hasExactKeys(candidate, Object.hasOwn(candidate, "askFor")
          ? ["toolCallId", "unitId", "decision", "askFor", "reason"]
          : ["toolCallId", "unitId", "decision", "reason"])) {
      return { ok: false, reason: "invalid-decision" };
    }
    const toolCallId = nonEmptyString(candidate.toolCallId);
    const unitId = nonEmptyString(candidate.unitId);
    const decision = candidate.decision;
    const askFor = candidate.askFor;
    const reason = nonEmptyString(candidate.reason);
    if (!toolCallId || !unitId || !reason) {
      return { ok: false, reason: "invalid-decision" };
    }
    if (!isCallDecision(decision)) {
      return { ok: false, reason: "invalid-decision" };
    }
    if (askFor !== undefined && (decision !== "ask" || (askFor !== "allow" && askFor !== "escalate"))) {
      return { ok: false, reason: "invalid-decision" };
    }
    if (decision === "escalate" && !ESCALATION_APPROVER_IDS.has(node.id)) {
      return { ok: false, reason: "invalid-decision" };
    }
    if (reason.length > MAX_REASON_LENGTH) {
      return { ok: false, reason: "reason-too-long" };
    }
    const call = state.calls.find((entry) => entry.toolCallId === toolCallId);
    if (!call) return { ok: false, reason: "unknown-tool-call-id" };
    if (callDenied(call)) return { ok: false, reason: "call-already-denied" };
    const unit = call.units.find((entry) => entry.unitId === unitId);
    if (!unit) {
      const elsewhere = state.calls.some((otherCall) =>
        otherCall.units.some((otherUnit) => otherUnit.unitId === unitId));
      return { ok: false, reason: elsewhere ? "cross-call-identity" : "unknown-unit" };
    }
    if (decision === "allow" && unit.decision === "ask" &&
        !(unit.history.length === 1 && unit.history[0]?.nodeId === "structure-analysis")) {
      return { ok: false, reason: "ask-cannot-be-allowed" };
    }
    if (unit.review !== undefined && node.id !== "runtime/node-fault") {
      return { ok: false, reason: "unit-already-reviewed" };
    }
    if (
      decision === "allow" &&
      unit.askFor === "escalate" &&
      !ESCALATION_APPROVER_IDS.has(node.id)
    ) {
      return { ok: false, reason: "invalid-decision" };
    }
    const key = JSON.stringify([toolCallId, unitId]);
    const previous = seen.get(key);
    if (previous) {
      return {
        ok: false,
        reason: previous.decision === decision && previous.askFor === askFor && previous.reason === reason
          ? "duplicate-decision"
          : "conflicting-decision",
      };
    }
    const validatedDecision: UnitDecision = freezeTree({
      toolCallId,
      unitId,
      decision,
      ...(askFor === undefined ? {} : { askFor }),
      reason,
    });
    seen.set(key, validatedDecision);
    validated.push(validatedDecision);
  }

  const validatedReviews: UnitReview[] = [];
  const seenReviews = new Map<string, UnitReview>();
  for (const candidate of reviews) {
    if (!isRecord(candidate) ||
        !hasExactKeys(candidate, ["toolCallId", "unitId", "decision", "reason"])) {
      return { ok: false, reason: "invalid-review" };
    }
    const toolCallId = nonEmptyString(candidate.toolCallId);
    const unitId = nonEmptyString(candidate.unitId);
    const decision = candidate.decision;
    const reason = nonEmptyString(candidate.reason);
    if (!toolCallId || !unitId || !reason || (decision !== "approve" && decision !== "deny")) {
      return { ok: false, reason: "invalid-review" };
    }
    if (reason.length > MAX_REASON_LENGTH) return { ok: false, reason: "reason-too-long" };
    const call = state.calls.find((entry) => entry.toolCallId === toolCallId);
    if (!call) return { ok: false, reason: "unknown-tool-call-id" };
    const decisionsByUnit = new Map(validated
      .filter((entry) => entry.toolCallId === toolCallId)
      .map((entry) => [entry.unitId, entry.decision]));
    const callDeniedByBatch = call.units.some((unit) =>
      decisionsByUnit.get(unit.unitId) === "deny" ||
      unit.decision === "deny" ||
      unit.review?.decision === "deny");
    if (callDenied(call) || callDeniedByBatch) return { ok: false, reason: "call-already-denied" };
    const unit = call.units.find((entry) => entry.unitId === unitId);
    if (!unit) {
      const elsewhere = state.calls.some((otherCall) =>
        otherCall.units.some((otherUnit) => otherUnit.unitId === unitId));
      return { ok: false, reason: elsewhere ? "cross-call-identity" : "unknown-unit" };
    }
    const projectedDecision = decisionsByUnit.get(unitId) ?? unit.decision;
    if (unit.review !== undefined ||
        (decision === "approve" && projectedDecision !== "ask") ||
        (decision === "deny" && projectedDecision !== "ask" && projectedDecision !== "allow")) {
      return { ok: false, reason: "unit-not-pending-review" };
    }
    const projectedAskFor = validated.find((entry) =>
      entry.toolCallId === toolCallId && entry.unitId === unitId)?.askFor ?? unit.askFor;
    if (decision === "approve" && projectedAskFor === "escalate" &&
        !ESCALATION_APPROVER_IDS.has(node.id)) {
      return { ok: false, reason: "invalid-review" };
    }
    const key = JSON.stringify([toolCallId, unitId]);
    const previous = seenReviews.get(key);
    if (previous !== undefined) {
      return {
        ok: false,
        reason: previous.decision === decision && previous.reason === reason
          ? "duplicate-review"
          : "conflicting-review",
      };
    }
    const review = freezeTree({ toolCallId, unitId, decision, reason }) as UnitReview;
    seenReviews.set(key, review);
    validatedReviews.push(review);
  }
  const reviewDecisionsByCall = new Map<string, Set<UnitReview["decision"]>>();
  for (const review of validatedReviews) {
    const decisionsForCall = reviewDecisionsByCall.get(review.toolCallId) ?? new Set();
    decisionsForCall.add(review.decision);
    reviewDecisionsByCall.set(review.toolCallId, decisionsForCall);
  }
  if ([...reviewDecisionsByCall.values()].some((decisionsForCall) => decisionsForCall.size > 1)) {
    return { ok: false, reason: "invalid-review" };
  }

  if (validated.length === 0 && validatedReviews.length === 0) {
    // A facts-only acceptance never moves unit state: no revision, no unit
    // history, no forged unit change — the run record stays a no-op.
    return supplements.accepted === undefined
      ? { ok: true, state, applied: [] }
      : { ok: true, state, applied: [], acceptedFacts: supplements.accepted };
  }

  const byCall = new Map<string, UnitDecision[]>();
  for (const decision of validated) {
    const list = byCall.get(decision.toolCallId) ?? [];
    list.push(decision);
    byCall.set(decision.toolCallId, list);
  }

  const revision = state.revision + 1;
  const calls = state.calls.map((call) => {
    const callDecisions = byCall.get(call.toolCallId);
    if (!callDecisions) return call;
    const decisionsByUnit = new Map(callDecisions.map((entry) => [entry.unitId, entry]));
    const units = call.units.map((unit) => {
      const decision = decisionsByUnit.get(unit.unitId);
      if (!decision) return unit;
      const askFor = decision.askFor ?? (call.askFor === "escalate" ? "escalate" : undefined);
      return freezeTree({
        unitId: unit.unitId,
        decision: decision.decision,
        ...(decision.decision === "ask" && askFor !== undefined ? { askFor } : {}),
        reason: decision.reason,
        source: node.id,
        history: [
          ...unit.history,
          {
            revision,
            nodeId: node.id,
            priority: node.priority,
            decision: decision.decision,
            ...(decision.decision === "ask" && askFor !== undefined ? { askFor } : {}),
            reason: decision.reason,
          },
        ],
      });
    });
    const askFor = call.askFor === "escalate" || callDecisions.some((entry) =>
      entry.decision === "ask" && entry.askFor === "escalate")
      ? "escalate" as const
      : call.askFor;
    return freezeTree({ ...call, ...(askFor === undefined ? {} : { askFor }), units });
  });

  const reviewsByCall = new Map<string, UnitReview[]>();
  for (const review of validatedReviews) {
    const list = reviewsByCall.get(review.toolCallId) ?? [];
    list.push(review);
    reviewsByCall.set(review.toolCallId, list);
  }
  const reviewedCalls = calls.map((call) => {
    const callReviews = reviewsByCall.get(call.toolCallId);
    if (callReviews === undefined) return call;
    const reviewsByUnit = new Map(callReviews.map((review) => [review.unitId, review]));
    const units = call.units.map((unit) => {
      const review = reviewsByUnit.get(unit.unitId);
      if (review === undefined) return unit;
      return freezeTree({
        ...unit,
        review: {
          revision,
          nodeId: node.id,
          decision: review.decision,
          reason: review.reason,
        },
      });
    });
    return freezeTree({ ...call, units });
  });

  const facts = {
    stepKey: state.stepKey,
    sessionId: state.sessionId,
    sourceEntryId: state.sourceEntryId,
    captureDigest: state.captureDigest,
    revision,
    calls: reviewedCalls,
  };
  const next = freezeTree({ ...facts, digest: jsonDigest(facts) });
  STATES.add(next);
  return {
    ok: true,
    state: next,
    applied: validated,
    ...(validatedReviews.length === 0 ? {} : { appliedReviews: validatedReviews }),
    ...(supplements.accepted === undefined ? {} : { acceptedFacts: supplements.accepted }),
  };
}

/* ------------------------------------------------------------------ */
/* Whole-call summary                                                  */
/* ------------------------------------------------------------------ */

export interface CallReason {
  readonly unitId: string;
  readonly decision: CallDecision;
  readonly askFor?: AskTarget;
  readonly reason: string;
  readonly review?: {
    readonly decision: "approve" | "deny";
    readonly nodeId: string;
    readonly reason: string;
  };
}

export interface CallSummary {
  readonly toolCallId: string;
  readonly decision: CallDecision;
  readonly askFor?: AskTarget;
  readonly reasons: readonly CallReason[];
  readonly pendingUnitIds: readonly string[];
}

/**
 * Pure summary of the current frozen state. Readiness is owned by the runtime:
 * a call may be published only after every applicable node has completed.
 */
export function readyCallResults(state: StepState): readonly CallSummary[] {
  if (!STATES.has(state)) return [];
  return freezeTree(state.calls.map((call) => {
    const denied = call.units.filter((unit) => unit.decision === "deny" || unit.review?.decision === "deny");
    if (denied.length > 0) {
      return {
        toolCallId: call.toolCallId,
        decision: "deny" as const,
        reasons: denied.map((unit) => unit.review?.decision === "deny"
          ? { ...summaryReason(unit), decision: "deny" as const }
          : summaryReason(unit)),
        pendingUnitIds: call.units
          .filter((unit) => unit.decision === "ask" && unit.review === undefined)
          .map((unit) => unit.unitId),
      };
    }
    const pending = call.units.filter((unit) => unit.decision === "ask" && unit.review === undefined);
    if (pending.length > 0) {
      return {
        toolCallId: call.toolCallId,
        decision: "ask" as const,
        askFor: call.askFor === "escalate" || pending.some((unit) => unit.askFor === "escalate")
          ? "escalate" as const
          : "allow" as const,
        reasons: pending.map(summaryReason),
        pendingUnitIds: pending.map((unit) => unit.unitId),
      };
    }
    const escalated = call.units.filter((unit) => unit.decision === "escalate");
    if (escalated.length > 0 || call.askFor === "escalate" || call.hostExecutionRequest !== undefined) {
      const reasons = escalated.length > 0
        ? escalated.map(summaryReason)
        : call.units.filter((unit) => unit.review?.decision === "approve").map(summaryReason);
      return {
        toolCallId: call.toolCallId,
        decision: "escalate" as const,
        reasons,
        pendingUnitIds: [],
      };
    }
    return {
      toolCallId: call.toolCallId,
      decision: "allow" as const,
      reasons: call.units.filter((unit) => unit.review?.decision === "approve").map(summaryReason),
      pendingUnitIds: [],
    };
  }));
}

/* ------------------------------------------------------------------ */
/* Call-level model result mapping                                     */
/* ------------------------------------------------------------------ */

export interface CallReviewInput {
  readonly toolCallId: string;
  readonly decision: ReviewDecision;
  readonly reason: string;
}

export type MapCallReviewFailure =
  | "invalid-state"
  | "invalid-node"
  | "invalid-decision"
  | "unknown-tool-call-id"
  | "call-already-denied"
  | "no-pending-unit";

export type MapCallReviewResult =
  | { readonly ok: true; readonly submission: NodeSubmission }
  | { readonly ok: false; readonly reason: MapCallReviewFailure };

/**
 * Map one reviewer verdict onto the units that are still ask for this exact
 * call. The review is stored separately from each unit's rule result.
 */
export function mapCallReview(
  state: StepState,
  node: NodeIdentity,
  input: CallReviewInput,
): MapCallReviewResult {
  if (!STATES.has(state)) return { ok: false, reason: "invalid-state" };
  let nodeData: JsonValue;
  try {
    nodeData = freezeJson(node);
  } catch {
    return { ok: false, reason: "invalid-node" };
  }
  const validatedNode = validNode(nodeData);
  if (!validatedNode) return { ok: false, reason: "invalid-node" };

  let data: JsonValue;
  try {
    data = freezeJson(input);
  } catch {
    return { ok: false, reason: "invalid-decision" };
  }
  if (!isRecord(data) ||
      !hasExactKeys(data, ["toolCallId", "decision", "reason"])) {
    return { ok: false, reason: "invalid-decision" };
  }
  const toolCallId = nonEmptyString(data.toolCallId);
  const reason = nonEmptyString(data.reason);
  const decision = data.decision;
  if (!toolCallId || !reason || reason.length > MAX_REASON_LENGTH) {
    return { ok: false, reason: "invalid-decision" };
  }
  if (decision !== "approve" && decision !== "deny" && decision !== "defer") {
    return { ok: false, reason: "invalid-decision" };
  }
  const call = state.calls.find((entry) => entry.toolCallId === toolCallId);
  if (!call) return { ok: false, reason: "unknown-tool-call-id" };
  if (callDenied(call)) return { ok: false, reason: "call-already-denied" };
  const pending = call.units.filter((unit) => unit.decision === "ask" && unit.review === undefined);
  if (pending.length === 0) return { ok: false, reason: "no-pending-unit" };

  if (decision === "approve" &&
      pending.some((unit) => unit.askFor === "escalate") &&
      !ESCALATION_APPROVER_IDS.has(validatedNode.id)) {
    return { ok: false, reason: "invalid-decision" };
  }
  const reviews: UnitReview[] = decision === "defer" ? [] : pending.map((unit) => freezeTree({
    toolCallId,
    unitId: unit.unitId,
    decision,
    reason,
  }));
  return {
    ok: true,
    submission: freezeTree({
      node: validatedNode,
      evaluatedRevision: state.revision,
      result: { decisions: [], reviews },
    }),
  };
}

/* ------------------------------------------------------------------ */
/* Final results                                                       */
/* ------------------------------------------------------------------ */

export interface FinalCallResult {
  readonly stepKey: string;
  readonly sessionId: string;
  readonly toolCallId: string;
  readonly revision: number;
  readonly generation: number;
  readonly decision: "allow" | "deny" | "escalate";
  readonly reasons: readonly CallReason[];
  readonly publishedAt: number;
  readonly expiresAt: number;
}

export type PublishFailure =
  | "invalid-state"
  | "invalid-lifecycle"
  | "unknown-tool-call-id"
  | "duplicate-tool-call-id"
  | "unresolved-ask";

export type PublishFinalResultsResult =
  | { readonly ok: true; readonly results: readonly FinalCallResult[] }
  | { readonly ok: false; readonly reason: PublishFailure };

const PUBLISH_KEYS = ["toolCallIds", "generation", "nowMs", "ttlMs"] as const;

/** Publish resolved per-call results. A call that still has ask is not final. */
export function publishFinalResults(
  state: StepState,
  input: {
    readonly toolCallIds: readonly string[];
    readonly generation: number;
    readonly nowMs: number;
    readonly ttlMs: number;
  },
): PublishFinalResultsResult {
  if (!STATES.has(state)) return { ok: false, reason: "invalid-state" };

  let data: JsonValue;
  try {
    data = freezeJson(input);
  } catch {
    return { ok: false, reason: "invalid-lifecycle" };
  }
  if (!isRecord(data) || !hasExactKeys(data, PUBLISH_KEYS)) {
    return { ok: false, reason: "invalid-lifecycle" };
  }
  if (
    !isSafeInteger(data.generation) ||
    data.generation < 0 ||
    !isSafeInteger(data.nowMs) ||
    data.nowMs < 0 ||
    !isSafeInteger(data.ttlMs) ||
    data.ttlMs <= 0
  ) {
    return { ok: false, reason: "invalid-lifecycle" };
  }
  const expiresAt = data.nowMs + data.ttlMs;
  if (!isSafeInteger(expiresAt)) {
    return { ok: false, reason: "invalid-lifecycle" };
  }
  if (!Array.isArray(data.toolCallIds)) {
    return { ok: false, reason: "invalid-lifecycle" };
  }

  const seen = new Set<string>();
  const summaries = readyCallResults(state);
  const results: FinalCallResult[] = [];
  for (const candidate of data.toolCallIds) {
    const toolCallId = nonEmptyString(candidate);
    if (!toolCallId) return { ok: false, reason: "invalid-lifecycle" };
    if (seen.has(toolCallId)) {
      return { ok: false, reason: "duplicate-tool-call-id" };
    }
    seen.add(toolCallId);
    const call = state.calls.find((entry) => entry.toolCallId === toolCallId);
    if (!call) return { ok: false, reason: "unknown-tool-call-id" };
    const summary = summaries.find((entry) => entry.toolCallId === toolCallId);
    if (!summary) return { ok: false, reason: "unknown-tool-call-id" };
    if (summary.decision === "ask") {
      return { ok: false, reason: "unresolved-ask" };
    }
    const result = freezeTree({
      stepKey: state.stepKey,
      sessionId: state.sessionId,
      toolCallId,
      revision: state.revision,
      generation: data.generation,
      decision: summary.decision,
      reasons: summary.reasons,
      publishedAt: data.nowMs,
      expiresAt,
    });
    results.push(result);
  }
  return { ok: true, results };
}

import { MAX_NODE_ID_LENGTH } from "./effective-nodes";

export { describeEffectiveNodes } from "./effective-nodes";
export { BUILTIN_NODE_DESCRIPTIONS, describeNode } from "./node-descriptions";
export { BUILTIN_FRONT_NODES, BUILTIN_OPTIONAL_FRONT_NODES } from "./node-ids";
export { MAX_NODE_ID_LENGTH } from "./effective-nodes";
export type {
  DescribeEffectiveNodesResult,
  DescribeNodesFailure,
  EffectiveNode,
  EffectiveNodeConfiguration,
  NodeConfigEntry,
  NodeConfigWarning,
} from "./effective-nodes";

// ── Deterministic permission types (from the former engine contracts) ──

import type {
  DenyWithReason,
  FlatPermissionConfig,
  PatternValue,
  PermissionState,
} from "../config/config-schema";
import type { RuleOrigin } from "./policy/rule";
import { freezeJson, jsonDigest, type JsonObject, type JsonValue } from "../json";

// The config-file shape types are derived from the zod schema
// (config-schema.ts) — the single source of truth — and re-exported here so
// existing importers keep their import path.
export type {
  DenyWithReason,
  FlatPermissionConfig,
  PatternValue,
  PermissionState,
  RuleOrigin,
};

/**
 * Per-scope permission config shape after loading and validation.
 * Holds only the flat permission map — all policy is expressed there.
 */
export interface ScopeConfig {
  permission?: FlatPermissionConfig;
  /**
   * True when the scope's config file was present but failed to load or
   * validate (JSON parse error or schema rejection). Absent and valid files
   * leave this unset. Drives the fail-closed allow→ask clamp for non-global
   * scopes (#646).
   */
  invalid?: boolean;
}

/**
 * Execution context of a bash command nested inside a substitution or subshell.
 * Absent for current-shell (top-level) commands.
 */
export type BashCommandContext =
  | "command_substitution"
  | "process_substitution"
  | "subshell";

/**
 * Why an indirection wrapper's floor did not apply after all (#803).
 *
 * `"core-reader"` — the command the wrapper runs is in the built-in pure-reader
 * core, so it is read-only for any argument feed and the floor's reason (an
 * unknown direction behind the wrapper) does not hold.
 *
 * `"execution-modifier"` — every wrapper layer (`time`, `timeout`, `nice`,
 * `stdbuf`, `setsid`) changes only how the visible inner command runs, so the
 * unit is decided by that command's own rule whatever it does (#963).
 *
 * `"no-command"` — the wrapper names no command at all, and its bare form runs
 * nothing (`env` alone prints the environment), so there is nothing for it to
 * hide and the unit is decided by its own rule, as `printenv` is.
 *
 * A named reason rather than a boolean, so the review log states *why* a
 * wrapper was let through, and so a later source (a chain verdict, a user
 * declaration) is an added member rather than a second flag. ADR 0013 §11
 * keeps both reasons package-audited; user declarations do not lift the floor.
 */
export type FloorExemption =
  | "core-reader"
  | "execution-modifier"
  | "no-command";

export interface PermissionCheckResult {
  toolName: string;
  state: PermissionState;
  /** Custom denial reason from a deny-with-reason pattern, when present. */
  reason?: string;
  matchedPattern?: string;
  command?: string;
  /** Whether a Bash advisory query used structured analysis. */
  bashAnalysis?: "decomposed" | "whole-command" | "incomplete";
  target?: string;
  source: "tool" | "bash" | "mcp" | "skill" | "special" | "default" | "session";
  /** Which source contributed the winning rule. */
  origin: RuleOrigin;
  /**
   * Execution context of the offending nested command, when the winning bash
   * unit came from a substitution or subshell. Absent for current-shell
   * (top-level) commands.
   */
  commandContext?: BashCommandContext;
  /**
   * The command the winning bash unit actually runs, when it is a wrapper whose
   * inner command differs from the unit text (#713). Display-only: the gate
   * decides on `command`, and on `executedUnit`'s rules only when
   * {@link floorExemption} says the wrapper's floor has no reason to hold.
   */
  executedUnit?: string;
  /**
   * The spelling of the bash unit the winning rule matched, when the rule did
   * not also match the unit as typed — the absolute spelling of a relative
   * path argument, say (#910). Display-only: absent whenever the typed text
   * decided, and dropped by a floor that replaces {@link matchedPattern}.
   */
  matchedSpelling?: string;
  /**
   * Set when the winning bash unit is a wrapper the floor no longer covers,
   * naming why (#803, #963). Recorded in the review log so an allow the floor would
   * once have prompted for is auditable to the reason that let it through.
   */
  floorExemption?: FloorExemption;
  /**
   * The synthetic pattern of a floor that raised this ask on the bash chain —
   * on the deciding unit, or on another asking unit of the same command. Only
   * the child's parse knows it, so a forwarded ask carries it for the serving
   * node to clamp its own `allow` with.
   */
  floor?: string;
  /**
   * Every unit of the bash chain that resolved to `ask` and was not
   * session-granted, in chain order, each with its own floor. Set only on an
   * asking chain winner: the serving node of a forwarded ask judges each one,
   * since the winner alone would approve commands it never saw.
   */
  askingUnits?: readonly AskingBashUnit[];
}

/**
 * One unit of a bash chain the gate left asking, as the serving node of a
 * forwarded ask needs it: the unit as typed, and the floor that raised it.
 */
export interface AskingBashUnit {
  command: string;
  floor?: string;
}

/**
 * True when an `ask` is the builtin universal default and nothing else.
 *
 * This is the one ask the new default policy may move off the prompt path
 * (design §35.1, AR16): the universal fallback fired because no explicit rule
 * matched at all. Every other ask keeps its prompt:
 *
 * - a config/session rule sets `matchedPattern`, so the user asked for it;
 * - a floor sets `floor` (and replaces `matchedPattern` with its sentinel), so
 *   a parser or wrapper guard raised it, not a user policy;
 * - a config-scope origin (or the MCP `baseline` layer) means a scope or a
 *   metadata default contributed the rule, not the builtin fallback.
 *
 * `origin === "builtin"` alone is not enough, because the universal fallback
 * and `evaluate()`'s no-match default share that origin with the synthetic
 * asks above; the flags are what keep them apart.
 */
export function isBuiltinDefaultAsk(check: PermissionCheckResult): boolean {
  return (
    check.state === "ask" &&
    check.origin === "builtin" &&
    check.matchedPattern === undefined &&
    check.floor === undefined
  );
}

export function isPermissionState(value: unknown): value is PermissionState {
  return value === "allow" || value === "deny" || value === "ask";
}

/**
 * Narrow type guard: a raw value representing a DenyWithReason object.
 * Accepts `{ action: "deny" }` and `{ action: "deny", reason: "…" }`.
 * Rejects a non-string `reason` to keep malformed config out of the rule set.
 */
export function isDenyWithReason(value: unknown): value is DenyWithReason {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return (
    record.action === "deny" &&
    (record.reason === undefined || typeof record.reason === "string")
  );
}
