import {
  MAX_REASON_LENGTH,
  type CallState,
  type CapturedDirectCall,
  type StepCapture,
  type StepState,
  type UnitDecision,
  type UnitState,
} from "#approve-core/contracts";
import type { ChainNode, StepContext } from "#approve-core/runtime";
import { jsonDigest } from "../../../json";

/**
 * Identity and integrity node.
 *
 * Identity is established from facts the runtime already froze, not from a
 * second mutable registry: the capture's step metadata and call digests, the
 * current state's re-computed digest, and each call's argument digest / unit
 * history. If the step cannot be tied to the capture, or a call cannot be tied
 * to its original frozen call, the affected original call is denied as a whole.
 * A unit-level inconsistency also denies its whole call: a unit is never an
 * independently executable action.
 */

export interface IdentityNodeOptions {
  /** Optional expected host facts; a mismatch denies the whole step. */
  readonly expected?: {
    readonly stepKey?: string;
    readonly sessionId?: string;
    readonly sourceEntryId?: string;
  };
}

const DENY_REASON_PREFIX = "identity-denied:";

function clip(text: string): string {
  return text.length <= MAX_REASON_LENGTH
    ? text
    : `${text.slice(0, MAX_REASON_LENGTH - 3)}...`;
}

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function safeDigest(value: unknown): string | undefined {
  try {
    return jsonDigest(value);
  } catch {
    return undefined;
  }
}

function captureFacts(capture: StepCapture): Record<string, unknown> {
  return {
    stepKey: capture.stepKey,
    sessionId: capture.sessionId,
    sourceEntryId: capture.sourceEntryId,
    manifestRevision: capture.manifestRevision,
    complete: true,
    directCalls: capture.directCalls,
  };
}

function captureCallFacts(call: CapturedDirectCall): Record<string, unknown> {
  return {
    toolCallId: call.toolCallId,
    toolName: call.toolName,
    arguments: call.arguments,
    argumentsDigest: call.argumentsDigest,
    ...(call.hostExecutionRequest === undefined
      ? {}
      : { hostExecutionRequest: call.hostExecutionRequest }),
    ...(call.parentToolCallId === undefined
      ? {}
      : { parentToolCallId: call.parentToolCallId }),
  };
}

function stateFacts(state: StepState): Record<string, unknown> {
  return {
    stepKey: state.stepKey,
    sessionId: state.sessionId,
    sourceEntryId: state.sourceEntryId,
    captureDigest: state.captureDigest,
    revision: state.revision,
    calls: state.calls,
  };
}

function verifyUnit(unit: UnitState, revision: number): readonly string[] {
  const issues: string[] = [];
  if (!nonEmpty(unit.unitId)) issues.push("unit-id");
  if (unit.decision !== "allow" && unit.decision !== "ask" && unit.decision !== "deny") {
    issues.push("unit-decision");
  }
  if (!nonEmpty(unit.source)) issues.push("unit-source");
  if (!nonEmpty(unit.reason) || unit.reason.length > MAX_REASON_LENGTH) {
    issues.push("unit-reason");
  }
  if (!Array.isArray(unit.history) || unit.history.length === 0) {
    issues.push("unit-history");
    return issues;
  }
  const first = unit.history[0];
  if (
    first.revision !== 1 ||
    first.nodeId !== "structure-analysis" ||
    first.decision !== "ask" ||
    !nonEmpty(first.reason)
  ) {
    issues.push("unit-origin");
  }
  for (const [index, record] of unit.history.entries()) {
    if (
      typeof record.revision !== "number" ||
      !Number.isSafeInteger(record.revision) ||
      record.revision < 1 ||
      record.revision > revision ||
      typeof record.nodeId !== "string" ||
      record.nodeId.length === 0 ||
      (record.decision !== "allow" && record.decision !== "ask" && record.decision !== "deny") ||
      typeof record.reason !== "string" ||
      record.reason.length === 0 ||
      record.reason.length > MAX_REASON_LENGTH
    ) {
      issues.push(`unit-history-${index}`);
      break;
    }
    if (index > 0) {
      const previous = unit.history[index - 1];
      if (record.revision <= previous.revision) {
        issues.push("unit-history-order");
        break;
      }
    }
  }
  const last = unit.history.at(-1);
  if (last && (last.decision !== unit.decision || last.nodeId !== unit.source)) {
    issues.push("unit-current-state");
  }
  return issues;
}

function verifyCall(
  captureCall: CapturedDirectCall | undefined,
  call: CallState,
  revision: number,
): readonly string[] {
  if (!captureCall) return ["call-missing-from-capture"];
  const issues: string[] = [];
  if (call.toolCallId !== captureCall.toolCallId) issues.push("call-id");
  if (call.toolName !== captureCall.toolName) issues.push("call-tool");
  if (call.parentToolCallId !== captureCall.parentToolCallId) issues.push("call-parent");
  if (call.argumentsDigest !== captureCall.argumentsDigest) issues.push("call-arguments-digest");
  if (safeDigest(call.arguments) !== call.argumentsDigest) issues.push("call-arguments-frozen");
  if (call.digest !== captureCall.digest) issues.push("call-digest");
  if (safeDigest(captureCallFacts(call)) !== call.digest) issues.push("call-digest-frozen");
  if (!Array.isArray(call.units) || call.units.length === 0) {
    issues.push("call-without-unit");
    return issues;
  }
  for (const unit of call.units) {
    const unitIssues = verifyUnit(unit, revision);
    if (unitIssues.length > 0) {
      issues.push(`unit:${unit.unitId || "<empty>"}:${unitIssues[0]}`);
      break;
    }
  }
  return issues;
}

interface IdentityAnalysis {
  readonly stepIssues: readonly string[];
  readonly callIssues: ReadonlyMap<string, readonly string[]>;
}

function analyzeIdentity(capture: StepCapture, state: StepState): IdentityAnalysis {
  const stepIssues: string[] = [];
  const callIssues = new Map<string, readonly string[]>();

  if (safeDigest(captureFacts(capture)) !== capture.digest) {
    stepIssues.push("capture-digest");
  }
  for (const directCall of capture.directCalls) {
    if (safeDigest(captureCallFacts(directCall)) !== directCall.digest) {
      stepIssues.push(`capture-call:${directCall.toolCallId}`);
    }
  }

  if (
    state.stepKey !== capture.stepKey ||
    state.sessionId !== capture.sessionId ||
    state.sourceEntryId !== capture.sourceEntryId ||
    state.captureDigest !== capture.digest
  ) {
    stepIssues.push("metadata");
  }
  if (!Number.isSafeInteger(state.revision) || state.revision < 1) {
    stepIssues.push("revision");
  }
  if (safeDigest(stateFacts(state)) !== state.digest) {
    stepIssues.push("state-digest");
  }

  const capturedById = new Map(
    capture.directCalls.map((call) => [call.toolCallId, call]),
  );
  const stateIds = new Set<string>();
  for (const call of state.calls) {
    if (!nonEmpty(call.toolCallId) || stateIds.has(call.toolCallId)) {
      stepIssues.push("call-set");
      continue;
    }
    stateIds.add(call.toolCallId);
  }
  if (
    state.calls.length !== capture.directCalls.length ||
    capture.directCalls.some((call) => !stateIds.has(call.toolCallId))
  ) {
    stepIssues.push("call-set");
  }

  const unitOwners = new Map<string, string[]>();
  for (const call of state.calls) {
    for (const unit of call.units) {
      const owners = unitOwners.get(unit.unitId) ?? [];
      owners.push(call.toolCallId);
      unitOwners.set(unit.unitId, owners);
    }
  }
  const sharedUnitsByCall = new Map<string, string[]>();
  for (const [unitId, owners] of unitOwners) {
    if (owners.length <= 1) continue;
    for (const owner of owners) {
      const shared = sharedUnitsByCall.get(owner) ?? [];
      shared.push(unitId);
      sharedUnitsByCall.set(owner, shared);
    }
  }

  for (const call of state.calls) {
    const issues = [...verifyCall(capturedById.get(call.toolCallId), call, state.revision)];
    for (const unitId of sharedUnitsByCall.get(call.toolCallId) ?? []) {
      issues.push(`unit-shared:${unitId}`);
    }
    if (issues.length > 0) callIssues.set(call.toolCallId, issues);
  }

  return { stepIssues, callIssues };
}

/**
 * Human-readable identity issues for one capture/state pair. An empty array
 * means every call and unit can be tied to the frozen capture.
 */
export function verifyStepIdentity(
  capture: StepCapture,
  state: StepState,
): readonly string[] {
  const analysis = analyzeIdentity(capture, state);
  const issues = new Set<string>(analysis.stepIssues);
  for (const [callId, callIssues] of analysis.callIssues) {
    for (const issue of callIssues) issues.add(`${callId}:${issue}`);
  }
  return Object.freeze([...issues]);
}

function denyCall(call: CallState, reason: string): readonly UnitDecision[] {
  if (call.units.some((unit) => unit.decision === "deny")) return [];
  const text = clip(`${DENY_REASON_PREFIX}${reason}`);
  return call.units.map((unit) => Object.freeze({
    toolCallId: call.toolCallId,
    unitId: unit.unitId,
    decision: "deny" as const,
    reason: text,
  }));
}

/**
 * The fixed front identity node. It never returns allow: either the snapshot is
 * consistent (no decision), or the affected original calls are denied whole.
 */
export function createIdentityNode(options: IdentityNodeOptions = {}): ChainNode {
  return Object.freeze({
    apiVersion: "1" as const,
    id: "builtin/identity",
    evaluate: (context: StepContext) => {
      const { capture, state } = context;
      const expected = options.expected;
      const expectedIssue = expected && (
        (expected.stepKey !== undefined && expected.stepKey !== capture.stepKey) ||
        (expected.sessionId !== undefined && expected.sessionId !== capture.sessionId) ||
        (expected.sourceEntryId !== undefined &&
          expected.sourceEntryId !== capture.sourceEntryId)
      );
      if (expectedIssue) {
        return {
          decisions: state.calls.flatMap((call) =>
            denyCall(call, "identity:step:host-expectation")),
        };
      }

      const analysis = analyzeIdentity(capture, state);
      if (analysis.stepIssues.length > 0) {
        const reason = `identity:step:${analysis.stepIssues.join(",")}`;
        return {
          decisions: state.calls.flatMap((call) => denyCall(call, reason)),
        };
      }

      const decisions: UnitDecision[] = [];
      for (const call of state.calls) {
        const issues = analysis.callIssues.get(call.toolCallId);
        if (!issues || issues.length === 0) continue;
        const unitIssue = issues.some((issue) => issue.startsWith("unit"));
        decisions.push(...denyCall(
          call,
          `${unitIssue ? "identity:unit" : "identity:call"}:${call.toolCallId}:${issues.join(",")}`,
        ));
      }
      return { decisions };
    },
  });
}
