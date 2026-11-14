import {
  MAX_NODE_DECISIONS,
  MAX_REASON_LENGTH,
  MAX_RESULT_BYTES,
  applyNodeResult,
  mapCallReview,
  prepareStep,
  publishFinalResults,
  readyCallResults,
  type BashProgramFactsEntry,
  type BashProgramFactsView,
  type CallDecision,
  type CallState,
  type CallSummary,
  type Decision,
  type FinalCallResult,
  type NodeResult,
  type StepCapture,
  type StepState,
  type UnitDecision,
  type UnitReview,
  type UnitPreparation,
} from "./contracts";
import type { PermissionMode } from "../contracts";
import type { PowerShellProgramFactsView } from "#approve-core/utils/access-intent/powershell/analysis";

/**
 * Chain runtime.
 *
 * The caller supplies a frozen step capture, the analysis units produced by
 * the analysis nodes, and runtime node bindings. The facade owns ordering, propagation,
 * node fault/timeout handling, human fallback, and final publication. It does
 * not analyze commands, load modules, host a Pi session, or execute tools.
 */
export type ChainPosition = "front" | "user" | "post";

const MAX_CHAIN_NODES = 128;
const DEFAULT_NODE_TIMEOUT_MS = 30_000;
const DEFAULT_RESULT_TTL_MS = 60_000;

export interface ChainNode {
  readonly apiVersion: "1";
  readonly id: string;
  evaluate(context: StepContext, host: NodeHost): NodeResult | Promise<NodeResult>;
}

export interface NodeBinding {
  readonly node: ChainNode;
  readonly position: ChainPosition;
  readonly priority: number | null;
  readonly timeoutMs?: number;
}

export interface StepContext {
  readonly capture: StepCapture;
  readonly state: StepState;
  readonly node: {
    readonly id: string;
    readonly position: ChainPosition;
    readonly priority: number | null;
  };
  readonly signal: AbortSignal;
  readonly deadlineAt: number | null;
  /**
   * The read-only per-call fact views of this step, keyed by the
   * captured toolCallId. A call without a parsed Bash program has no entry, so
   * reading it answers `undefined`. Absent entirely when the step holds no
   * fact views. Nodes may ignore this entry; the views never change a unit's
   * decision by themselves.
   */
  readonly bashPrograms?: Readonly<Record<string, BashProgramFactsView>>;
  readonly powershellPrograms?: Readonly<Record<string, PowerShellProgramFactsView>>;
}

/**
 * One node end as the runtime observed it. The outcome covers every way an
 * actually started evaluate can end: an adopted result (applied/noop), an
 * invalid result or throw (fault), a node or step timeout, and a run that
 * stopped the node before it returned (cancelled). The reason is the runtime's
 * raw fault reason; the host applies the audit sanitization rules.
 */
export interface ChainAuditEntry {
  readonly kind: "node";
  readonly nodeId: string;
  readonly position: ChainPosition;
  readonly priority: number | null;
  readonly revisionBefore: number;
  readonly revisionAfter: number;
  readonly outcome: "applied" | "noop" | "fault" | "timeout" | "cancelled";
  readonly reason?: string;
}

/**
 * The structural input summary recorded when the runtime actually starts one
 * node's evaluate. It carries only identity and revision facts.
 */
export interface ChainNodeStartEntry {
  readonly kind: "node-start";
  readonly nodeId: string;
  readonly position: ChainPosition;
  readonly priority: number | null;
  readonly revision: number;
}

/**
 * One unit change the runtime formally adopted, taken directly from the
 * accepted batch instead of scanned from unit history.
 */
export interface ChainUnitChange {
  readonly toolCallId: string;
  readonly unitId: string;
  readonly nodeId: string;
  readonly revision: number;
  readonly decision: CallDecision;
  readonly askFor?: "allow" | "escalate";
  readonly reason: string;
}

export interface ChainReviewChange {
  readonly toolCallId: string;
  readonly unitId: string;
  readonly nodeId: string;
  readonly revision: number;
  readonly decision: "approve" | "deny";
  readonly reason: string;
}

export interface NodeHost {
  readonly log: (entry: ChainAuditEntry) => void;
  /**
   * Optional internal callback fired once per actually started evaluate,
   * before the node runs. Observers must not change the chain decision.
   */
  readonly nodeStarted?: (entry: ChainNodeStartEntry) => void;
  /**
   * Optional internal callback fired after the runtime formally adopts a
   * batch of unit state: the prepared initial asks, one node result, a human
   * response or a fault fallback. Each change carries its own revision; a
   * multi-batch fallback keeps the batch order. Observers must not change the
   * chain decision.
   */
  readonly unitsAccepted?: (changes: readonly ChainUnitChange[]) => void;
  readonly reviewsAccepted?: (changes: readonly ChainReviewChange[]) => void;
}

export interface NodeRunRecord {
  readonly nodeId: string;
  readonly position: ChainPosition;
  readonly priority: number | null;
  readonly revisionBefore: number;
  readonly revisionAfter: number;
  readonly outcome: "applied" | "noop" | "fault";
}

export interface ChainFault {
  readonly nodeId: string;
  readonly reason: string;
}

export interface HumanRequest {
  readonly capture: StepCapture;
  readonly call: CallState;
  readonly summary: CallSummary;
  readonly state: StepState;
  readonly mode?: PermissionMode;
  readonly signal: AbortSignal;
}

export interface HumanResponse {
  readonly decision: "approve" | "deny" | "cancel";
  readonly reason: string;
}

export type HumanApprover = (
  request: HumanRequest,
) => HumanResponse | Promise<HumanResponse>;

/**
 * One call as the session memory sees it. A matching memory result is stored as
 * a separate review outcome for pending units and never rewrites their rule
 * verdicts.
 */
export interface SessionReviewRequest {
  readonly toolCallId: string;
  readonly toolName: string;
  readonly arguments: Readonly<Record<string, unknown>>;
}

export interface SessionReviewDecision {
  readonly decision: "approve" | "deny";
  readonly reason: string;
}

/**
 * The host's session memory. Returning `undefined` means "the memory has no
 * opinion", which is the normal case; the port must never throw, because a
 * memory failure must not decide a call.
 */
export type SessionReviewPort = (
  request: SessionReviewRequest,
) => Promise<SessionReviewDecision | undefined>;

type HumanOutcome =
  | { readonly kind: "response"; readonly response: HumanResponse }
  | { readonly kind: "cancelled" }
  | { readonly kind: "deadline" };

export type ChainRunStatus = "completed" | "needs-human" | "cancelled" | "deadline";

export type OrderChainNodesResult =
  | { readonly ok: true; readonly nodes: readonly NodeBinding[] }
  | {
      readonly ok: false;
      readonly reason:
        | "invalid-nodes"
        | "node-limit-exceeded"
        | "invalid-node"
        | "duplicate-node-id"
        | "invalid-position"
        | "invalid-priority";
    };

export interface RunStepChainInput {
  readonly capture: StepCapture;
  readonly units: readonly UnitPreparation[];
  readonly nodes: readonly NodeBinding[];
  readonly generation: number;
  readonly mode?: PermissionMode;
  readonly signal?: AbortSignal;
  readonly deadlineAt?: number | null;
  readonly nodeTimeoutMs?: number;
  readonly resultTtlMs?: number;
  readonly now?: () => number;
  readonly human?: HumanApprover;
  /** The host's scoped review result; deny can reject an allow, approve resolves asks. */
  readonly sessionReviews?: SessionReviewPort;
  readonly onReady?: (result: FinalCallResult, state: StepState) => void;
  readonly host?: NodeHost;
  /**
   * The host's per-call fact views for this step, keyed by
   * toolCallId. The runtime owns them for the run: accepted node supplements
   * publish new keys for the subsequent nodes while views an earlier node
   * already held stay fixed. No view outlives the run.
   */
  readonly bashPrograms?: Readonly<Record<string, BashProgramFactsView>>;
  readonly powershellPrograms?: Readonly<Record<string, PowerShellProgramFactsView>>;
}

export type RunStepChainResult =
  | {
      readonly ok: true;
      readonly state: StepState;
      readonly results: readonly FinalCallResult[];
      readonly pendingToolCallIds: readonly string[];
      readonly runs: readonly NodeRunRecord[];
      readonly faults: readonly ChainFault[];
      readonly status: ChainRunStatus;
    }
  | {
      readonly ok: false;
      readonly reason:
        | "invalid-input"
        | "prepare-failed"
        | "publish-failed"
        | "fault-fallback-failed";
      readonly detail?: string;
    };

const NOOP_HOST: NodeHost = { log: () => undefined };

/**
 * Deliver one audit observation to the host. A failing observer must never
 * change the chain decision, so its errors are dropped here.
 */
function notifyObserver(notify: () => void): void {
  try {
    notify();
  } catch {
    // An audit observer must never change the chain decision.
  }
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isPosition(value: unknown): value is ChainPosition {
  return value === "front" || value === "user" || value === "post";
}

/**
 * Validate the runtime bindings and return the deterministic front, user and
 * post order. A user priority can never move a node outside the user section.
 */
export function orderChainNodes(
  nodes: readonly NodeBinding[],
): OrderChainNodesResult {
  if (!Array.isArray(nodes)) return { ok: false, reason: "invalid-nodes" };
  if (nodes.length > MAX_CHAIN_NODES) {
    return { ok: false, reason: "node-limit-exceeded" };
  }

  const seen = new Set<string>();
  for (const binding of nodes) {
    if (!binding || typeof binding !== "object") {
      return { ok: false, reason: "invalid-node" };
    }
    const node = binding.node;
    if (
      !node ||
      node.apiVersion !== "1" ||
      !nonEmptyString(node.id) ||
      typeof node.evaluate !== "function"
    ) {
      return { ok: false, reason: "invalid-node" };
    }
    if (seen.has(node.id)) {
      return { ok: false, reason: "duplicate-node-id" };
    }
    seen.add(node.id);
    if (!isPosition(binding.position)) {
      return { ok: false, reason: "invalid-position" };
    }
    if (binding.position === "user") {
      if (!Number.isSafeInteger(binding.priority)) {
        return { ok: false, reason: "invalid-priority" };
      }
    } else if (binding.priority !== null) {
      return { ok: false, reason: "invalid-priority" };
    }
  }

  const snapshots: NodeBinding[] = nodes.map((binding) => Object.freeze({
    position: binding.position,
    priority: binding.priority,
    ...(binding.timeoutMs === undefined ? {} : { timeoutMs: binding.timeoutMs }),
    node: Object.freeze({
      apiVersion: "1" as const,
      id: binding.node.id,
      evaluate: binding.node.evaluate,
    }),
  }));

  const front = snapshots.filter((binding) => binding.position === "front");
  const user = snapshots
    .map((binding, index) => ({ binding, index }))
    .filter((entry) => entry.binding.position === "user")
    .sort((left, right) => {
      const priority = (left.binding.priority as number) - (right.binding.priority as number);
      return priority === 0 ? left.index - right.index : priority;
    })
    .map((entry) => entry.binding);
  const post = snapshots.filter((binding) => binding.position === "post");

  return { ok: true, nodes: Object.freeze([...front, ...user, ...post]) };
}

const HUMAN_NODE = Object.freeze({ id: "builtin/human", priority: null });
const FAULT_NODE = Object.freeze({ id: "runtime/node-fault", priority: null });

/**
 * The nodeId of the initial ask history record prepareStep writes for every
 * prepared unit. The initial audit batch uses the same identity.
 */
const INITIAL_UNIT_NODE_ID = "structure-analysis";

function jsonBytes(value: unknown): number {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}

/**
 * Map one adopted batch onto the audit unit changes: the applied
 * decisions of the batch plus the revision it produced. Nothing is read back
 * from unit history.
 */
function unitChanges(
  nodeId: string,
  applied: readonly UnitDecision[],
  revision: number,
): ChainUnitChange[] {
  return applied.map((decision) => ({
    toolCallId: decision.toolCallId,
    unitId: decision.unitId,
    nodeId,
    revision,
    decision: decision.decision,
    ...(decision.askFor === undefined ? {} : { askFor: decision.askFor }),
    reason: decision.reason,
  }));
}

function reviewChanges(
  nodeId: string,
  applied: readonly UnitReview[],
  revision: number,
): ChainReviewChange[] {
  return applied.map((review) => ({
    toolCallId: review.toolCallId,
    unitId: review.unitId,
    nodeId,
    revision,
    decision: review.decision,
    reason: review.reason,
  }));
}

/** A plain dictionary that inherits nothing from Object.prototype. */
function nullProtoRecord<T>(source: Readonly<Record<string, T>>): Record<string, T> {
  return Object.assign(Object.create(null), source);
}

/**
 * Publish accepted fact supplements: only the necessary new
 * dictionary containers are created, reusing the old view's property values —
 * the built-in BashProgram facts keep their references and nothing is
 * re-parsed or deep-copied. Views an earlier node already held stay fixed.
 */
function withPublishedFacts(
  views: Readonly<Record<string, BashProgramFactsView>>,
  facts: readonly BashProgramFactsEntry[],
): Readonly<Record<string, BashProgramFactsView>> {
  const next: Record<string, BashProgramFactsView> = nullProtoRecord(views);
  const patches = new Map<string, Record<string, unknown>>();
  for (const entry of facts) {
    let patch = patches.get(entry.toolCallId);
    if (patch === undefined) {
      patch = nullProtoRecord(views[entry.toolCallId] as Record<string, unknown>);
      patches.set(entry.toolCallId, patch);
    }
    Object.assign(patch, entry.values);
  }
  for (const [toolCallId, patch] of patches) {
    next[toolCallId] = Object.freeze(patch) as BashProgramFactsView;
  }
  return Object.freeze(next);
}

function faultAskBatches(decisions: readonly UnitDecision[]): UnitDecision[][] {
  const batches: UnitDecision[][] = [];
  let current: UnitDecision[] = [];
  for (const decision of decisions) {
    const candidate = [...current, decision];
    const tooMany = candidate.length > MAX_NODE_DECISIONS;
    const tooLarge = jsonBytes({ decisions: candidate }) > MAX_RESULT_BYTES;
    if (current.length > 0 && (tooMany || tooLarge)) {
      batches.push(current);
      current = [decision];
    } else {
      current = candidate;
    }
  }
  if (current.length > 0) batches.push(current);
  return batches;
}

/**
 * Reset every still-ask unit to ask under the fault node. The helper returns
 * the changes of every applied batch with its own revision; the caller adopts
 * the whole result and only then records them. A failed batch
 * discards the intermediate states, so no partial change can be observed.
 */
function applyFaultAsk(
  state: StepState,
  reason: string,
):
  | {
      readonly ok: true;
      readonly state: StepState;
      readonly changes: readonly ChainUnitChange[];
    }
  | { readonly ok: false; readonly reason: string } {
  const decisions = state.calls
    .filter((call) => !call.units.some((unit) => unit.decision === "deny" || unit.review?.decision === "deny"))
    .flatMap((call) => call.units.map((unit) => ({
      toolCallId: call.toolCallId,
      unitId: unit.unitId,
      decision: call.hostExecutionRequest === undefined ? "ask" as const : "deny" as const,
      reason: reason.slice(0, MAX_REASON_LENGTH),
    })));
  if (decisions.length === 0) return { ok: true, state, changes: [] };

  let next = state;
  const changes: ChainUnitChange[] = [];
  for (const decisionsBatch of faultAskBatches(decisions)) {
    const applied = applyNodeResult(next, {
      node: FAULT_NODE,
      evaluatedRevision: next.revision,
      result: { decisions: decisionsBatch },
    });
    if (!applied.ok) return { ok: false, reason: applied.reason };
    next = applied.state;
    changes.push(...unitChanges(FAULT_NODE.id, applied.applied, next.revision));
  }
  return { ok: true, state: next, changes };
}

function validHumanResponse(value: unknown): HumanResponse | null {
  if (!value || typeof value !== "object") return null;
  const decision = (value as { decision?: unknown }).decision;
  const reason = (value as { reason?: unknown }).reason;
  if (decision !== "approve" && decision !== "deny" && decision !== "cancel") {
    return null;
  }
  if (!nonEmptyString(reason) || reason.length > MAX_REASON_LENGTH) return null;
  return { decision, reason };
}

/**
 * Apply one human response to its call. The helper returns the accepted batch
 * with the revision it produced; the runtime records the changes only after it
 * formally adopts the new state.
 */
function applyHumanResponse(
  state: StepState,
  toolCallId: string,
  response: HumanResponse,
):
  | {
      readonly ok: true;
      readonly state: StepState;
      readonly changes: readonly ChainUnitChange[];
      readonly reviews: readonly ChainReviewChange[];
    }
  | { readonly ok: false; readonly reason: string } {
  if (response.decision === "approve") {
    const mapped = mapCallReview(state, HUMAN_NODE, {
      toolCallId,
      decision: "approve",
      reason: response.reason,
    });
    if (!mapped.ok) return { ok: false, reason: mapped.reason };
    const applied = applyNodeResult(state, mapped.submission);
    if (!applied.ok) return { ok: false, reason: applied.reason };
    return {
      ok: true,
      state: applied.state,
      changes: unitChanges(HUMAN_NODE.id, applied.applied, applied.state.revision),
      reviews: reviewChanges(HUMAN_NODE.id, applied.appliedReviews ?? [], applied.state.revision),
    };
  }

  const call = state.calls.find((entry) => entry.toolCallId === toolCallId);
  if (!call) return { ok: false, reason: "unknown-tool-call-id" };
  const applied = applyNodeResult(state, {
    node: HUMAN_NODE,
    evaluatedRevision: state.revision,
    result: {
      decisions: [],
      reviews: call.units
        .filter((unit) => unit.decision === "ask" && unit.review === undefined)
        .map((unit) => ({
          toolCallId,
          unitId: unit.unitId,
          decision: "deny" as const,
          reason: response.reason,
        })),
    },
  });
  if (!applied.ok) return { ok: false, reason: applied.reason };
  return {
    ok: true,
    state: applied.state,
    changes: unitChanges(HUMAN_NODE.id, applied.applied, applied.state.revision),
    reviews: reviewChanges(HUMAN_NODE.id, applied.appliedReviews ?? [], applied.state.revision),
  };
}

/**
 * Run one prepared step through an ordered node chain, resolve final asks
 * through the injected human adapter, and publish final allow/deny results.
 */
export async function runStepChain(
  input: RunStepChainInput,
): Promise<RunStepChainResult> {
  if (
    !input ||
    typeof input !== "object" ||
    !Number.isSafeInteger(input.generation) ||
    input.generation < 0
  ) {
    return { ok: false, reason: "invalid-input" };
  }

  const capture = input.capture;
  const units = input.units;
  const generation = input.generation;
  const human = input.human;
  const onReady = input.onReady;

  const ordered = orderChainNodes(input.nodes);
  if (!ordered.ok) {
    return { ok: false, reason: "invalid-input", detail: ordered.reason };
  }

  const prepared = prepareStep(capture, units);
  if (!prepared.ok) {
    return { ok: false, reason: "prepare-failed", detail: prepared.reason };
  }

  const now = input.now ?? Date.now;
  const nowMs = now();
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
    return { ok: false, reason: "invalid-input", detail: "now" };
  }

  const resultTtlMs = input.resultTtlMs ?? DEFAULT_RESULT_TTL_MS;
  if (!Number.isSafeInteger(resultTtlMs) || resultTtlMs <= 0) {
    return { ok: false, reason: "invalid-input", detail: "resultTtlMs" };
  }

  const nodeTimeoutMs = input.nodeTimeoutMs ?? DEFAULT_NODE_TIMEOUT_MS;
  if (!Number.isSafeInteger(nodeTimeoutMs) || nodeTimeoutMs <= 0) {
    return { ok: false, reason: "invalid-input", detail: "nodeTimeoutMs" };
  }

  const deadlineAt = input.deadlineAt ?? null;
  if (deadlineAt !== null && (!Number.isSafeInteger(deadlineAt) || deadlineAt < 0)) {
    return { ok: false, reason: "invalid-input", detail: "deadlineAt" };
  }

  const signal = input.signal ?? new AbortController().signal;
  const host = input.host ?? NOOP_HOST;
  let state = prepared.state;
  // This step's fact views. Normalized into a frozen dictionary
  // with own data properties; every later publication replaces the record for
  // the subsequent nodes only.
  let bashPrograms = input.bashPrograms === undefined
    ? undefined
    : Object.freeze(nullProtoRecord(input.bashPrograms));
  const powershellPrograms = input.powershellPrograms === undefined
    ? undefined
    : Object.freeze(nullProtoRecord(input.powershellPrograms));
  const runs: NodeRunRecord[] = [];
  const faults: ChainFault[] = [];
  const readyResults: FinalCallResult[] = [];
  const publishedIds = new Set<string>();

  const stopped = (status: "cancelled" | "deadline"): RunStepChainResult => ({
    ok: true,
    state,
    results: readyResults,
    pendingToolCallIds: readyCallResults(state)
      .filter((summary) => summary.decision === "ask")
      .map((summary) => summary.toolCallId),
    runs,
    faults,
    status,
  });

  const publishReady = (
    publishState: StepState,
  ):
    | { readonly ok: true }
    | {
        readonly ok: false;
        readonly reason: "cancelled" | "deadline" | "publish-failed";
        readonly detail?: string;
      } => {
    const toolCallIds = readyCallResults(publishState)
      .filter((summary) => summary.decision !== "ask" && !publishedIds.has(summary.toolCallId))
      .map((summary) => summary.toolCallId);
    if (toolCallIds.length === 0) return { ok: true };
    if (signal.aborted) return { ok: false, reason: "cancelled" };
    const publishNow = now();
    if (deadlineAt !== null && publishNow >= deadlineAt) {
      return { ok: false, reason: "deadline" };
    }
    const published = publishFinalResults(publishState, {
      toolCallIds,
      generation,
      nowMs: publishNow,
      ttlMs: resultTtlMs,
    });
    if (!published.ok) {
      return { ok: false, reason: "publish-failed", detail: published.reason };
    }
    for (const result of published.results) {
      publishedIds.add(result.toolCallId);
      readyResults.push(result);
      if (onReady) {
        try {
          onReady(result, publishState);
        } catch {
          // The observer must not change the chain decision.
        }
      }
    }
    return { ok: true };
  };

  // After structural preparation succeeded, record the initial ask
  // events for this batch of prepared units only. This is the run's first
  // audit batch; every later batch comes from an adopted node result.
  const initialChanges = prepared.state.calls.flatMap((call) =>
    call.units.map((unit) => ({
      toolCallId: call.toolCallId,
      unitId: unit.unitId,
      nodeId: INITIAL_UNIT_NODE_ID,
      revision: prepared.state.revision,
      decision: unit.decision,
      reason: unit.reason,
    })));
  if (initialChanges.length > 0) {
    notifyObserver(() => host.unitsAccepted?.(initialChanges));
  }

  for (const binding of ordered.nodes) {
    const current = readyCallResults(state);
    if (current.length > 0 && current.every((summary) => summary.decision === "deny")) {
      break;
    }
    if (signal.aborted) {
      return {
        ok: true,
        state,
        results: [],
        pendingToolCallIds: readyCallResults(state)
          .filter((summary) => summary.decision === "ask")
          .map((summary) => summary.toolCallId),
        runs,
        faults,
        status: "cancelled",
      };
    }
    if (deadlineAt !== null && now() >= deadlineAt) {
      return {
        ok: true,
        state,
        results: [],
        pendingToolCallIds: readyCallResults(state)
          .filter((summary) => summary.decision === "ask")
          .map((summary) => summary.toolCallId),
        runs,
        faults,
        status: "deadline",
      };
    }

    const revisionBefore = state.revision;
    let faultReason: string | null = null;
    const bindingTimeout = Number.isSafeInteger(binding.timeoutMs) && binding.timeoutMs! > 0
      ? binding.timeoutMs! : nodeTimeoutMs;
    const remaining = deadlineAt === null
      ? bindingTimeout
      : Math.min(bindingTimeout, deadlineAt - now());
    if (remaining <= 0) {
      return {
        ok: true,
        state,
        results: [],
        pendingToolCallIds: readyCallResults(state)
          .filter((summary) => summary.decision === "ask")
          .map((summary) => summary.toolCallId),
        runs,
        faults,
        status: "deadline",
      };
    }

    const nodeController = new AbortController();
    const onOuterAbort = () => nodeController.abort(signal.reason);
    signal.addEventListener("abort", onOuterAbort, { once: true });
    const aborted = new Promise<never>((_, reject) => {
      const rejectAbort = () => reject(nodeController.signal.reason ?? new Error("aborted"));
      if (nodeController.signal.aborted) rejectAbort();
      else nodeController.signal.addEventListener("abort", rejectAbort, { once: true });
    });
    const timer = setTimeout(
      () => nodeController.abort(new Error("timeout")),
      remaining,
    );

    try {
      // The start event corresponds to this actual evaluate only.
      notifyObserver(() => host.nodeStarted?.({
        kind: "node-start",
        nodeId: binding.node.id,
        position: binding.position,
        priority: binding.priority,
        revision: revisionBefore,
      }));
      const evaluation = Promise.resolve().then(() => binding.node.evaluate(
        Object.freeze({
          capture,
          state,
          node: {
            id: binding.node.id,
            position: binding.position,
            priority: binding.priority,
          },
          signal: nodeController.signal,
          deadlineAt,
          ...(bashPrograms === undefined ? {} : { bashPrograms }),
          ...(powershellPrograms === undefined ? {} : { powershellPrograms }),
        }),
        host,
      ));
      evaluation.catch(() => undefined);
      const result = await Promise.race([evaluation, aborted]);
      const applied = applyNodeResult(state, {
        node: { id: binding.node.id, priority: binding.priority },
        evaluatedRevision: revisionBefore,
        result,
      }, bashPrograms === undefined ? {} : { bashPrograms });
      if (applied.ok) {
        state = applied.state;
        if (bashPrograms !== undefined && applied.acceptedFacts !== undefined) {
          bashPrograms = withPublishedFacts(bashPrograms, applied.acceptedFacts);
        }
        // The batch is formally adopted here — record exactly the
        // accepted decisions with the revision it produced. A noop records no
        // unit events.
        if (applied.applied.length > 0) {
          notifyObserver(() => host.unitsAccepted?.(
            unitChanges(binding.node.id, applied.applied, state.revision),
          ));
        }
        if ((applied.appliedReviews?.length ?? 0) > 0) {
          notifyObserver(() => host.reviewsAccepted?.(
            reviewChanges(binding.node.id, applied.appliedReviews ?? [], state.revision),
          ));
        }
        const outcome = applied.applied.length > 0 || (applied.appliedReviews?.length ?? 0) > 0
          ? "applied"
          : "noop";
        const run: NodeRunRecord = {
          nodeId: binding.node.id,
          position: binding.position,
          priority: binding.priority,
          revisionBefore,
          revisionAfter: state.revision,
          outcome,
        };
        runs.push(run);
        notifyObserver(() => host.log({ kind: "node", ...run }));
        continue;
      }
      faultReason = applied.reason;
    } catch (error) {
      if (signal.aborted) {
        // The started node ended without a decision because the run
        // stopped it; the cancellation is expressed by its own end event.
        notifyObserver(() => host.log({
          kind: "node",
          nodeId: binding.node.id,
          position: binding.position,
          priority: binding.priority,
          revisionBefore,
          revisionAfter: revisionBefore,
          outcome: "cancelled",
        }));
        return {
          ok: true,
          state,
          results: [],
          pendingToolCallIds: readyCallResults(state)
            .filter((summary) => summary.decision === "ask")
            .map((summary) => summary.toolCallId),
          runs,
          faults,
          status: "cancelled",
        };
      }
      if (deadlineAt !== null && now() >= deadlineAt) {
        notifyObserver(() => host.log({
          kind: "node",
          nodeId: binding.node.id,
          position: binding.position,
          priority: binding.priority,
          revisionBefore,
          revisionAfter: revisionBefore,
          outcome: "timeout",
          reason: "deadline",
        }));
        return {
          ok: true,
          state,
          results: [],
          pendingToolCallIds: readyCallResults(state)
            .filter((summary) => summary.decision === "ask")
            .map((summary) => summary.toolCallId),
          runs,
          faults,
          status: "deadline",
        };
      }
      faultReason = error instanceof Error && error.message === "timeout"
        ? "timeout"
        : error instanceof Error
          ? `threw: ${error.message}`
          : "threw";
    } finally {
      clearTimeout(timer);
      signal.removeEventListener("abort", onOuterAbort);
    }

    faults.push({ nodeId: binding.node.id, reason: faultReason });
    const fallback = applyFaultAsk(state, `node-fault: ${faultReason}`);
    if (!fallback.ok) {
      return {
        ok: false,
        reason: "fault-fallback-failed",
        detail: fallback.reason,
      };
    }
    state = fallback.state;
    // The fallback batches are formally adopted here. A multi-batch
    // fallback keeps each batch's revision and order; nothing was recorded
    // while the outcome was still uncertain.
    if (fallback.changes.length > 0) {
      notifyObserver(() => host.unitsAccepted?.(fallback.changes));
    }
    const run: NodeRunRecord = {
      nodeId: binding.node.id,
      position: binding.position,
      priority: binding.priority,
      revisionBefore,
      revisionAfter: state.revision,
      outcome: "fault",
    };
    runs.push(run);
    // A node timeout ended the evaluate without a result; the audit states
    // that directly instead of folding it into an invalid-result fault.
    notifyObserver(() => host.log({
      kind: "node",
      ...run,
      outcome: faultReason === "timeout" ? "timeout" : "fault",
      reason: faultReason,
    }));
    break;
  }

  if (signal.aborted) {
    return {
      ok: true,
      state,
      results: [],
      pendingToolCallIds: readyCallResults(state)
        .filter((summary) => summary.decision === "ask")
        .map((summary) => summary.toolCallId),
      runs,
      faults,
      status: "cancelled",
    };
  }
  if (deadlineAt !== null && now() >= deadlineAt) {
    return {
      ok: true,
      state,
      results: [],
      pendingToolCallIds: readyCallResults(state)
        .filter((summary) => summary.decision === "ask")
        .map((summary) => summary.toolCallId),
      runs,
      faults,
      status: "deadline",
    };
  }

  if (onReady) {
    const initialReady = publishReady(state);
    if (!initialReady.ok) {
      if (initialReady.reason === "cancelled") return stopped("cancelled");
      if (initialReady.reason === "deadline") return stopped("deadline");
      return { ok: false, reason: "publish-failed", detail: initialReady.detail };
    }
  }

  let summaries = readyCallResults(state);
  let pending = summaries.filter((summary) => summary.decision === "ask");

  if (pending.length > 0 && human) {
    const approver = human;
    const requestHuman = async (pendingSummary: CallSummary): Promise<HumanOutcome> => {
      if (signal.aborted) return { kind: "cancelled" };
      if (deadlineAt !== null && now() >= deadlineAt) return { kind: "deadline" };

      const call = state.calls.find(
        (entry) => entry.toolCallId === pendingSummary.toolCallId,
      );
      if (!call) {
        return {
          kind: "response",
          response: { decision: "deny", reason: "unknown-tool-call-id" },
        };
      }

      const humanController = new AbortController();
      const onHumanAbort = () => humanController.abort(signal.reason);
      signal.addEventListener("abort", onHumanAbort, { once: true });
      const humanAborted = new Promise<never>((_, reject) => {
        const rejectAbort = () => reject(humanController.signal.reason ?? new Error("aborted"));
        if (humanController.signal.aborted) rejectAbort();
        else humanController.signal.addEventListener("abort", rejectAbort, { once: true });
      });
      const humanRemaining = deadlineAt === null ? null : deadlineAt - now();
      if (humanRemaining !== null && humanRemaining <= 0) {
        signal.removeEventListener("abort", onHumanAbort);
        return { kind: "deadline" };
      }
      const humanTimer = humanRemaining === null
        ? null
        : setTimeout(
            () => humanController.abort(new Error("deadline")),
            humanRemaining,
          );
      const request: HumanRequest = Object.freeze({
        capture,
        call,
        summary: pendingSummary,
        state,
        ...(input.mode === undefined ? {} : { mode: input.mode }),
        signal: humanController.signal,
      });

      let raw: HumanResponse;
      try {
        const response = Promise.resolve().then(() => approver(request));
        response.catch(() => undefined);
        raw = await Promise.race([response, humanAborted]);
      } catch {
        if (signal.aborted) return { kind: "cancelled" };
        if (deadlineAt !== null && now() >= deadlineAt) return { kind: "deadline" };
        raw = { decision: "deny", reason: "human adapter failed" };
      } finally {
        if (humanTimer !== null) clearTimeout(humanTimer);
        signal.removeEventListener("abort", onHumanAbort);
      }

      if (signal.aborted) return { kind: "cancelled" };
      if (deadlineAt !== null && now() >= deadlineAt) return { kind: "deadline" };
      return {
        kind: "response",
        response: validHumanResponse(raw) ?? {
          decision: "deny",
          reason: "invalid human response",
        },
      };
    };

    const completions = new Map(
      pending.map((summary) => [requestHuman(summary), summary] as const),
    );
    const remaining = new Set(completions.keys());
    while (remaining.size > 0) {
      const completion = await Promise.race(
        [...remaining].map(async (promise) => ({ promise, outcome: await promise })),
      );
      remaining.delete(completion.promise);
      const summary = completions.get(completion.promise);
      if (!summary) continue;
      const outcome = completion.outcome;
      if (outcome.kind === "cancelled") return stopped("cancelled");
      if (outcome.kind === "deadline") return stopped("deadline");

      if (signal.aborted) return stopped("cancelled");
      if (deadlineAt !== null && now() >= deadlineAt) return stopped("deadline");

      const applied = applyHumanResponse(
        state,
        summary.toolCallId,
        outcome.response,
      );
      if (!applied.ok) {
        faults.push({ nodeId: HUMAN_NODE.id, reason: applied.reason });
        break;
      }
      state = applied.state;
      // The human decision is formally accepted here; only now are
      // its unit changes recorded, before any final delivery.
      if (applied.changes.length > 0) {
        notifyObserver(() => host.unitsAccepted?.(applied.changes));
      }
      if (applied.reviews.length > 0) {
        notifyObserver(() => host.reviewsAccepted?.(applied.reviews));
      }
      if (onReady) {
        const publishedNow = publishReady(state);
        if (!publishedNow.ok) {
          if (publishedNow.reason === "cancelled") return stopped("cancelled");
          if (publishedNow.reason === "deadline") return stopped("deadline");
          return { ok: false, reason: "publish-failed", detail: publishedNow.detail };
        }
      }
    }
    summaries = readyCallResults(state);
    pending = summaries.filter((summary) => summary.decision === "ask");
  }

  if (signal.aborted) return stopped("cancelled");
  if (deadlineAt !== null && now() >= deadlineAt) return stopped("deadline");

  const finalReady = publishReady(state);
  if (!finalReady.ok) {
    if (finalReady.reason === "cancelled") return stopped("cancelled");
    if (finalReady.reason === "deadline") return stopped("deadline");
    return { ok: false, reason: "publish-failed", detail: finalReady.detail };
  }

  const pendingToolCallIds = pending.map((summary) => summary.toolCallId);
  return {
    ok: true,
    state,
    results: readyResults,
    pendingToolCallIds,
    runs,
    faults,
    status: pendingToolCallIds.length > 0 ? "needs-human" : "completed",
  };
}
