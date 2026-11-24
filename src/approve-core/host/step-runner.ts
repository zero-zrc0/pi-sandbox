/**
 * Host step runner (specs/host-integration.md §4).
 *
 * One chain run per step, one join promise per direct call. The runner owns the
 * host-side lifecycle: begin validation, generation fencing, capacity, abort
 * linking, result publication into the per-call joins, settled retention,
 * invalidation, deferred-learning release and the audit envelope around the
 * injected chain runtime.
 *
 * The chain runtime is an injected port, so this module never imports the
 * runtime/contracts implementation as a value: capture, units, nodes and
 * results are treated as plain frozen data and only their shared shapes are
 * imported as types.
 */
import type {
  ChainAuditEntry,
  ChainNodeStartEntry,
  ChainReviewChange,
  ChainRunStatus,
  ChainUnitChange,
  HumanApprover,
  NodeBinding,
  NodeHost,
  RunStepChainInput,
  RunStepChainResult,
  SessionReviewPort,
} from "#approve-core/runtime";
import type {
  BashProgramFactsView,
  FinalCallResult,
  StepCapture,
  StepState,
  UnitPreparation,
} from "#approve-core/contracts";
import type { PowerShellProgramFactsView } from "#approve-core/utils/access-intent/powershell/analysis";
import type {
  LearningFinalizeInput,
  ReviewerMode,
  ReviewerSessionFacts,
} from "#approve-core/context/types";

/** Host boundaries the runner applies; any positive integer override replaces one entry. */
export interface StepRunnerLimits {
  readonly nodeTimeoutMs: number;
  readonly resultTtlMs: number;
  readonly stepDeadlineMs: number;
  readonly maxActiveSteps: number;
  readonly maxPendingCalls: number;
  readonly maxSettledCalls: number;
  readonly settledRetentionMs: number;
}

/** Default host boundaries; any positive integer override replaces one entry. */
export const STEP_RUNNER_LIMITS: Readonly<StepRunnerLimits> = Object.freeze({
  nodeTimeoutMs: 30_000,
  resultTtlMs: 5 * 60_000,
  stepDeadlineMs: 5 * 60_000,
  maxActiveSteps: 64,
  maxPendingCalls: 512,
  maxSettledCalls: 512,
  settledRetentionMs: 60_000,
});

export type StepBlockedReason =
  | "aborted"
  | "disposed"
  | "deadline"
  | "invalid-input"
  | "generation-stale"
  | "capture-mismatch"
  | "unknown-step"
  | "unknown-call"
  | "chain-failed"
  | "chain-cancelled"
  | "chain-deadline"
  | "needs-human"
  | "no-result"
  | "capacity"
  | "duplicate-step";

export type StepOutcome =
  | { readonly decision: "allow" | "deny" | "escalate"; readonly result: FinalCallResult }
  | { readonly decision: "blocked"; readonly reason: StepBlockedReason };

export type StepAuditEvent =
  | {
      readonly kind: "node";
      readonly generation: number;
      readonly stepKey: string;
      readonly captureDigest: string;
      readonly entry: ChainAuditEntry;
    }
  | {
      readonly kind: "node-start";
      readonly generation: number;
      readonly stepKey: string;
      readonly captureDigest: string;
      readonly entry: ChainNodeStartEntry;
    }
  | {
      readonly kind: "unit-change";
      readonly generation: number;
      readonly stepKey: string;
      readonly captureDigest: string;
      readonly changes: readonly ChainUnitChange[];
    }
  | {
      readonly kind: "review-change";
      readonly generation: number;
      readonly stepKey: string;
      readonly captureDigest: string;
      readonly changes: readonly ChainReviewChange[];
    };

export interface StepBeginInput {
  readonly capture: StepCapture;
  readonly units: readonly UnitPreparation[];
  readonly nodes: readonly NodeBinding[];
  readonly generation: number;
  readonly mode: ReviewerMode;
  readonly sessionFacts: ReviewerSessionFacts;
  readonly bashPrograms?: Readonly<Record<string, BashProgramFactsView>>;
  readonly powershellPrograms?: Readonly<Record<string, PowerShellProgramFactsView>>;
  readonly selectedFilePaths?: Readonly<Record<string, string>>;
  readonly signal?: AbortSignal;
  readonly deadlineAt?: number | null;
  readonly human?: HumanApprover;
  /** The host session memory, checked as a scoped review for pending asks. */
  readonly sessionReviews?: SessionReviewPort;
  readonly onFinal?: (result: FinalCallResult, state: StepState) => void;
}

export type StepBeginOk = { readonly ok: true; readonly handle: StepHandle };
export type StepBeginFailure = {
  readonly ok: false;
  readonly reason:
    | "invalid-input"
    | "generation-stale"
    | "capture-mismatch"
    | "capacity"
    | "duplicate-step";
};
export type StepBeginResult = StepBeginOk | StepBeginFailure;

export interface StepHandle {
  readonly stepKey: string;
  readonly captureDigest: string;
  readonly generation: number;
  readonly done: Promise<readonly StepOutcome[]>;
  join(toolCallId: string, options?: { readonly signal?: AbortSignal }): Promise<StepOutcome>;
}

export interface StepRunnerLearningPort {
  finalize(input: LearningFinalizeInput): unknown | Promise<unknown>;
  discard(toolCallId: string): void;
  dispose?(): void;
}

export interface StepRunnerOptions {
  readonly currentGeneration: () => number | undefined;
  readonly runChain: (input: RunStepChainInput) => Promise<RunStepChainResult>;
  readonly now?: () => number;
  readonly limits?: Partial<typeof STEP_RUNNER_LIMITS>;
  readonly learning?: StepRunnerLearningPort;
  readonly onAudit?: (event: StepAuditEvent) => void;
}

export interface StepRunner {
  begin(input: StepBeginInput): StepBeginResult;
  join(input: {
    readonly toolCallId: string;
    readonly captureDigest?: string;
    readonly signal?: AbortSignal;
  }): Promise<StepOutcome>;
  /** Active steps only. */
  hasStep(stepKey: string): boolean;
  /** Active pending calls and settled results within TTL. */
  hasCall(toolCallId: string): boolean;
  invalidate(): void;
  dispose(): void;
  state(): {
    readonly activeSteps: number;
    readonly pendingCalls: number;
    readonly settledCalls: number;
  };
}

type ResolvedLimits = typeof STEP_RUNNER_LIMITS;

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function positiveInteger(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0 ? value : fallback;
}

const REVIEWER_MODES: readonly ReviewerMode[] = [
  "read-only",
  "default",
  "auto-review",
  "full-access",
];

/** Structural capture check: the runner only relies on plain frozen data. */
function isCaptureLike(value: unknown): value is StepCapture {
  if (!isRecord(value)) return false;
  if (
    !nonEmptyString(value.stepKey) ||
    !nonEmptyString(value.sessionId) ||
    !nonEmptyString(value.sourceEntryId) ||
    !nonEmptyString(value.digest)
  ) {
    return false;
  }
  if (!Number.isSafeInteger(value.manifestRevision) || (value.manifestRevision as number) < 0) {
    return false;
  }
  if (value.complete !== true) return false;
  const directCalls = value.directCalls;
  if (!Array.isArray(directCalls) || directCalls.length === 0) return false;
  const seen = new Set<string>();
  for (const call of directCalls) {
    if (!isRecord(call) || !nonEmptyString(call.toolCallId)) return false;
    if (seen.has(call.toolCallId)) return false;
    seen.add(call.toolCallId);
  }
  return true;
}

function isValidBeginInput(input: StepBeginInput): boolean {
  if (!isRecord(input)) return false;
  if (!isCaptureLike(input.capture)) return false;
  if (!Array.isArray(input.units) || !Array.isArray(input.nodes)) return false;
  if (!Number.isSafeInteger(input.generation) || input.generation < 0) return false;
  if (!REVIEWER_MODES.includes(input.mode)) return false;
  if (!isRecord(input.sessionFacts) || !isRecord(input.sessionFacts.view)) return false;
  const deadlineAt = input.deadlineAt;
  if (
    deadlineAt !== undefined &&
    deadlineAt !== null &&
    (!Number.isSafeInteger(deadlineAt) || deadlineAt < 0)
  ) {
    return false;
  }
  return true;
}

function resolveLimits(overrides: Partial<ResolvedLimits> | undefined): ResolvedLimits {
  const source = isRecord(overrides) ? overrides : {};
  return Object.freeze({
    nodeTimeoutMs: positiveInteger(source.nodeTimeoutMs, STEP_RUNNER_LIMITS.nodeTimeoutMs),
    resultTtlMs: positiveInteger(source.resultTtlMs, STEP_RUNNER_LIMITS.resultTtlMs),
    stepDeadlineMs: positiveInteger(source.stepDeadlineMs, STEP_RUNNER_LIMITS.stepDeadlineMs),
    maxActiveSteps: positiveInteger(source.maxActiveSteps, STEP_RUNNER_LIMITS.maxActiveSteps),
    maxPendingCalls: positiveInteger(source.maxPendingCalls, STEP_RUNNER_LIMITS.maxPendingCalls),
    maxSettledCalls: positiveInteger(source.maxSettledCalls, STEP_RUNNER_LIMITS.maxSettledCalls),
    settledRetentionMs: positiveInteger(source.settledRetentionMs, STEP_RUNNER_LIMITS.settledRetentionMs),
  });
}

function blocked(reason: StepBlockedReason): StepOutcome {
  return Object.freeze({ decision: "blocked" as const, reason });
}

const AUDIT_OMISSION = "…";

/**
 * Host-side audit redaction: a reason may describe the structural category but
 * a Bash command fragment (after `command:` or a backtick-quoted command) never
 * reaches the audit sink.
 */
function sanitizeAuditReason(reason: string): string {
  return reason
    .replace(/`[^`\n]*`/g, AUDIT_OMISSION)
    .replace(/(command\s*:)[^\n]*/gi, `$1 ${AUDIT_OMISSION}`)
    // The structure-analysis node embeds the analyzed Bash fragment after the
    // unit index; the audit keeps only the category.
    .replace(/^(structure:bash:\d+):[\s\S]*$/, `$1:${AUDIT_OMISSION}`);
}

function sanitizeNodeAudit(entry: ChainAuditEntry): ChainAuditEntry {
  if (entry.reason === undefined) return entry;
  return Object.freeze({ ...entry, reason: sanitizeAuditReason(entry.reason) });
}

function sanitizeUnitChanges(changes: readonly ChainUnitChange[]): readonly ChainUnitChange[] {
  return Object.freeze(changes.map((change) =>
    Object.freeze({ ...change, reason: sanitizeAuditReason(change.reason) })));
}

function sanitizeReviewChanges(changes: readonly ChainReviewChange[]): readonly ChainReviewChange[] {
  return Object.freeze(changes.map((change) =>
    Object.freeze({ ...change, reason: sanitizeAuditReason(change.reason) })));
}

/** A pending join of one direct call. The promise is created once and shared. */
interface PendingCall {
  readonly toolCallId: string;
  readonly promise: Promise<StepOutcome>;
  resolve(outcome: StepOutcome): void;
}

interface StepRecord {
  readonly stepKey: string;
  readonly captureDigest: string;
  readonly generation: number;
  readonly capture: StepCapture;
  readonly sessionFacts: ReviewerSessionFacts;
  readonly mode: ReviewerMode;
  readonly signal: AbortSignal;
  readonly controller: AbortController;
  readonly deadlineAt: number | null;
  readonly callOrder: readonly string[];
  readonly pending: Map<string, PendingCall>;
  /** Calls whose final result already reached their join while the run was live. */
  readonly delivered: Set<string>;
  readonly done: Promise<readonly StepOutcome[]>;
  readonly resolveDone: (outcomes: readonly StepOutcome[]) => void;
  readonly handle: StepHandle;
  readonly onFinal?: (result: FinalCallResult, state: StepState) => void;
  readonly externalCleanups: (() => void)[];
  readonly detachAbort: () => void;
  /** Why the step is being torn down; `undefined` until an abort is requested. */
  abortReason: StepBlockedReason | undefined;
  ended: boolean;
}

interface SettledCall {
  readonly outcome: StepOutcome;
  readonly captureDigest: string;
  readonly stepKey: string;
  readonly settledAt: number;
}

/** Link a caller abort signal into a join without losing the shared promise. */
function withJoinSignal(promise: Promise<StepOutcome>, signal: AbortSignal | undefined): Promise<StepOutcome> {
  if (signal === undefined) return promise;
  if (signal.aborted) return Promise.resolve(blocked("aborted"));
  return new Promise<StepOutcome>((resolve) => {
    let settled = false;
    const onAbort = () => {
      if (settled) return;
      settled = true;
      resolve(blocked("aborted"));
    };
    signal.addEventListener("abort", onAbort, { once: true });
    void promise.then((outcome) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      resolve(outcome);
    });
  });
}

export function createStepRunner(options: StepRunnerOptions): StepRunner {
  const now = typeof options.now === "function" ? options.now : () => Date.now();
  const limits = resolveLimits(options.limits);
  const learning = options.learning;
  const onAudit = typeof options.onAudit === "function" ? options.onAudit : undefined;

  const steps = new Map<string, StepRecord>();
  const pendingIndex = new Map<string, { readonly step: StepRecord; readonly pending: PendingCall }>();
  const settled = new Map<string, SettledCall>();
  let disposed = false;

  function notifyAudit(event: StepAuditEvent): void {
    if (onAudit === undefined) return;
    try {
      onAudit(event);
    } catch {
      // An audit sink must never change the chain decision.
    }
  }

  function currentGeneration(): number | undefined {
    try {
      return options.currentGeneration();
    } catch {
      return undefined;
    }
  }

  function readNow(): number {
    const value = now();
    return typeof value === "number" && Number.isFinite(value) ? value : 0;
  }

  /** True when a settled entry may no longer be served to a join. */
  function settledExpired(entry: SettledCall, at: number): boolean {
    if (at - entry.settledAt >= limits.settledRetentionMs) return true;
    if (entry.outcome.decision === "blocked") return false;
    return at >= entry.outcome.result.expiresAt;
  }

  function pruneSettled(): void {
    const at = readNow();
    for (const [callId, entry] of settled) {
      if (settledExpired(entry, at)) settled.delete(callId);
    }
  }

  /** Keep the settled table inside its capacity, dropping the oldest entries first. */
  function enforceSettledCapacity(): void {
    while (settled.size > limits.maxSettledCalls) {
      const oldest = settled.keys().next();
      if (oldest.done === true) return;
      settled.delete(oldest.value);
    }
  }

  function createStepRecord(input: StepBeginInput): StepRecord {
    const capture = input.capture;
    const controller = new AbortController();
    const deadlineAt = input.deadlineAt === undefined
      ? readNow() + limits.stepDeadlineMs
      : input.deadlineAt;

    const pending = new Map<string, PendingCall>();
    const callOrder: string[] = [];
    for (const call of capture.directCalls) {
      let resolvePending!: (outcome: StepOutcome) => void;
      const promise = new Promise<StepOutcome>((resolve) => {
        resolvePending = resolve;
      });
      pending.set(call.toolCallId, { toolCallId: call.toolCallId, promise, resolve: resolvePending });
      callOrder.push(call.toolCallId);
    }

    let resolveDone!: (outcomes: readonly StepOutcome[]) => void;
    const done = new Promise<readonly StepOutcome[]>((resolve) => {
      resolveDone = resolve;
    });

    const handle: StepHandle = {
      stepKey: capture.stepKey,
      captureDigest: capture.digest,
      generation: input.generation,
      done,
      join: (toolCallId, joinOptions) => joinStepCall(record, toolCallId, joinOptions?.signal),
    };

    const externalCleanups: (() => void)[] = [];
    const record: StepRecord = {
      stepKey: capture.stepKey,
      captureDigest: capture.digest,
      generation: input.generation,
      capture,
      sessionFacts: input.sessionFacts,
      mode: input.mode,
      signal: controller.signal,
      controller,
      deadlineAt,
      callOrder,
      pending,
      delivered: new Set<string>(),
      done,
      resolveDone,
      handle,
      onFinal: input.onFinal,
      externalCleanups,
      detachAbort: () => {
        for (const cleanup of externalCleanups) cleanup();
        externalCleanups.length = 0;
      },
      abortReason: undefined,
      ended: false,
    };

    // An aborted step stops delivering immediately, whatever the chain later reports.
    controller.signal.addEventListener("abort", () => {
      if (record.ended) return;
      finishStep(record, blockAll(record, record.abortReason ?? "aborted"), undefined);
    }, { once: true });

    return record;
  }

  function joinStepCall(
    step: StepRecord,
    toolCallId: string,
    signal: AbortSignal | undefined,
  ): Promise<StepOutcome> {
    if (!nonEmptyString(toolCallId)) return Promise.resolve(blocked("invalid-input"));
    const pending = step.pending.get(toolCallId);
    if (pending !== undefined) return withJoinSignal(pending.promise, signal);
    pruneSettled();
    const settledCall = settled.get(toolCallId);
    if (settledCall !== undefined) {
      return withJoinSignal(Promise.resolve(settledCall.outcome), signal);
    }
    return Promise.resolve(blocked("unknown-call"));
  }

  /**
   * Deliver one call's final result as soon as the chain publishes it (§4: one
   * call's allow must not wait for a sibling's human prompt). Delivery is
   * fenced by the publication generation; the remaining calls are settled when
   * the run ends.
   */
  function deliverReady(
    step: StepRecord,
    result: FinalCallResult,
    finalState: StepState | undefined,
  ): void {
    if (step.ended) return;
    if (step.delivered.has(result.toolCallId)) return;
    if (currentGeneration() !== step.generation) return;
    const pending = step.pending.get(result.toolCallId);
    if (pending === undefined) return;
    const outcome: StepOutcome = Object.freeze({ decision: result.decision, result });
    step.delivered.add(result.toolCallId);
    step.pending.delete(result.toolCallId);
    pendingIndex.delete(result.toolCallId);
    if (finalState !== undefined && step.onFinal !== undefined) {
      try {
        step.onFinal(result, finalState);
      } catch {
        // A final observer must never change the chain decision.
      }
    }
    settled.set(
      result.toolCallId,
      Object.freeze({
        outcome,
        captureDigest: step.captureDigest,
        stepKey: step.stepKey,
        settledAt: readNow(),
      }),
    );
    enforceSettledCapacity();
    pending.resolve(outcome);
  }

  function blockAll(step: StepRecord, reason: StepBlockedReason): readonly StepOutcome[] {
    return step.callOrder.map(() => blocked(reason));
  }

  /**
   * Settle the deferred-learning candidates for one finished step: blocked and
   * non-allow calls are discarded immediately, a final allow is finalized after
   * the join delivery. A learning failure never changes the host decision.
   */
  function releaseLearning(
    step: StepRecord,
    outcomes: readonly StepOutcome[],
    finalState: StepState | undefined,
  ): void {
    const port = learning;
    if (port === undefined) return;

    const allowIds = new Set<string>();
    for (let index = 0; index < step.callOrder.length; index += 1) {
      const callId = step.callOrder[index];
      const outcome = outcomes[index];
      if (outcome === undefined) continue;
      if (outcome.decision === "allow") {
        allowIds.add(callId);
        continue;
      }
      try {
        port.discard(callId);
      } catch {
        // Releasing a candidate never changes the host decision.
      }
    }
    if (allowIds.size === 0 || finalState === undefined) return;

    const calls = finalState.calls
      .filter((call) => allowIds.has(call.toolCallId))
      .map((call) => Object.freeze({
        toolCallId: call.toolCallId,
        toolName: call.toolName,
        ...(call.parentToolCallId === undefined ? {} : { parentToolCallId: call.parentToolCallId }),
        arguments: call.arguments,
        argumentsDigest: call.argumentsDigest,
        digest: call.digest,
        units: call.units,
        decision: "allow" as const,
      }));
    if (calls.length === 0) return;

    const input: LearningFinalizeInput = Object.freeze({
      stepKey: step.stepKey,
      sessionId: step.capture.sessionId,
      owner: step.sessionFacts.view.owner,
      calls,
      mode: step.mode,
      revisions: step.sessionFacts.revisions,
      signal: step.signal,
      deadline: step.deadlineAt,
    });
    queueMicrotask(() => {
      try {
        const returned = port.finalize(input);
        if (
          returned !== null &&
          returned !== undefined &&
          typeof (returned as PromiseLike<unknown>).then === "function"
        ) {
          void Promise.resolve(returned).catch(() => undefined);
        }
      } catch {
        // Deferred learning never changes a delivered decision.
      }
    });
  }

  /**
   * Install one step's final outcomes. Every call leaves the pending table
   * exactly once; the outcome (allow, deny, escalate or blocked) stays joinable
   * for the settled retention window.
   */
  function finishStep(
    step: StepRecord,
    outcomes: readonly StepOutcome[],
    finalState: StepState | undefined,
  ): void {
    if (step.ended) return;
    step.ended = true;
    steps.delete(step.stepKey);
    step.detachAbort();
    for (const callId of step.callOrder) pendingIndex.delete(callId);
    pruneSettled();

    const settledAt = readNow();
    for (let index = 0; index < step.callOrder.length; index += 1) {
      const callId = step.callOrder[index];
      const pending = step.pending.get(callId);
      const outcome = outcomes[index] ?? blocked("no-result");
      if (pending === undefined) continue;
      step.pending.delete(callId);
      // Observers and the audit write precede the join delivery; their failure
      // never changes the published outcome.
      if (outcome.decision !== "blocked" && finalState !== undefined && step.onFinal !== undefined) {
        try {
          step.onFinal(outcome.result, finalState);
        } catch {
          // A final observer must never change the chain decision.
        }
      }
      settled.set(
        callId,
        Object.freeze({
          outcome,
          captureDigest: step.captureDigest,
          stepKey: step.stepKey,
          settledAt,
        }),
      );
      pending.resolve(outcome);
    }
    releaseLearning(step, outcomes, finalState);
    enforceSettledCapacity();
    step.resolveDone(outcomes);
  }

  /** The blocked reason a chain ending leaves for calls it never published. */
  function endingReason(status: ChainRunStatus): StepBlockedReason {
    switch (status) {
      case "cancelled":
        return "chain-cancelled";
      case "deadline":
        return "chain-deadline";
      case "needs-human":
        return "needs-human";
      default:
        return "no-result";
    }
  }

  function handleChainResult(step: StepRecord, result: RunStepChainResult): void {
    if (step.ended) return;
    // A step only publishes into the publication generation it was frozen for.
    if (currentGeneration() !== step.generation) {
      finishStep(step, blockAll(step, "generation-stale"), undefined);
      return;
    }
    if (!result.ok) {
      finishStep(step, blockAll(step, "chain-failed"), undefined);
      return;
    }
    const byId = new Map<string, FinalCallResult>();
    for (const finalResult of result.results) byId.set(finalResult.toolCallId, finalResult);
    const missingReason = endingReason(result.status);
    const outcomes = step.callOrder.map((callId): StepOutcome => {
      const finalResult = byId.get(callId);
      if (finalResult === undefined) return blocked(missingReason);
      return Object.freeze({ decision: finalResult.decision, result: finalResult });
    });
    finishStep(step, outcomes, result.state);
  }

  function begin(input: StepBeginInput): StepBeginResult {
    if (disposed) return { ok: false, reason: "invalid-input" };
    if (!isValidBeginInput(input)) return { ok: false, reason: "invalid-input" };
    if (currentGeneration() !== input.generation) {
      return { ok: false, reason: "generation-stale" };
    }

    const existing = steps.get(input.capture.stepKey);
    if (existing !== undefined) {
      return existing.captureDigest === input.capture.digest
        ? { ok: true, handle: existing.handle }
        : { ok: false, reason: "capture-mismatch" };
    }
    // A step whose results are still joinable is not started a second time.
    pruneSettled();
    for (const entry of settled.values()) {
      if (entry.stepKey !== input.capture.stepKey) continue;
      return entry.captureDigest === input.capture.digest
        ? { ok: false, reason: "duplicate-step" }
        : { ok: false, reason: "capture-mismatch" };
    }
    // Capacity is decided before the chain starts: a rejected begin leaves no
    // pending call and no chain run behind.
    if (steps.size >= limits.maxActiveSteps) return { ok: false, reason: "capacity" };
    if (pendingIndex.size + input.capture.directCalls.length > limits.maxPendingCalls) {
      return { ok: false, reason: "capacity" };
    }

    const step = createStepRecord(input);
    steps.set(step.stepKey, step);
    for (const callId of step.callOrder) {
      pendingIndex.set(callId, { step, pending: step.pending.get(callId)! });
    }

    const external = input.signal;
    if (external !== undefined) {
      if (external.aborted) {
        step.controller.abort();
      } else {
        const listener = () => {
          step.controller.abort();
        };
        external.addEventListener("abort", listener, { once: true });
        step.externalCleanups.push(() => external.removeEventListener("abort", listener));
      }
    }
    // Aborting before the chain starts ends the step without any chain work.
    if (step.ended) return { ok: true, handle: step.handle };

    const host: NodeHost = {
      log: (entry) =>
        notifyAudit({
          kind: "node",
          generation: step.generation,
          stepKey: step.stepKey,
          captureDigest: step.captureDigest,
          entry: sanitizeNodeAudit(entry),
        }),
      nodeStarted: (entry) =>
        notifyAudit({
          kind: "node-start",
          generation: step.generation,
          stepKey: step.stepKey,
          captureDigest: step.captureDigest,
          entry,
        }),
      unitsAccepted: (changes) =>
        notifyAudit({
          kind: "unit-change",
          generation: step.generation,
          stepKey: step.stepKey,
          captureDigest: step.captureDigest,
          changes: sanitizeUnitChanges(changes),
        }),
      reviewsAccepted: (changes) =>
        notifyAudit({
          kind: "review-change",
          generation: step.generation,
          stepKey: step.stepKey,
          captureDigest: step.captureDigest,
          changes: sanitizeReviewChanges(changes),
        }),
    };

    const chainInput: RunStepChainInput = {
      capture: step.capture,
      units: input.units,
      nodes: input.nodes,
      generation: step.generation,
      mode: input.mode,
      signal: step.signal,
      deadlineAt: step.deadlineAt,
      nodeTimeoutMs: limits.nodeTimeoutMs,
      resultTtlMs: limits.resultTtlMs,
      now,
      human: input.human,
      ...(input.sessionReviews === undefined ? {} : { sessionReviews: input.sessionReviews }),
      bashPrograms: input.bashPrograms,
      powershellPrograms: input.powershellPrograms,
      selectedFilePaths: input.selectedFilePaths,
      host,
      onReady: (result, state) => deliverReady(step, result, state),
    };
    let chain: Promise<RunStepChainResult>;
    try {
      chain = options.runChain(chainInput);
    } catch (error) {
      chain = Promise.reject(error);
    }
    chain.then(
      (result) => {
        handleChainResult(step, result);
      },
      () => {
        finishStep(step, blockAll(step, "chain-failed"), undefined);
      },
    );

    return { ok: true, handle: step.handle };
  }

  function join(input: {
    readonly toolCallId: string;
    readonly captureDigest?: string;
    readonly signal?: AbortSignal;
  }): Promise<StepOutcome> {
    if (!isRecord(input) || !nonEmptyString(input.toolCallId)) {
      return Promise.resolve(blocked("invalid-input"));
    }
    const indexed = pendingIndex.get(input.toolCallId);
    if (indexed !== undefined) {
      if (input.captureDigest !== undefined && input.captureDigest !== indexed.step.captureDigest) {
        return Promise.resolve(blocked("capture-mismatch"));
      }
      return withJoinSignal(indexed.pending.promise, input.signal);
    }
    pruneSettled();
    const settledCall = settled.get(input.toolCallId);
    if (settledCall !== undefined) {
      if (input.captureDigest !== undefined && input.captureDigest !== settledCall.captureDigest) {
        return Promise.resolve(blocked("capture-mismatch"));
      }
      return withJoinSignal(Promise.resolve(settledCall.outcome), input.signal);
    }
    return Promise.resolve(blocked(steps.size === 0 ? "unknown-step" : "unknown-call"));
  }

  /** Force every active step into its blocked terminal state. */
  function tearDownActive(reason: StepBlockedReason): void {
    for (const step of [...steps.values()]) {
      step.abortReason = reason;
      step.controller.abort();
    }
  }

  function invalidate(): void {
    tearDownActive("aborted");
    settled.clear();
  }

  function dispose(): void {
    if (disposed) return;
    disposed = true;
    tearDownActive("disposed");
    settled.clear();
    try {
      learning?.dispose?.();
    } catch {
      // Releasing deferred learning never changes a host decision.
    }
  }

  return {
    begin,
    join,
    hasStep: (stepKey) => typeof stepKey === "string" && steps.has(stepKey),
    hasCall: (toolCallId) => {
      if (typeof toolCallId !== "string") return false;
      if (pendingIndex.has(toolCallId)) return true;
      pruneSettled();
      return settled.has(toolCallId);
    },
    invalidate,
    dispose,
    state: () => {
      pruneSettled();
      return {
        activeSteps: steps.size,
        pendingCalls: pendingIndex.size,
        settledCalls: settled.size,
      };
    },
  };
}

