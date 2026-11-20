import {
  DEFAULT_CANCEL_GRACE_MS,
  DEFAULT_EXECUTION_DEADLINE_MS,
  DEFAULT_START_TIMEOUT_MS,
  MAX_CONCURRENT_EXECUTIONS,
  MAX_DEADLINE_HORIZON_MS,
  MAX_EXECUTION_STDERR_BYTES,
  MAX_EXECUTION_STDOUT_BYTES,
  MAX_QUEUED_EXECUTIONS,
  type BackendCapabilities,
  type BackendIdentity,
  type CancellationCode,
  type ExecutionFailureCode,
  type ExecutionOutcome,
  type ExecutionPlan,
  type ExecutionRequest,
  type ExecutionRecord,
  type ExecutionStarted,
  type ImpactState,
} from "#sandbox/types";
import { captureExecutionRequest } from "#sandbox/plan";
import { capabilityGap, backendFailureCode, requiredCapabilities } from "#sandbox/backend/capabilities";
import type { DirectBackendDriver, DirectBackendUnavailable, NativeLaunchPlan } from "#sandbox/backend/direct";
import { runNativeProcess, type NativeProcessResult } from "#sandbox/backend/native-process";
import { correlationKey } from "#sandbox/keys";
import {
  isExecutionValidityGuard,
  validityRefusal,
  type ExecutionValidityGuard,
  type ValidityRefusal,
} from "#sandbox/validity";

export interface BackendProbeSuccess {
  readonly status: "available";
  readonly backend: BackendIdentity;
  readonly capabilities: BackendCapabilities;
}

export type BackendProbeResult = BackendProbeSuccess | {
  readonly status: "unavailable" | "setup-failed";
  readonly reason: string;
};

export interface EgressGrantRef {
  readonly leaseId: string;
  readonly proxyHost: string;
  readonly proxyPort: number;
  readonly credential: string;
}

export interface EgressProvider {
  acquire(request: ExecutionRequest): Promise<EgressGrantRef | null>;
  revoke(leaseId: string): void;
}

export interface ExecutionControllerOptions {
  readonly directBackend?: DirectBackendDriver;
  readonly unavailableReason?: string;
  readonly runtimeUseLease?: () => Promise<() => void>;
  readonly startTimeoutMs?: number;
  readonly cancelGraceMs?: number;
  readonly maxConcurrent?: number;
  readonly maxQueue?: number;
  readonly executionDeadlineMs?: number;
  readonly now?: () => number;
  readonly onRecord?: (record: ExecutionRecord) => void;
  readonly probeTimeoutMs?: number;
  readonly egress?: EgressProvider;
}

export interface ExecuteInput {
  readonly request: ExecutionRequest;
  readonly signal?: AbortSignal;
  readonly validity?: ExecutionValidityGuard;
  readonly onOutput?: (chunk: {
    readonly stream: "stdout" | "stderr";
    readonly data: string;
  }) => void;
}

interface CancelIntent {
  readonly code: CancellationCode;
  readonly reason: string;
}

interface PendingTask {
  readonly request: ExecutionRequest;
  readonly generation: number;
  readonly signal: AbortController;
  readonly validity?: ExecutionValidityGuard;
  readonly onOutput?: ExecuteInput["onOutput"];
  readonly resolve: (outcome: ExecutionOutcome) => void;
  readonly settled: Promise<void>;
  externalSignal?: AbortSignal;
  externalAbortHandler?: () => void;
  timer?: NodeJS.Timeout;
  cancel?: CancelIntent;
  starting?: Promise<void>;
  resolved: boolean;
}

interface ActiveExecution {
  readonly task: PendingTask;
  readonly generation: number;
  readonly timers: Set<NodeJS.Timeout>;
  startTimer?: NodeJS.Timeout;
  started: ExecutionStarted;
  startAttempted: boolean;
  startTimedOut: boolean;
  outputLimit: boolean;
  stdout: string;
  stderr: string;
  stdoutBytes: number;
  stderrBytes: number;
  diagnostics: string;
  failure?: { readonly code: string; readonly reason: string };
  capabilityGap?: readonly string[];
  validityRefusal?: ValidityRefusal;
  result?: NativeProcessResult;
  cancel?: CancelIntent;
  egress?: EgressGrantRef;
  egressSettled: boolean;
}

function keyFor(request: ExecutionRequest): string {
  return correlationKey(request.requestId, request.toolCallId);
}

const ABORT_REASONS: Readonly<Record<CancellationCode, string>> = Object.freeze({
  "execution-cancelled": "request was aborted",
  "execution-timeout": "execution deadline expired",
  "plan-invalidated": "configuration changed",
  "session-disposed": "session disposed",
});

function abortIntent(signal: AbortSignal): CancelIntent {
  const reason = signal.reason;
  if (typeof reason === "string" && Object.hasOwn(ABORT_REASONS, reason)) {
    const code = reason as CancellationCode;
    return { code, reason: ABORT_REASONS[code] };
  }
  return { code: "execution-cancelled", reason: ABORT_REASONS["execution-cancelled"] };
}

function startedState(active: ActiveExecution): ExecutionStarted {
  if (active.result) return active.result.started;
  if (active.started === true || active.started === "unknown") return active.started;
  return active.startAttempted ? "unknown" : false;
}

function impactState(started: ExecutionStarted): ImpactState {
  return started === false ? "none" : "unknown";
}

function makeRecord(
  request: ExecutionRequest | undefined,
  generation: number,
  state: ExecutionRecord["state"],
  started: ExecutionStarted,
  impact: ImpactState,
  extra?: {
    readonly code?: ExecutionFailureCode | CancellationCode;
    readonly exitCode?: number;
  },
): ExecutionRecord {
  return {
    requestId: request?.requestId ?? "unknown",
    toolCallId: request?.toolCallId ?? "unknown",
    actionDigest: request?.actionDigest ?? "unknown",
    planDigest: request?.plan.digest ?? "unknown",
    generation,
    toolName: request?.toolName ?? "unknown",
    started,
    state,
    impact,
    ...(extra?.code === undefined ? {} : { code: extra.code }),
    ...(extra?.exitCode === undefined ? {} : { exitCode: extra.exitCode }),
  };
}

function completedOutcome(active: ActiveExecution, result: NativeProcessResult): ExecutionOutcome {
  const exitCode = result.exitCode ?? -1;
  const record = makeRecord(active.task.request, active.generation, "completed", true, result.impact, { exitCode });
  return {
    state: "completed",
    started: true,
    exitCode,
    stdout: active.stdout,
    stderr: active.stderr,
    truncated: false,
    ...(result.dataBase64 === undefined ? {} : { dataBase64: result.dataBase64 }),
    record,
  };
}

function failedOutcome(
  active: ActiveExecution,
  code: ExecutionFailureCode,
  reason: string,
  started: ExecutionStarted,
  impact: ImpactState,
): ExecutionOutcome {
  const result = active.result;
  return {
    state: "failed",
    started,
    code,
    reason,
    impact,
    stdout: active.stdout,
    stderr: active.stderr || active.diagnostics || result?.diagnostics || "",
    truncated: false,
    ...(result?.dataBase64 === undefined ? {} : { dataBase64: result.dataBase64 }),
    record: makeRecord(active.task.request, active.generation, "failed", started, impact, { code }),
  };
}

function cancelledOutcome(active: ActiveExecution, code: CancellationCode, reason: string): ExecutionOutcome {
  const started = startedState(active);
  const impact = impactState(started);
  return {
    state: "cancelled",
    started,
    code,
    reason,
    impact,
    stdout: active.stdout,
    stderr: active.stderr,
    truncated: false,
    record: makeRecord(active.task.request, active.generation, "cancelled", started, impact, { code }),
  };
}

function outcomeFor(active: ActiveExecution): ExecutionOutcome {
  if (active.validityRefusal) {
    return cancelledOutcome(active, active.validityRefusal.code, active.validityRefusal.reason);
  }
  if (active.outputLimit) {
    return failedOutcome(active, "sandbox-output-limit", "native process output exceeded the configured bound", true, "unknown");
  }
  if (active.capabilityGap) {
    return failedOutcome(active, "sandbox-capability-unsupported", `backend cannot express: ${active.capabilityGap.join(", ")}`, false, "none");
  }
  if (active.startTimedOut) {
    return failedOutcome(
      active,
      "sandbox-start-failed",
      "native process did not report a start within the start timeout",
      startedState(active),
      impactState(startedState(active)),
    );
  }
  if (active.failure) {
    const mapped = backendFailureCode(active.failure.code);
    const code: ExecutionFailureCode = startedState(active) === true &&
      (mapped === "sandbox-start-failed" || mapped === "sandbox-setup-failed")
      ? "execution-failed"
      : mapped;
    const started = startedState(active);
    return failedOutcome(active, code, active.failure.reason, started, impactState(started));
  }
  if (active.result?.errorCode !== undefined) {
    const mapped = backendFailureCode(active.result.errorCode);
    const code: ExecutionFailureCode = active.result.started === true &&
      (mapped === "sandbox-start-failed" || mapped === "sandbox-setup-failed")
      ? "execution-failed"
      : mapped;
    return failedOutcome(active, code, active.result.error ?? "native process reported an execution error", active.result.started, active.result.impact);
  }
  if (active.result && active.result.exitCode === null && !active.result.cancelled) {
    return failedOutcome(active, "execution-failed", "native process terminated without an exit code", active.result.started, active.result.impact);
  }
  if (active.result && !active.result.cancelled) return completedOutcome(active, active.result);
  if (active.cancel) return cancelledOutcome(active, active.cancel.code, active.cancel.reason);
  if (active.result?.cancelled) {
    return cancelledOutcome(active, "execution-cancelled", "native process reported cancellation");
  }
  const started = startedState(active);
  return failedOutcome(active, "sandbox-start-failed", "native process ended without a result", started, impactState(started));
}

/** Plans and runs one controlled operation through a trusted native backend. */
export class ExecutionController {
  private readonly directBackend: DirectBackendDriver | undefined;
  private readonly unavailableReason: string | undefined;
  private readonly runtimeUseLease: ExecutionControllerOptions["runtimeUseLease"];
  private readonly startTimeoutMs: number;
  private readonly cancelGraceMs: number;
  private readonly maxConcurrent: number;
  private readonly maxQueue: number;
  private readonly executionDeadlineMs: number;
  private readonly now: () => number;
  private readonly onRecord?: (record: ExecutionRecord) => void;
  private readonly probeTimeoutMs: number;
  private readonly egress: EgressProvider | undefined;
  private generation = 1;
  private disposed = false;
  private readonly queue: PendingTask[] = [];
  private readonly starting = new Map<string, PendingTask>();
  private readonly active = new Map<string, ActiveExecution>();
  private readonly probes = new Set<AbortController>();
  private readonly settling = new Set<Promise<void>>();

  constructor(options: ExecutionControllerOptions) {
    this.directBackend = options.directBackend;
    this.unavailableReason = options.unavailableReason ??
      (options.directBackend === undefined ? "native sandbox backend is unavailable" : undefined);
    this.runtimeUseLease = options.runtimeUseLease;
    this.startTimeoutMs = options.startTimeoutMs ?? DEFAULT_START_TIMEOUT_MS;
    this.cancelGraceMs = options.cancelGraceMs ?? DEFAULT_CANCEL_GRACE_MS;
    this.maxConcurrent = options.maxConcurrent ?? MAX_CONCURRENT_EXECUTIONS;
    this.maxQueue = options.maxQueue ?? MAX_QUEUED_EXECUTIONS;
    this.executionDeadlineMs = options.executionDeadlineMs ?? DEFAULT_EXECUTION_DEADLINE_MS;
    this.now = options.now ?? Date.now;
    this.onRecord = options.onRecord;
    this.probeTimeoutMs = options.probeTimeoutMs ?? this.startTimeoutMs;
    this.egress = options.egress;
    if (!Number.isInteger(this.maxConcurrent) || this.maxConcurrent < 1 ||
        this.maxConcurrent > MAX_CONCURRENT_EXECUTIONS || !Number.isInteger(this.maxQueue) ||
        this.maxQueue < 0 || this.maxQueue > MAX_QUEUED_EXECUTIONS) {
      throw new Error("execution queue bounds are invalid");
    }
  }

  get currentGeneration(): number {
    return this.generation;
  }

  get activeCount(): number {
    return this.active.size;
  }

  get queuedCount(): number {
    return this.queue.length;
  }

  deadlineFromNow(remainingMs?: number): number {
    return this.now() + (remainingMs ?? this.executionDeadlineMs);
  }

  probe(): Promise<BackendProbeResult> {
    const run = this.probeInternal();
    const tracked = run.then(() => undefined, () => undefined);
    this.settling.add(tracked);
    void tracked.finally(() => this.settling.delete(tracked));
    return run;
  }

  private async probeInternal(): Promise<BackendProbeResult> {
    if (this.disposed) return { status: "setup-failed", reason: "execution controller is disposed" };
    if (this.active.size + this.probes.size + this.starting.size >= this.maxConcurrent) {
      return { status: "setup-failed", reason: "native backend probe limit reached" };
    }
    if (this.unavailableReason !== undefined || this.directBackend === undefined) {
      return { status: "unavailable", reason: this.unavailableReason ?? "native sandbox backend is unavailable" };
    }

    const controller = new AbortController();
    this.probes.add(controller);
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort("probe-timeout");
    }, this.probeTimeoutMs);
    timer.unref?.();
    try {
      const result = await this.directBackend.probe(controller.signal);
      if (timedOut) return { status: "setup-failed", reason: "native backend probe timed out" };
      if (controller.signal.aborted) return { status: "setup-failed", reason: "native backend probe was cancelled" };
      if (!result.ok) {
        return {
          status: result.code === "unavailable" ? "unavailable" : "setup-failed",
          reason: result.reason,
        };
      }
      return {
        status: "available",
        backend: { id: this.directBackend.id, version: this.directBackend.version },
        capabilities: result.capabilities,
      };
    } catch (error) {
      return {
        status: timedOut ? "setup-failed" : "unavailable",
        reason: timedOut ? "native backend probe timed out" : error instanceof Error ? error.message : String(error),
      };
    } finally {
      clearTimeout(timer);
      this.probes.delete(controller);
      this.drain();
    }
  }

  async execute(input: ExecuteInput): Promise<ExecutionOutcome> {
    if (input.validity !== undefined && !isExecutionValidityGuard(input.validity)) {
      return this.invalidPlanOutcome("execution validity lease was not issued by the host", undefined, "invalid-plan");
    }
    const request = captureExecutionRequest(input.request);
    if (!request) {
      return this.invalidPlanOutcome("execution request is missing, malformed or contains accessors", undefined, "invalid-plan");
    }
    if (request.start.deadlineAt - this.now() > MAX_DEADLINE_HORIZON_MS) {
      return this.invalidPlanOutcome("execution deadline exceeds the maximum horizon", request, "invalid-plan");
    }
    if (request.mode === "full-access") {
      return this.invalidPlanOutcome("full-access has no module sandbox", request, "full-access-no-sandbox");
    }
    if (this.disposed) return this.invalidPlanOutcome("execution controller is disposed", request, "invalid-plan");
    if (input.signal?.aborted) {
      const intent = abortIntent(input.signal);
      return this.failureOutcome(request, this.generation, "cancelled", false, "none", intent);
    }
    if (this.queue.length >= this.maxQueue &&
        this.active.size + this.probes.size + this.starting.size >= this.maxConcurrent) {
      return this.immediateFailure(request, "sandbox-queue-full", "execution queue is full");
    }
    if (request.start.deadlineAt <= this.now()) {
      return this.immediateFailure(request, "sandbox-deadline-exceeded", "plan deadline has passed");
    }

    const key = keyFor(request);
    if (this.active.has(key) || this.starting.has(key) || this.queue.some((task) => keyFor(task.request) === key)) {
      return this.immediateFailure(request, "binding-mismatch", "duplicate requestId/toolCallId is already active or queued");
    }

    return new Promise<ExecutionOutcome>((resolve) => {
      let settle!: () => void;
      const settled = new Promise<void>((done) => { settle = done; });
      const task: PendingTask = {
        request,
        generation: this.generation,
        signal: new AbortController(),
        ...(input.validity === undefined ? {} : { validity: input.validity }),
        ...(input.onOutput === undefined ? {} : { onOutput: input.onOutput }),
        settled,
        resolved: false,
        resolve: (outcome) => {
          if (task.resolved) return;
          task.resolved = true;
          resolve(outcome);
          settle();
        },
      };
      if (input.signal) {
        task.externalSignal = input.signal;
        task.externalAbortHandler = () => this.cancelTask(task, abortIntent(input.signal as AbortSignal));
        input.signal.addEventListener("abort", task.externalAbortHandler, { once: true });
        if (input.signal.aborted) task.externalAbortHandler();
      }
      if (task.resolved) return;
      this.queue.push(task);
      task.timer = setTimeout(() => {
        this.removeQueued(task);
        const outcome = this.queuedFailure(task, "sandbox-deadline-exceeded", "plan deadline expired while queued");
        this.finishTask(task, outcome);
        this.drain();
      }, Math.max(0, request.start.deadlineAt - this.now()));
      task.timer.unref?.();
      this.drain();
    });
  }

  async updateConfiguration(): Promise<void> {
    this.generation += 1;
    this.invalidateQueued("plan-invalidated", "configuration changed");
    for (const task of this.starting.values()) this.cancelStarting(task, "plan-invalidated", "configuration changed");
    for (const active of this.active.values()) this.beginCancel(active, "plan-invalidated", "configuration changed");
    for (const probe of this.probes) probe.abort("plan-invalidated");
    await this.waitForSettling();
  }

  async cancelSession(sessionId: string, reason = "session disposed"): Promise<void> {
    this.invalidateQueued("session-disposed", reason, (task) => task.request.sessionId === sessionId);
    const cancelled: Promise<void>[] = [];
    for (const task of this.starting.values()) {
      if (task.request.sessionId !== sessionId) continue;
      cancelled.push(this.cancelStarting(task, "session-disposed", reason));
    }
    for (const active of this.active.values()) {
      if (active.task.request.sessionId !== sessionId) continue;
      cancelled.push(active.task.settled);
      this.beginCancel(active, "session-disposed", reason);
    }
    await Promise.all(cancelled);
  }

  async cancel(requestId: string, reason = "cancelled by host"): Promise<void> {
    this.invalidateQueued("execution-cancelled", reason, (task) => task.request.requestId === requestId);
    const cancelled: Promise<void>[] = [];
    for (const task of this.starting.values()) {
      if (task.request.requestId !== requestId) continue;
      cancelled.push(this.cancelStarting(task, "execution-cancelled", reason));
    }
    for (const active of this.active.values()) {
      if (active.task.request.requestId !== requestId) continue;
      cancelled.push(active.task.settled);
      this.beginCancel(active, "execution-cancelled", reason);
    }
    await Promise.all(cancelled);
  }

  async dispose(): Promise<void> {
    if (this.disposed) {
      await this.waitForSettling();
      return;
    }
    this.disposed = true;
    this.generation += 1;
    this.invalidateQueued("session-disposed", "controller disposed");
    for (const task of this.starting.values()) this.cancelStarting(task, "session-disposed", "controller disposed");
    for (const active of this.active.values()) this.beginCancel(active, "session-disposed", "controller disposed");
    for (const probe of this.probes) probe.abort("session-disposed");
    await this.waitForSettling();
  }

  private async waitForSettling(): Promise<void> {
    await Promise.all([...this.settling]);
  }

  private drain(): void {
    while (!this.disposed && this.active.size + this.probes.size + this.starting.size < this.maxConcurrent && this.queue.length > 0) {
      const task = this.queue.shift()!;
      if (task.cancel) {
        this.finishTask(task, this.queuedCancelled(task, task.cancel.code, task.cancel.reason));
        continue;
      }
      this.clearQueueTimer(task);
      const key = keyFor(task.request);
      this.starting.set(key, task);
      const run = this.runTask(task);
      task.starting = run;
      this.settling.add(run);
      void run.finally(() => {
        this.settling.delete(run);
        this.starting.delete(key);
        this.drain();
      });
    }
  }

  private cancelTask(task: PendingTask, intent: CancelIntent): void {
    if (task.resolved || task.cancel) return;
    task.cancel = intent;
    if (this.queue.includes(task)) {
      this.cancelQueued(task, intent.code, intent.reason);
      return;
    }
    const active = this.active.get(keyFor(task.request));
    if (active) this.beginCancel(active, intent.code, intent.reason);
    else task.signal.abort(intent.code);
  }

  private cancelStarting(task: PendingTask, code: CancellationCode, reason: string): Promise<void> {
    task.cancel ??= { code, reason };
    task.signal.abort(task.cancel.code);
    return task.starting ?? Promise.resolve();
  }

  private removeQueued(task: PendingTask): void {
    const index = this.queue.indexOf(task);
    if (index >= 0) this.queue.splice(index, 1);
    this.clearQueueTimer(task);
  }

  private clearQueueTimer(task: PendingTask): void {
    if (task.timer) {
      clearTimeout(task.timer);
      task.timer = undefined;
    }
  }

  private detachExternalAbort(task: PendingTask): void {
    if (task.externalSignal && task.externalAbortHandler) {
      task.externalSignal.removeEventListener("abort", task.externalAbortHandler);
      task.externalAbortHandler = undefined;
    }
  }

  private finishTask(task: PendingTask, outcome: ExecutionOutcome): void {
    this.clearQueueTimer(task);
    this.detachExternalAbort(task);
    task.resolve(outcome);
  }

  private invalidateQueued(
    code: CancellationCode,
    reason: string,
    predicate?: (task: PendingTask) => boolean,
  ): void {
    for (const task of [...this.queue]) {
      if (predicate && !predicate(task)) continue;
      this.cancelQueued(task, code, reason);
    }
  }

  private cancelQueued(task: PendingTask, code: CancellationCode, reason: string): void {
    this.removeQueued(task);
    task.cancel ??= { code, reason };
    task.signal.abort(task.cancel.code);
    this.finishTask(task, this.queuedCancelled(task, task.cancel.code, task.cancel.reason));
  }

  private queuedCancelled(task: PendingTask, code: CancellationCode, reason: string): ExecutionOutcome {
    return this.failureOutcome(task.request, task.generation, "cancelled", false, "none", { code, reason });
  }

  private queuedFailure(task: PendingTask, code: ExecutionFailureCode, reason: string): ExecutionOutcome {
    return this.failureOutcome(task.request, task.generation, "failed", false, "none", { code, reason });
  }

  private immediateFailure(request: ExecutionRequest, code: ExecutionFailureCode, reason: string): ExecutionOutcome {
    return this.failureOutcome(request, this.generation, "failed", false, "none", { code, reason });
  }

  private invalidPlanOutcome(reason: string, request: ExecutionRequest | undefined, code: ExecutionFailureCode): ExecutionOutcome {
    return this.failureOutcome(request, this.generation, "failed", false, "none", { code, reason });
  }

  private failureOutcome(
    request: ExecutionRequest | undefined,
    generation: number,
    state: "failed" | "cancelled",
    started: ExecutionStarted,
    impact: ImpactState,
    detail: { readonly code: ExecutionFailureCode | CancellationCode; readonly reason: string },
  ): ExecutionOutcome {
    const record = makeRecord(request, generation, state, started, impact, { code: detail.code });
    const outcome: ExecutionOutcome = state === "failed"
      ? { state: "failed", started, code: detail.code as ExecutionFailureCode, reason: detail.reason, impact, stdout: "", stderr: "", truncated: false, record }
      : { state: "cancelled", started, code: detail.code as CancellationCode, reason: detail.reason, impact, stdout: "", stderr: "", truncated: false, record };
    this.record(outcome);
    return outcome;
  }

  private async runTask(task: PendingTask): Promise<void> {
    const request = task.request;
    const generation = task.generation;
    if (task.cancel) {
      this.finishTask(task, this.queuedCancelled(task, task.cancel.code, task.cancel.reason));
      return;
    }
    if (generation !== this.generation || this.disposed) {
      this.finishTask(task, this.queuedCancelled(task, "plan-invalidated", "configuration changed"));
      return;
    }
    if (request.start.deadlineAt <= this.now()) {
      this.finishTask(task, this.queuedFailure(task, "sandbox-deadline-exceeded", "plan deadline expired while queued"));
      return;
    }
    if (this.directBackend === undefined || this.unavailableReason !== undefined) {
      this.finishTask(task, this.queuedFailure(task, "sandbox-unavailable", this.unavailableReason ?? "native sandbox backend is unavailable"));
      return;
    }
    if (request.backendId !== this.directBackend.id) {
      this.finishTask(task, this.queuedFailure(task, "binding-mismatch", `request backend ${request.backendId} does not match the active native backend`));
      return;
    }

    const key = keyFor(request);
    const active: ActiveExecution = {
      task,
      generation,
      timers: new Set(),
      started: false,
      startAttempted: false,
      startTimedOut: false,
      outputLimit: false,
      stdout: "",
      stderr: "",
      stdoutBytes: 0,
      stderrBytes: 0,
      diagnostics: "",
      egressSettled: false,
    };
    this.starting.delete(key);
    this.active.set(key, active);
    const addTimer = (timer: NodeJS.Timeout): void => {
      timer.unref?.();
      active.timers.add(timer);
    };
    const startTimer = setTimeout(() => {
      if (active.started === true || task.resolved) return;
      active.startTimedOut = true;
      this.beginCancel(active, "execution-timeout", "start timed out");
    }, this.startTimeoutMs);
    active.startTimer = startTimer;
    addTimer(startTimer);
    addTimer(setTimeout(() => {
      if (task.resolved) return;
      this.beginCancel(active, "execution-timeout", "execution deadline expired");
    }, Math.max(0, request.start.deadlineAt - this.now())));

    let releaseRuntimeUse: (() => void) | undefined;
    let outcome: ExecutionOutcome;
    try {
      const queuedRefusal = validityRefusal(task.validity);
      if (queuedRefusal) {
        active.validityRefusal = queuedRefusal;
        outcome = outcomeFor(active);
      } else {
        releaseRuntimeUse = await this.runtimeUseLease?.();
        if (task.cancel) {
          active.cancel = task.cancel;
        } else if (generation !== this.generation || this.disposed) {
          active.cancel = { code: "plan-invalidated", reason: "configuration changed" };
        }

        if (!active.cancel) {
          const probe = await this.directBackend.probe(task.signal.signal);
          if (task.cancel) active.cancel = task.cancel;
          let capabilities: BackendCapabilities | undefined;
          if (!active.cancel && !probe.ok) {
            active.failure = { code: probe.code, reason: probe.reason };
          } else if (!active.cancel && probe.ok) {
            capabilities = probe.capabilities;
          }
          if (!active.cancel && capabilities) {
            const gaps = capabilityGap(capabilities, requiredCapabilities(request.plan, request.start));
            if (gaps.length > 0) active.capabilityGap = gaps;
          }
        }

        if (!active.cancel && !active.failure && !active.capabilityGap) {
          const refusal = validityRefusal(task.validity);
          if (refusal) active.validityRefusal = refusal;
        }

        if (!active.cancel && !active.failure && !active.capabilityGap && !active.validityRefusal && request.plan.network.kind === "destinations") {
          let grant: EgressGrantRef | null = null;
          try { grant = this.egress ? await this.egress.acquire(request) : null; }
          catch { grant = null; }
          if (task.cancel) {
            if (grant) this.settleEgress(active, grant);
            active.cancel = task.cancel;
          } else if (!grant) {
            active.failure = { code: "unsupported", reason: "host egress service is unavailable for this destination plan" };
          } else {
            active.egress = grant;
          }
        }

        if (!active.cancel && !active.failure && !active.capabilityGap && !active.validityRefusal) {
          const refusal = validityRefusal(task.validity);
          if (refusal) active.validityRefusal = refusal;
        }

        if (!active.cancel && !active.failure && !active.capabilityGap && !active.validityRefusal) {
          let prepared: NativeLaunchPlan | DirectBackendUnavailable;
          try {
            prepared = await this.directBackend.prepare(request, active.egress, task.signal.signal);
          } catch (error) {
            prepared = {
              ok: false,
              code: "setup",
              reason: error instanceof Error ? error.message : String(error),
            };
          }
          if (task.cancel) active.cancel = task.cancel;
          if (!active.cancel && "ok" in prepared && !prepared.ok) {
            active.failure = { code: prepared.code, reason: prepared.reason };
          } else if (!active.cancel) {
            const refusal = validityRefusal(task.validity);
            if (refusal) active.validityRefusal = refusal;
            else {
              active.startAttempted = true;
              const result = await runNativeProcess(prepared as NativeLaunchPlan, {
                signal: task.signal.signal,
                cancelGraceMs: this.cancelGraceMs,
                onStarted: () => {
                  active.started = true;
                  this.clearStartTimer(active);
                },
                onOutput: (chunk) => this.handleOutput(active, chunk),
              });
              active.result = result;
              active.started = result.started;
              active.diagnostics = result.diagnostics;
              if (active.cancel === undefined && task.cancel) active.cancel = task.cancel;
            }
          }
        }
        outcome = outcomeFor(active);
      }
    } catch (error) {
      if (task.cancel) active.cancel = task.cancel;
      else active.failure = { code: "setup", reason: error instanceof Error ? error.message : String(error) };
      outcome = outcomeFor(active);
    } finally {
      if (active.egress) this.settleEgress(active, active.egress);
      if (active.startTimer) clearTimeout(active.startTimer);
      for (const timer of active.timers) clearTimeout(timer);
      active.timers.clear();
      try { releaseRuntimeUse?.(); } catch { /* Preserve the execution result while releasing the runtime lease. */ }
      this.active.delete(key);
      this.detachExternalAbort(task);
    }

    if (!active.validityRefusal) this.recordAsync(outcome!);
    this.finishTask(task, outcome!);
    this.drain();
  }

  private handleOutput(active: ActiveExecution, chunk: { readonly stream: "stdout" | "stderr"; readonly data: string }): void {
    if (active.outputLimit || active.cancel) return;
    const bytes = Buffer.byteLength(chunk.data, "utf8");
    if (chunk.stream === "stdout") {
      if (active.stdoutBytes + bytes > MAX_EXECUTION_STDOUT_BYTES) {
        active.outputLimit = true;
        this.stopForOutputLimit(active);
        return;
      }
      active.stdoutBytes += bytes;
      active.stdout += chunk.data;
    } else {
      if (active.stderrBytes + bytes > MAX_EXECUTION_STDERR_BYTES) {
        active.outputLimit = true;
        this.stopForOutputLimit(active);
        return;
      }
      active.stderrBytes += bytes;
      active.stderr += chunk.data;
    }
    try { active.task.onOutput?.(chunk); } catch { /* An observer cannot interrupt execution or cleanup. */ }
  }

  private stopForOutputLimit(active: ActiveExecution): void {
    if (active.egress) this.settleEgress(active, active.egress);
    if (!active.task.signal.signal.aborted) active.task.signal.abort("output-limit");
  }

  private settleEgress(active: ActiveExecution, grant: EgressGrantRef): void {
    if (active.egressSettled) return;
    active.egressSettled = true;
    try { this.egress?.revoke(grant.leaseId); }
    catch { /* Revocation is best-effort at settle; the proxy also expires leases. */ }
  }

  private clearStartTimer(active: ActiveExecution): void {
    if (!active.startTimer) return;
    clearTimeout(active.startTimer);
    active.timers.delete(active.startTimer);
    active.startTimer = undefined;
  }

  private beginCancel(active: ActiveExecution, code: CancellationCode, reason: string): void {
    if (active.cancel) return;
    active.cancel = { code, reason };
    active.task.cancel ??= active.cancel;
    if (active.egress) this.settleEgress(active, active.egress);
    if (!active.task.signal.signal.aborted) active.task.signal.abort(code);
  }

  private record(outcome: ExecutionOutcome): void {
    try { this.onRecord?.(outcome.record); }
    catch { /* Observation is separate from the execution result and its cleanup. */ }
  }

  private recordAsync(outcome: ExecutionOutcome): void {
    queueMicrotask(() => this.record(outcome));
  }
}
