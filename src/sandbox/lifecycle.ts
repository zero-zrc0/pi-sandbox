import { isAbsolute } from "node:path";

import {
  decodeHelperMessage,
  encodeHostMessage,
  helloMessage,
  type CancelledMessage,
  type HelperDecodeResult,
  type HelperErrorMessage,
  type ReadyMessage,
  type RejectedMessage,
  type ResultMessage,
} from "#sandbox/protocol";
import {
  capabilityGap,
  helperFailureCode,
  requiredCapabilities,
  resolveTrustedHelper,
  versionMatches,
  type TrustedHelperInstallation,
} from "#sandbox/helper";
import {
  captureExecutionPlan,
  executionPlanVerifies,
} from "#sandbox/plan";
import {
  spawnHelper,
  type HelperExitInfo,
  type HelperProcessSpec,
  type HelperTransport,
} from "#sandbox/transport";
import { correlationKey } from "#sandbox/keys";
import {
  isExecutionValidityGuard,
  validityRefusal,
  type ExecutionValidityGuard,
  type ValidityRefusal,
} from "#sandbox/validity";
import {
  DEFAULT_CANCEL_GRACE_MS,
  DEFAULT_EXECUTION_DEADLINE_MS,
  DEFAULT_START_TIMEOUT_MS,
  HELPER_PROTOCOL_VERSION,
  MAX_CONCURRENT_EXECUTIONS,
  MAX_EXECUTION_STDERR_BYTES,
  MAX_EXECUTION_STDOUT_BYTES,
  MAX_HELPER_MESSAGES,
  MAX_QUEUED_EXECUTIONS,
  type BackendCapabilities,
  type BackendIdentity,
  type CancellationCode,
  type ExecutionFailureCode,
  type ExecutionOutcome,
  type ExecutionPlan,
  type ExecutionRecord,
  type ExecutionStarted,
  type ImpactState,
} from "#sandbox/types";

export interface HelperProbeSuccess {
  readonly status: "available";
  readonly backend: BackendIdentity;
  readonly capabilities: BackendCapabilities;
  readonly protocolVersion: number;
}

export type HelperProbeResult =
  | HelperProbeSuccess
  | {
      readonly status:
        | "missing"
        | "version-mismatch"
        | "setup-failed"
        | "start-failed"
        | "protocol-error";
      readonly reason: string;
    };

export type HelperProcessPreparation =
  | { readonly ok: true; readonly spec: HelperProcessSpec }
  | {
      readonly ok: false;
      readonly code:
        | "sandbox-unavailable"
        | "sandbox-setup-failed"
        | "sandbox-capability-unsupported";
      readonly reason: string;
    };

export type PrepareHelperProcess = (input: {
  readonly installation: TrustedHelperInstallation;
  readonly spec: HelperProcessSpec;
  readonly plan?: ExecutionPlan;
}) => HelperProcessPreparation;

/**
 * Host-owned egress seam. The controller asks for one lease before the
 * business start is sent and revokes it on cancel and after settle;
 * revocation must be idempotent. A `null` grant refuses the launch before
 * the sandboxed process exists.
 */
export interface EgressProvider {
  acquire(plan: ExecutionPlan): Promise<EgressGrantRef | null>;
  revoke(leaseId: string): void;
}

export interface EgressGrantRef {
  readonly leaseId: string;
  readonly proxyHost: string;
  readonly proxyPort: number;
  readonly credential: string;
}

export interface ExecutionControllerOptions {
  readonly installation: TrustedHelperInstallation;
  readonly unavailableReason?: string;
  /** Host-owned working directory for helper processes, outside the workspace. */
  readonly helperCwd: string;
  /** Agent workspace; an install root inside it is never trusted. */
  readonly workspace?: string;
  /** Explicitly filtered helper environment; never the controller environment. */
  readonly helperEnvironment: Readonly<Record<string, string>>;
  /** Host-owned hook to apply a platform boundary before the helper starts. */
  readonly prepareHelperProcess?: PrepareHelperProcess;
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
  readonly plan: ExecutionPlan;
  readonly signal?: AbortSignal;
  /**
   * Host-issued lease re-checked after every wait this controller owns.
   * Direct controller consumers that own their validity facts may omit it;
   * anything arriving through the controlled adapter must always supply one,
   * and a value that is not an issued lease is refused rather than ignored.
   */
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
  readonly plan: ExecutionPlan;
  readonly generation: number;
  readonly signal?: AbortSignal;
  readonly validity?: ExecutionValidityGuard;
  readonly onOutput?: ExecuteInput["onOutput"];
  readonly resolve: (outcome: ExecutionOutcome) => void;
  /** Settles only after this task has released its physical helper. */
  readonly settled: Promise<void>;
  timer?: NodeJS.Timeout;
  abortHandler?: () => void;
  cancelled?: ExecutionOutcome;
}

interface ActiveExecution {
  readonly task: PendingTask;
  readonly generation: number;
  readonly transport: HelperTransport;
  readonly done: Promise<void>;
  signalDone: () => void;
  finished: boolean;
  phase: "handshake" | "starting" | "running";
  ready?: ReadyMessage;
  startedAck: boolean;
  startSent: boolean;
  helperStarted?: boolean | "unknown";
  result?: ResultMessage;
  rejected?: RejectedMessage;
  cancelledByHelper?: CancelledMessage;
  helperError?: HelperErrorMessage;
  protocolError?: string;
  exitInfo?: HelperExitInfo;
  versionMismatch?: string;
  capabilityGap?: readonly string[];
  /** The host lease refused before the business start was sent. */
  validityRefusal?: ValidityRefusal;
  startTimedOut: boolean;
  outputLimit: boolean;
  nextSequence: number;
  stdout: string;
  stderr: string;
  stdoutBytes: number;
  stderrBytes: number;
  messageCount: number;
  cancel?: CancelIntent;
  cancelSent: boolean;
  startTimer?: NodeJS.Timeout;
  timers: Set<NodeJS.Timeout>;
  /** Host-issued egress lease held by this execution, if any. */
  egress?: EgressGrantRef;
  egressSettled: boolean;
}

function keyFor(plan: ExecutionPlan): string {
  return correlationKey(plan.requestId, plan.toolCallId);
}

const ABORT_REASONS: Readonly<Record<CancellationCode, string>> = Object.freeze({
  "execution-cancelled": "request was aborted",
  "execution-timeout": "execution deadline expired",
  "plan-invalidated": "configuration changed",
  "session-disposed": "session disposed",
});

/**
 * An aborted signal can carry the invalidation that caused it, so a session or
 * configuration change is recorded as itself instead of as a user cancellation.
 */
function abortIntent(
  signal: AbortSignal,
): { readonly code: CancellationCode; readonly reason: string } {
  const reason = signal.reason;
  if (
    typeof reason === "string" &&
    Object.hasOwn(ABORT_REASONS, reason)
  ) {
    const code = reason as CancellationCode;
    return { code, reason: ABORT_REASONS[code] };
  }
  return { code: "execution-cancelled", reason: ABORT_REASONS["execution-cancelled"] };
}

function startedState(active: ActiveExecution): ExecutionStarted {
  if (active.startedAck || active.helperStarted === true) return true;
  if (active.helperStarted === "unknown") return "unknown";
  return active.startSent ? "unknown" : false;
}

function impactState(
  started: ExecutionStarted,
  explicit?: ImpactState,
): ImpactState {
  if (explicit) return explicit;
  if (started === false) return "none";
  return "unknown";
}

function makeRecord(
  plan: ExecutionPlan | undefined,
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
    requestId: plan?.requestId ?? "unknown",
    toolCallId: plan?.toolCallId ?? "unknown",
    actionDigest: plan?.actionDigest ?? "unknown",
    planDigest: plan?.digest ?? "unknown",
    generation,
    toolName: plan?.tool.name ?? "unknown",
    started,
    state,
    impact,
    ...(extra?.code === undefined ? {} : { code: extra.code }),
    ...(extra?.exitCode === undefined ? {} : { exitCode: extra.exitCode }),
  };
}

function completedOutcome(
  active: ActiveExecution,
  result: ResultMessage,
): ExecutionOutcome {
  const exitCode = result.exitCode ?? -1;
  const record = makeRecord(
    active.task.plan,
    active.generation,
    "completed",
    true,
    result.impact,
    { exitCode },
  );
  return {
    state: "completed",
    started: true,
    exitCode,
    stdout: active.stdout,
    stderr: active.stderr,
    truncated: false,
    ...(result.dataBase64 === undefined
      ? {}
      : { dataBase64: result.dataBase64 }),
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
  return {
    state: "failed",
    started,
    code,
    reason,
    impact,
    stdout: active.stdout,
    stderr: active.stderr || active.transport.diagnostics,
    truncated: false,
    ...(active.result?.dataBase64 === undefined ? {} : { dataBase64: active.result.dataBase64 }),
    record: makeRecord(
      active.task.plan,
      active.generation,
      "failed",
      started,
      impact,
      { code },
    ),
  };
}

function cancelledOutcome(
  active: ActiveExecution,
  code: CancellationCode,
  reason: string,
): ExecutionOutcome {
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
    record: makeRecord(
      active.task.plan,
      active.generation,
      "cancelled",
      started,
      impact,
      { code },
    ),
  };
}

function outcomeFor(
  active: ActiveExecution,
): ExecutionOutcome {
  if (active.validityRefusal) {
    return cancelledOutcome(
      active,
      active.validityRefusal.code,
      active.validityRefusal.reason,
    );
  }
  if (active.outputLimit) {
    return failedOutcome(
      active,
      "sandbox-output-limit",
      "helper output exceeded the configured bound",
      true,
      "unknown",
    ) as ExecutionOutcome;
  }
  if (active.versionMismatch) {
    return failedOutcome(
      active,
      "sandbox-version-mismatch",
      active.versionMismatch,
      false,
      "none",
    );
  }
  if (active.capabilityGap) {
    return failedOutcome(
      active,
      "sandbox-capability-unsupported",
      `backend cannot express: ${active.capabilityGap.join(", ")}`,
      false,
      "none",
    );
  }
  if (active.rejected) {
    return failedOutcome(
      active,
      helperFailureCode(active.rejected.code),
      active.rejected.reason,
      false,
      "none",
    );
  }
  if (active.result) {
    if (active.result.errorCode !== undefined) {
      const mapped = helperFailureCode(active.result.errorCode);
      const code: ExecutionFailureCode =
        mapped === "sandbox-start-failed" || mapped === "sandbox-setup-failed"
          ? "execution-failed"
          : mapped;
      return failedOutcome(
        active,
        code,
        active.result.error ?? "helper reported an execution error",
        true,
        active.result.impact,
      );
    }
    if (active.result.exitCode === null) {
      return failedOutcome(
        active,
        "execution-failed",
        "helper reported a terminated process without an exit code",
        true,
        active.result.impact,
      );
    }
    return completedOutcome(active, active.result);
  }
  if (active.helperError) {
    const mapped = helperFailureCode(active.helperError.code);
    const started = startedState(active);
    return failedOutcome(
      active,
      started === true ? "execution-failed" : mapped,
      active.helperError.message || active.helperError.code,
      started,
      impactState(started),
    );
  }
  if (active.startTimedOut) {
    return failedOutcome(
      active,
      "sandbox-start-failed",
      "helper did not report a start within the start timeout",
      active.startSent ? "unknown" : false,
      active.startSent ? "unknown" : "none",
    );
  }
  if (active.protocolError) {
    return failedOutcome(
      active,
      "sandbox-protocol-error",
      active.protocolError,
      startedState(active),
      startedState(active) === false ? "none" : "unknown",
    );
  }
  if (active.cancel) {
    return cancelledOutcome(active, active.cancel.code, active.cancel.reason);
  }
  if (active.cancelledByHelper) {
    return cancelledOutcome(
      active,
      "execution-cancelled",
      "helper reported cancellation",
    );
  }
  if (active.exitInfo) {
    return failedOutcome(
      active,
      "sandbox-transport-lost",
      `helper exited before a result (code=${String(active.exitInfo.code)}, signal=${String(active.exitInfo.signal)})`,
      startedState(active),
      startedState(active) === false ? "none" : "unknown",
    );
  }
  return failedOutcome(
    active,
    "sandbox-start-failed",
    "helper ended without a start or result",
    startedState(active),
    startedState(active) === false ? "none" : "unknown",
  );
}

/**
 * Plans, queues, starts, streams, cancels, and records helper executions.
 * Approval verdicts stay with the caller; this class only reports execution.
 */
export class ExecutionController {
  private readonly installation: TrustedHelperInstallation;
  private readonly unavailableReason: string | undefined;
  private readonly helperCwd: string;
  private readonly workspace: string | undefined;
  private readonly helperEnvironment: Readonly<Record<string, string>>;
  private readonly prepareHelperProcess: PrepareHelperProcess | undefined;
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
  private readonly active = new Map<string, ActiveExecution>();
  private readonly probes = new Set<HelperTransport>();
  private readonly settling = new Set<Promise<void>>();

  constructor(options: ExecutionControllerOptions) {
    this.installation = options.installation;
    this.unavailableReason = options.unavailableReason;
    this.helperCwd = options.helperCwd;
    this.workspace = options.workspace;
    this.helperEnvironment = Object.freeze({ ...options.helperEnvironment });
    this.prepareHelperProcess = options.prepareHelperProcess;
    this.startTimeoutMs = options.startTimeoutMs ?? DEFAULT_START_TIMEOUT_MS;
    this.cancelGraceMs = options.cancelGraceMs ?? DEFAULT_CANCEL_GRACE_MS;
    this.maxConcurrent = options.maxConcurrent ?? MAX_CONCURRENT_EXECUTIONS;
    this.maxQueue = options.maxQueue ?? MAX_QUEUED_EXECUTIONS;
    this.executionDeadlineMs =
      options.executionDeadlineMs ?? DEFAULT_EXECUTION_DEADLINE_MS;
    this.now = options.now ?? Date.now;
    this.onRecord = options.onRecord;
    this.probeTimeoutMs = options.probeTimeoutMs ?? this.startTimeoutMs;
    this.egress = options.egress;
    if (!isAbsolute(this.helperCwd)) {
      throw new Error("helperCwd must be an absolute path");
    }
    if (!Number.isInteger(this.maxConcurrent) || this.maxConcurrent < 1 ||
        this.maxConcurrent > MAX_CONCURRENT_EXECUTIONS ||
        !Number.isInteger(this.maxQueue) || this.maxQueue < 0 ||
        this.maxQueue > MAX_QUEUED_EXECUTIONS) {
      throw new Error("execution queue bounds are invalid");
    }
  }

  get currentGeneration(): number {
    return this.generation;
  }

  /** Running helper count, used by hosts to expose local health. */
  get activeCount(): number {
    return this.active.size;
  }

  get queuedCount(): number {
    return this.queue.length;
  }

  /** Suggested absolute deadline for a plan compiled now. */
  deadlineFromNow(remainingMs?: number): number {
    return this.now() + (remainingMs ?? this.executionDeadlineMs);
  }

  probe(): Promise<HelperProbeResult> {
    const run = this.probeInternal();
    const tracked = run.then(
      () => undefined,
      () => undefined,
    );
    this.settling.add(tracked);
    void tracked.finally(() => this.settling.delete(tracked));
    return run;
  }

  private async probeInternal(): Promise<HelperProbeResult> {
    if (this.disposed) {
      return {
        status: "setup-failed",
        reason: "execution controller is disposed",
      };
    }
    if (this.active.size + this.probes.size >= this.maxConcurrent) {
      return {
        status: "setup-failed",
        reason: "helper probe limit reached",
      };
    }
    const generation = this.generation;
    const requestId = `probe-${generation}-${this.now()}`;
    const spawned = this.resolveAndSpawn();
    if (!spawned.ok) {
      return {
        status:
          spawned.code === "sandbox-unavailable"
            ? "missing"
            : spawned.code === "sandbox-start-failed"
              ? "start-failed"
              : "setup-failed",
        reason: spawned.reason,
      };
    }
    const transport = spawned.transport;
    this.probes.add(transport);
    try {
      const result = await this.handshake(transport, requestId, generation);
      const hello = encodeHostMessage({ type: "shutdown" });
      if (hello.ok) transport.send(hello.line);
      return result;
    } finally {
      try {
        await transport.close(500);
      } finally {
        this.probes.delete(transport);
        this.drain();
      }
    }
  }

  private resolveAndSpawn(plan?: ExecutionPlan):
    | { readonly ok: true; readonly transport: HelperTransport }
    | {
        readonly ok: false;
        readonly code:
          | "sandbox-unavailable"
          | "sandbox-setup-failed"
          | "sandbox-capability-unsupported"
          | "sandbox-start-failed";
        readonly reason: string;
      } {
    if (this.unavailableReason !== undefined) {
      return { ok: false, code: "sandbox-unavailable", reason: this.unavailableReason };
    }
    const resolution = resolveTrustedHelper(this.installation, {
      cwd: this.helperCwd,
      ...(this.workspace === undefined ? {} : { workspace: this.workspace }),
    });
    if (!resolution.ok) {
      return { ok: false, code: resolution.code, reason: resolution.reason };
    }
    try {
      const spec: HelperProcessSpec = {
        executable: resolution.installation.executable,
        args: resolution.installation.args ?? [],
        cwd: this.helperCwd,
        environment: this.helperEnvironment,
      };
      const preparation = this.prepareHelperProcess?.({
        installation: resolution.installation,
        spec,
        ...(plan === undefined ? {} : { plan }),
      });
      if (preparation && !preparation.ok) return preparation;
      return {
        ok: true,
        transport: spawnHelper(preparation?.spec ?? spec),
      };
    } catch (error) {
      return {
        ok: false,
        code: "sandbox-start-failed",
        reason: error instanceof Error ? error.message : String(error),
      };
    }
  }

  async execute(input: ExecuteInput): Promise<ExecutionOutcome> {
    if (input.validity !== undefined && !isExecutionValidityGuard(input.validity)) {
      return this.invalidPlanOutcome(
        "execution validity lease was not issued by the host",
        undefined,
        "invalid-plan",
      );
    }
    const plan = captureExecutionPlan(input.plan);
    if (!plan) {
      return this.invalidPlanOutcome(
        "plan is missing, malformed or contains accessors",
        undefined,
        "invalid-plan",
      );
    }
    if (!executionPlanVerifies(plan)) {
      return this.invalidPlanOutcome(
        "plan digest does not verify",
        undefined,
        "invalid-plan",
      );
    }
    if (plan.mode === "full-access") {
      return this.invalidPlanOutcome(
        "full-access has no module sandbox",
        plan,
        "full-access-no-sandbox",
      );
    }
    if (this.disposed) {
      return this.invalidPlanOutcome(
        "execution controller is disposed",
        plan,
        "invalid-plan",
      );
    }
    if (this.queue.length >= this.maxQueue && this.active.size + this.probes.size >= this.maxConcurrent) {
      return this.immediateFailure(
        plan,
        "sandbox-queue-full",
        "execution queue is full",
      );
    }
    if (plan.deadlineAt <= this.now()) {
      return this.immediateFailure(
        plan,
        "sandbox-deadline-exceeded",
        "plan deadline has passed",
      );
    }
    const key = keyFor(plan);
    if (
      this.active.has(key) ||
      this.queue.some((task) => keyFor(task.plan) === key)
    ) {
      return this.immediateFailure(
        plan,
        "binding-mismatch",
        "duplicate requestId/toolCallId is already active or queued",
      );
    }

    return new Promise<ExecutionOutcome>((resolve) => {
      let settle!: () => void;
      const settled = new Promise<void>(done => { settle = done; });
      const task: PendingTask = {
        plan,
        generation: this.generation,
        ...(input.signal === undefined ? {} : { signal: input.signal }),
        ...(input.validity === undefined ? {} : { validity: input.validity }),
        ...(input.onOutput === undefined ? {} : { onOutput: input.onOutput }),
        settled,
        resolve: outcome => { resolve(outcome); settle(); },
      };
      this.queue.push(task);
      task.timer = setTimeout(() => {
        this.removeQueued(task);
        resolve(this.queuedFailure(task, "sandbox-deadline-exceeded", "plan deadline expired while queued"));
      }, Math.max(0, plan.deadlineAt - this.now()));
      task.timer.unref?.();
      if (task.signal) {
        if (task.signal.aborted) {
          const intent = abortIntent(task.signal);
          this.cancelQueued(task, intent.code, intent.reason);
          return;
        }
        task.abortHandler = () => {
          const intent = abortIntent(task.signal as AbortSignal);
          this.cancelQueued(task, intent.code, intent.reason);
        };
        task.signal.addEventListener("abort", task.abortHandler, { once: true });
      }
      this.drain();
    });
  }

  /** Invalidate queued plans and cancel running helpers after a config change. */
  async updateConfiguration(): Promise<void> {
    this.generation += 1;
    this.invalidateQueued("plan-invalidated", "configuration changed");
    for (const active of this.active.values()) {
      this.beginCancel(active, "plan-invalidated", "configuration changed");
    }
    for (const probe of this.probes) probe.kill(0);
    await this.waitForSettling();
  }

  async cancelSession(
    sessionId: string,
    reason = "session disposed",
  ): Promise<void> {
    this.invalidateQueued(
      "session-disposed",
      reason,
      (task) => task.plan.sessionId === sessionId,
    );
    const cancelled: Promise<void>[] = [];
    for (const active of this.active.values()) {
      if (active.task.plan.sessionId !== sessionId) continue;
      cancelled.push(active.task.settled);
      this.beginCancel(active, "session-disposed", reason);
    }
    await Promise.all(cancelled);
  }

  async cancel(
    requestId: string,
    reason = "cancelled by host",
  ): Promise<void> {
    this.invalidateQueued(
      "execution-cancelled",
      reason,
      (task) => task.plan.requestId === requestId,
    );
    const cancelled: Promise<void>[] = [];
    for (const active of this.active.values()) {
      if (active.task.plan.requestId !== requestId) continue;
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
    for (const active of this.active.values()) {
      this.beginCancel(active, "session-disposed", "controller disposed");
    }
    for (const probe of this.probes) probe.kill(0);
    await this.waitForSettling();
  }

  private async waitForSettling(): Promise<void> {
    await Promise.all([...this.settling]);
  }

  private drain(): void {
    while (
      !this.disposed &&
      this.active.size + this.probes.size < this.maxConcurrent &&
      this.queue.length > 0
    ) {
      const task = this.queue.shift()!;
      if (task.cancelled) {
        task.resolve(task.cancelled);
        continue;
      }
      this.clearQueued(task);
      const run = this.runTask(task);
      this.settling.add(run);
      void run.finally(() => this.settling.delete(run));
    }
  }

  private removeQueued(task: PendingTask): void {
    const index = this.queue.indexOf(task);
    if (index >= 0) this.queue.splice(index, 1);
    this.clearQueued(task);
  }

  private clearQueued(task: PendingTask): void {
    if (task.timer) {
      clearTimeout(task.timer);
      task.timer = undefined;
    }
    if (task.signal && task.abortHandler) {
      task.signal.removeEventListener("abort", task.abortHandler);
      task.abortHandler = undefined;
    }
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

  private cancelQueued(
    task: PendingTask,
    code: CancellationCode,
    reason: string,
  ): void {
    this.removeQueued(task);
    task.resolve(this.queuedCancelled(task, code, reason));
  }

  private queuedCancelled(
    task: PendingTask,
    code: CancellationCode,
    reason: string,
  ): ExecutionOutcome {
    return this.failureOutcome(
      task.plan,
      task.generation,
      "cancelled",
      false,
      "none",
      { code, reason },
    );
  }

  private queuedFailure(
    task: PendingTask,
    code: ExecutionFailureCode,
    reason: string,
  ): ExecutionOutcome {
    return this.failureOutcome(
      task.plan,
      task.generation,
      "failed",
      false,
      "none",
      { code, reason },
    );
  }

  private immediateFailure(
    plan: ExecutionPlan,
    code: ExecutionFailureCode,
    reason: string,
  ): ExecutionOutcome {
    return this.failureOutcome(
      plan,
      this.generation,
      "failed",
      false,
      "none",
      { code, reason },
    );
  }

  private invalidPlanOutcome(
    reason: string,
    plan: ExecutionPlan | undefined,
    code: ExecutionFailureCode,
  ): ExecutionOutcome {
    return this.failureOutcome(
      plan,
      this.generation,
      "failed",
      false,
      "none",
      { code, reason },
    );
  }

  private failureOutcome(
    plan: ExecutionPlan | undefined,
    generation: number,
    state: "failed" | "cancelled",
    started: ExecutionStarted,
    impact: ImpactState,
    detail:
      | { readonly code: ExecutionFailureCode; readonly reason: string }
      | { readonly code: CancellationCode; readonly reason: string },
  ): ExecutionOutcome {
    const outcome = this.buildFailure(
      plan,
      generation,
      state,
      started,
      impact,
      detail,
    );
    this.record(outcome);
    return outcome;
  }

  /**
   * Builds an outcome without publishing an execution record. A host lease
   * refusal belongs to the approval domain: the plan was never executed and
   * never became an execution result, so the caller is told and no execution
   * record is written. Failures caused by this layer keep recording.
   */
  private buildFailure(
    plan: ExecutionPlan | undefined,
    generation: number,
    state: "failed" | "cancelled",
    started: ExecutionStarted,
    impact: ImpactState,
    detail:
      | { readonly code: ExecutionFailureCode; readonly reason: string }
      | { readonly code: CancellationCode; readonly reason: string },
  ): ExecutionOutcome {
    const record = makeRecord(plan, generation, state, started, impact, {
      code: detail.code,
    });
    return state === "failed"
      ? {
          state: "failed",
          started,
          code: detail.code as ExecutionFailureCode,
          reason: detail.reason,
          impact,
          stdout: "",
          stderr: "",
          truncated: false,
          record,
        }
      : {
          state: "cancelled",
          started,
          code: detail.code as CancellationCode,
          reason: detail.reason,
          impact,
          stdout: "",
          stderr: "",
          truncated: false,
          record,
        };
  }

  private async handshake(
    transport: HelperTransport,
    requestId: string,
    generation: number,
  ): Promise<HelperProbeResult> {
    const hello = encodeHostMessage(helloMessage(requestId, generation));
    if (!hello.ok) {
      return { status: "protocol-error", reason: hello.reason };
    }
    const ready = await new Promise<
      | { readonly ok: true; readonly message: ReadyMessage }
      | { readonly ok: false; readonly reason: string; readonly kind: "exit" | "protocol" | "timeout" | "unavailable" }
    >((resolve) => {
      let settled = false;
      const finish = (
        value:
          | { readonly ok: true; readonly message: ReadyMessage }
          | { readonly ok: false; readonly reason: string; readonly kind: "exit" | "protocol" | "timeout" | "unavailable" },
      ) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        unsubscribeLine();
        unsubscribeError();
        resolve(value);
      };
      const timer = setTimeout(() => {
        finish({ ok: false, reason: "helper ready timed out", kind: "timeout" });
      }, this.probeTimeoutMs);
      timer.unref?.();
      const unsubscribeLine = transport.onLine((line) => {
        const decoded = decodeHelperMessage(line);
        if (!decoded.ok) {
          finish({ ok: false, reason: decoded.reason, kind: "protocol" });
          return;
        }
        if (decoded.message.type === "error" && decoded.message.code === "unavailable" &&
          decoded.message.requestId === requestId && decoded.message.generation === generation) {
          finish({ ok: false, reason: decoded.message.message, kind: "unavailable" });
          return;
        }
        if (decoded.message.type !== "ready") {
          finish({
            ok: false,
            reason: `expected ready, received ${decoded.message.type}`,
            kind: "protocol",
          });
          return;
        }
        finish({ ok: true, message: decoded.message });
      });
      const unsubscribeError = transport.onError((error) => {
        finish({ ok: false, reason: error.message, kind: "exit" });
      });
      void transport.waitForExit().then((info) => {
        finish({
          ok: false,
          reason: `helper exited before ready (code=${String(info.code)})`,
          kind: "exit",
        });
      });
      const sent = transport.send(hello.line);
      if (!sent.ok) {
        finish({ ok: false, reason: sent.reason ?? "send failed", kind: "exit" });
      }
    });
    if (!ready.ok) {
      return {
        status: ready.kind === "protocol" ? "protocol-error" : ready.kind === "unavailable" ? "missing" : "start-failed",
        reason: ready.reason,
      };
    }
    const message = ready.message;
    if (message.requestId !== requestId || message.generation !== generation) {
      return {
        status: "protocol-error",
        reason: "ready message correlation does not match",
      };
    }
    if (!versionMatches(this.installation, message.protocolVersion, message.backend.version, message.backend.id)) {
      return {
        status: "version-mismatch",
        reason: `helper protocol ${message.protocolVersion} (backend ${message.backend.version}) does not match the host requirement`,
      };
    }
    return {
      status: "available",
      backend: message.backend,
      capabilities: message.capabilities,
      protocolVersion: HELPER_PROTOCOL_VERSION,
    };
  }

  private async runTask(task: PendingTask): Promise<void> {
    const plan = task.plan;
    const generation = task.generation;
    if (generation !== this.generation || this.disposed) {
      task.resolve(
        this.queuedCancelled(task, "plan-invalidated", "configuration changed"),
      );
      return;
    }
    if (task.signal?.aborted) {
      task.resolve(
        this.queuedCancelled(task, "execution-cancelled", "request was aborted"),
      );
      return;
    }

    if (
      this.installation.expectedBackendId !== undefined &&
      plan.backend.id !== this.installation.expectedBackendId
    ) {
      task.resolve(
        this.failureOutcome(
          plan,
          generation,
          "failed",
          false,
          "none",
          {
            code: "binding-mismatch",
            reason: `plan backend ${plan.backend.id} does not match the installed backend`,
          },
        ),
      );
      return;
    }

    // The lease was checked when the caller queued this task. Time in the
    // queue is unbounded from the host's point of view, so the facts behind
    // the approval are re-read before any process exists.
    const queuedRefusal = validityRefusal(task.validity);
    if (queuedRefusal) {
      task.resolve(
        this.buildFailure(
          task.plan,
          task.generation,
          "cancelled",
          false,
          "none",
          queuedRefusal,
        ),
      );
      return;
    }

    const spawned = this.resolveAndSpawn(plan);
    if (!spawned.ok) {
      const outcome = this.failureOutcome(
        plan,
        generation,
        "failed",
        false,
        "none",
        { code: spawned.code, reason: spawned.reason },
      );
      task.resolve(outcome);
      return;
    }
    const transport = spawned.transport;

    let resolveDone!: () => void;
    const done = new Promise<void>((resolve) => {
      resolveDone = resolve;
    });
    const active: ActiveExecution = {
      task,
      generation,
      transport,
      done,
      signalDone: () => {
        if (!active.finished) {
          active.finished = true;
          resolveDone();
        }
      },
      finished: false,
      phase: "handshake",
      startedAck: false,
      startSent: false,
      startTimedOut: false,
      outputLimit: false,
      nextSequence: 0,
      stdout: "",
      stderr: "",
      stdoutBytes: 0,
      stderrBytes: 0,
      messageCount: 0,
      cancelSent: false,
      timers: new Set(),
      egressSettled: false,
    };
    this.active.set(keyFor(plan), active);

    const addTimer = (timer: NodeJS.Timeout): void => {
      timer.unref?.();
      active.timers.add(timer);
    };
    const startTimer = setTimeout(() => {
      if (active.startedAck || active.finished) return;
      active.startTimedOut = true;
      this.beginCancel(active, "execution-timeout", "start timed out");
    }, this.startTimeoutMs);
    active.startTimer = startTimer;
    addTimer(startTimer);
    const deadlineTimer = setTimeout(() => {
      if (active.finished) return;
      this.beginCancel(active, "execution-timeout", "execution deadline expired");
    }, Math.max(0, plan.deadlineAt - this.now()));
    addTimer(deadlineTimer);

    const onAbort = () => {
      const intent = abortIntent(task.signal as AbortSignal);
      this.beginCancel(active, intent.code, intent.reason);
    };
    task.signal?.addEventListener("abort", onAbort, { once: true });

    const unsubscribeLine = transport.onLine((line) => {
      this.handleLine(active, line);
    });
    const unsubscribeError = transport.onError((error) => {
      if (active.finished) return;
      active.protocolError = `helper transport error: ${error.message}`;
      active.signalDone();
    });
    const unsubscribeExit = transport.onExit((info) => {
      if (active.finished) return;
      active.exitInfo = info;
      active.signalDone();
    });

    const hello = encodeHostMessage(helloMessage(plan.requestId, generation));
    const sentHello = hello.ok
      ? transport.send(hello.line)
      : { ok: false, reason: hello.reason };
    if (!sentHello.ok) {
      active.protocolError = sentHello.reason ?? "could not send hello";
      active.signalDone();
    }

    await done;
    if (active.egress) this.settleEgress(active, active.egress);
    if (startTimer) clearTimeout(startTimer);
    if (deadlineTimer) clearTimeout(deadlineTimer);
    for (const timer of active.timers) clearTimeout(timer);
    active.timers.clear();
    task.signal?.removeEventListener("abort", onAbort);
    unsubscribeLine();
    unsubscribeError();
    unsubscribeExit();

    const outcome = outcomeFor(active);
    try {
      await transport.close(500);
    } catch {
      // The outcome already reflects any transport failure; cleanup continues.
    }
    this.active.delete(keyFor(plan));
    if (!active.validityRefusal) this.recordAsync(outcome);
    task.resolve(outcome);
    this.drain();
  }

  /**
   * Acquire the egress lease a `destinations` plan needs, then send the
   * business start. The lease is taken before the sandboxed process exists,
   * so a missing grant refuses the launch with nothing started.
   */
  private async acquireEgressAndSendStart(active: ActiveExecution): Promise<void> {
    const plan = active.task.plan;
    if (plan.network.kind === "destinations") {
      let grant: EgressGrantRef | null = null;
      try {
        grant = this.egress ? await this.egress.acquire(plan) : null;
      } catch {
        grant = null;
      }
      if (active.finished) {
        // Cancelled while the lease was being taken: drop it unused.
        if (grant) this.settleEgress(active, grant);
        return;
      }
      if (!grant) {
        active.rejected = {
          type: "rejected",
          requestId: plan.requestId,
          generation: active.generation,
          started: false,
          code: "unsupported",
          reason: "host egress service is unavailable for this destination plan",
        };
        active.signalDone();
        return;
      }
      active.egress = grant;
    }
    const start = encodeHostMessage({
      type: "start",
      requestId: plan.requestId,
      generation: active.generation,
      plan,
      ...(active.egress === undefined
        ? {}
        : {
            egress: {
              leaseId: active.egress.leaseId,
              proxyHost: active.egress.proxyHost,
              proxyPort: active.egress.proxyPort,
              credential: active.egress.credential,
            },
          }),
    });
    if (!start.ok) {
      active.protocolError = start.reason;
      active.signalDone();
      return;
    }
    active.startSent = true;
    const sent = active.transport.send(start.line);
    if (!sent.ok) {
      active.protocolError = sent.reason ?? "could not send start";
      active.signalDone();
    }
  }

  /** Revoke one egress lease once; repeated calls are no-ops. */
  private settleEgress(active: ActiveExecution, grant: EgressGrantRef): void {
    if (active.egressSettled) return;
    active.egressSettled = true;
    try {
      this.egress?.revoke(grant.leaseId);
    } catch {
      // Revocation is best-effort at settle; the proxy also expires leases.
    }
  }

  private handleLine(active: ActiveExecution, line: string): void {
    if (active.finished) return;
    if (active.messageCount >= MAX_HELPER_MESSAGES) {
      active.protocolError = "helper exceeded the message limit";
      active.signalDone();
      return;
    }
    active.messageCount += 1;
    const decoded: HelperDecodeResult = decodeHelperMessage(line);
    if (!decoded.ok) {
      active.protocolError = `invalid helper message: ${decoded.reason}`;
      this.beginCancel(active, "execution-cancelled", "protocol error");
      active.signalDone();
      return;
    }
    const message = decoded.message;
    if (message.type !== "error") {
      if (message.generation !== active.generation) return; // late, old generation
      if (message.requestId !== active.task.plan.requestId) {
        active.protocolError = "helper message correlation does not match the plan";
        active.signalDone();
        return;
      }
    } else if (
      message.generation !== undefined &&
      message.generation !== active.generation
    ) {
      return;
    }

    switch (message.type) {
      case "ready": {
        if (active.phase !== "handshake") {
          active.protocolError = "duplicate ready message";
          active.signalDone();
          return;
        }
        active.ready = message;
        if (
          !versionMatches(
            this.installation,
            message.protocolVersion,
            message.backend.version,
            message.backend.id,
          )
        ) {
          active.versionMismatch = `helper protocol ${message.protocolVersion} (backend ${message.backend.version}) does not match`;
          active.signalDone();
          return;
        }
        const gaps = capabilityGap(
          message.capabilities,
          requiredCapabilities(active.task.plan),
        );
        if (gaps.length > 0) {
          active.capabilityGap = gaps;
          active.signalDone();
          return;
        }
        // Handshake is a wait too. Re-reading the lease here is the last point
        // at which no business effect has happened; after the start is sent
        // the real state is at best unknown and can never be reported as
        // "never executed".
        const preStartRefusal = validityRefusal(active.task.validity);
        if (preStartRefusal) {
          active.validityRefusal = preStartRefusal;
          active.signalDone();
          return;
        }
        active.phase = "starting";
        void this.acquireEgressAndSendStart(active);
        return;
      }
      case "started": {
        if (active.phase !== "starting" || active.startedAck) {
          active.protocolError = "unexpected started message";
          active.signalDone();
          return;
        }
        active.phase = "running";
        active.startedAck = true;
        active.helperStarted = true;
        this.clearStartTimer(active);
        return;
      }
      case "output": {
        if (active.phase !== "running") {
          active.protocolError = "output before started";
          active.signalDone();
          return;
        }
        if (message.sequence !== active.nextSequence) {
          active.protocolError = `output sequence ${message.sequence} is out of order`;
          active.signalDone();
          return;
        }
        active.nextSequence += 1;
        const bytes = Buffer.byteLength(message.data, "utf8");
        if (message.stream === "stdout") {
          active.stdoutBytes += bytes;
          if (active.stdoutBytes > MAX_EXECUTION_STDOUT_BYTES) {
            active.outputLimit = true;
            this.beginCancel(active, "execution-cancelled", "stdout limit");
            return;
          }
          active.stdout += message.data;
        } else {
          active.stderrBytes += bytes;
          if (active.stderrBytes > MAX_EXECUTION_STDERR_BYTES) {
            active.outputLimit = true;
            this.beginCancel(active, "execution-cancelled", "stderr limit");
            return;
          }
          active.stderr += message.data;
        }
        try {
          active.task.onOutput?.({ stream: message.stream, data: message.data });
        } catch {
          // An observer must not break protocol processing or resource cleanup.
        }
        return;
      }
      case "result": {
        if (active.phase !== "running") {
          active.protocolError = "result before started";
          active.signalDone();
          return;
        }
        active.result = message;
        active.signalDone();
        return;
      }
      case "rejected": {
        if (active.phase !== "starting") {
          active.protocolError = "unexpected rejected message";
          active.signalDone();
          return;
        }
        active.rejected = message;
        active.helperStarted = false;
        active.signalDone();
        return;
      }
      case "cancelled": {
        active.cancelledByHelper = message;
        active.helperStarted = message.started;
        if (message.started === true) active.startedAck = true;
        active.signalDone();
        return;
      }
      case "error": {
        active.helperError = message;
        active.signalDone();
        return;
      }
    }
  }

  private clearStartTimer(active: ActiveExecution): void {
    if (!active.startTimer) return;
    clearTimeout(active.startTimer);
    active.timers.delete(active.startTimer);
    active.startTimer = undefined;
  }

  private beginCancel(
    active: ActiveExecution,
    code: CancellationCode,
    reason: string,
  ): void {
    if (active.finished) return;
    if (active.cancel) return;
    active.cancel = { code, reason };
    // Permission removal lands before the kill: the proxy refuses new
    // connections and drops live ones while the process tree is ending.
    if (active.egress) this.settleEgress(active, active.egress);
    if (!active.startSent) {
      active.signalDone();
      return;
    }
    if (!active.cancelSent) {
      const message = encodeHostMessage({
        type: "cancel",
        requestId: active.task.plan.requestId,
        generation: active.generation,
        reason: code,
      });
      if (message.ok) {
        active.transport.send(message.line);
        active.cancelSent = true;
      }
    }
    const force = setTimeout(() => {
      if (active.finished) return;
      active.transport.kill(0);
      active.signalDone();
    }, this.cancelGraceMs);
    force.unref?.();
    active.timers.add(force);
  }

  private record(outcome: ExecutionOutcome): void {
    try {
      this.onRecord?.(outcome.record);
    } catch {
      // Observation is separate from the execution result and its cleanup.
    }
  }

  private recordAsync(outcome: ExecutionOutcome): void {
    queueMicrotask(() => this.record(outcome));
  }
}
