/**
 * Intent barrier state machine (specs/project-rule-learning.md §2).
 *
 * Learned project rules start closed: the session has not proven that older
 * rules still describe the current conversation. A new user input advances the
 * intent revision and makes every pending reconciliation stale; a hidden model
 * run may then prove that the rules still apply. Only an installed
 * `still-applicable` (or a durable `persistent-revoke` / a proven narrow
 * own-commit) opens the gate, and a technical error never counts as proof.
 *
 * The class owns state and lifecycle only. The physical run, the durable revoke
 * and the audit sink are injected, and each run is driven by an explicit
 * ticket, so every transition is deterministic in tests. Completions are
 * idempotent: late, cancelled, disposed or superseded results are discarded and
 * can never change the gate.
 */
import type { ProjectRulesIntentBarrier } from "./service";
import type { ProjectRulesCommitGuard } from "./storage";

export type LearningBarrierOutcome = "still-applicable" | "current-task-paused" | "persistent-revoke";

export interface LearningBarrierRunContext {
  readonly revision: number;
  readonly signal: AbortSignal;
}

export interface LearningBarrierOptions {
  readonly learningEnabled: () => boolean;
  readonly run: (context: LearningBarrierRunContext) => Promise<LearningBarrierOutcome>;
  /** Durable revoke that must succeed before `persistent-revoke` opens the gate. */
  readonly durableRevoke?: (context: { readonly revision: number }) => Promise<boolean>;
  readonly audit?: (event: LearningBarrierAuditEvent) => void | Promise<void>;
  readonly maxLocalRuns?: number;
  readonly maxGlobalRuns?: number;
}

export type LearningBarrierAuditEvent = {
  readonly kind:
    | "run-started"
    | "run-finished"
    | "run-discarded"
    | "barrier-opened"
    | "current-task-paused"
    | "persistent-revoke-failed"
    | "own-commit-opened";
  readonly revision: number;
  readonly reason?: string;
};

export interface LearningBarrierTicket {
  readonly revision: number;
  readonly signal: AbortSignal;
  cancel(): void;
  complete(outcome: LearningBarrierOutcome): void;
}

/** At most two hidden requests per barrier over its whole lifetime. */
const DEFAULT_MAX_LOCAL_RUNS = 2;
/** At most eight hidden requests in flight across every barrier of the process. */
const DEFAULT_MAX_GLOBAL_RUNS = 8;
/** Sessions start needing reconciliation; each user input advances the revision. */
const INITIAL_INTENT_REVISION = 1;

/** Occupancy shared by every barrier instance in this module. */
let globalRunsInFlight = 0;

interface RunRecord {
  readonly revision: number;
  /** Intent epoch observed when the ticket was issued; a mismatch supersedes it. */
  readonly epoch: number;
  readonly controller: AbortController;
  readonly ticket: LearningBarrierTicket;
  cancelled: boolean;
  /** The physical run promise settled, either way. */
  finished: boolean;
  /** One completion was routed into the state machine for this ticket. */
  installStarted: boolean;
  installed: boolean;
  /** The global occupancy slot was returned. */
  released: boolean;
}

export class LearningIntentBarrier implements ProjectRulesIntentBarrier {
  private readonly learningEnabledHook: () => boolean;
  private readonly runHook: (context: LearningBarrierRunContext) => Promise<LearningBarrierOutcome>;
  private readonly durableRevokeHook: ((context: { readonly revision: number }) => Promise<boolean>) | undefined;
  private readonly auditHook: ((event: LearningBarrierAuditEvent) => void | Promise<void>) | undefined;
  private readonly maxLocalRuns: number;
  private readonly maxGlobalRuns: number;

  private intentRevision = INITIAL_INTENT_REVISION;
  private needsReconciliationFlag = true;
  /** Revision the current-task pause still applies to; older revisions never count. */
  private pausedRevision: number | undefined;
  /** Last revision whose intent was proven reconciled (spec §2 state). */
  private lastReconciledRevision: number | undefined;
  /**
   * Revision/epoch the last issued ticket observed. `recordOwnCommit` compares
   * them so a narrow own transaction cannot open the gate after newer input.
   */
  private observedRevision = INITIAL_INTENT_REVISION;
  private observedEpoch = 0;
  /** Bumped when the observed intent is invalidated without a revision change. */
  private intentEpoch = 0;
  private disposed = false;
  private currentTicket: RunRecord | undefined;
  private localRunsStarted = 0;
  private readonly activeRuns = new Set<RunRecord>();

  constructor(options: LearningBarrierOptions) {
    this.learningEnabledHook = options.learningEnabled;
    this.runHook = options.run;
    this.durableRevokeHook = options.durableRevoke;
    this.auditHook = options.audit;
    this.maxLocalRuns = options.maxLocalRuns ?? DEFAULT_MAX_LOCAL_RUNS;
    this.maxGlobalRuns = options.maxGlobalRuns ?? DEFAULT_MAX_GLOBAL_RUNS;
  }

  get revision(): number {
    return this.intentRevision;
  }

  needsReconciliation(): boolean {
    return this.needsReconciliationFlag;
  }

  currentTaskPaused(): boolean {
    // A pause is bound to the revision that produced it: after new input the
    // old pause no longer applies.
    return this.pausedRevision !== undefined && this.pausedRevision === this.intentRevision;
  }

  learningDisabled(): boolean {
    return this.disposed || !this.learningEnabledHook();
  }

  holdsRevision(revision: number): ProjectRulesCommitGuard {
    // Observing a revision is also what a later `recordOwnCommit` matches: the
    // store re-checks the guard before publishing, so this is the revision the
    // caller based its transaction on.
    this.observedRevision = revision;
    this.observedEpoch = this.intentEpoch;
    return Object.freeze({
      isCurrent: () => !this.disposed && this.intentRevision === revision,
    });
  }

  recordUserInput(): number {
    if (this.disposed) return this.intentRevision;
    this.intentRevision += 1;
    this.intentEpoch += 1;
    this.needsReconciliationFlag = true;
    this.invalidateCurrentTicket();
    return this.intentRevision;
  }

  requireReconciliation(): void {
    if (this.disposed) return;
    this.needsReconciliationFlag = true;
    this.intentEpoch += 1;
    // The in-flight answer was computed from facts that just became invalid.
    this.invalidateCurrentTicket();
  }

  begin(requestedRevision?: number): LearningBarrierTicket | undefined {
    if (this.disposed) return undefined;
    if (requestedRevision !== undefined && requestedRevision !== this.intentRevision) return undefined;

    const existing = this.currentTicket;
    if (existing !== undefined && existing.revision === this.intentRevision) return existing.ticket;
    if (!this.learningEnabledHook()) return undefined;
    if (this.localRunsStarted >= this.maxLocalRuns) return undefined;
    if (globalRunsInFlight >= this.maxGlobalRuns) return undefined;

    const revision = this.intentRevision;
    const epoch = this.intentEpoch;
    const controller = new AbortController();
    let record!: RunRecord;
    const ticket: LearningBarrierTicket = Object.freeze({
      revision,
      signal: controller.signal,
      cancel: () => this.cancelRecord(record),
      complete: (outcome: LearningBarrierOutcome) => this.completeTicket(record, outcome),
    });
    record = {
      revision,
      epoch,
      controller,
      ticket,
      cancelled: false,
      finished: false,
      installStarted: false,
      installed: false,
      released: false,
    };

    this.localRunsStarted += 1;
    globalRunsInFlight += 1;
    this.activeRuns.add(record);
    this.currentTicket = record;
    this.observedRevision = revision;
    this.observedEpoch = this.intentEpoch;

    this.emit("run-started", revision);
    try {
      const outcome = this.runHook({ revision, signal: controller.signal });
      void Promise.resolve(outcome).then(
        (value) => this.finishRun(record, value),
        () => this.failRun(record),
      );
    } catch {
      // A synchronous throw is a technical error, not a proven intent.
      this.failRun(record);
    }
    return ticket;
  }

  recordOwnCommit(): boolean {
    if (this.disposed) return false;
    if (this.observedRevision !== this.intentRevision || this.observedEpoch !== this.intentEpoch) return false;

    // The own transaction proves the current revision for the rules it touched;
    // an older reconciliation is moot.
    this.invalidateCurrentTicket();
    this.needsReconciliationFlag = false;
    this.pausedRevision = undefined;
    this.lastReconciledRevision = this.intentRevision;
    this.emit("own-commit-opened", this.intentRevision);
    return true;
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.currentTicket = undefined;
    for (const record of [...this.activeRuns]) {
      record.cancelled = true;
      record.controller.abort();
      // Disposal ends the logical run; the slot must not leak if the physical
      // request never settles.
      this.releaseRun(record);
    }
  }

  /** Test seam: how many physical runs are in flight across all barriers. */
  pendingRuns(): number {
    return globalRunsInFlight;
  }

  // -------------------------------------------------------------------------
  // Completion plumbing
  // -------------------------------------------------------------------------

  private finishRun(record: RunRecord, outcome: LearningBarrierOutcome): void {
    record.finished = true;
    this.releaseRun(record);
    this.emit("run-finished", record.revision, outcome);
    if (!this.canInstall(record)) {
      this.emit("run-discarded", record.revision, this.staleReason(record));
      return;
    }
    if (record.installStarted) {
      // A manual completion already supplied the result for this ticket.
      this.emit("run-discarded", record.revision, "already-completed");
      return;
    }
    this.install(record, outcome);
  }

  private failRun(record: RunRecord): void {
    record.finished = true;
    this.releaseRun(record);
    this.emit("run-finished", record.revision, "error");
    // A technical error proves nothing: reconciliation stays open and the caller
    // may retry the same revision with the remaining run budget.
    if (this.currentTicket === record) this.currentTicket = undefined;
  }

  private completeTicket(record: RunRecord, outcome: LearningBarrierOutcome): void {
    if (record.installStarted) {
      this.emit("run-discarded", record.revision, "already-completed");
      return;
    }
    if (!this.canInstall(record)) {
      this.emit("run-discarded", record.revision, this.staleReason(record));
      return;
    }
    if (record.finished) {
      this.emit("run-discarded", record.revision, "already-finished");
      return;
    }
    this.install(record, outcome);
  }

  private install(record: RunRecord, outcome: LearningBarrierOutcome): void {
    record.installStarted = true;
    switch (outcome) {
      case "still-applicable":
        record.installed = true;
        this.needsReconciliationFlag = false;
        this.pausedRevision = undefined;
        this.lastReconciledRevision = record.revision;
        this.emit("barrier-opened", record.revision, "still-applicable");
        return;
      case "current-task-paused":
        record.installed = true;
        this.needsReconciliationFlag = false;
        this.pausedRevision = record.revision;
        this.lastReconciledRevision = record.revision;
        this.emit("current-task-paused", record.revision);
        return;
      case "persistent-revoke":
        // The durable revoke is asynchronous, so the gate must stay closed until
        // it actually succeeds.
        void this.installPersistentRevoke(record);
        return;
    }
  }

  private async installPersistentRevoke(record: RunRecord): Promise<void> {
    if (!this.canInstall(record)) {
      this.emit("run-discarded", record.revision, this.staleReason(record));
      return;
    }
    const durableRevoke = this.durableRevokeHook;
    if (durableRevoke === undefined) {
      this.emit("persistent-revoke-failed", record.revision, "missing-durable-revoke");
      return;
    }

    let revoked: boolean;
    try {
      revoked = await durableRevoke({ revision: record.revision });
    } catch {
      this.emit("persistent-revoke-failed", record.revision, "error");
      return;
    }
    if (!revoked) {
      this.emit("persistent-revoke-failed", record.revision, "declined");
      return;
    }
    // New input, a plain reconciliation request or dispose may have landed
    // while the durable revoke was running; the result is then discarded.
    if (!this.canInstall(record)) {
      this.emit("run-discarded", record.revision, this.staleReason(record));
      return;
    }
    record.installed = true;
    this.needsReconciliationFlag = false;
    this.pausedRevision = undefined;
    this.lastReconciledRevision = record.revision;
    this.emit("barrier-opened", record.revision, "persistent-revoke");
  }

  // -------------------------------------------------------------------------
  // Cancellation, staleness and accounting
  // -------------------------------------------------------------------------

  private cancelRecord(record: RunRecord): void {
    record.cancelled = true;
    record.controller.abort();
    // The spec returns the run count for cancellations too: a cancelled ticket is
    // logically finished even when the physical request is still winding down.
    this.releaseRun(record);
    if (this.currentTicket === record) this.currentTicket = undefined;
  }

  private invalidateCurrentTicket(): void {
    const record = this.currentTicket;
    if (record === undefined) return;
    this.currentTicket = undefined;
    this.cancelRecord(record);
  }

  private canInstall(record: RunRecord): boolean {
    return (
      !this.disposed &&
      !record.cancelled &&
      record.revision === this.intentRevision &&
      record.epoch === this.intentEpoch &&
      !record.installed
    );
  }

  private staleReason(record: RunRecord): string {
    if (this.disposed) return "disposed";
    if (record.cancelled) return "cancelled";
    if (record.revision !== this.intentRevision) return "revision-changed";
    if (record.epoch !== this.intentEpoch) return "superseded";
    if (record.installed) return "already-completed";
    return "stale";
  }

  private releaseRun(record: RunRecord): void {
    if (record.released) return;
    record.released = true;
    globalRunsInFlight = Math.max(0, globalRunsInFlight - 1);
    this.activeRuns.delete(record);
  }

  private emit(kind: LearningBarrierAuditEvent["kind"], revision: number, reason?: string): void {
    const audit = this.auditHook;
    if (audit === undefined) return;
    const event: LearningBarrierAuditEvent = reason === undefined ? { kind, revision } : { kind, revision, reason };
    try {
      const result = audit(event);
      if (result !== undefined) void Promise.resolve(result).catch(() => undefined);
    } catch {
      // An audit failure must never change barrier state or an outcome.
    }
  }
}
