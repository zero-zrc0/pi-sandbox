import { afterEach, describe, expect, it } from "vitest";
import {
  LearningIntentBarrier,
  type LearningBarrierAuditEvent,
  type LearningBarrierOutcome,
  type LearningBarrierRunContext,
  type LearningBarrierTicket,
} from "#approve-core/policy/project-rules/barrier";
import type { ProjectRulesIntentBarrier } from "#approve-core/policy/project-rules/service";
import type { ProjectRulesCommitGuard } from "#approve-core/policy/project-rules/storage";

// The initial revision is an implementation detail that the service only ever
// compares for equality; fix it here so the contract stays observable.
const INITIAL_REVISION = 1;

// ---------------------------------------------------------------------------
// Controllable run promise seam
// ---------------------------------------------------------------------------

interface Deferred<T> {
  readonly promise: Promise<T>;
  resolve(value: T): void;
  reject(error?: unknown): void;
}

function deferred<T>(): Deferred<T> {
  let settle!: (value: T) => void;
  let fail!: (error?: unknown) => void;
  const promise = new Promise<T>((resolve, reject) => {
    settle = resolve;
    fail = reject;
  });
  return { promise, resolve: settle, reject: fail };
}

/** Drain the promise microtask queue without depending on timers. */
async function flush(times = 6): Promise<void> {
  for (let index = 0; index < times; index += 1) await Promise.resolve();
}

interface PendingRun {
  readonly context: LearningBarrierRunContext;
  readonly outcome: Deferred<LearningBarrierOutcome>;
  settled: boolean;
}

interface FixtureOptions {
  readonly maxLocalRuns?: number;
  readonly maxGlobalRuns?: number;
  readonly omitDurableRevoke?: boolean;
}

const fixtures: Fixture[] = [];

class Fixture {
  enabled = true;
  auditThrows = false;
  auditRejects = false;
  durableRevokeImpl: (context: { readonly revision: number }) => Promise<boolean> = async () => false;
  readonly events: LearningBarrierAuditEvent[] = [];
  readonly runs: PendingRun[] = [];
  readonly durableRevokeCalls: Array<{ readonly revision: number }> = [];
  readonly cleanup: Array<() => void> = [];
  readonly barrier: LearningIntentBarrier;

  constructor(options: FixtureOptions = {}) {
    this.barrier = new LearningIntentBarrier({
      learningEnabled: () => this.enabled,
      run: (context) => {
        const outcome = deferred<LearningBarrierOutcome>();
        this.runs.push({ context, outcome, settled: false });
        return outcome.promise;
      },
      audit: (event) => {
        this.events.push(event);
        if (this.auditThrows) throw new Error("audit failure");
        if (this.auditRejects) return Promise.reject(new Error("audit rejection"));
        return undefined;
      },
      ...(options.omitDurableRevoke
        ? {}
        : {
            durableRevoke: (context: { readonly revision: number }) => {
              this.durableRevokeCalls.push({ revision: context.revision });
              return this.durableRevokeImpl(context);
            },
          }),
      ...(options.maxLocalRuns === undefined ? {} : { maxLocalRuns: options.maxLocalRuns }),
      ...(options.maxGlobalRuns === undefined ? {} : { maxGlobalRuns: options.maxGlobalRuns }),
    });
  }

  get runCount(): number {
    return this.runs.length;
  }

  runAt(index: number): PendingRun {
    const run = this.runs[index];
    if (run === undefined) throw new Error(`missing run ${index}`);
    return run;
  }

  settle(index: number, outcome: LearningBarrierOutcome): void {
    const run = this.runAt(index);
    if (run.settled) throw new Error(`run ${index} already settled`);
    run.settled = true;
    run.outcome.resolve(outcome);
  }

  fail(index: number, error: unknown = new Error("model unavailable")): void {
    const run = this.runAt(index);
    if (run.settled) throw new Error(`run ${index} already settled`);
    run.settled = true;
    run.outcome.reject(error);
  }

  async settleAndFlush(index: number, outcome: LearningBarrierOutcome): Promise<void> {
    this.settle(index, outcome);
    await flush();
  }

  async failAndFlush(index: number, error?: unknown): Promise<void> {
    this.fail(index, error);
    await flush();
  }

  /** Durable-revoke gate the afterEach hook can always release. */
  manualDurableRevoke(): Deferred<boolean> {
    const gate = deferred<boolean>();
    this.durableRevokeImpl = () => gate.promise;
    this.cleanup.push(() => gate.resolve(true));
    return gate;
  }

  kinds(): string[] {
    return this.events.map((event) => event.kind);
  }

  revisionOfKinds(kind: LearningBarrierAuditEvent["kind"]): number[] {
    return this.events.filter((event) => event.kind === kind).map((event) => event.revision);
  }
}

function createFixture(options: FixtureOptions = {}): Fixture {
  const fixture = new Fixture(options);
  fixtures.push(fixture);
  return fixture;
}

afterEach(async () => {
  // Never leak the module-global run occupancy into the next test.
  for (const fixture of fixtures) {
    fixture.barrier.dispose();
    for (const run of fixture.runs) {
      if (run.settled) continue;
      run.settled = true;
      run.outcome.resolve("still-applicable");
    }
    for (const release of fixture.cleanup) release();
  }
  fixtures.length = 0;
  await flush(10);
});

// ---------------------------------------------------------------------------
// Initial state and the learning switch
// ---------------------------------------------------------------------------

describe("initial state", () => {
  it("requires reconciliation until an intent run proves the rules still apply", () => {
    const fixture = createFixture();
    expect(fixture.barrier.revision).toBe(INITIAL_REVISION);
    expect(fixture.barrier.needsReconciliation()).toBe(true);
    expect(fixture.barrier.currentTaskPaused()).toBe(false);
    expect(fixture.barrier.learningDisabled()).toBe(false);
    expect(fixture.barrier.pendingRuns()).toBe(0);
    expect(fixture.runCount).toBe(0);
  });

  it("starts no hidden run while learning is disabled", () => {
    const fixture = createFixture();
    fixture.enabled = false;
    expect(fixture.barrier.learningDisabled()).toBe(true);
    expect(fixture.barrier.begin()).toBeUndefined();
    expect(fixture.runCount).toBe(0);
    expect(fixture.barrier.needsReconciliation()).toBe(true);
  });

  it("starts no hidden run for an explicit revision while learning is disabled", () => {
    const fixture = createFixture();
    fixture.enabled = false;
    expect(fixture.barrier.begin(fixture.barrier.revision)).toBeUndefined();
    expect(fixture.runCount).toBe(0);
  });

  it("starts running once learning is enabled again", () => {
    const fixture = createFixture();
    fixture.enabled = false;
    expect(fixture.barrier.begin()).toBeUndefined();
    fixture.enabled = true;
    expect(fixture.barrier.begin()?.revision).toBe(INITIAL_REVISION);
    expect(fixture.runCount).toBe(1);
  });

  it("reports learning disabled after dispose", () => {
    const fixture = createFixture();
    fixture.barrier.dispose();
    expect(fixture.barrier.learningDisabled()).toBe(true);
    expect(fixture.barrier.begin()).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// begin: reuse, revisions and explicit requests
// ---------------------------------------------------------------------------

describe("begin", () => {
  it("starts one physical run bound to the current revision with an active signal", () => {
    const fixture = createFixture();
    const ticket = fixture.barrier.begin();
    expect(ticket).toBeDefined();
    expect(ticket?.revision).toBe(INITIAL_REVISION);
    expect(ticket?.signal.aborted).toBe(false);
    expect(fixture.runCount).toBe(1);
    expect(fixture.runAt(0).context.revision).toBe(INITIAL_REVISION);
    expect(fixture.runAt(0).context.signal).toBe(ticket?.signal);
    expect(fixture.barrier.pendingRuns()).toBe(1);
    expect(fixture.revisionOfKinds("run-started")).toEqual([INITIAL_REVISION]);
  });

  it("returns the existing ticket for the same revision instead of starting another run", () => {
    const fixture = createFixture();
    const first = fixture.barrier.begin();
    const second = fixture.barrier.begin();
    expect(second).toBe(first);
    expect(fixture.runCount).toBe(1);
  });

  it("keeps returning the installed ticket for the same revision", () => {
    const fixture = createFixture();
    const ticket = fixture.barrier.begin() as LearningBarrierTicket;
    ticket.complete("still-applicable");
    expect(fixture.barrier.begin()).toBe(ticket);
    expect(fixture.runCount).toBe(1);
  });

  it("refuses an explicitly stale revision", () => {
    const fixture = createFixture();
    fixture.barrier.recordUserInput();
    expect(fixture.barrier.begin(fixture.barrier.revision - 1)).toBeUndefined();
    expect(fixture.runCount).toBe(0);
  });

  it("accepts an explicitly current revision", () => {
    const fixture = createFixture();
    expect(fixture.barrier.begin(fixture.barrier.revision)).not.toBeUndefined();
    expect(fixture.runCount).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// User input and plain reconciliation requests
// ---------------------------------------------------------------------------

describe("recordUserInput", () => {
  it("bumps the revision, reopens reconciliation and aborts the in-flight ticket", async () => {
    const fixture = createFixture();
    const ticket = fixture.barrier.begin() as LearningBarrierTicket;
    const revision = fixture.barrier.recordUserInput();
    expect(revision).toBe(INITIAL_REVISION + 1);
    expect(fixture.barrier.revision).toBe(INITIAL_REVISION + 1);
    expect(fixture.barrier.needsReconciliation()).toBe(true);
    expect(ticket.signal.aborted).toBe(true);

    await fixture.settleAndFlush(0, "still-applicable");
    expect(fixture.barrier.needsReconciliation()).toBe(true);
    expect(fixture.kinds()).toContain("run-discarded");
    expect(fixture.kinds()).not.toContain("barrier-opened");
  });

  it("starts a fresh run for the new revision", () => {
    const fixture = createFixture();
    fixture.barrier.begin();
    const revision = fixture.barrier.recordUserInput();
    const ticket = fixture.barrier.begin();
    expect(ticket?.revision).toBe(revision);
    expect(fixture.runCount).toBe(2);
    expect(fixture.runAt(1).context.revision).toBe(revision);
  });

  it("does not restart the cancelled revision", () => {
    const fixture = createFixture();
    fixture.barrier.begin();
    fixture.barrier.recordUserInput();
    expect(fixture.barrier.begin(INITIAL_REVISION)).toBeUndefined();
    expect(fixture.runCount).toBe(1);
  });

  it("discards a late completion that arrives after new input", async () => {
    const fixture = createFixture();
    const ticket = fixture.barrier.begin() as LearningBarrierTicket;
    fixture.barrier.recordUserInput();
    ticket.complete("still-applicable");
    await flush();
    expect(fixture.barrier.needsReconciliation()).toBe(true);
    expect(fixture.revisionOfKinds("run-discarded")).toEqual([INITIAL_REVISION]);
  });
});

describe("requireReconciliation", () => {
  it("keeps the revision and invalidates the in-flight run", async () => {
    const fixture = createFixture();
    const first = fixture.barrier.begin() as LearningBarrierTicket;
    fixture.barrier.requireReconciliation();
    expect(fixture.barrier.revision).toBe(INITIAL_REVISION);
    expect(fixture.barrier.needsReconciliation()).toBe(true);
    expect(first.signal.aborted).toBe(true);

    const retry = fixture.barrier.begin();
    expect(retry).not.toBeUndefined();
    expect(retry).not.toBe(first);
    expect(fixture.runCount).toBe(2);

    await fixture.settleAndFlush(0, "still-applicable");
    expect(fixture.barrier.needsReconciliation()).toBe(true);
    await fixture.settleAndFlush(1, "still-applicable");
    expect(fixture.barrier.needsReconciliation()).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Local and global run budgets
// ---------------------------------------------------------------------------

describe("run limits", () => {
  it("bounds one barrier to two physical runs for its whole lifetime", () => {
    const fixture = createFixture();
    fixture.barrier.begin();
    fixture.barrier.recordUserInput();
    fixture.barrier.begin();
    fixture.barrier.recordUserInput();
    expect(fixture.barrier.begin()).toBeUndefined();
    expect(fixture.runCount).toBe(2);
  });

  it("honours a custom local run budget", () => {
    const fixture = createFixture({ maxLocalRuns: 3 });
    fixture.barrier.begin();
    fixture.barrier.recordUserInput();
    fixture.barrier.begin();
    fixture.barrier.recordUserInput();
    fixture.barrier.begin();
    fixture.barrier.recordUserInput();
    expect(fixture.barrier.begin()).toBeUndefined();
    expect(fixture.runCount).toBe(3);
  });

  it("returns the global slot when a run finishes", async () => {
    const owner = createFixture({ maxGlobalRuns: 1 });
    owner.barrier.begin();
    expect(owner.barrier.pendingRuns()).toBe(1);

    const blocked = createFixture({ maxGlobalRuns: 1 });
    expect(blocked.barrier.begin()).toBeUndefined();

    await owner.settleAndFlush(0, "still-applicable");
    expect(owner.barrier.pendingRuns()).toBe(0);
    expect(blocked.barrier.begin()).not.toBeUndefined();
  });

  it("returns the global slot when a run fails", async () => {
    const owner = createFixture({ maxGlobalRuns: 1 });
    owner.barrier.begin();
    await owner.failAndFlush(0);
    expect(owner.barrier.pendingRuns()).toBe(0);
    const other = createFixture({ maxGlobalRuns: 1 });
    expect(other.barrier.begin()).not.toBeUndefined();
  });

  it("returns the global slot as soon as a ticket is cancelled", async () => {
    const owner = createFixture({ maxGlobalRuns: 1 });
    const ticket = owner.barrier.begin() as LearningBarrierTicket;
    expect(owner.barrier.pendingRuns()).toBe(1);

    ticket.cancel();
    expect(owner.barrier.pendingRuns()).toBe(0);
    const other = createFixture({ maxGlobalRuns: 1 });
    expect(other.barrier.begin()).not.toBeUndefined();

    // A late settlement of the cancelled run must not release the slot twice.
    await owner.settleAndFlush(0, "still-applicable");
    expect(other.barrier.pendingRuns()).toBe(1);
  });

  it("returns the global slot when a barrier with a run in flight is disposed", () => {
    const owner = createFixture({ maxGlobalRuns: 1 });
    owner.barrier.begin();
    expect(owner.barrier.pendingRuns()).toBe(1);
    owner.barrier.dispose();
    expect(owner.barrier.pendingRuns()).toBe(0);
  });

  it("allows at most eight concurrent runs across every barrier by default", async () => {
    const eight = Array.from({ length: 8 }, () => createFixture());
    for (const fixture of eight) {
      expect(fixture.barrier.begin()).not.toBeUndefined();
    }
    expect(eight[0]?.barrier.pendingRuns()).toBe(8);

    const ninth = createFixture();
    expect(ninth.barrier.begin()).toBeUndefined();

    await eight[0]?.settleAndFlush(0, "still-applicable");
    expect(ninth.barrier.pendingRuns()).toBe(7);
    expect(ninth.barrier.begin()).not.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Installed outcomes
// ---------------------------------------------------------------------------

describe("barrier outcomes", () => {
  it("opens the barrier when the run proves the intent still applies", async () => {
    const fixture = createFixture();
    fixture.barrier.begin();
    await fixture.settleAndFlush(0, "still-applicable");
    expect(fixture.barrier.needsReconciliation()).toBe(false);
    expect(fixture.barrier.currentTaskPaused()).toBe(false);
    expect(fixture.revisionOfKinds("barrier-opened")).toEqual([INITIAL_REVISION]);
    expect(fixture.revisionOfKinds("run-finished")).toEqual([INITIAL_REVISION]);
    expect(fixture.barrier.pendingRuns()).toBe(0);
  });

  it("pauses only the revision that the run observed", async () => {
    const fixture = createFixture();
    fixture.barrier.begin();
    await fixture.settleAndFlush(0, "current-task-paused");
    expect(fixture.barrier.needsReconciliation()).toBe(false);
    expect(fixture.barrier.currentTaskPaused()).toBe(true);
    expect(fixture.revisionOfKinds("current-task-paused")).toEqual([INITIAL_REVISION]);

    const next = fixture.barrier.recordUserInput();
    expect(next).toBe(INITIAL_REVISION + 1);
    expect(fixture.barrier.currentTaskPaused()).toBe(false);
    expect(fixture.barrier.needsReconciliation()).toBe(true);
  });

  it("keeps reconciliation open after a technical run failure", async () => {
    const fixture = createFixture();
    fixture.barrier.begin();
    await fixture.failAndFlush(0);
    expect(fixture.barrier.needsReconciliation()).toBe(true);
    expect(fixture.barrier.pendingRuns()).toBe(0);
    expect(fixture.revisionOfKinds("run-finished")).toEqual([INITIAL_REVISION]);

    const retry = fixture.barrier.begin();
    expect(retry).not.toBeUndefined();
    expect(fixture.runCount).toBe(2);
  });

  it("discards a completion delivered after a technical failure", async () => {
    const fixture = createFixture();
    const ticket = fixture.barrier.begin() as LearningBarrierTicket;
    await fixture.failAndFlush(0);
    ticket.complete("still-applicable");
    await flush();
    expect(fixture.barrier.needsReconciliation()).toBe(true);
    expect(fixture.kinds()).toContain("run-discarded");
  });
});

// ---------------------------------------------------------------------------
// persistent-revoke must be durable first
// ---------------------------------------------------------------------------

describe("persistent revoke", () => {
  it("awaits the durable revoke before opening the barrier", async () => {
    const fixture = createFixture();
    const gate = fixture.manualDurableRevoke();
    const ticket = fixture.barrier.begin() as LearningBarrierTicket;
    ticket.complete("persistent-revoke");
    await flush();
    expect(fixture.durableRevokeCalls).toEqual([{ revision: INITIAL_REVISION }]);
    expect(fixture.barrier.needsReconciliation()).toBe(true);

    gate.resolve(true);
    await flush();
    expect(fixture.barrier.needsReconciliation()).toBe(false);
    expect(fixture.revisionOfKinds("barrier-opened")).toEqual([INITIAL_REVISION]);
  });

  it("keeps the barrier closed when the durable revoke declines", async () => {
    const fixture = createFixture();
    fixture.durableRevokeImpl = async () => false;
    const ticket = fixture.barrier.begin() as LearningBarrierTicket;
    ticket.complete("persistent-revoke");
    await flush();
    expect(fixture.barrier.needsReconciliation()).toBe(true);
    expect(fixture.kinds()).toContain("persistent-revoke-failed");
    expect(fixture.kinds()).not.toContain("barrier-opened");
  });

  it("keeps the barrier closed when the durable revoke throws", async () => {
    const fixture = createFixture();
    fixture.durableRevokeImpl = async () => {
      throw new Error("io failure");
    };
    const ticket = fixture.barrier.begin() as LearningBarrierTicket;
    ticket.complete("persistent-revoke");
    await flush();
    expect(fixture.barrier.needsReconciliation()).toBe(true);
    expect(fixture.kinds()).toContain("persistent-revoke-failed");
  });

  it("keeps the barrier closed when no durable revoke is configured", async () => {
    const fixture = createFixture({ omitDurableRevoke: true });
    const ticket = fixture.barrier.begin() as LearningBarrierTicket;
    ticket.complete("persistent-revoke");
    await flush();
    expect(fixture.barrier.needsReconciliation()).toBe(true);
    expect(fixture.kinds()).toContain("persistent-revoke-failed");
  });

  it("opens from a physical run that returns persistent-revoke", async () => {
    const fixture = createFixture();
    fixture.durableRevokeImpl = async () => true;
    fixture.barrier.begin();
    await fixture.settleAndFlush(0, "persistent-revoke");
    expect(fixture.durableRevokeCalls).toEqual([{ revision: INITIAL_REVISION }]);
    expect(fixture.barrier.needsReconciliation()).toBe(false);
  });

  it("discards a durable revoke that completes after new user input", async () => {
    const fixture = createFixture();
    const gate = fixture.manualDurableRevoke();
    const ticket = fixture.barrier.begin() as LearningBarrierTicket;
    ticket.complete("persistent-revoke");
    await flush();

    fixture.barrier.recordUserInput();
    gate.resolve(true);
    await flush();
    expect(fixture.barrier.needsReconciliation()).toBe(true);
    expect(fixture.kinds()).toContain("run-discarded");
    expect(fixture.kinds()).not.toContain("barrier-opened");
  });

  it("discards a durable revoke that resolves after dispose", async () => {
    const fixture = createFixture();
    const gate = fixture.manualDurableRevoke();
    const ticket = fixture.barrier.begin() as LearningBarrierTicket;
    ticket.complete("persistent-revoke");
    await flush();

    fixture.barrier.dispose();
    gate.resolve(true);
    await flush();
    expect(fixture.kinds()).toContain("run-discarded");
    expect(fixture.kinds()).not.toContain("barrier-opened");
  });
});

// ---------------------------------------------------------------------------
// Ticket lifecycle: install once, discard stale results
// ---------------------------------------------------------------------------

describe("ticket completion", () => {
  it("installs a completion once and ignores later completions", () => {
    const fixture = createFixture();
    const ticket = fixture.barrier.begin() as LearningBarrierTicket;
    ticket.complete("still-applicable");
    expect(fixture.barrier.needsReconciliation()).toBe(false);

    ticket.complete("current-task-paused");
    expect(fixture.barrier.currentTaskPaused()).toBe(false);
    expect(fixture.barrier.needsReconciliation()).toBe(false);
    expect(fixture.kinds()).toContain("run-discarded");
  });

  it("discards a completion after dispose", async () => {
    const fixture = createFixture();
    const ticket = fixture.barrier.begin() as LearningBarrierTicket;
    fixture.barrier.dispose();
    ticket.complete("still-applicable");
    await flush();
    expect(fixture.kinds()).toContain("run-discarded");
    expect(fixture.kinds()).not.toContain("barrier-opened");
  });

  it("cancels the ticket idempotently and allows a retry for the same revision", () => {
    const fixture = createFixture();
    const ticket = fixture.barrier.begin() as LearningBarrierTicket;
    ticket.cancel();
    ticket.cancel();
    expect(ticket.signal.aborted).toBe(true);

    const retry = fixture.barrier.begin();
    expect(retry).not.toBe(ticket);
    expect(fixture.runCount).toBe(2);
  });
});

describe("out of order completion", () => {
  it("keeps the newest revision outcome when results arrive out of order", async () => {
    const fixture = createFixture({ maxLocalRuns: 3 });
    fixture.barrier.begin();
    fixture.barrier.recordUserInput();
    fixture.barrier.begin();

    await fixture.settleAndFlush(1, "still-applicable");
    expect(fixture.barrier.needsReconciliation()).toBe(false);

    await fixture.settleAndFlush(0, "current-task-paused");
    expect(fixture.barrier.needsReconciliation()).toBe(false);
    expect(fixture.barrier.currentTaskPaused()).toBe(false);
    expect(fixture.revisionOfKinds("run-discarded")).toEqual([INITIAL_REVISION]);
  });
});

// ---------------------------------------------------------------------------
// Currentness guard consumed by the store
// ---------------------------------------------------------------------------

describe("holdsRevision", () => {
  it("reports current only for the live revision", () => {
    const fixture = createFixture();
    const revision = fixture.barrier.revision;
    const guard: ProjectRulesCommitGuard = fixture.barrier.holdsRevision(revision);
    expect(guard.isCurrent()).toBe(true);
    expect(fixture.barrier.holdsRevision(revision + 1).isCurrent()).toBe(false);
  });

  it("turns stale after new user input", () => {
    const fixture = createFixture();
    const revision = fixture.barrier.revision;
    const guard = fixture.barrier.holdsRevision(revision);
    fixture.barrier.recordUserInput();
    expect(guard.isCurrent()).toBe(false);
  });

  it("turns stale after dispose", () => {
    const fixture = createFixture();
    const revision = fixture.barrier.revision;
    const guard = fixture.barrier.holdsRevision(revision);
    fixture.barrier.dispose();
    expect(guard.isCurrent()).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Own-commit fast path
// ---------------------------------------------------------------------------

describe("recordOwnCommit", () => {
  it("opens the barrier for the current intent revision", () => {
    const fixture = createFixture();
    expect(fixture.barrier.recordOwnCommit()).toBe(true);
    expect(fixture.barrier.needsReconciliation()).toBe(false);
    expect(fixture.barrier.currentTaskPaused()).toBe(false);
    expect(fixture.revisionOfKinds("own-commit-opened")).toEqual([INITIAL_REVISION]);
  });

  it("refuses after a newer user input was observed", () => {
    const fixture = createFixture();
    fixture.barrier.recordUserInput();
    expect(fixture.barrier.recordOwnCommit()).toBe(false);
    expect(fixture.barrier.needsReconciliation()).toBe(true);
  });

  it("opens again once a ticket observed the new revision", () => {
    const fixture = createFixture();
    fixture.barrier.recordUserInput();
    fixture.barrier.begin();
    expect(fixture.barrier.recordOwnCommit()).toBe(true);
    expect(fixture.barrier.needsReconciliation()).toBe(false);
  });

  it("matches the revision observed through holdsRevision", () => {
    const fixture = createFixture();
    fixture.barrier.recordUserInput();
    const revision = fixture.barrier.revision;
    fixture.barrier.holdsRevision(revision);
    expect(fixture.barrier.recordOwnCommit()).toBe(true);
    expect(fixture.barrier.needsReconciliation()).toBe(false);
  });

  it("refuses when the observed revision changed while the commit was pending", () => {
    const fixture = createFixture();
    const revision = fixture.barrier.revision;
    fixture.barrier.holdsRevision(revision);
    fixture.barrier.recordUserInput();
    expect(fixture.barrier.recordOwnCommit()).toBe(false);
    expect(fixture.barrier.needsReconciliation()).toBe(true);
  });

  it("refuses after requireReconciliation invalidated the observation", () => {
    const fixture = createFixture();
    fixture.barrier.begin();
    fixture.barrier.requireReconciliation();
    expect(fixture.barrier.recordOwnCommit()).toBe(false);
    expect(fixture.barrier.needsReconciliation()).toBe(true);
  });

  it("cancels an in-flight reconciliation when it opens the barrier", async () => {
    const fixture = createFixture();
    const ticket = fixture.barrier.begin() as LearningBarrierTicket;
    expect(ticket.signal.aborted).toBe(false);
    expect(fixture.barrier.recordOwnCommit()).toBe(true);
    expect(ticket.signal.aborted).toBe(true);

    await fixture.settleAndFlush(0, "still-applicable");
    expect(fixture.barrier.needsReconciliation()).toBe(false);
    expect(fixture.kinds()).toContain("run-discarded");
  });
});

// ---------------------------------------------------------------------------
// Dispose
// ---------------------------------------------------------------------------

describe("dispose", () => {
  it("cancels in-flight runs, refuses new runs and discards late results", async () => {
    const fixture = createFixture();
    const ticket = fixture.barrier.begin() as LearningBarrierTicket;
    fixture.barrier.dispose();
    expect(ticket.signal.aborted).toBe(true);
    expect(fixture.barrier.begin()).toBeUndefined();
    expect(fixture.runCount).toBe(1);

    await fixture.settleAndFlush(0, "still-applicable");
    expect(fixture.kinds()).toContain("run-discarded");
    expect(fixture.kinds()).not.toContain("barrier-opened");
    expect(fixture.barrier.pendingRuns()).toBe(0);
  });

  it("is idempotent", () => {
    const fixture = createFixture();
    fixture.barrier.begin();
    fixture.barrier.dispose();
    fixture.barrier.dispose();
    fixture.barrier.dispose();
    expect(fixture.runCount).toBe(1);
    expect(fixture.barrier.begin()).toBeUndefined();
    expect(fixture.barrier.recordOwnCommit()).toBe(false);
    expect(fixture.barrier.holdsRevision(INITIAL_REVISION).isCurrent()).toBe(false);
  });

  it("ignores user input and reconciliation requests after disposal", () => {
    const fixture = createFixture();
    fixture.barrier.dispose();
    const revision = fixture.barrier.revision;
    expect(fixture.barrier.recordUserInput()).toBe(revision);
    fixture.barrier.requireReconciliation();
    expect(fixture.barrier.revision).toBe(revision);
    expect(fixture.barrier.begin()).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Audit failures never change state or results
// ---------------------------------------------------------------------------

describe("audit failures", () => {
  it("does not change outcomes when the audit callback throws", async () => {
    const fixture = createFixture();
    fixture.auditThrows = true;
    expect(fixture.barrier.begin()).not.toBeUndefined();
    await fixture.settleAndFlush(0, "still-applicable");
    expect(fixture.barrier.needsReconciliation()).toBe(false);
    expect(fixture.barrier.pendingRuns()).toBe(0);
  });

  it("does not change outcomes when the audit callback rejects", async () => {
    const fixture = createFixture();
    fixture.auditRejects = true;
    fixture.barrier.begin();
    await fixture.settleAndFlush(0, "current-task-paused");
    expect(fixture.barrier.needsReconciliation()).toBe(false);
    expect(fixture.barrier.currentTaskPaused()).toBe(true);
  });

  it("keeps the own-commit fast path when the audit callback throws", () => {
    const fixture = createFixture();
    fixture.auditThrows = true;
    expect(fixture.barrier.recordOwnCommit()).toBe(true);
    expect(fixture.barrier.needsReconciliation()).toBe(false);
  });

  it("keeps a failing durable revoke observable despite a throwing audit", async () => {
    const fixture = createFixture();
    fixture.auditThrows = true;
    fixture.durableRevokeImpl = async () => false;
    const ticket = fixture.barrier.begin() as LearningBarrierTicket;
    ticket.complete("persistent-revoke");
    await flush();
    expect(fixture.barrier.needsReconciliation()).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Read-only service contract
// ---------------------------------------------------------------------------

describe("service contract", () => {
  it("is usable as the read-only ProjectRulesIntentBarrier", () => {
    const fixture = createFixture();
    const barrier: ProjectRulesIntentBarrier = fixture.barrier;
    expect(barrier.revision).toBe(INITIAL_REVISION);
    expect(barrier.needsReconciliation()).toBe(true);
    expect(barrier.currentTaskPaused()).toBe(false);
    expect(barrier.learningDisabled()).toBe(false);
    const guard = barrier.holdsRevision(barrier.revision);
    expect(guard.isCurrent()).toBe(true);
  });

  it("closes the gate again when a new user input arrives", async () => {
    const fixture = createFixture();
    fixture.barrier.begin();
    await fixture.settleAndFlush(0, "still-applicable");
    fixture.barrier.recordUserInput();
    expect(fixture.barrier.needsReconciliation()).toBe(true);
  });
});
