/**
 * Deferred learning lifecycle tests (specs/reviewer-context.md §10).
 *
 * The lifecycle owns pending candidates that a model review accepted but that
 * only become durable after the host finally allows the call. Every seam is
 * injected through the public options: a fake collector records staging and
 * discard calls, a fake commit port lets a test hold the durable transaction
 * open, and the clock is a plain mutable value. No internal collaborator is
 * mocked.
 */
import { describe, expect, it } from "vitest";
import {
  ReviewerDeferredLearning,
  type DeferredLearningEvent,
  type DeferredLearningFinalizeResult,
} from "#approve-core/context/learning";
import type {
  ChainCallUnit,
  DeferredLearningCommitInput,
  LearningAcceptInput,
  LearningCallFacts,
  LearningFinalCall,
  LearningFinalizeInput,
  ReviewRevisions,
  ReviewView,
} from "#approve-core/context/types";
import type { LearningCommitResult } from "#approve-core/policy/project-rules/learning";
import { LearningCandidateCollector } from "#approve-core/policy/project-rules/candidates";

// ---------------------------------------------------------------------------
// Domain fixtures
// ---------------------------------------------------------------------------

const SESSION_ID = "session-1";
const STEP_KEY = "step-1";
const OWNER = "owner-1";
const T0 = 1_000;
const TTL = 5 * 60_000;

function viewOf(overrides: Partial<ReviewView> = {}): ReviewView {
  return {
    owner: OWNER,
    sessionId: SESSION_ID,
    historyVersion: 3,
    captureSeq: 7,
    leafId: "leaf-1",
    branchRootId: "root-1",
    transcript: [],
    authorization: [],
    degraded: false,
    ...overrides,
  };
}

function revisionsOf(overrides: Partial<ReviewRevisions> = {}): ReviewRevisions {
  return {
    owner: 1,
    navigation: 2,
    authorization: 3,
    projectRules: 4,
    intent: 5,
    ...overrides,
  };
}

function unitOf(overrides: Partial<ChainCallUnit> = {}): ChainCallUnit {
  return {
    unitId: "unit-1",
    decision: "ask",
    reason: "pending",
    source: "chain",
    history: [],
    ...overrides,
  };
}

function callOf(overrides: Partial<LearningCallFacts> = {}): LearningCallFacts {
  return {
    toolCallId: "call-1",
    toolName: "bash",
    parentToolCallId: undefined,
    arguments: Object.freeze({ command: "ls" }),
    argumentsDigest: "arguments-digest",
    digest: "call-digest",
    units: Object.freeze([unitOf()]),
    ...overrides,
  };
}

function finalCallOf(overrides: Partial<LearningFinalCall> = {}): LearningFinalCall {
  return {
    ...callOf(),
    units: Object.freeze([unitOf({ decision: "allow" })]),
    decision: "allow",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Injected seams
// ---------------------------------------------------------------------------

interface StagedView {
  readonly candidates: readonly unknown[];
  readonly rejections: readonly unknown[];
}

interface ParseCall {
  readonly attemptId: string | undefined;
  readonly requestId: string;
  readonly input: unknown;
}

function stagedCount(input: unknown): number {
  const raw = typeof input === "object" && input !== null
    ? (input as { count?: unknown }).count
    : input;
  return typeof raw === "number" && Number.isSafeInteger(raw) && raw > 0 ? raw : 0;
}

/** Behavioural stand-in for the Phase 9 collector; injected through the port. */
class FakeCollector {
  readonly parseCalls: ParseCall[] = [];
  readonly hasStagedCalls: Array<string | undefined> = [];
  readonly discardedAttempts: string[] = [];
  throwOnParse = false;
  throwOnHasStagedData = false;
  throwOnDiscard = false;
  implicitAttemptId: string | undefined = undefined;
  readonly #buckets = new Map<string, Map<string, unknown[]>>();

  currentAttemptId(): string | undefined {
    return this.implicitAttemptId;
  }

  parse(input: unknown, context: { attemptId?: string; requestId: string }): StagedView {
    this.parseCalls.push({ attemptId: context.attemptId, requestId: context.requestId, input });
    if (this.throwOnParse) throw new Error("parse failure");
    const count = stagedCount(input);
    const attemptId = context.attemptId;
    if (attemptId === undefined || count === 0) return { candidates: [], rejections: [] };
    const candidates = Array.from({ length: count }, (_value, index) => ({ index }));
    this.#bucket(attemptId).set(context.requestId, candidates);
    return { candidates, rejections: [] };
  }

  hasStagedData(attemptId?: string): boolean {
    this.hasStagedCalls.push(attemptId);
    if (this.throwOnHasStagedData) throw new Error("has-staged-data failure");
    if (attemptId !== undefined) return (this.#buckets.get(attemptId)?.size ?? 0) > 0;
    return this.#buckets.size > 0;
  }

  discardAttempt(attemptId: string): void {
    this.discardedAttempts.push(attemptId);
    if (this.throwOnDiscard) throw new Error("discard failure");
    this.#buckets.delete(attemptId);
  }

  seedStaged(attemptId: string, count = 1, requestId = "request"): void {
    this.#bucket(attemptId).set(
      requestId,
      Array.from({ length: count }, (_value, index) => ({ index })),
    );
  }

  stagedRequestIds(attemptId: string): string[] {
    return [...(this.#buckets.get(attemptId)?.keys() ?? [])];
  }

  hasBucket(attemptId: string): boolean {
    return this.#buckets.has(attemptId);
  }

  #bucket(attemptId: string): Map<string, unknown[]> {
    const existing = this.#buckets.get(attemptId);
    if (existing !== undefined) return existing;
    const created = new Map<string, unknown[]>();
    this.#buckets.set(attemptId, created);
    return created;
  }
}

function committedResult(revision = 2): LearningCommitResult {
  return {
    kind: "committed",
    durable: true,
    revision,
    previousRevision: revision - 1,
    durableRuleIds: ["rule-1"],
    revokedRuleIds: [],
    rejections: [],
    currentIntentValid: true,
    needsReconciliation: false,
    ownCommitRecorded: true,
    intentRevision: 1,
  };
}

function noChangeResult(): LearningCommitResult {
  return {
    kind: "no-change",
    durable: false,
    revision: 1,
    previousRevision: 1,
    rejections: [],
    currentIntentValid: true,
    needsReconciliation: false,
    ownCommitRecorded: false,
    intentRevision: 1,
  };
}

function failedResult(): LearningCommitResult {
  return {
    kind: "failed",
    durable: false,
    category: "disabled",
    reason: "learning-disabled",
    currentIntentValid: false,
    rejections: [],
  };
}

type CommitImpl = (
  input: DeferredLearningCommitInput,
) => LearningCommitResult | Promise<LearningCommitResult>;

class FakeCommit {
  readonly calls: DeferredLearningCommitInput[] = [];
  impl: CommitImpl = () => committedResult();

  commit(input: DeferredLearningCommitInput): LearningCommitResult | Promise<LearningCommitResult> {
    this.calls.push(input);
    return this.impl(input);
  }

  get callCount(): number {
    return this.calls.length;
  }

  lastCall(): DeferredLearningCommitInput {
    const call = this.calls[this.calls.length - 1];
    if (call === undefined) throw new Error("no commit call recorded");
    return call;
  }
}

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

async function flush(times = 6): Promise<void> {
  for (let index = 0; index < times; index += 1) await Promise.resolve();
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

interface FixtureOptions {
  readonly maxPending?: number;
  readonly ttlMs?: number;
  readonly learningEnabled?: () => boolean;
  readonly now?: () => number;
  readonly observers?: readonly ((event: DeferredLearningEvent) => void)[];
}

class Fixture {
  clock = T0;
  enabled = true;
  observerThrows = false;
  readonly collector = new FakeCollector();
  readonly commit = new FakeCommit();
  readonly events: DeferredLearningEvent[] = [];
  readonly learning: ReviewerDeferredLearning;

  constructor(options: FixtureOptions = {}) {
    this.learning = new ReviewerDeferredLearning({
      collector: this.collector,
      commit: this.commit,
      learningEnabled: options.learningEnabled ?? (() => this.enabled),
      now: options.now ?? (() => this.clock),
      ...(options.maxPending === undefined ? {} : { maxPending: options.maxPending }),
      ...(options.ttlMs === undefined ? {} : { ttlMs: options.ttlMs }),
      observers: [
        (event) => {
          this.events.push(event);
          if (this.observerThrows) throw new Error("observer failure");
        },
        ...(options.observers ?? []),
      ],
    });
  }

  beginStaged(toolCallId = "call-1", count = 1): { attemptId: string; toolCallId: string } {
    const attemptId = this.learning.beginAttempt();
    this.learning.stage(attemptId, toolCallId, { count });
    return { attemptId, toolCallId };
  }

  accept(attemptId: string, toolCallId = "call-1", overrides: Partial<LearningAcceptInput> = {}): void {
    this.learning.accept({
      attemptId,
      stepKey: STEP_KEY,
      sessionId: SESSION_ID,
      call: callOf({ toolCallId }),
      view: viewOf(),
      revisions: revisionsOf(),
      mode: "auto-review",
      verdict: "allow",
      ...overrides,
    });
  }

  acceptStaged(
    toolCallId = "call-1",
    overrides: Partial<LearningAcceptInput> = {},
    count = 1,
  ): { attemptId: string; toolCallId: string } {
    const ids = this.beginStaged(toolCallId, count);
    this.accept(ids.attemptId, toolCallId, overrides);
    return ids;
  }

  finalize(overrides: Partial<LearningFinalizeInput> = {}): Promise<DeferredLearningFinalizeResult> {
    return this.learning.finalize({
      stepKey: STEP_KEY,
      sessionId: SESSION_ID,
      owner: OWNER,
      calls: [finalCallOf()],
      ...overrides,
    });
  }

  kinds(): string[] {
    return this.events.map((event) => event.kind);
  }
}

const fixtures: Fixture[] = [];

function createFixture(options: FixtureOptions = {}): Fixture {
  const fixture = new Fixture(options);
  fixtures.push(fixture);
  return fixture;
}

// ---------------------------------------------------------------------------
// Slice A: attempt allocation and staging
// ---------------------------------------------------------------------------

describe("attempts and staging", () => {
  it("beginAttempt issues a distinct and increasing id for every call", () => {
    const fixture = createFixture();
    const first = fixture.learning.beginAttempt();
    const second = fixture.learning.beginAttempt();
    const third = fixture.learning.beginAttempt();
    expect(new Set([first, second, third]).size).toBe(3);
    expect(second > first).toBe(true);
    expect(third > second).toBe(true);
  });

  it("stage parses the payload for the attempt and the tool-call request", () => {
    const fixture = createFixture();
    const attemptId = fixture.learning.beginAttempt();
    const staged = fixture.learning.stage(attemptId, "call-9", { count: 3 });
    expect(staged).toBe(3);
    expect(fixture.collector.parseCalls).toEqual([
      { attemptId, requestId: "call-9", input: { count: 3 } },
    ]);
    expect(fixture.collector.stagedRequestIds(attemptId)).toEqual(["call-9"]);
  });

  it("stage returns zero when the payload holds no candidate", () => {
    const fixture = createFixture();
    const attemptId = fixture.learning.beginAttempt();
    expect(fixture.learning.stage(attemptId, "call-1", { count: 0 })).toBe(0);
    expect(fixture.collector.hasStagedData(attemptId)).toBe(false);
  });

  it("stage tolerates a throwing collector instead of propagating the failure", () => {
    const fixture = createFixture();
    const attemptId = fixture.learning.beginAttempt();
    fixture.collector.throwOnParse = true;
    expect(fixture.learning.stage(attemptId, "call-1", { count: 2 })).toBe(0);
  });

  it("stage ignores unusable ids without calling the collector", () => {
    const fixture = createFixture();
    expect(fixture.learning.stage("", "call-1", { count: 1 })).toBe(0);
    expect(fixture.learning.stage("attempt-1", "", { count: 1 })).toBe(0);
    expect(fixture.collector.parseCalls).toHaveLength(0);
  });

  it("stage is a no-op after dispose", () => {
    const fixture = createFixture();
    const attemptId = fixture.learning.beginAttempt();
    fixture.learning.dispose();
    expect(fixture.learning.stage(attemptId, "call-1", { count: 1 })).toBe(0);
    expect(fixture.collector.parseCalls).toHaveLength(0);
  });
});

function acceptRaw(fixture: Fixture, input: unknown): void {
  fixture.learning.accept(input as LearningAcceptInput);
}

function acceptFailureReasons(fixture: Fixture): string[] {
  return fixture.events
    .filter((event) => event.kind === "accept-rejected")
    .map((event) => (event as { reason: string }).reason);
}

// ---------------------------------------------------------------------------
// Slice B: accept requirements and pending state
// ---------------------------------------------------------------------------

describe("accept requirements", () => {
  it("rejects and discards the new attempt after dispose", () => {
    const fixture = createFixture();
    const ids = fixture.beginStaged();
    fixture.learning.dispose();
    fixture.accept(ids.attemptId);
    expect(fixture.collector.discardedAttempts).toContain(ids.attemptId);
    expect(acceptFailureReasons(fixture)).toEqual(["disposed"]);
    expect(fixture.learning.pendingCount).toBe(0);
  });

  it("rejects a verdict that is not allow", () => {
    const deny = createFixture();
    const denyIds = deny.beginStaged();
    deny.accept(denyIds.attemptId, "call-1", { verdict: "deny" });
    expect(acceptFailureReasons(deny)).toEqual(["invalid-verdict"]);
    expect(deny.collector.discardedAttempts).toContain(denyIds.attemptId);

    const ask = createFixture();
    const askIds = ask.beginStaged();
    ask.accept(askIds.attemptId, "call-1", { verdict: "ask" });
    expect(acceptFailureReasons(ask)).toEqual(["invalid-verdict"]);
    expect(ask.learning.pendingCount).toBe(0);
  });

  it("rejects every mode except auto-review", () => {
    for (const mode of ["read-only", "default", "full-access"] as const) {
      const fixture = createFixture();
      const ids = fixture.beginStaged();
      fixture.accept(ids.attemptId, "call-1", { mode });
      expect(acceptFailureReasons(fixture)).toEqual(["not-auto-review"]);
      expect(fixture.collector.discardedAttempts).toContain(ids.attemptId);
    }
  });

  it("rejects while learning is disabled and discards the attempt", () => {
    const fixture = createFixture();
    const ids = fixture.beginStaged();
    fixture.enabled = false;
    fixture.accept(ids.attemptId);
    expect(acceptFailureReasons(fixture)).toEqual(["learning-disabled"]);
    expect(fixture.collector.discardedAttempts).toContain(ids.attemptId);
  });

  it("treats a throwing learning switch as disabled", () => {
    const fixture = createFixture({
      learningEnabled: () => {
        throw new Error("switch failure");
      },
    });
    const ids = fixture.beginStaged();
    fixture.accept(ids.attemptId);
    expect(acceptFailureReasons(fixture)).toEqual(["learning-disabled"]);
    expect(fixture.learning.pendingCount).toBe(0);
  });

  it("rejects when the attempt staged no candidate", () => {
    const fixture = createFixture();
    const attemptId = fixture.learning.beginAttempt();
    fixture.accept(attemptId);
    expect(acceptFailureReasons(fixture)).toEqual(["no-candidates"]);
    expect(fixture.collector.discardedAttempts).toContain(attemptId);
    expect(fixture.learning.pendingCount).toBe(0);
  });

  it("treats a throwing staging check as no candidate", () => {
    const fixture = createFixture();
    const ids = fixture.beginStaged();
    fixture.collector.throwOnHasStagedData = true;
    fixture.accept(ids.attemptId);
    expect(acceptFailureReasons(fixture)).toEqual(["no-candidates"]);
    expect(fixture.learning.pendingCount).toBe(0);
  });

  it("rejects an empty session id and discards the attempt", () => {
    const fixture = createFixture();
    const ids = fixture.beginStaged();
    fixture.accept(ids.attemptId, "call-1", { sessionId: "" });
    expect(acceptFailureReasons(fixture)).toEqual(["invalid-input"]);
    expect(fixture.collector.discardedAttempts).toContain(ids.attemptId);
  });

  it("rejects an empty step key", () => {
    const fixture = createFixture();
    const ids = fixture.beginStaged();
    fixture.accept(ids.attemptId, "call-1", { stepKey: "" });
    expect(acceptFailureReasons(fixture)).toEqual(["invalid-input"]);
    expect(fixture.learning.pendingCount).toBe(0);
  });

  it("rejects a missing call fact object", () => {
    const fixture = createFixture();
    const ids = fixture.beginStaged();
    acceptRaw(fixture, {
      attemptId: ids.attemptId,
      stepKey: STEP_KEY,
      sessionId: SESSION_ID,
      call: undefined,
      view: viewOf(),
      revisions: revisionsOf(),
      mode: "auto-review",
      verdict: "allow",
    });
    expect(acceptFailureReasons(fixture)).toEqual(["invalid-input"]);
    expect(fixture.collector.discardedAttempts).toContain(ids.attemptId);
  });

  it("rejects an empty tool call id", () => {
    const fixture = createFixture();
    const ids = fixture.beginStaged();
    fixture.accept(ids.attemptId, "call-1", { call: callOf({ toolCallId: "" }) });
    expect(acceptFailureReasons(fixture)).toEqual(["invalid-input"]);
  });

  it("keeps staged candidates and the attempt after a successful accept", () => {
    const fixture = createFixture();
    const ids = fixture.acceptStaged();
    expect(fixture.learning.pendingCount).toBe(1);
    expect(fixture.collector.hasBucket(ids.attemptId)).toBe(true);
    expect(fixture.collector.discardedAttempts).not.toContain(ids.attemptId);
  });

  it("freezes the accepted facts under the session/step/call key", () => {
    const fixture = createFixture();
    fixture.clock = T0 + 500;
    const ids = fixture.acceptStaged();
    const state = fixture.learning.state();
    expect(state.disposed).toBe(false);
    expect(state.pendingCount).toBe(1);
    expect(state.pending).toEqual([
      {
        sessionId: SESSION_ID,
        stepKey: STEP_KEY,
        toolCallId: ids.toolCallId,
        attemptId: ids.attemptId,
        acceptedAt: T0 + 500,
      },
    ]);
    expect(Object.isFrozen(state)).toBe(true);
    expect(Object.isFrozen(state.pending)).toBe(true);
    expect(fixture.kinds()).toContain("accepted");
  });

  it("does not let an observer failure change the accept decision", () => {
    const fixture = createFixture();
    fixture.observerThrows = true;
    const ids = fixture.beginStaged();
    expect(() => fixture.accept(ids.attemptId)).not.toThrow();
    expect(fixture.learning.pendingCount).toBe(1);
    expect(fixture.collector.discardedAttempts).not.toContain(ids.attemptId);
  });
});

// ---------------------------------------------------------------------------
// Slice C: capacity before same-key replacement
// ---------------------------------------------------------------------------

describe("pending capacity and replacement", () => {
  it("rejects a same-key accept while full and keeps the old pending untouched", () => {
    const fixture = createFixture({ maxPending: 1 });
    const first = fixture.acceptStaged("call-1");
    fixture.clock = T0 + 10;
    const second = fixture.beginStaged("call-1", 2);
    fixture.accept(second.attemptId);

    expect(acceptFailureReasons(fixture)).toEqual(["capacity"]);
    expect(fixture.learning.pendingCount).toBe(1);
    const pending = fixture.learning.state().pending[0];
    expect(pending?.attemptId).toBe(first.attemptId);
    expect(pending?.acceptedAt).toBe(T0);
    expect(fixture.collector.hasBucket(first.attemptId)).toBe(true);
    expect(fixture.collector.hasBucket(second.attemptId)).toBe(false);
    expect(fixture.collector.discardedAttempts).toEqual([second.attemptId]);
  });

  it("rejects a different-key accept while full and keeps the old pending", () => {
    const fixture = createFixture({ maxPending: 1 });
    const first = fixture.acceptStaged("call-1");
    const second = fixture.beginStaged("call-2", 1);
    fixture.accept(second.attemptId, "call-2");

    expect(acceptFailureReasons(fixture)).toEqual(["capacity"]);
    expect(fixture.learning.pendingCount).toBe(1);
    expect(fixture.learning.state().pending[0]?.attemptId).toBe(first.attemptId);
    expect(fixture.collector.discardedAttempts).toEqual([second.attemptId]);
  });

  it("replaces a same-key pending and discards the old attempt when not full", () => {
    const fixture = createFixture();
    const first = fixture.acceptStaged("call-1");
    fixture.clock = T0 + 25;
    const second = fixture.acceptStaged("call-1", {}, 2);

    expect(fixture.learning.pendingCount).toBe(1);
    const pending = fixture.learning.state().pending[0];
    expect(pending?.attemptId).toBe(second.attemptId);
    expect(pending?.acceptedAt).toBe(T0 + 25);
    expect(fixture.collector.discardedAttempts).toContain(first.attemptId);
    expect(fixture.collector.hasBucket(first.attemptId)).toBe(false);
    expect(fixture.collector.hasBucket(second.attemptId)).toBe(true);
  });

  it("keeps distinct keys pending while capacity is available", () => {
    const fixture = createFixture({ maxPending: 2 });
    fixture.acceptStaged("call-1");
    fixture.acceptStaged("call-2");
    expect(fixture.learning.pendingCount).toBe(2);
  });

  it("uses the default pending bound of 128", () => {
    const fixture = createFixture();
    for (let index = 0; index < 128; index += 1) fixture.acceptStaged(`call-${index}`);
    expect(fixture.learning.pendingCount).toBe(128);

    const extra = fixture.beginStaged("call-overflow");
    fixture.accept(extra.attemptId, "call-overflow");
    expect(acceptFailureReasons(fixture)).toEqual(["capacity"]);
    expect(fixture.learning.pendingCount).toBe(128);
    expect(fixture.collector.discardedAttempts).toEqual([extra.attemptId]);
  });

  it("falls back to the default bound for an unusable maxPending", () => {
    const fixture = createFixture({ maxPending: 0 });
    for (let index = 0; index < 128; index += 1) fixture.acceptStaged(`call-${index}`);
    expect(fixture.learning.pendingCount).toBe(128);
  });
});

// ---------------------------------------------------------------------------
// Slice D: discard, discardAttempt and dispose
// ---------------------------------------------------------------------------

describe("discard, discardAttempt and dispose", () => {
  it("discard removes every pending registered under the tool call id", () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    fixture.acceptStaged("call-2");
    fixture.acceptStaged("call-1", { sessionId: "session-2", stepKey: "step-2" });
    expect(fixture.learning.pendingCount).toBe(3);

    fixture.learning.discard("call-1");
    expect(fixture.learning.pendingCount).toBe(1);
    const remaining = fixture.learning.state().pending;
    expect(remaining.map((entry) => entry.toolCallId)).toEqual(["call-2"]);
    expect(fixture.kinds()).toContain("pending-discarded");
  });

  it("discard discards the collector attempt of every removed pending", () => {
    const fixture = createFixture();
    const first = fixture.acceptStaged("call-1");
    const second = fixture.acceptStaged("call-1", { sessionId: "session-2" });
    fixture.learning.discard("call-1");
    expect(fixture.collector.discardedAttempts).toContain(first.attemptId);
    expect(fixture.collector.discardedAttempts).toContain(second.attemptId);
    expect(fixture.collector.hasBucket(first.attemptId)).toBe(false);
    expect(fixture.collector.hasBucket(second.attemptId)).toBe(false);
  });

  it("discard ignores an unusable tool call id", () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    expect(() => fixture.learning.discard("")).not.toThrow();
    expect(fixture.learning.pendingCount).toBe(1);
  });

  it("discard tolerates a throwing collector while still clearing pending", () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    fixture.collector.throwOnDiscard = true;
    expect(() => fixture.learning.discard("call-1")).not.toThrow();
    expect(fixture.learning.pendingCount).toBe(0);
  });

  it("discardAttempt removes the pending owned by the attempt and clears staging", () => {
    const fixture = createFixture();
    const ids = fixture.acceptStaged("call-1");
    expect(fixture.learning.pendingCount).toBe(1);

    fixture.learning.discardAttempt(ids.attemptId);
    expect(fixture.learning.pendingCount).toBe(0);
    expect(fixture.collector.discardedAttempts).toContain(ids.attemptId);
    expect(fixture.collector.hasBucket(ids.attemptId)).toBe(false);
  });

  it("discardAttempt asks the collector to discard a staged attempt without pending", () => {
    const fixture = createFixture();
    const attemptId = fixture.learning.beginAttempt();
    fixture.collector.seedStaged(attemptId, 1, "call-1");
    fixture.learning.discardAttempt(attemptId);
    expect(fixture.collector.discardedAttempts).toEqual([attemptId]);
    expect(fixture.collector.hasBucket(attemptId)).toBe(false);
  });

  it("discardAttempt ignores an unusable attempt id", () => {
    const fixture = createFixture();
    expect(() => fixture.learning.discardAttempt("")).not.toThrow();
    expect(fixture.collector.discardedAttempts).toHaveLength(0);
  });

  it("discardAttempt tolerates a throwing collector while still clearing pending", () => {
    const fixture = createFixture();
    const ids = fixture.acceptStaged("call-1");
    fixture.collector.throwOnDiscard = true;
    expect(() => fixture.learning.discardAttempt(ids.attemptId)).not.toThrow();
    expect(fixture.learning.pendingCount).toBe(0);
  });

  it("dispose clears pending, discards known attempts and is idempotent", () => {
    const fixture = createFixture();
    const ids = fixture.acceptStaged("call-1");
    expect(fixture.learning.disposed).toBe(false);

    fixture.learning.dispose();
    expect(fixture.learning.disposed).toBe(true);
    expect(fixture.learning.pendingCount).toBe(0);
    expect(fixture.collector.discardedAttempts).toContain(ids.attemptId);
    expect(fixture.collector.hasBucket(ids.attemptId)).toBe(false);

    fixture.learning.dispose();
    expect(fixture.kinds().filter((kind) => kind === "disposed")).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Slice E: finalize commit path, reentrancy and commit failures
// ---------------------------------------------------------------------------

describe("finalize commit path", () => {
  it("commits the frozen facts of a finally-allowed call and discards the attempt", async () => {
    const fixture = createFixture();
    const ids = fixture.acceptStaged("call-1");
    const result = await fixture.finalize();

    expect(fixture.commit.callCount).toBe(1);
    expect(fixture.commit.lastCall()).toEqual({
      sessionId: SESSION_ID,
      stepKey: STEP_KEY,
      toolCallId: "call-1",
      attemptId: ids.attemptId,
      call: callOf(),
      view: viewOf(),
      revisions: revisionsOf(),
      mode: "auto-review",
      verdict: "allow",
    });
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected a committed result");
    expect(result.committed).toBe(true);
    expect(result.commits).toHaveLength(1);
    expect(result.commits[0]?.result).toEqual(committedResult());
    expect(result.rejections).toEqual([]);
    expect(fixture.learning.pendingCount).toBe(0);
    expect(fixture.collector.discardedAttempts).toContain(ids.attemptId);
    expect(fixture.kinds()).toContain("committed");
  });

  it("removes the pending entry before awaiting the durable commit", async () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    const gate = deferred<LearningCommitResult>();
    fixture.commit.impl = () => gate.promise;

    const first = fixture.finalize();
    await flush();
    expect(fixture.commit.callCount).toBe(1);
    expect(fixture.learning.pendingCount).toBe(0);

    const second = await fixture.finalize();
    expect(second.ok).toBe(false);
    if (second.ok) throw new Error("expected a rejected result");
    expect(second.reason).toBe("duplicate-finalize");
    expect(fixture.commit.callCount).toBe(1);

    gate.resolve(committedResult());
    await expect(first).resolves.toMatchObject({ ok: true, committed: true });
  });

  it("reports duplicate-finalize after a committed finalize", async () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    const first = await fixture.finalize();
    expect(first.committed).toBe(true);

    const second = await fixture.finalize();
    expect(second.committed).toBe(false);
    if (second.ok) throw new Error("expected a rejected result");
    expect(second.reason).toBe("duplicate-finalize");
    expect(fixture.commit.callCount).toBe(1);
  });

  it("resolves with commit-threw when the commit port throws", async () => {
    const fixture = createFixture();
    const ids = fixture.acceptStaged("call-1");
    fixture.commit.impl = () => {
      throw new Error("durable store unavailable");
    };

    const result = await fixture.finalize();
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected a rejected result");
    expect(result.reason).toBe("commit-threw");
    expect(result.rejections).toEqual([
      { toolCallId: "call-1", attemptId: ids.attemptId, reason: "commit-threw" },
    ]);
    expect(fixture.learning.pendingCount).toBe(0);
    expect(fixture.collector.discardedAttempts).toContain(ids.attemptId);
  });

  it("resolves with commit-threw when the commit promise rejects", async () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    fixture.commit.impl = () => Promise.reject(new Error("network failure"));

    const result = await fixture.finalize();
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected a rejected result");
    expect(result.reason).toBe("commit-threw");
  });

  it("reports commit-failed when the durable transaction reports no change", async () => {
    const fixture = createFixture();
    const ids = fixture.acceptStaged("call-1");
    fixture.commit.impl = () => noChangeResult();

    const result = await fixture.finalize();
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected a rejected result");
    expect(result.reason).toBe("commit-failed");
    expect(result.rejections).toEqual([
      { toolCallId: "call-1", attemptId: ids.attemptId, reason: "commit-failed" },
    ]);
    expect(fixture.collector.discardedAttempts).toContain(ids.attemptId);
  });

  it("reports commit-failed when the durable transaction fails", async () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    fixture.commit.impl = () => failedResult();

    const result = await fixture.finalize();
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected a rejected result");
    expect(result.reason).toBe("commit-failed");
  });

  it("commits every pending candidate of one step and discards each attempt", async () => {
    const fixture = createFixture();
    const first = fixture.acceptStaged("call-1");
    const second = fixture.acceptStaged("call-2");

    const result = await fixture.finalize({
      calls: [finalCallOf(), finalCallOf({ toolCallId: "call-2" })],
    });
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected a committed result");
    expect(result.commits.map((entry) => entry.toolCallId)).toEqual(["call-1", "call-2"]);
    expect(fixture.commit.callCount).toBe(2);
    expect(fixture.learning.pendingCount).toBe(0);
    expect(fixture.collector.discardedAttempts).toContain(first.attemptId);
    expect(fixture.collector.discardedAttempts).toContain(second.attemptId);
  });

  it("keeps a successful commit when another candidate's commit throws", async () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    fixture.acceptStaged("call-2");
    let calls = 0;
    fixture.commit.impl = () => {
      calls += 1;
      return calls === 2 ? Promise.reject(new Error("second failed")) : committedResult();
    };

    const result = await fixture.finalize({
      calls: [finalCallOf(), finalCallOf({ toolCallId: "call-2" })],
    });
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected a committed result");
    expect(result.commits).toHaveLength(1);
    expect(result.rejections.map((entry) => entry.reason)).toEqual(["commit-threw"]);
  });

  it("commits the accepted facts even when the caller mutates its call object", async () => {
    const fixture = createFixture();
    const attemptId = fixture.learning.beginAttempt();
    fixture.learning.stage(attemptId, "call-1", { count: 1 });
    const mutableCall = callOf() as unknown as { toolName: string };
    fixture.accept(attemptId, "call-1", { call: mutableCall as unknown as LearningCallFacts });
    mutableCall.toolName = "mutated-after-accept";

    const result = await fixture.finalize();
    expect(result.ok).toBe(true);
    expect(fixture.commit.lastCall().call.toolName).toBe("bash");
  });
});

function expectReason(result: DeferredLearningFinalizeResult, reason: string): void {
  expect(result.ok).toBe(false);
  expect(result.committed).toBe(false);
  if (result.ok) throw new Error("expected a rejected result");
  expect(result.reason).toBe(reason);
}

// ---------------------------------------------------------------------------
// Slice F: finalize validation
// ---------------------------------------------------------------------------

describe("finalize validation", () => {
  it("reports no-pending when nothing was accepted for the step", async () => {
    const fixture = createFixture();
    expectReason(await fixture.finalize(), "no-pending");
    expect(fixture.commit.callCount).toBe(0);
  });

  it("reports no-pending for a missing session id or step key", async () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    expectReason(await fixture.finalize({ sessionId: "" }), "no-pending");
    expectReason(await fixture.finalize({ stepKey: "" }), "no-pending");
    expect(fixture.learning.pendingCount).toBe(1);
  });

  it("reports disposed after dispose even with a matching session and step", async () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    fixture.learning.dispose();
    expectReason(await fixture.finalize(), "disposed");
    expect(fixture.commit.callCount).toBe(0);
  });

  it("discards pending and reports cancelled for an aborted signal", async () => {
    const fixture = createFixture();
    const ids = fixture.acceptStaged("call-1");
    const controller = new AbortController();
    controller.abort();

    expectReason(await fixture.finalize({ signal: controller.signal }), "cancelled");
    expect(fixture.learning.pendingCount).toBe(0);
    expect(fixture.commit.callCount).toBe(0);
    expect(fixture.collector.discardedAttempts).toContain(ids.attemptId);
  });

  it("discards pending and reports deadline when the deadline already passed", async () => {
    const fixture = createFixture();
    const ids = fixture.acceptStaged("call-1");
    fixture.clock = T0 + 100;

    expectReason(await fixture.finalize({ deadline: T0 + 50 }), "deadline");
    expect(fixture.learning.pendingCount).toBe(0);
    expect(fixture.commit.callCount).toBe(0);
    expect(fixture.collector.discardedAttempts).toContain(ids.attemptId);
  });

  it("ignores a null deadline", async () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    const result = await fixture.finalize({ deadline: null });
    expect(result.ok).toBe(true);
  });

  it("rejects a final call whose own decision is not allow", async () => {
    const fixture = createFixture();
    const ids = fixture.acceptStaged("call-1");
    expectReason(await fixture.finalize({ calls: [finalCallOf({ decision: "deny" })] }), "not-final-allow");
    expect(fixture.commit.callCount).toBe(0);
    expect(fixture.learning.pendingCount).toBe(0);
    expect(fixture.collector.discardedAttempts).toContain(ids.attemptId);
  });

  it("rejects a final call when any unit is still not allow", async () => {
    for (const decision of ["ask", "deny", "escalate"] as const) {
      const fixture = createFixture();
      fixture.acceptStaged("call-1");
      expectReason(
        await fixture.finalize({ calls: [finalCallOf({ units: [unitOf({ decision })] })] }),
        "not-final-allow",
      );
      expect(fixture.commit.callCount).toBe(0);
    }
  });

  it("rejects a final call with an allow call but a mixed unit list", async () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    expectReason(
      await fixture.finalize({
        calls: [
          finalCallOf({
            units: [unitOf({ decision: "allow" }), unitOf({ unitId: "unit-2", decision: "deny" })],
          }),
        ],
      }),
      "not-final-allow",
    );
  });

  it("rejects when the final decision omits the pending call", async () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    expectReason(
      await fixture.finalize({ calls: [finalCallOf({ toolCallId: "unrelated-call" })] }),
      "not-final-allow",
    );
    expect(fixture.learning.pendingCount).toBe(0);
  });

  it("rejects a digest mismatch against the accepted facts", async () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    expectReason(
      await fixture.finalize({ calls: [finalCallOf({ digest: "different-digest" })] }),
      "identity-mismatch",
    );
    expect(fixture.commit.callCount).toBe(0);
  });

  it("rejects an arguments digest mismatch against the accepted facts", async () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    expectReason(
      await fixture.finalize({ calls: [finalCallOf({ argumentsDigest: "different-arguments" })] }),
      "identity-mismatch",
    );
  });

  it("rejects a tool name mismatch against the accepted facts", async () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    expectReason(
      await fixture.finalize({ calls: [finalCallOf({ toolName: "other-tool" })] }),
      "identity-mismatch",
    );
  });

  it("rejects a parent tool call mismatch in both directions", async () => {
    const withParent = createFixture();
    withParent.acceptStaged("call-1", { call: callOf({ parentToolCallId: "parent-1" }) });
    expectReason(
      await withParent.finalize({ calls: [finalCallOf({ parentToolCallId: "parent-2" })] }),
      "identity-mismatch",
    );

    const withoutParent = createFixture();
    withoutParent.acceptStaged("call-1");
    expectReason(
      await withoutParent.finalize({ calls: [finalCallOf({ parentToolCallId: "parent-1" })] }),
      "identity-mismatch",
    );
  });

  it("accepts a matching parent tool call", async () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1", {
      call: callOf({ parentToolCallId: "parent-1" }),
    });
    const result = await fixture.finalize({
      calls: [finalCallOf({ parentToolCallId: "parent-1" })],
    });
    expect(result.ok).toBe(true);
  });

  it("rejects an owner mismatch against the accepted view", async () => {
    const fixture = createFixture();
    const ids = fixture.acceptStaged("call-1");
    expectReason(await fixture.finalize({ owner: "other-owner" }), "identity-mismatch");
    expect(fixture.commit.callCount).toBe(0);
    expect(fixture.collector.discardedAttempts).toContain(ids.attemptId);
  });

  it("rejects a view session that disagrees with the accepted session", async () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1", { view: viewOf({ sessionId: "other-session" }) });
    expectReason(await fixture.finalize(), "identity-mismatch");
    expect(fixture.commit.callCount).toBe(0);
  });

  it("rejects a mode that changed since the accept", async () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    expectReason(await fixture.finalize({ mode: "default" }), "identity-mismatch");
    expect(fixture.commit.callCount).toBe(0);
    expect(fixture.learning.pendingCount).toBe(0);
  });

  it("rejects revisions that changed since the accept", async () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    expectReason(
      await fixture.finalize({ revisions: revisionsOf({ intent: 6 }) }),
      "identity-mismatch",
    );
    expect(fixture.commit.callCount).toBe(0);
    expect(fixture.learning.pendingCount).toBe(0);
  });

  it("commits when the supplied mode and revisions still match the accept", async () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    const result = await fixture.finalize({ mode: "auto-review", revisions: revisionsOf() });
    expect(result.ok).toBe(true);
    expect(fixture.commit.callCount).toBe(1);
  });

  it("rejects a pending candidate that outlived its ttl", async () => {
    const fixture = createFixture({ ttlMs: 1_000 });
    fixture.acceptStaged("call-1");
    fixture.clock = T0 + 1_000;
    expectReason(await fixture.finalize(), "expired");
    expect(fixture.learning.pendingCount).toBe(0);
    expect(fixture.commit.callCount).toBe(0);
  });

  it("commits a pending candidate younger than its ttl", async () => {
    const fixture = createFixture({ ttlMs: 1_000 });
    fixture.acceptStaged("call-1");
    fixture.clock = T0 + 999;
    const result = await fixture.finalize();
    expect(result.ok).toBe(true);
  });

  it("rejects when learning was disabled after the accept", async () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    fixture.enabled = false;
    expectReason(await fixture.finalize(), "learning-disabled");
    expect(fixture.learning.pendingCount).toBe(0);
    expect(fixture.commit.callCount).toBe(0);
  });

  it("treats a throwing learning switch at finalize as disabled", async () => {
    let failing = false;
    const fixture = createFixture({
      learningEnabled: () => {
        if (failing) throw new Error("switch failure");
        return true;
      },
    });
    fixture.acceptStaged("call-1");
    failing = true;
    expectReason(await fixture.finalize(), "learning-disabled");
    expect(fixture.commit.callCount).toBe(0);
  });

  it("discards only the candidates of the finalized step", async () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    fixture.acceptStaged("call-2", { stepKey: "step-2" });

    expectReason(await fixture.finalize({ calls: [finalCallOf({ decision: "deny" })] }), "not-final-allow");
    expect(fixture.learning.pendingCount).toBe(1);
    expect(fixture.learning.state().pending[0]?.stepKey).toBe("step-2");
  });

  it("remembers a rejected finalize so a repetition reports duplicate-finalize", async () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    expectReason(await fixture.finalize({ calls: [finalCallOf({ decision: "deny" })] }), "not-final-allow");
    expectReason(await fixture.finalize(), "duplicate-finalize");
    expect(fixture.commit.callCount).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Slice G: observers and defensive lifecycle edges
// ---------------------------------------------------------------------------

describe("observers and defensive edges", () => {
  it("notifies observers about each lifecycle transition in order", async () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    await fixture.finalize();
    expect(fixture.kinds()).toEqual([
      "attempt-begun",
      "candidates-staged",
      "accepted",
      "commit-started",
      "committed",
    ]);
    const accepted = fixture.events.find((event) => event.kind === "accepted");
    expect(accepted).toMatchObject({
      sessionId: SESSION_ID,
      stepKey: STEP_KEY,
      toolCallId: "call-1",
    });
  });

  it("ignores a throwing observer during finalize", async () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    fixture.observerThrows = true;
    const result = await fixture.finalize();
    expect(result.ok).toBe(true);
    expect(fixture.commit.callCount).toBe(1);
    expect(fixture.learning.pendingCount).toBe(0);
  });

  it("ignores a throwing observer during dispose", () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    fixture.observerThrows = true;
    expect(() => fixture.learning.dispose()).not.toThrow();
    expect(fixture.learning.disposed).toBe(true);
  });

  it("swallows an observer that returns a rejected promise", async () => {
    const fixture = createFixture({
      observers: [() => Promise.reject(new Error("observer rejection"))],
    });
    fixture.acceptStaged("call-1");
    const result = await fixture.finalize();
    await flush(10);
    expect(result.ok).toBe(true);
  });

  it("keeps a new same-key accept independent from an in-flight commit", async () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    const gate = deferred<LearningCommitResult>();
    fixture.commit.impl = () => gate.promise;

    const first = fixture.finalize();
    await flush();
    const replacement = fixture.acceptStaged("call-1");
    expect(fixture.learning.pendingCount).toBe(1);

    gate.resolve(committedResult());
    await first;
    expect(fixture.learning.state().pending[0]?.attemptId).toBe(replacement.attemptId);

    fixture.commit.impl = () => committedResult(3);
    const second = await fixture.finalize();
    expect(second.ok).toBe(true);
    expect(fixture.commit.callCount).toBe(2);
  });

  it("still returns the in-flight commit result when dispose lands while awaiting it", async () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    const gate = deferred<LearningCommitResult>();
    fixture.commit.impl = () => gate.promise;

    const finalizePromise = fixture.finalize();
    await flush();
    fixture.learning.dispose();
    gate.resolve(committedResult());

    const result = await finalizePromise;
    expect(result.ok).toBe(true);
    expect(fixture.learning.disposed).toBe(true);
    expect(fixture.learning.pendingCount).toBe(0);
  });

  it("treats a commit port returning no result as commit-failed", async () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    fixture.commit.impl = (() => undefined) as unknown as CommitImpl;
    expectReason(await fixture.finalize(), "commit-failed");
    expect(fixture.learning.pendingCount).toBe(0);
  });

  it("defaults to enabled learning and no observers", async () => {
    const collector = new FakeCollector();
    const commit = new FakeCommit();
    const learning = new ReviewerDeferredLearning({
      collector,
      commit,
      now: () => T0,
    });
    const attemptId = learning.beginAttempt();
    learning.stage(attemptId, "call-1", { count: 1 });
    learning.accept({
      attemptId,
      stepKey: STEP_KEY,
      sessionId: SESSION_ID,
      call: callOf(),
      view: viewOf(),
      revisions: revisionsOf(),
      mode: "auto-review",
      verdict: "allow",
    });
    expect(learning.pendingCount).toBe(1);

    const result = await learning.finalize({
      stepKey: STEP_KEY,
      sessionId: SESSION_ID,
      owner: OWNER,
      calls: [finalCallOf()],
    });
    expect(result.ok).toBe(true);
    expect(commit.callCount).toBe(1);
  });

  it("ignores final calls that do not match a pending candidate", async () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    const result = await fixture.finalize({
      calls: [
        finalCallOf(),
        finalCallOf({ toolCallId: "unrelated-call", decision: "deny" }),
      ],
    });
    expect(result.ok).toBe(true);
    expect(fixture.commit.callCount).toBe(1);
  });

  it("reports not-final-allow when the final decision has no call list", async () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    const result = await fixture.finalize({ calls: [] });
    expectReason(result, "not-final-allow");
    expect(fixture.learning.pendingCount).toBe(0);
  });

  it("keeps pending snapshots frozen and detached from the pending table", () => {
    const fixture = createFixture();
    fixture.acceptStaged("call-1");
    const snapshot = fixture.learning.state();
    expect(Object.isFrozen(snapshot.pending[0])).toBe(true);
    expect(() => {
      (snapshot.pending as unknown as unknown[]).push({});
    }).toThrow();
    expect(fixture.learning.pendingCount).toBe(1);
  });

  it("allocates attempts even after dispose but never admits them", () => {
    const fixture = createFixture();
    fixture.learning.dispose();
    const attemptId = fixture.learning.beginAttempt();
    expect(attemptId).toMatch(/learning-attempt-/);
    expect(fixture.collector.discardedAttempts).not.toContain(attemptId);
  });
});

// ---------------------------------------------------------------------------
// Real Phase 9 collector compatibility (structural port, no cast)
// ---------------------------------------------------------------------------

describe("real collector port", () => {
  it("runs the lifecycle against the real LearningCandidateCollector", async () => {
    const collector = new LearningCandidateCollector();
    const commit = new FakeCommit();
    const learning = new ReviewerDeferredLearning({
      collector,
      commit,
      now: () => T0,
    });

    const attemptId = learning.beginAttempt();
    const staged = learning.stage(attemptId, "call-1", {
      create: [
        {
          effect: "allow",
          scope: "exact_action",
          actionRef: "current-action",
          sourceEntryId: "entry-1",
          quote: "ls is allowed here",
          confidence: 0.9,
        },
      ],
    });
    expect(staged).toBe(1);
    expect(collector.hasStagedData(attemptId)).toBe(true);

    learning.accept({
      attemptId,
      stepKey: STEP_KEY,
      sessionId: SESSION_ID,
      call: callOf(),
      view: viewOf(),
      revisions: revisionsOf(),
      mode: "auto-review",
      verdict: "allow",
    });
    expect(learning.pendingCount).toBe(1);

    const result = await learning.finalize({
      stepKey: STEP_KEY,
      sessionId: SESSION_ID,
      owner: OWNER,
      calls: [finalCallOf()],
    });
    expect(result.ok).toBe(true);
    expect(commit.callCount).toBe(1);
    // The accepted attempt was released from the real collector after commit.
    expect(collector.hasStagedData(attemptId)).toBe(false);
  });
});
