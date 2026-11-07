/**
 * Phase 12 host step runner (specs/host-integration.md §4).
 *
 * The chain runtime is an injected port: every fixture below is plain frozen
 * data and a fake clock, so the suite observes the runner's own semantics —
 * one chain run per step, one shared join per direct call, capacity, settled
 * retention, generation fencing, blocked endings, learning release and the
 * audit envelope. Expected values are worked examples, never recomputed from
 * the implementation.
 */
import { describe, expect, it } from "vitest";
import {
  STEP_RUNNER_LIMITS,
  createStepRunner,
  type StepAuditEvent,
  type StepBeginInput,
  type StepHandle,
  type StepOutcome,
  type StepRunner,
  type StepRunnerLearningPort,
  type StepRunnerOptions,
} from "#approve-core/host/step-runner";
import type {
  BashProgramFactsView,
  FinalCallResult,
  StepCapture,
  StepState,
  UnitPreparation,
} from "#approve-core/contracts";
import type {
  ChainAuditEntry,
  ChainNodeStartEntry,
  ChainUnitChange,
  HumanApprover,
  NodeBinding,
  RunStepChainInput,
  RunStepChainResult,
} from "#approve-core/runtime";
import type {
  LearningFinalizeInput,
  ReviewerMode,
  ReviewerSessionFacts,
} from "#approve-core/context/types";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const CLOCK_START = 1_000_000;
const DEFAULT_GENERATION = 3;

interface TestClock {
  now(): number;
  advance(ms: number): void;
}

function createClock(start = CLOCK_START): TestClock {
  let current = start;
  return {
    now: () => current,
    advance: (ms: number) => {
      current += ms;
    },
  };
}

function makeCall(toolCallId: string): Record<string, unknown> {
  return {
    toolCallId,
    toolName: "bash",
    arguments: { command: `run ${toolCallId}` },
    argumentsDigest: "a".repeat(64),
    digest: `call-digest-${toolCallId}`,
  };
}

interface CaptureInput {
  stepKey?: string;
  sessionId?: string;
  digest?: string;
  toolCallIds?: readonly string[];
}

function makeCapture(input: CaptureInput = {}): StepCapture {
  return {
    stepKey: input.stepKey ?? "step-1",
    sessionId: input.sessionId ?? "session-1",
    sourceEntryId: "entry-1",
    manifestRevision: 4,
    complete: true,
    directCalls: (input.toolCallIds ?? ["call-1"]).map(makeCall),
    digest: input.digest ?? "capture-digest-1",
  } as unknown as StepCapture;
}

function makeUnits(toolCallIds: readonly string[]): readonly UnitPreparation[] {
  return toolCallIds.map((toolCallId) => ({
    toolCallId,
    unitId: `${toolCallId}:unit-1`,
    actionDigest: `call-digest-${toolCallId}`,
    reason: "structure:analysis:whole-command",
  })) as unknown as readonly UnitPreparation[];
}

const NODES: readonly NodeBinding[] = [
  {
    node: {
      apiVersion: "1",
      id: "builtin/test-node",
      evaluate: () => ({ decisions: [] }),
    },
    position: "front",
    priority: null,
  },
] as unknown as readonly NodeBinding[];

const BASH_PROGRAMS: Readonly<Record<string, BashProgramFactsView>> = Object.freeze({
  "call-1": Object.freeze({
    commandText: "git status",
    commands: Object.freeze([]),
    programCalls: Object.freeze([]),
    workingDirectory: "C:/workspace",
    pathRuleCandidates: Object.freeze([]),
    externalAccesses: Object.freeze([]),
  }) as unknown as BashProgramFactsView,
});

function makeFacts(owner = "owner-a"): ReviewerSessionFacts {
  return {
    view: {
      owner,
      sessionId: "session-1",
      historyVersion: 7,
      captureSeq: 2,
      leafId: "leaf-1",
      branchRootId: "root-1",
      transcript: [],
      authorization: [],
      degraded: false,
    },
    revisions: { owner: 1, navigation: 2, authorization: 3, projectRules: 4, intent: 5 },
    mode: "auto-review",
  } as unknown as ReviewerSessionFacts;
}

function makeState(toolCallIds: readonly string[]): StepState {
  return {
    stepKey: "step-1",
    sessionId: "session-1",
    sourceEntryId: "entry-1",
    captureDigest: "capture-digest-1",
    revision: 1,
    calls: toolCallIds.map((toolCallId) => ({
      toolCallId,
      toolName: "bash",
      arguments: {},
      argumentsDigest: "a".repeat(64),
      digest: `call-digest-${toolCallId}`,
      units: [
        {
          unitId: `${toolCallId}:unit-1`,
          decision: "allow",
          reason: "structure:analysis:whole-command",
          source: "structure-analysis",
          history: [
            {
              revision: 1,
              nodeId: "structure-analysis",
              priority: null,
              decision: "allow",
              reason: "structure:analysis:whole-command",
            },
          ],
        },
      ],
    })),
    digest: "state-digest-1",
  } as unknown as StepState;
}

function makeFinalResult(
  toolCallId: string,
  decision: "allow" | "deny" | "escalate",
  overrides: Partial<FinalCallResult> = {},
): FinalCallResult {
  return {
    stepKey: "step-1",
    sessionId: "session-1",
    toolCallId,
    revision: 1,
    generation: DEFAULT_GENERATION,
    decision,
    reasons: [],
    publishedAt: CLOCK_START,
    expiresAt: CLOCK_START + STEP_RUNNER_LIMITS.resultTtlMs,
    ...overrides,
  } as unknown as FinalCallResult;
}

function chainOk(
  state: StepState,
  results: readonly FinalCallResult[],
  pendingToolCallIds: readonly string[] = [],
  status: "completed" | "needs-human" | "cancelled" | "deadline" = "completed",
): RunStepChainResult {
  return {
    ok: true,
    state,
    results,
    pendingToolCallIds,
    runs: [],
    faults: [],
    status,
  } as unknown as RunStepChainResult;
}

function chainFailed(reason: "invalid-input" | "prepare-failed" | "publish-failed" | "fault-fallback-failed"): RunStepChainResult {
  return { ok: false, reason };
}

interface ChainRun {
  readonly input: RunStepChainInput;
  resolve(result: RunStepChainResult): void;
  reject(error: unknown): void;
}

interface FakeChain {
  readonly runs: ChainRun[];
  readonly runChain: (input: RunStepChainInput) => Promise<RunStepChainResult>;
}

function createChain(): FakeChain {
  const runs: ChainRun[] = [];
  return {
    runs,
    runChain: (input) =>
      new Promise<RunStepChainResult>((resolve, reject) => {
        runs.push({ input, resolve, reject });
      }),
  };
}

/** A chain port whose body runs synchronously with the recorded input. */
function createInlineChain(
  handler: (input: RunStepChainInput) => Promise<RunStepChainResult>,
): FakeChain {
  const runs: ChainRun[] = [];
  return {
    runs,
    runChain: (input) => {
      runs.push({ input, resolve: () => undefined, reject: () => undefined });
      return handler(input);
    },
  };
}

interface FakeLearning {
  readonly port: StepRunnerLearningPort;
  readonly finalized: LearningFinalizeInput[];
  readonly discarded: string[];
  readonly disposeCount: () => number;
}

function createLearning(): FakeLearning {
  const finalized: LearningFinalizeInput[] = [];
  const discarded: string[] = [];
  let disposeCount = 0;
  return {
    port: {
      finalize: (input) => {
        finalized.push(input);
        return Promise.resolve({ ok: false as const, reason: "no-pending" });
      },
      discard: (toolCallId) => {
        discarded.push(toolCallId);
      },
      dispose: () => {
        disposeCount += 1;
      },
    },
    finalized,
    discarded,
    disposeCount: () => disposeCount,
  };
}

interface RunnerHarness {
  readonly runner: StepRunner;
  readonly clock: TestClock;
  readonly chain: FakeChain;
  readonly audit: StepAuditEvent[];
}

function makeRunner(
  options: {
    readonly clock?: TestClock;
    readonly generation?: () => number | undefined;
    readonly limits?: Partial<typeof STEP_RUNNER_LIMITS>;
    readonly learning?: StepRunnerLearningPort;
    readonly chain?: FakeChain;
    readonly onAudit?: (event: StepAuditEvent) => void;
  } = {},
): RunnerHarness {
  const clock = options.clock ?? createClock();
  const chain = options.chain ?? createChain();
  const audit: StepAuditEvent[] = [];
  const runner = createStepRunner({
    currentGeneration: options.generation ?? (() => DEFAULT_GENERATION),
    runChain: chain.runChain,
    now: clock.now,
    limits: options.limits,
    learning: options.learning,
    onAudit: options.onAudit ?? ((event) => audit.push(event)),
  } satisfies StepRunnerOptions);
  return { runner, clock, chain, audit };
}

function baseBeginInput(overrides: Partial<StepBeginInput> = {}): StepBeginInput {
  return {
    capture: makeCapture(),
    units: makeUnits(["call-1"]),
    nodes: NODES,
    generation: DEFAULT_GENERATION,
    mode: "auto-review",
    sessionFacts: makeFacts(),
    ...overrides,
  };
}

function beginOk(runner: StepRunner, overrides: Partial<StepBeginInput> = {}): StepHandle {
  const result = runner.begin(baseBeginInput(overrides));
  if (!result.ok) throw new Error(`expected begin to succeed, got ${result.reason}`);
  return result.handle;
}

function beginFailure(runner: StepRunner, overrides: Partial<StepBeginInput> = {}): string {
  const result = runner.begin(baseBeginInput(overrides));
  if (result.ok) throw new Error("expected begin to fail");
  return result.reason;
}

async function flushAsync(turns = 4): Promise<void> {
  for (let index = 0; index < turns; index += 1) await Promise.resolve();
}

// ---------------------------------------------------------------------------
// Slice 1: frozen limits, first chain run and per-call join sharing
// ---------------------------------------------------------------------------

describe("createStepRunner: limits and first chain run", () => {
  it("publishes the frozen default host boundaries", () => {
    expect(STEP_RUNNER_LIMITS).toEqual({
      nodeTimeoutMs: 30_000,
      resultTtlMs: 5 * 60_000,
      stepDeadlineMs: 5 * 60_000,
      maxActiveSteps: 64,
      maxPendingCalls: 512,
      maxSettledCalls: 512,
      settledRetentionMs: 60_000,
    });
    expect(Object.isFrozen(STEP_RUNNER_LIMITS)).toBe(true);
  });

  it("starts one chain run with the step facts, default deadline and configured limits", () => {
    const { runner, clock, chain } = makeRunner();
    const capture = makeCapture();
    const units = makeUnits(["call-1"]);
    const external = new AbortController();

    const handle = beginOk(runner, {
      capture,
      units,
      nodes: NODES,
      signal: external.signal,
      bashPrograms: BASH_PROGRAMS,
    });

    expect(handle.stepKey).toBe("step-1");
    expect(handle.captureDigest).toBe("capture-digest-1");
    expect(handle.generation).toBe(DEFAULT_GENERATION);
    expect(chain.runs).toHaveLength(1);

    const input = chain.runs[0].input;
    expect(input.capture).toBe(capture);
    expect(input.units).toBe(units);
    expect(input.nodes).toBe(NODES);
    expect(input.generation).toBe(DEFAULT_GENERATION);
    expect(input.mode).toBe("auto-review");
    expect(input.now).toBe(clock.now);
    expect(input.deadlineAt).toBe(CLOCK_START + STEP_RUNNER_LIMITS.stepDeadlineMs);
    expect(input.nodeTimeoutMs).toBe(STEP_RUNNER_LIMITS.nodeTimeoutMs);
    expect(input.resultTtlMs).toBe(STEP_RUNNER_LIMITS.resultTtlMs);
    expect(input.bashPrograms).toBe(BASH_PROGRAMS);
    expect(input.human).toBeUndefined();
    // The runtime never receives the caller's signal directly: the step links it.
    expect(input.signal).toBeDefined();
    expect(input.signal).not.toBe(external.signal);
    expect(input.signal?.aborted).toBe(false);

    expect(runner.state()).toEqual({ activeSteps: 1, pendingCalls: 1, settledCalls: 0 });
    expect(runner.hasStep("step-1")).toBe(true);
    expect(runner.hasStep("step-2")).toBe(false);
    expect(runner.hasCall("call-1")).toBe(true);
    expect(runner.hasCall("call-2")).toBe(false);
    expect(handle.done).toBeInstanceOf(Promise);

    external.abort();
    expect(input.signal?.aborted).toBe(true);
  });

  it("applies positive integer limit overrides and keeps defaults for invalid ones", () => {
    const { runner, clock, chain } = makeRunner({
      limits: {
        nodeTimeoutMs: 5_000,
        resultTtlMs: 60_000,
        stepDeadlineMs: 7_000,
        maxPendingCalls: 0,
      },
    });

    const first = beginOk(runner);
    void first;
    expect(chain.runs[0].input.nodeTimeoutMs).toBe(5_000);
    expect(chain.runs[0].input.resultTtlMs).toBe(60_000);
    expect(chain.runs[0].input.deadlineAt).toBe(CLOCK_START + 7_000);

    // `maxPendingCalls: 0` is not a positive integer, so the default applies
    // and a two-call capture still fits.
    expect(clock.now()).toBe(CLOCK_START);
    const second = beginOk(runner, {
      capture: makeCapture({ stepKey: "step-2", digest: "capture-digest-2", toolCallIds: ["call-2"] }),
      units: makeUnits(["call-2"]),
    });
    void second;
  });

  it("forwards an explicit deadline and the human approver to the chain run", () => {
    const { runner, chain } = makeRunner();
    const human: HumanApprover = () => ({ decision: "approve", reason: "ok" });

    beginOk(runner, { deadlineAt: CLOCK_START + 1_234, human });

    expect(chain.runs[0].input.deadlineAt).toBe(CLOCK_START + 1_234);
    expect(chain.runs[0].input.human).toBe(human);

    const { runner: nullDeadlineRunner, chain: nullDeadlineChain } = makeRunner();
    beginOk(nullDeadlineRunner, { deadlineAt: null });
    expect(nullDeadlineChain.runs[0].input.deadlineAt).toBeNull();
  });

  it("shares one join promise per direct call across handle and runner joins", () => {
    const { runner } = makeRunner();
    const capture = makeCapture({ toolCallIds: ["call-1", "call-2"] });
    const handle = beginOk(runner, { capture, units: makeUnits(["call-1", "call-2"]) });

    const handleJoin = handle.join("call-1");
    const runnerJoin = runner.join({ toolCallId: "call-1" });
    expect(handleJoin).toBe(runnerJoin);
    expect(runner.join({ toolCallId: "call-1" })).toBe(handleJoin);
    expect(handle.join("call-1")).toBe(handleJoin);
    // A different direct call has its own independent join.
    expect(handle.join("call-2")).not.toBe(handleJoin);
    expect(runner.state()).toEqual({ activeSteps: 1, pendingCalls: 2, settledCalls: 0 });
  });
});

// ---------------------------------------------------------------------------
// Slice 2: begin validation and the generation fence
// ---------------------------------------------------------------------------

describe("createStepRunner: begin validation and generation fence", () => {
  it("rejects malformed begin input with invalid-input and starts nothing", () => {
    const { runner, chain } = makeRunner();
    const base = makeCapture();
    const cases: readonly Partial<StepBeginInput>[] = [
      { capture: { ...base, directCalls: [] } as unknown as StepCapture },
      { capture: { ...base, complete: false } as unknown as StepCapture },
      { capture: { ...base, digest: "" } as unknown as StepCapture },
      {
        capture: {
          ...base,
          directCalls: [{ ...makeCall("call-1"), toolCallId: "" }],
        } as unknown as StepCapture,
      },
      {
        capture: {
          ...base,
          directCalls: [makeCall("call-1"), makeCall("call-1")],
        } as unknown as StepCapture,
      },
      { units: undefined as unknown as readonly UnitPreparation[] },
      { nodes: {} as unknown as readonly NodeBinding[] },
      { mode: "unknown" as ReviewerMode },
      { sessionFacts: undefined as unknown as ReviewerSessionFacts },
      { deadlineAt: -1 },
      { deadlineAt: 1.5 },
    ];

    for (const overrides of cases) {
      expect(beginFailure(runner, overrides)).toBe("invalid-input");
    }
    expect(runner.state()).toEqual({ activeSteps: 0, pendingCalls: 0, settledCalls: 0 });
    expect(chain.runs).toHaveLength(0);
  });

  it("rejects a negative or fractional generation with invalid-input", () => {
    const { runner, chain } = makeRunner();
    expect(beginFailure(runner, { generation: -1 })).toBe("invalid-input");
    expect(beginFailure(runner, { generation: 1.5 })).toBe("invalid-input");
    expect(chain.runs).toHaveLength(0);
  });

  it("rejects a step whose generation is not the current publication generation", () => {
    const { runner, chain } = makeRunner({ generation: () => 4 });
    expect(beginFailure(runner, { generation: 3 })).toBe("generation-stale");
    expect(chain.runs).toHaveLength(0);

    const { runner: unavailable, chain: unavailableChain } = makeRunner({
      generation: () => undefined,
    });
    expect(beginFailure(unavailable, { generation: 3 })).toBe("generation-stale");
    expect(unavailableChain.runs).toHaveLength(0);
    expect(unavailable.state()).toEqual({ activeSteps: 0, pendingCalls: 0, settledCalls: 0 });
  });
});

// ---------------------------------------------------------------------------
// Slice 3: same-step handle reuse and digest mismatch
// ---------------------------------------------------------------------------

describe("createStepRunner: same-step handle reuse and digest mismatch", () => {
  it("returns the existing handle for the same stepKey and captureDigest without rerunning the chain", () => {
    const { runner, chain } = makeRunner();
    const first = beginOk(runner);

    const second = runner.begin(baseBeginInput());
    expect(second.ok).toBe(true);
    if (!second.ok) throw new Error("expected the existing handle");
    expect(second.handle).toBe(first);
    expect(chain.runs).toHaveLength(1);
    expect(runner.state()).toEqual({ activeSteps: 1, pendingCalls: 1, settledCalls: 0 });
  });

  it("rejects a same-step begin whose captureDigest differs", () => {
    const { runner, chain } = makeRunner();
    beginOk(runner);

    expect(beginFailure(runner, { capture: makeCapture({ digest: "capture-digest-2" }) })).toBe(
      "capture-mismatch",
    );
    expect(chain.runs).toHaveLength(1);
    expect(runner.state()).toEqual({ activeSteps: 1, pendingCalls: 1, settledCalls: 0 });
  });
});

// ---------------------------------------------------------------------------
// Slice 4: active step and pending call capacity
// ---------------------------------------------------------------------------

describe("createStepRunner: capacity", () => {
  it("rejects a new step while the active step limit is reached", async () => {
    const { runner, chain } = makeRunner({ limits: { maxActiveSteps: 1 } });
    beginOk(runner);
    expect(
      beginFailure(runner, {
        capture: makeCapture({ stepKey: "step-2", digest: "capture-digest-2" }),
      }),
    ).toBe("capacity");
    expect(chain.runs).toHaveLength(1);

    chain.runs[0].resolve(chainOk(makeState(["call-1"]), [makeFinalResult("call-1", "allow")]));
    await flushAsync();
    expect(runner.state()).toEqual({ activeSteps: 0, pendingCalls: 0, settledCalls: 1 });

    beginOk(runner, {
      capture: makeCapture({ stepKey: "step-2", digest: "capture-digest-2" }),
      units: makeUnits(["call-1"]),
    });
    expect(chain.runs).toHaveLength(2);
  });

  it("rejects a begin whose direct calls would exceed the pending call limit", () => {
    const { runner, chain } = makeRunner({ limits: { maxPendingCalls: 2 } });
    beginOk(runner, {
      capture: makeCapture({ toolCallIds: ["call-1", "call-2"] }),
      units: makeUnits(["call-1", "call-2"]),
    });
    expect(
      beginFailure(runner, {
        capture: makeCapture({ stepKey: "step-2", digest: "capture-digest-2", toolCallIds: ["call-3"] }),
        units: makeUnits(["call-3"]),
      }),
    ).toBe("capacity");
    expect(chain.runs).toHaveLength(1);

    const { runner: fresh, chain: freshChain } = makeRunner({
      limits: { maxPendingCalls: 2 },
    });
    expect(
      beginFailure(fresh, {
        capture: makeCapture({ toolCallIds: ["call-1", "call-2", "call-3"] }),
        units: makeUnits(["call-1", "call-2", "call-3"]),
      }),
    ).toBe("capacity");
    expect(freshChain.runs).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Slice 5: published chain results reach the per-call joins
// ---------------------------------------------------------------------------

describe("createStepRunner: published chain results", () => {
  it("delivers allow, deny and escalate results to their own joins", async () => {
    const { runner, chain } = makeRunner();
    const toolCallIds = ["call-1", "call-2", "call-3"];
    const handle = beginOk(runner, {
      capture: makeCapture({ toolCallIds }),
      units: makeUnits(toolCallIds),
    });
    const joins = toolCallIds.map((toolCallId) => handle.join(toolCallId));

    const state = makeState(toolCallIds);
    const results = [
      makeFinalResult("call-1", "allow"),
      makeFinalResult("call-2", "deny"),
      makeFinalResult("call-3", "escalate"),
    ];
    chain.runs[0].resolve(chainOk(state, results));

    const outcomes = await Promise.all(joins);
    expect(outcomes).toEqual([
      { decision: "allow", result: results[0] },
      { decision: "deny", result: results[1] },
      { decision: "escalate", result: results[2] },
    ]);

    const doneOutcomes = await handle.done;
    expect(doneOutcomes).toHaveLength(3);
    expect(doneOutcomes[0]).toBe(outcomes[0]);
    expect(doneOutcomes[1]).toBe(outcomes[1]);
    expect(doneOutcomes[2]).toBe(outcomes[2]);
  });

  it("delivers one call's allow before a sibling call and its human prompt finish", async () => {
    const order: string[] = [];
    let releaseSibling: (() => void) | undefined;
    const siblingGate = new Promise<void>((resolve) => {
      releaseSibling = resolve;
    });
    const chain = createInlineChain(async (input) => {
      const first = makeFinalResult("call-1", "allow");
      input.onReady?.(first, makeState(["call-1", "call-2"]));
      await siblingGate;
      return chainOk(
        makeState(["call-1", "call-2"]),
        [first],
        ["call-2"],
        "needs-human",
      );
    });
    const { runner } = makeRunner({ chain });
    const toolCallIds = ["call-1", "call-2"];
    const handle = beginOk(runner, {
      capture: makeCapture({ toolCallIds }),
      units: makeUnits(toolCallIds),
      onFinal: (result) => {
        order.push(`onFinal:${result.toolCallId}`);
      },
    });
    const first = handle.join("call-1").then((outcome) => {
      order.push(`join:${outcome.decision === "blocked" ? outcome.reason : outcome.result.toolCallId}`);
      return outcome;
    });

    // The first call is delivered while the sibling gate is still closed.
    const firstOutcome = await first;
    expect(firstOutcome).toEqual({
      decision: "allow",
      result: expect.objectContaining({ toolCallId: "call-1" }),
    });
    expect(order).toEqual(["onFinal:call-1", "join:call-1"]);

    releaseSibling?.();
    const [secondOutcome] = await Promise.all([handle.join("call-2"), handle.done]);
    expect(secondOutcome).toEqual({
      decision: "blocked",
      reason: "needs-human",
    });
  });

  it("retires the active step and keeps its settled results joinable", async () => {
    const { runner, chain } = makeRunner();
    const handle = beginOk(runner);
    const joinBeforeSettled = handle.join("call-1");

    const results = [makeFinalResult("call-1", "allow")];
    chain.runs[0].resolve(chainOk(makeState(["call-1"]), results));

    expect(await joinBeforeSettled).toEqual({ decision: "allow", result: results[0] });
    expect(runner.state()).toEqual({ activeSteps: 0, pendingCalls: 0, settledCalls: 1 });
    expect(runner.hasStep("step-1")).toBe(false);
    expect(runner.hasCall("call-1")).toBe(true);

    const late = await runner.join({ toolCallId: "call-1" });
    expect(late).toEqual({ decision: "allow", result: results[0] });
    expect(await handle.join("call-1")).toEqual({ decision: "allow", result: results[0] });
    expect(await runner.join({ toolCallId: "call-missing" })).toEqual({
      decision: "blocked",
      reason: "unknown-step",
    });
  });

  it("orders the collected outcomes by the capture's direct calls, not by result order", async () => {
    const { runner, chain } = makeRunner();
    const toolCallIds = ["call-1", "call-2"];
    const handle = beginOk(runner, {
      capture: makeCapture({ toolCallIds }),
      units: makeUnits(toolCallIds),
    });
    const results = [makeFinalResult("call-2", "deny"), makeFinalResult("call-1", "allow")];

    chain.runs[0].resolve(chainOk(makeState(toolCallIds), results));

    const outcomes = await handle.done;
    expect(outcomes.map((outcome) => (outcome.decision === "blocked" ? outcome.reason : outcome.result.toolCallId)))
      .toEqual(["call-1", "call-2"]);
  });
});

// ---------------------------------------------------------------------------
// Slice 6: blocked endings
// ---------------------------------------------------------------------------

describe("createStepRunner: blocked endings", () => {
  it("blocks every pending call when the chain run reports failure", async () => {
    const { runner, chain } = makeRunner();
    const toolCallIds = ["call-1", "call-2"];
    const handle = beginOk(runner, {
      capture: makeCapture({ toolCallIds }),
      units: makeUnits(toolCallIds),
    });

    chain.runs[0].resolve(chainFailed("prepare-failed"));

    expect(await handle.join("call-1")).toEqual({ decision: "blocked", reason: "chain-failed" });
    expect(await handle.join("call-2")).toEqual({ decision: "blocked", reason: "chain-failed" });
    expect(runner.state()).toEqual({ activeSteps: 0, pendingCalls: 0, settledCalls: 2 });
  });

  it("blocks every pending call when the chain run rejects", async () => {
    const { runner, chain } = makeRunner();
    const handle = beginOk(runner);

    chain.runs[0].reject(new Error("chain exploded"));

    expect(await handle.join("call-1")).toEqual({ decision: "blocked", reason: "chain-failed" });
    expect(await handle.done).toEqual([{ decision: "blocked", reason: "chain-failed" }]);
  });

  it("keeps published results and blocks the rest for cancelled, deadline and needs-human endings", async () => {
    for (const [status, expectedReason] of [
      ["cancelled", "chain-cancelled"],
      ["deadline", "chain-deadline"],
      ["needs-human", "needs-human"],
    ] as const) {
      const { runner, chain } = makeRunner();
      const toolCallIds = ["call-1", "call-2"];
      const handle = beginOk(runner, {
        capture: makeCapture({ toolCallIds }),
        units: makeUnits(toolCallIds),
      });
      const results = [makeFinalResult("call-1", "allow")];

      chain.runs[0].resolve(chainOk(makeState(toolCallIds), results, ["call-2"], status));

      expect(await handle.join("call-1")).toEqual({ decision: "allow", result: results[0] });
      expect(await handle.join("call-2")).toEqual({ decision: "blocked", reason: expectedReason });
      expect(runner.state()).toEqual({ activeSteps: 0, pendingCalls: 0, settledCalls: 2 });
    }
  });

  it("blocks a completed call without a result with no-result", async () => {
    const { runner, chain } = makeRunner();
    const toolCallIds = ["call-1", "call-2"];
    const handle = beginOk(runner, {
      capture: makeCapture({ toolCallIds }),
      units: makeUnits(toolCallIds),
    });

    chain.runs[0].resolve(chainOk(makeState(toolCallIds), [makeFinalResult("call-1", "allow")]));

    expect(await handle.join("call-1")).toEqual({
      decision: "allow",
      result: expect.objectContaining({ toolCallId: "call-1" }),
    });
    expect(await handle.join("call-2")).toEqual({ decision: "blocked", reason: "no-result" });
    expect(runner.state()).toEqual({ activeSteps: 0, pendingCalls: 0, settledCalls: 2 });
  });

  it("blocks pending calls when the caller's signal aborts and ignores the late chain result", async () => {
    const { runner, chain } = makeRunner();
    const toolCallIds = ["call-1", "call-2"];
    const external = new AbortController();
    const handle = beginOk(runner, {
      capture: makeCapture({ toolCallIds }),
      units: makeUnits(toolCallIds),
      signal: external.signal,
    });

    external.abort();
    expect(await handle.join("call-1")).toEqual({ decision: "blocked", reason: "aborted" });
    expect(await handle.join("call-2")).toEqual({ decision: "blocked", reason: "aborted" });
    expect(runner.state()).toEqual({ activeSteps: 0, pendingCalls: 0, settledCalls: 2 });

    // A late allow from the still-running chain never reaches the joins.
    chain.runs[0].resolve(chainOk(makeState(toolCallIds), [makeFinalResult("call-1", "allow")]));
    await flushAsync();
    expect(await handle.join("call-1")).toEqual({ decision: "blocked", reason: "aborted" });
  });

  it("ends an already-aborted step without starting a chain run", async () => {
    const { runner, chain } = makeRunner();
    const external = new AbortController();
    external.abort();

    const handle = beginOk(runner, { signal: external.signal });

    expect(await handle.join("call-1")).toEqual({ decision: "blocked", reason: "aborted" });
    expect(chain.runs).toHaveLength(0);
    expect(runner.state()).toEqual({ activeSteps: 0, pendingCalls: 0, settledCalls: 1 });
  });
});

// ---------------------------------------------------------------------------
// Slice 7: settled retention, eviction and join identity checks
// ---------------------------------------------------------------------------

describe("createStepRunner: settled results", () => {
  it("joins a settled result inside the retention window and forgets it afterwards", async () => {
    const { runner, chain, clock } = makeRunner({ limits: { settledRetentionMs: 1_000 } });
    const handle = beginOk(runner);
    const results = [makeFinalResult("call-1", "allow")];
    chain.runs[0].resolve(chainOk(makeState(["call-1"]), results));
    await handle.done;

    clock.advance(999);
    expect(runner.hasCall("call-1")).toBe(true);
    expect(await runner.join({ toolCallId: "call-1" })).toEqual({
      decision: "allow",
      result: results[0],
    });

    clock.advance(1);
    expect(runner.hasCall("call-1")).toBe(false);
    expect(runner.state()).toEqual({ activeSteps: 0, pendingCalls: 0, settledCalls: 0 });
    expect(await runner.join({ toolCallId: "call-1" })).toEqual({
      decision: "blocked",
      reason: "unknown-step",
    });
  });

  it("stops joining a settled result whose published TTL has elapsed", async () => {
    const { runner, chain, clock } = makeRunner({
      limits: { resultTtlMs: 1_000, settledRetentionMs: 60_000 },
    });
    const handle = beginOk(runner);
    const results = [makeFinalResult("call-1", "allow", { expiresAt: CLOCK_START + 1_000 })];
    chain.runs[0].resolve(chainOk(makeState(["call-1"]), results));
    await handle.done;

    clock.advance(1_000);
    expect(runner.hasCall("call-1")).toBe(false);
    expect(await runner.join({ toolCallId: "call-1" })).toEqual({
      decision: "blocked",
      reason: "unknown-step",
    });
  });

  it("evicts the oldest settled results beyond the settled call capacity", async () => {
    const { runner, chain } = makeRunner({ limits: { maxSettledCalls: 2 } });
    const toolCallIds = ["call-1", "call-2", "call-3"];
    const handle = beginOk(runner, {
      capture: makeCapture({ toolCallIds }),
      units: makeUnits(toolCallIds),
    });
    chain.runs[0].resolve(
      chainOk(
        makeState(toolCallIds),
        toolCallIds.map((toolCallId) => makeFinalResult(toolCallId, "allow")),
      ),
    );
    await handle.done;

    expect(runner.state()).toEqual({ activeSteps: 0, pendingCalls: 0, settledCalls: 2 });
    expect(runner.hasCall("call-1")).toBe(false);
    expect(runner.hasCall("call-2")).toBe(true);
    expect(runner.hasCall("call-3")).toBe(true);

    // Keep one active step so a forgotten call is reported as an unknown call.
    beginOk(runner, {
      capture: makeCapture({ stepKey: "step-2", digest: "capture-digest-2", toolCallIds: ["call-4"] }),
      units: makeUnits(["call-4"]),
    });
    expect(await runner.join({ toolCallId: "call-1" })).toEqual({
      decision: "blocked",
      reason: "unknown-call",
    });
  });

  it("requires the supplied captureDigest to match on both pending and settled joins", async () => {
    const { runner, chain } = makeRunner();
    const handle = beginOk(runner);

    expect(await runner.join({ toolCallId: "call-1", captureDigest: "cap-2" })).toEqual({
      decision: "blocked",
      reason: "capture-mismatch",
    });

    const results = [makeFinalResult("call-1", "allow")];
    chain.runs[0].resolve(chainOk(makeState(["call-1"]), results));
    await handle.done;

    expect(await runner.join({ toolCallId: "call-1", captureDigest: "cap-2" })).toEqual({
      decision: "blocked",
      reason: "capture-mismatch",
    });
    expect(
      await runner.join({ toolCallId: "call-1", captureDigest: "capture-digest-1" }),
    ).toEqual({ decision: "allow", result: results[0] });
  });
});

// ---------------------------------------------------------------------------
// Slice 8: audit envelope and reason sanitization
// ---------------------------------------------------------------------------

describe("createStepRunner: audit envelope", () => {
  const nodeEntry: ChainAuditEntry = {
    kind: "node",
    nodeId: "builtin/rules",
    position: "post",
    priority: null,
    revisionBefore: 1,
    revisionAfter: 2,
    outcome: "fault",
    reason: "rules:bash:deny command: rm -rf /tmp/x",
  };
  const startEntry: ChainNodeStartEntry = {
    kind: "node-start",
    nodeId: "builtin/rules",
    position: "post",
    priority: null,
    revision: 2,
  };
  const unitChanges: readonly ChainUnitChange[] = [
    {
      toolCallId: "call-1",
      unitId: "call-1:unit-1",
      nodeId: "builtin/rules",
      revision: 2,
      decision: "deny",
      reason: "rules:bash:deny `git push --force`",
    },
  ];

  it("completes node events with the step identity and omits embedded command fragments", () => {
    const chain = createInlineChain((input) => {
      input.host?.log(nodeEntry);
      input.host?.nodeStarted?.(startEntry);
      input.host?.unitsAccepted?.(unitChanges);
      return new Promise<RunStepChainResult>(() => undefined);
    });
    const { runner, audit } = makeRunner({ chain });

    beginOk(runner);

    // The node events are written while the chain runs, before any join delivery.
    expect(audit).toEqual([
      {
        kind: "node",
        generation: DEFAULT_GENERATION,
        stepKey: "step-1",
        captureDigest: "capture-digest-1",
        entry: { ...nodeEntry, reason: "rules:bash:deny command: …" },
      },
      {
        kind: "node-start",
        generation: DEFAULT_GENERATION,
        stepKey: "step-1",
        captureDigest: "capture-digest-1",
        entry: startEntry,
      },
      {
        kind: "unit-change",
        generation: DEFAULT_GENERATION,
        stepKey: "step-1",
        captureDigest: "capture-digest-1",
        changes: [{ ...unitChanges[0], reason: "rules:bash:deny …" }],
      },
    ]);
  });

  it("leaves reasons without embedded commands untouched", () => {
    const chain = createInlineChain((input) => {
      input.host?.log({
        kind: "node",
        nodeId: "builtin/mode",
        position: "post",
        priority: null,
        revisionBefore: 2,
        revisionAfter: 3,
        outcome: "noop",
        reason: "mode:default:network-needs-approval",
      });
      return new Promise<RunStepChainResult>(() => undefined);
    });
    const { runner, audit } = makeRunner({ chain });

    beginOk(runner);

    expect(audit).toEqual([
      expect.objectContaining({
        kind: "node",
        entry: expect.objectContaining({ reason: "mode:default:network-needs-approval" }),
      }),
    ]);
  });

  it("redacts the Bash fragment embedded by the structure-analysis reason format", () => {
    const chain = createInlineChain((input) => {
      input.host?.log({
        kind: "node",
        nodeId: "builtin/structure-analysis",
        position: "front",
        priority: null,
        revisionBefore: 1,
        revisionAfter: 1,
        outcome: "fault",
        reason: "structure:bash:2:rm -rf /tmp/secret",
      });
      return new Promise<RunStepChainResult>(() => undefined);
    });
    const { runner, audit } = makeRunner({ chain });

    beginOk(runner);

    expect(audit).toEqual([
      expect.objectContaining({
        kind: "node",
        entry: expect.objectContaining({ reason: "structure:bash:2:…" }),
      }),
    ]);
  });

  it("keeps a throwing audit observer from changing the delivered outcome", async () => {
    const { runner, chain } = makeRunner({
      onAudit: () => {
        throw new Error("audit sink down");
      },
    });
    const handle = beginOk(runner);

    chain.runs[0].input.host?.log(nodeEntry);
    const results = [makeFinalResult("call-1", "allow")];
    chain.runs[0].resolve(chainOk(makeState(["call-1"]), results));

    expect(await handle.join("call-1")).toEqual({ decision: "allow", result: results[0] });
    expect(runner.state()).toEqual({ activeSteps: 0, pendingCalls: 0, settledCalls: 1 });
  });
});

// ---------------------------------------------------------------------------
// Slice 9: the onFinal observer runs before the join is delivered
// ---------------------------------------------------------------------------

describe("createStepRunner: onFinal observer", () => {
  it("runs onFinal before the join promise resolves with the final state", async () => {
    const order: string[] = [];
    const observed: { result?: FinalCallResult; state?: StepState } = {};
    const { runner, chain } = makeRunner();
    const handle = beginOk(runner, {
      onFinal: (result, state) => {
        order.push("final");
        observed.result = result;
        observed.state = state;
      },
    });
    const join = handle.join("call-1").then((outcome) => {
      order.push("join");
      return outcome;
    });

    const state = makeState(["call-1"]);
    const results = [makeFinalResult("call-1", "allow")];
    chain.runs[0].resolve(chainOk(state, results));

    const outcome = await join;
    expect(order).toEqual(["final", "join"]);
    expect(observed.result).toBe(results[0]);
    expect(observed.state).toBe(state);
    expect(outcome).toEqual({ decision: "allow", result: results[0] });
  });

  it("never calls onFinal for a blocked outcome", async () => {
    const seen: FinalCallResult[] = [];
    const { runner, chain } = makeRunner();
    const handle = beginOk(runner, { onFinal: (result) => seen.push(result) });

    chain.runs[0].resolve(chainFailed("invalid-input"));

    expect(await handle.join("call-1")).toEqual({ decision: "blocked", reason: "chain-failed" });
    expect(seen).toHaveLength(0);
  });

  it("keeps a throwing onFinal from changing the delivered outcome", async () => {
    const { runner, chain } = makeRunner();
    const handle = beginOk(runner, {
      onFinal: () => {
        throw new Error("final observer down");
      },
    });
    const results = [makeFinalResult("call-1", "deny")];
    chain.runs[0].resolve(chainOk(makeState(["call-1"]), results));

    expect(await handle.join("call-1")).toEqual({ decision: "deny", result: results[0] });
    expect(runner.state()).toEqual({ activeSteps: 0, pendingCalls: 0, settledCalls: 1 });
  });
});

// ---------------------------------------------------------------------------
// Slice 10: generation fencing at publication
// ---------------------------------------------------------------------------

describe("createStepRunner: generation fencing at publication", () => {
  it("refuses to install an allow when the publication generation moved on", async () => {
    let generation: number | undefined = DEFAULT_GENERATION;
    const { runner, chain } = makeRunner({ generation: () => generation });
    const onFinalSeen: FinalCallResult[] = [];
    const handle = beginOk(runner, { onFinal: (result) => onFinalSeen.push(result) });
    const join = handle.join("call-1");

    generation = DEFAULT_GENERATION + 1;
    chain.runs[0].resolve(chainOk(makeState(["call-1"]), [makeFinalResult("call-1", "allow")]));

    expect(await join).toEqual({ decision: "blocked", reason: "generation-stale" });
    expect(onFinalSeen).toHaveLength(0);
    expect(runner.state()).toEqual({ activeSteps: 0, pendingCalls: 0, settledCalls: 1 });
    // A late join never sees the old allow either.
    expect(await runner.join({ toolCallId: "call-1" })).toEqual({
      decision: "blocked",
      reason: "generation-stale",
    });
  });

  it("treats an unavailable current generation as stale at publication", async () => {
    let generation: number | undefined = DEFAULT_GENERATION;
    const { runner, chain } = makeRunner({ generation: () => generation });
    const handle = beginOk(runner);
    const join = handle.join("call-1");

    generation = undefined;
    chain.runs[0].resolve(chainOk(makeState(["call-1"]), [makeFinalResult("call-1", "allow")]));

    expect(await join).toEqual({ decision: "blocked", reason: "generation-stale" });
  });
});

// ---------------------------------------------------------------------------
// Slice 11: invalidate and dispose
// ---------------------------------------------------------------------------

describe("createStepRunner: invalidate and dispose", () => {
  it("blocks active calls and clears settled results on invalidate", async () => {
    const { runner, chain } = makeRunner();
    const first = beginOk(runner);
    const firstResults = [makeFinalResult("call-1", "allow")];
    chain.runs[0].resolve(chainOk(makeState(["call-1"]), firstResults));
    await first.done;

    const second = beginOk(runner, {
      capture: makeCapture({ stepKey: "step-2", digest: "capture-digest-2", toolCallIds: ["call-2"] }),
      units: makeUnits(["call-2"]),
    });
    const secondJoin = second.join("call-2");

    runner.invalidate();

    expect(await secondJoin).toEqual({ decision: "blocked", reason: "aborted" });
    expect(runner.state()).toEqual({ activeSteps: 0, pendingCalls: 0, settledCalls: 0 });
    expect(runner.hasStep("step-2")).toBe(false);
    expect(runner.hasCall("call-1")).toBe(false);
    expect(await runner.join({ toolCallId: "call-1" })).toEqual({
      decision: "blocked",
      reason: "unknown-step",
    });

    // The still-running chain cannot satisfy a join after invalidation.
    chain.runs[1].resolve(chainOk(makeState(["call-2"]), [makeFinalResult("call-2", "allow")]));
    await flushAsync();
    expect(await runner.join({ toolCallId: "call-2" })).toEqual({
      decision: "blocked",
      reason: "unknown-step",
    });
  });

  it("disposes idempotently, blocks active calls as disposed and releases learning once", async () => {
    const learning = createLearning();
    const { runner, chain } = makeRunner({ learning: learning.port });
    const handle = beginOk(runner);
    const join = handle.join("call-1");

    runner.dispose();
    runner.dispose();

    expect(await join).toEqual({ decision: "blocked", reason: "disposed" });
    expect(runner.state()).toEqual({ activeSteps: 0, pendingCalls: 0, settledCalls: 0 });
    expect(learning.disposeCount()).toBe(1);
    expect(beginFailure(runner)).toBe("invalid-input");

    // A chain result arriving after dispose is ignored; the step facts are gone.
    chain.runs[0].resolve(chainOk(makeState(["call-1"]), [makeFinalResult("call-1", "allow")]));
    await flushAsync();
    expect(await handle.join("call-1")).toEqual({ decision: "blocked", reason: "unknown-call" });
  });
});

// ---------------------------------------------------------------------------
// Slice 12: a step may only be started once per capture identity
// ---------------------------------------------------------------------------

describe("createStepRunner: duplicate step", () => {
  it("rejects re-beginning a step while its settled results are still joinable", async () => {
    const { runner, chain, clock } = makeRunner({ limits: { settledRetentionMs: 1_000 } });
    const first = beginOk(runner);
    chain.runs[0].resolve(chainOk(makeState(["call-1"]), [makeFinalResult("call-1", "allow")]));
    await first.done;

    expect(beginFailure(runner)).toBe("duplicate-step");
    expect(beginFailure(runner, { capture: makeCapture({ digest: "capture-digest-2" }) })).toBe(
      "capture-mismatch",
    );
    expect(chain.runs).toHaveLength(1);

    // The new step can only start once the previous step's window is gone.
    clock.advance(1_000);
    beginOk(runner, { capture: makeCapture({ digest: "capture-digest-2" }) });
    expect(chain.runs).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// Slice 13: deferred learning release
// ---------------------------------------------------------------------------

describe("createStepRunner: deferred learning", () => {
  it("finalizes the allowed calls after the join was delivered", async () => {
    const order: string[] = [];
    const finalized: LearningFinalizeInput[] = [];
    const dropped: string[] = [];
    const learning: StepRunnerLearningPort = {
      finalize: (input) => {
        order.push("finalize");
        finalized.push(input);
        return Promise.resolve({ ok: true });
      },
      discard: (toolCallId) => {
        dropped.push(toolCallId);
      },
    };
    const { runner, chain } = makeRunner({ learning });
    const facts = makeFacts("owner-a");
    const toolCallIds = ["call-1", "call-2"];
    const handle = beginOk(runner, {
      capture: makeCapture({ toolCallIds }),
      units: makeUnits(toolCallIds),
      sessionFacts: facts,
    });
    const join = handle.join("call-1").then((outcome) => {
      order.push("join");
      return outcome;
    });

    const state = makeState(toolCallIds);
    const results = [makeFinalResult("call-1", "allow"), makeFinalResult("call-2", "deny")];
    chain.runs[0].resolve(chainOk(state, results));
    await join;
    await flushAsync();

    expect(order).toEqual(["join", "finalize"]);
    expect(dropped).toEqual(["call-2"]);
    expect(finalized).toHaveLength(1);
    expect(finalized[0]).toEqual({
      stepKey: "step-1",
      sessionId: "session-1",
      owner: "owner-a",
      calls: [
        {
          toolCallId: "call-1",
          toolName: "bash",
          arguments: {},
          argumentsDigest: "a".repeat(64),
          digest: "call-digest-call-1",
          units: state.calls[0].units,
          decision: "allow",
        },
      ],
      mode: "auto-review",
      revisions: facts.revisions,
      signal: chain.runs[0].input.signal,
      deadline: CLOCK_START + STEP_RUNNER_LIMITS.stepDeadlineMs,
    });
  });

  it("discards blocked calls and never finalizes when no call ended allow", async () => {
    const learning = createLearning();
    const { runner, chain } = makeRunner({ learning: learning.port });
    const toolCallIds = ["call-1", "call-2"];
    const handle = beginOk(runner, {
      capture: makeCapture({ toolCallIds }),
      units: makeUnits(toolCallIds),
    });

    chain.runs[0].resolve(chainOk(makeState(toolCallIds), [], toolCallIds, "cancelled"));
    await handle.done;
    await flushAsync();

    expect(learning.finalized).toHaveLength(0);
    expect(learning.discarded).toEqual(["call-1", "call-2"]);
  });

  it("keeps a throwing or rejecting finalize from changing the delivered outcome", async () => {
    const throwing: StepRunnerLearningPort = {
      finalize: () => {
        throw new Error("finalize threw");
      },
      discard: () => undefined,
    };
    const { runner, chain } = makeRunner({ learning: throwing });
    const handle = beginOk(runner);
    const join = handle.join("call-1");
    const results = [makeFinalResult("call-1", "allow")];
    chain.runs[0].resolve(chainOk(makeState(["call-1"]), results));

    expect(await join).toEqual({ decision: "allow", result: results[0] });
    await flushAsync();
    expect(runner.state()).toEqual({ activeSteps: 0, pendingCalls: 0, settledCalls: 1 });

    const rejecting: StepRunnerLearningPort = {
      finalize: () => Promise.reject(new Error("commit down")),
      discard: () => undefined,
    };
    const { runner: rejectingRunner, chain: rejectingChain } = makeRunner({ learning: rejecting });
    const rejectingHandle = beginOk(rejectingRunner);
    const rejectingJoin = rejectingHandle.join("call-1");
    rejectingChain.runs[0].resolve(
      chainOk(makeState(["call-1"]), [makeFinalResult("call-1", "allow")]),
    );

    expect(await rejectingJoin).toEqual({
      decision: "allow",
      result: expect.objectContaining({ toolCallId: "call-1" }),
    });
    await flushAsync();
  });
});

// ---------------------------------------------------------------------------
// Slice 14: join cancellation and invalid join input
// ---------------------------------------------------------------------------

describe("createStepRunner: join boundaries", () => {
  it("cancels only the joining caller when its own signal aborts", async () => {
    const { runner, chain } = makeRunner();
    const handle = beginOk(runner);
    const caller = new AbortController();
    const signalJoin = handle.join("call-1", { signal: caller.signal });

    caller.abort();
    expect(await signalJoin).toEqual({ decision: "blocked", reason: "aborted" });

    const results = [makeFinalResult("call-1", "allow")];
    chain.runs[0].resolve(chainOk(makeState(["call-1"]), results));
    // The step still delivers its own result to a caller that did not abort.
    expect(await handle.join("call-1")).toEqual({ decision: "allow", result: results[0] });
    expect(runner.state()).toEqual({ activeSteps: 0, pendingCalls: 0, settledCalls: 1 });
  });

  it("answers an already aborted join signal with a blocked aborted outcome", async () => {
    const { runner, chain } = makeRunner();
    const handle = beginOk(runner);
    const caller = new AbortController();
    caller.abort();

    expect(await handle.join("call-1", { signal: caller.signal })).toEqual({
      decision: "blocked",
      reason: "aborted",
    });
    expect(await runner.join({ toolCallId: "call-1", signal: caller.signal })).toEqual({
      decision: "blocked",
      reason: "aborted",
    });

    const results = [makeFinalResult("call-1", "allow")];
    chain.runs[0].resolve(chainOk(makeState(["call-1"]), results));
    expect(await handle.join("call-1")).toEqual({ decision: "allow", result: results[0] });
  });

  it("rejects an empty tool call id with invalid-input", async () => {
    const { runner } = makeRunner();
    expect(await runner.join({ toolCallId: "" })).toEqual({
      decision: "blocked",
      reason: "invalid-input",
    });
    const handle = beginOk(runner);
    expect(await handle.join("")).toEqual({ decision: "blocked", reason: "invalid-input" });
  });
});

