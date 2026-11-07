/**
 * Phase 11 Full/Delta reviewer context store (specs/reviewer-context.md §8).
 *
 * Every fixture is a hand-built frozen `ReviewView` / `ReviewerSessionFacts`
 * built through small helpers below; the clock is injected and every expected
 * value is a worked example from the spec, never recomputed from the
 * implementation. No module internals are mocked.
 */
import { describe, expect, it } from "vitest";
import {
  createReviewerContextStore,
  type ReviewerContextStoreOptions,
} from "#approve-core/context/store";
import {
  projectDeltaEvidence,
  projectFullEvidence,
  transcriptPrefixDigest,
} from "#approve-core/context/projection";
import {
  reviewDigest,
  type ContextBeginFailure,
  type ContextCommitFailure,
  type ContextSelection,
  type ReviewAuthorizationEntry,
  type ReviewerContextConsumerState,
  type ReviewerContextStop,
  type ReviewerContextStore,
  type ReviewerMode,
  type ReviewerSessionFacts,
  type ReviewRevisions,
  type ReviewTranscriptEntry,
  type ReviewView,
} from "#approve-core/context/types";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const CLOCK_START = 1_000_000;

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const item of Object.values(value as Record<string, unknown>)) deepFreeze(item);
  return value;
}

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

function makeEntry(key: string, overrides: Partial<ReviewTranscriptEntry> = {}): ReviewTranscriptEntry {
  const content = overrides.content ?? `content:${key}`;
  return deepFreeze({
    entryKey: key,
    sourceEntryId: key,
    kind: "assistant" as const,
    content,
    edited: false,
    digest: reviewDigest({ entryKey: key, content }),
    ...overrides,
  }) as ReviewTranscriptEntry;
}

/** Deterministic transcript of assistant text entries `start`..`start + count - 1`. */
function makeTranscript(start: number, count: number): ReviewTranscriptEntry[] {
  return Array.from({ length: count }, (_, index) => makeEntry(`e${start + index}`));
}

function makeAuthorization(id: string, text: string): ReviewAuthorizationEntry {
  return deepFreeze({ id, sourceEntryId: `source-${id}`, text });
}

interface ViewInput {
  owner?: string;
  sessionId?: string;
  historyVersion?: number;
  captureSeq?: number;
  transcript?: readonly ReviewTranscriptEntry[];
  authorization?: readonly ReviewAuthorizationEntry[];
}

function makeView(input: ViewInput = {}): ReviewView {
  return deepFreeze({
    owner: input.owner ?? "owner-a",
    sessionId: input.sessionId ?? "session-a",
    historyVersion: input.historyVersion ?? 1,
    captureSeq: input.captureSeq ?? 1,
    leafId: "leaf-1",
    branchRootId: "root-1",
    transcript: [...(input.transcript ?? [])],
    authorization: [...(input.authorization ?? [])],
    degraded: false,
  }) as ReviewView;
}

function makeRevisions(overrides: Partial<ReviewRevisions> = {}): ReviewRevisions {
  return {
    owner: 1,
    navigation: 1,
    authorization: 1,
    projectRules: 1,
    intent: 1,
    ...overrides,
  };
}

function makeFacts(
  view: ReviewView,
  options: { revisions?: Partial<ReviewRevisions>; mode?: ReviewerMode } = {},
): ReviewerSessionFacts {
  return deepFreeze({
    view,
    revisions: makeRevisions(options.revisions),
    mode: options.mode ?? "auto-review",
  }) as ReviewerSessionFacts;
}

function makeStore(
  clock: TestClock,
  options: Omit<ReviewerContextStoreOptions, "now"> = {},
): ReviewerContextStore {
  return createReviewerContextStore({ now: clock.now, ...options });
}

function beginOk(
  store: ReviewerContextStore,
  facts: ReviewerSessionFacts,
  consumer = "consumer-1",
  extra: { forceFull?: boolean; signal?: AbortSignal; deadline?: number | null } = {},
): ContextSelection {
  const begun = store.begin({ facts, consumer, ...extra });
  if (!begun.ok) throw new Error(`expected begin to succeed, got ${begun.reason}`);
  return begun.selection;
}

function beginFailure(
  store: ReviewerContextStore,
  input: Parameters<ReviewerContextStore["begin"]>[0],
): ContextBeginFailure {
  const begun = store.begin(input);
  if (begun.ok) throw new Error("expected begin to fail");
  return begun.reason;
}

function consumerSnapshot(
  store: ReviewerContextStore,
  consumer = "consumer-1",
  owner = "owner-a",
): ReviewerContextConsumerState | undefined {
  return store.state().find((entry) => entry.owner === owner && entry.consumer === consumer);
}

function commitOk(
  store: ReviewerContextStore,
  selection: ContextSelection,
  stop?: ReviewerContextStop,
): number {
  const committed = store.commit(selection, stop);
  if (!committed.ok) throw new Error(`expected commit to succeed, got ${committed.reason}`);
  return committed.generation;
}

function commitFailure(
  store: ReviewerContextStore,
  selection: ContextSelection,
  stop?: ReviewerContextStop,
): ContextCommitFailure {
  const committed = store.commit(selection, stop);
  if (committed.ok) throw new Error("expected commit to fail");
  return committed.reason;
}

// ---------------------------------------------------------------------------
// Slice 1: options, first Full selection, begin validation and stop states
// ---------------------------------------------------------------------------

describe("createReviewerContextStore: first Full selection", () => {
  it("serves a Full installable selection on the first read", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const transcript = makeTranscript(1, 3);
    const view = makeView({ transcript });
    const facts = makeFacts(view);

    const selection = beginOk(store, facts);

    expect(selection.owner).toBe("owner-a");
    expect(selection.consumer).toBe("consumer-1");
    expect(selection.view).toBe(view);
    expect(selection.revisions).toBe(facts.revisions);
    expect(selection.mode).toBe("full");
    expect(selection.generation).toBe(0);
    expect(selection.historyVersion).toBe(1);
    expect(selection.captureSeq).toBe(1);
    expect(selection.readCount).toBe(3);
    expect(selection.prefixDigest).toBe(transcriptPrefixDigest(view, 3));
    expect(selection.installable).toBe(true);
    expect(selection.authorization).toEqual(projectFullEvidence(view).authorization);
    expect(selection.evidence).toEqual(projectFullEvidence(view).evidence);
  });

  it("does not advance the stored cursor or generation when serving a Full selection", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const facts = makeFacts(makeView({ transcript: makeTranscript(1, 3) }));

    beginOk(store, facts);

    const snapshot = consumerSnapshot(store);
    expect(snapshot).toEqual({
      owner: "owner-a",
      consumer: "consumer-1",
      generation: 0,
      cursor: 0,
      prefixDigest: null,
      historyVersion: 1,
      captureSeq: 1,
      revisionDigest: reviewDigest(facts.revisions),
      forceFull: false,
      lastUsedAt: CLOCK_START,
    });
  });

  it("returns the full authorization list separately from the evidence region", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const authorization = [makeAuthorization("auth:1", "do the thing")];
    const facts = makeFacts(makeView({ transcript: makeTranscript(1, 2), authorization }));

    const selection = beginOk(store, facts);

    expect(selection.authorization).toEqual([{ sourceEntryId: "source-auth:1", text: "do the thing" }]);
    expect(selection.evidence).toEqual(projectFullEvidence(facts.view).evidence);
  });

  it("freezes the selection it returns", () => {
    const clock = createClock();
    const store = makeStore(clock);

    const selection = beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 1) })));

    expect(Object.isFrozen(selection)).toBe(true);
    expect(Object.isFrozen(selection.evidence)).toBe(true);
    expect(Object.isFrozen(selection.authorization)).toBe(true);
  });
});

describe("begin: validation", () => {
  function validFacts(): ReviewerSessionFacts {
    return makeFacts(makeView({ transcript: makeTranscript(1, 1) }));
  }

  it("rejects a missing, empty or non-string consumer", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const cases: unknown[] = [undefined, null, "", "   ", 42, {}, ["consumer"]];
    for (const consumer of cases) {
      expect(beginFailure(store, { facts: validFacts(), consumer } as never)).toBe("invalid-consumer");
    }
  });

  it("rejects a missing, empty or non-string view owner", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const cases: unknown[] = [undefined, null, "", "   ", 42];
    for (const owner of cases) {
      const facts = {
        view: { ...makeView(), owner },
        revisions: makeRevisions(),
        mode: "auto-review",
      } as unknown as ReviewerSessionFacts;
      expect(beginFailure(store, { facts, consumer: "consumer-1" })).toBe("invalid-owner");
    }
  });

  it("rejects a view with invalid history/capture counters or non-array lists", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const invalidViews: unknown[] = [
      { historyVersion: -1 },
      { historyVersion: 1.5 },
      { historyVersion: Number.NaN },
      { historyVersion: Number.POSITIVE_INFINITY },
      { captureSeq: -1 },
      { captureSeq: 2.5 },
      { captureSeq: Number.NaN },
      { transcript: "not-an-array" },
      { transcript: undefined },
      { authorization: "not-an-array" },
      { authorization: undefined },
    ];
    for (const overrides of invalidViews) {
      const view = { ...makeView(), ...(overrides as Record<string, unknown>) } as unknown as ReviewView;
      const facts = { view, revisions: makeRevisions(), mode: "auto-review" } as ReviewerSessionFacts;
      expect(beginFailure(store, { facts, consumer: "consumer-1" })).toBe("invalid-view");
    }
  });

  it("rejects facts without a usable view", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const cases = [
      {},
      { view: undefined },
      { view: null },
      { view: "view" },
      { view: [], revisions: makeRevisions(), mode: "auto-review" },
    ] as unknown as ReviewerSessionFacts[];
    for (const facts of cases) {
      expect(beginFailure(store, { facts, consumer: "consumer-1" })).toBe("invalid-view");
    }
    expect(beginFailure(store, { consumer: "consumer-1" } as never)).toBe("invalid-view");
  });

  it("rejects revisions that are not five non-negative safe integers", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const view = makeView();
    const invalidRevisions: unknown[] = [
      undefined,
      null,
      {},
      "revisions",
      { ...makeRevisions(), owner: -1 },
      { ...makeRevisions(), navigation: 1.5 },
      { ...makeRevisions(), authorization: Number.NaN },
      { ...makeRevisions(), projectRules: Number.POSITIVE_INFINITY },
      { ...makeRevisions(), intent: "1" },
    ];
    for (const revisions of invalidRevisions) {
      const facts = { view, revisions, mode: "auto-review" } as unknown as ReviewerSessionFacts;
      expect(beginFailure(store, { facts, consumer: "consumer-1" })).toBe("invalid-revision");
    }
  });

  it("fails validation before creating any state", () => {
    const clock = createClock();
    const store = makeStore(clock);
    beginFailure(store, { facts: validFacts(), consumer: "" });
    expect(store.state()).toEqual([]);
  });
});

describe("begin: stop conditions", () => {
  function validFacts(): ReviewerSessionFacts {
    return makeFacts(makeView({ transcript: makeTranscript(1, 1) }));
  }

  it("fails disposed once the store was disposed", () => {
    const clock = createClock();
    const store = makeStore(clock);
    store.dispose();
    expect(store.disposed).toBe(true);
    expect(beginFailure(store, { facts: validFacts(), consumer: "consumer-1" })).toBe("disposed");
  });

  it("fails cancelled for an aborted signal", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const controller = new AbortController();
    controller.abort();
    expect(beginFailure(store, {
      facts: validFacts(),
      consumer: "consumer-1",
      signal: controller.signal,
    })).toBe("cancelled");
    expect(store.state()).toEqual([]);
  });

  it("fails deadline when the injected clock reached a finite deadline", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const facts = validFacts();
    expect(beginFailure(store, { facts, consumer: "consumer-1", deadline: CLOCK_START })).toBe("deadline");
    expect(beginFailure(store, { facts, consumer: "consumer-1", deadline: CLOCK_START - 1 })).toBe("deadline");
    expect(store.state()).toEqual([]);
  });

  it("fails deadline for a non-finite deadline", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const facts = validFacts();
    for (const deadline of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      expect(beginFailure(store, { facts, consumer: "consumer-1", deadline })).toBe("deadline");
    }
  });

  it("treats null and undefined deadlines as no deadline", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const facts = validFacts();
    expect(beginOk(store, facts, "consumer-null", { deadline: null }).mode).toBe("full");
    expect(beginOk(store, facts, "consumer-undefined").mode).toBe("full");
  });

  it("serves a selection when the deadline is still in the future", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const facts = validFacts();
    expect(beginOk(store, facts, "consumer-1", { deadline: CLOCK_START + 5 }).mode).toBe("full");
  });
});

describe("commit: installing a Full selection and continuing with Delta", () => {
  it("installs a Full selection: advances the cursor, bumps the generation and clears forceFull", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const view = makeView({ transcript: makeTranscript(1, 3) });
    const facts = makeFacts(view);
    const selection = beginOk(store, facts);

    expect(commitOk(store, selection)).toBe(1);

    const snapshot = consumerSnapshot(store)!;
    expect(snapshot.generation).toBe(1);
    expect(snapshot.cursor).toBe(3);
    expect(snapshot.prefixDigest).toBe(transcriptPrefixDigest(view, 3));
    expect(snapshot.historyVersion).toBe(1);
    expect(snapshot.captureSeq).toBe(1);
    expect(snapshot.revisionDigest).toBe(reviewDigest(facts.revisions));
    expect(snapshot.forceFull).toBe(false);
    expect(snapshot.lastUsedAt).toBe(CLOCK_START);
  });

  it("serves an empty Delta when nothing was appended after the committed Full read", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const view = makeView({ transcript: makeTranscript(1, 3) });
    const facts = makeFacts(view);
    commitOk(store, beginOk(store, facts));

    const delta = beginOk(store, facts);

    expect(delta.mode).toBe("delta");
    expect(delta.readCount).toBe(0);
    expect(delta.evidence).toEqual(projectDeltaEvidence(view, 3).evidence);
    expect(delta.evidence).toEqual([]);
    expect(delta.installable).toBe(true);
    expect(delta.prefixDigest).toBe(transcriptPrefixDigest(view, 3));
  });

  it("does not advance the cursor until the Delta selection commits", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const facts1 = makeFacts(makeView({ transcript: makeTranscript(1, 2) }));
    commitOk(store, beginOk(store, facts1));

    const appendedView = makeView({
      transcript: makeTranscript(1, 4),
      captureSeq: 2,
    });
    const delta = beginOk(store, makeFacts(appendedView));
    expect(delta.mode).toBe("delta");
    expect(consumerSnapshot(store)!.cursor).toBe(2);

    commitOk(store, delta);
    expect(consumerSnapshot(store)!.cursor).toBe(4);
    expect(consumerSnapshot(store)!.captureSeq).toBe(2);
  });

  it("projects only the appended evidence in a Delta read", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const firstView = makeView({ transcript: makeTranscript(1, 2) });
    commitOk(store, beginOk(store, makeFacts(firstView)));

    const appendedView = makeView({ transcript: makeTranscript(1, 5), captureSeq: 2 });
    const delta = beginOk(store, makeFacts(appendedView));

    expect(delta.readCount).toBe(3);
    expect(delta.evidence).toEqual(projectDeltaEvidence(appendedView, 2).evidence);
    expect(delta.evidence.map((item) => item.id)).toEqual(["e3", "e4", "e5"]);
    expect(delta.prefixDigest).toBe(transcriptPrefixDigest(appendedView, 5));
  });

  it("accumulates delta reads across several commits", () => {
    const clock = createClock();
    const store = makeStore(clock);
    let facts = makeFacts(makeView({ transcript: makeTranscript(1, 1), captureSeq: 1 }));
    commitOk(store, beginOk(store, facts));
    expect(consumerSnapshot(store)!.cursor).toBe(1);

    for (const [captureSeq, start, count] of [[2, 2, 2], [3, 4, 1], [4, 5, 3]] as const) {
      clock.advance(10);
      facts = makeFacts(makeView({ transcript: makeTranscript(1, start + count - 1), captureSeq }));
      const delta = beginOk(store, facts);
      expect(delta.mode).toBe("delta");
      expect(delta.readCount).toBe(count);
      expect(delta.evidence.map((item) => item.id)).toEqual(
        makeTranscript(start, count).map((entry) => entry.entryKey),
      );
      commitOk(store, delta);
      expect(consumerSnapshot(store)!.cursor).toBe(start + count - 1);
      expect(consumerSnapshot(store)!.lastUsedAt).toBe(clock.now());
    }
  });

  it("updates lastUsedAt from the injected clock on begin and commit", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const facts = makeFacts(makeView({ transcript: makeTranscript(1, 1) }));
    const selection = beginOk(store, facts);
    expect(consumerSnapshot(store)!.lastUsedAt).toBe(CLOCK_START);

    clock.advance(25);
    commitOk(store, selection);
    expect(consumerSnapshot(store)!.lastUsedAt).toBe(CLOCK_START + 25);

    clock.advance(5);
    beginOk(store, facts);
    expect(consumerSnapshot(store)!.lastUsedAt).toBe(CLOCK_START + 30);
  });

  it("keeps independently committed cursors for two consumers in one owner", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const facts = makeFacts(makeView({ transcript: makeTranscript(1, 3) }));
    commitOk(store, beginOk(store, facts, "consumer-a"));
    const deltaB = beginOk(store, facts, "consumer-b");
    expect(deltaB.mode).toBe("full");
    commitOk(store, deltaB);

    expect(consumerSnapshot(store, "consumer-a")!.cursor).toBe(3);
    expect(consumerSnapshot(store, "consumer-b")!.cursor).toBe(3);
    expect(consumerSnapshot(store, "consumer-a")!.generation).toBe(1);
    expect(consumerSnapshot(store, "consumer-b")!.generation).toBe(1);
  });
});

describe("generations: revision and history changes", () => {
  it("bumps the generation, resets the cursor and forces Full when the revision digest changes", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const view = makeView({ transcript: makeTranscript(1, 3) });
    commitOk(store, beginOk(store, makeFacts(view)));
    expect(consumerSnapshot(store)!.generation).toBe(1);
    expect(consumerSnapshot(store)!.cursor).toBe(3);

    const revisedFacts = makeFacts(view, { revisions: { authorization: 2 } });
    const selection = beginOk(store, revisedFacts);

    expect(selection.mode).toBe("full");
    expect(selection.installable).toBe(true);
    expect(selection.generation).toBe(2);
    expect(consumerSnapshot(store)!.generation).toBe(2);
    expect(consumerSnapshot(store)!.cursor).toBe(0);
    expect(consumerSnapshot(store)!.forceFull).toBe(true);
    expect(consumerSnapshot(store)!.revisionDigest).toBe(reviewDigest(revisedFacts.revisions));

    expect(commitOk(store, selection)).toBe(3);
    expect(consumerSnapshot(store)!.forceFull).toBe(false);
    expect(consumerSnapshot(store)!.cursor).toBe(3);
  });

  it("bumps the generation, resets the cursor and adopts the capture when the history version changes", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const firstView = makeView({ transcript: makeTranscript(1, 2), captureSeq: 1 });
    commitOk(store, beginOk(store, makeFacts(firstView)));
    expect(consumerSnapshot(store)!.captureSeq).toBe(1);

    const nextView = makeView({ transcript: makeTranscript(1, 5), historyVersion: 2, captureSeq: 3 });
    const selection = beginOk(store, makeFacts(nextView));

    expect(selection.mode).toBe("full");
    expect(selection.installable).toBe(true);
    expect(selection.generation).toBe(2);
    expect(selection.historyVersion).toBe(2);
    expect(selection.captureSeq).toBe(3);
    expect(consumerSnapshot(store)!.cursor).toBe(0);
    expect(consumerSnapshot(store)!.historyVersion).toBe(2);
    expect(consumerSnapshot(store)!.captureSeq).toBe(3);

    expect(commitOk(store, selection)).toBe(3);
    expect(consumerSnapshot(store)!.cursor).toBe(5);
  });

  it("resets the cursor on a revision change even when the transcript was not appended", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const view = makeView({ transcript: makeTranscript(1, 2), captureSeq: 1 });
    commitOk(store, beginOk(store, makeFacts(view)));
    commitOk(store, beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 2), captureSeq: 2 }))));

    const currentView = makeView({ transcript: makeTranscript(1, 2), captureSeq: 2 });
    const revisedFacts = makeFacts(currentView, { revisions: { navigation: 7 } });
    const selection = beginOk(store, revisedFacts);

    expect(selection.mode).toBe("full");
    expect(consumerSnapshot(store)!.cursor).toBe(0);
    expect(selection.readCount).toBe(2);
  });

  it("does not bump the generation for a newer capture of the same history and revision", () => {
    const clock = createClock();
    const store = makeStore(clock);
    commitOk(store, beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 2), captureSeq: 1 }))));

    const selection = beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 2), captureSeq: 2 })));

    expect(selection.mode).toBe("delta");
    expect(selection.generation).toBe(1);
  });
});

describe("forced Full", () => {
  it("forces one Full read for an explicit forceFull request without persisting it", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const view = makeView({ transcript: makeTranscript(1, 2), captureSeq: 1 });
    commitOk(store, beginOk(store, makeFacts(view)));

    const forced = beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 3), captureSeq: 2 })), "consumer-1", { forceFull: true });

    expect(forced.mode).toBe("full");
    expect(forced.installable).toBe(true);
    expect(forced.readCount).toBe(3);
    expect(forced.generation).toBe(1);
    expect(commitOk(store, forced)).toBe(2);

    const after = beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 3), captureSeq: 2 })));
    expect(after.mode).toBe("delta");
  });

  it("keeps forcing Full after a store-forced read that was not committed", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const view = makeView({ transcript: makeTranscript(1, 2), captureSeq: 1 });
    commitOk(store, beginOk(store, makeFacts(view)));

    store.invalidate({ owner: "owner-a", consumer: "consumer-1" });
    expect(beginOk(store, makeFacts(view)).mode).toBe("full");
    expect(beginOk(store, makeFacts(view)).mode).toBe("full");
  });
});

describe("invalidate", () => {
  function committedStore(): { clock: TestClock; store: ReviewerContextStore } {
    const clock = createClock();
    const store = makeStore(clock);
    commitOk(store, beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 2), captureSeq: 1 }))));
    return { clock, store };
  }

  it("forces Full for one exact owner and consumer", () => {
    const { clock, store } = committedStore();
    store.invalidate({ owner: "owner-a", consumer: "consumer-1" });
    expect(consumerSnapshot(store)!.forceFull).toBe(true);

    const selection = beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 3), captureSeq: 2 })));
    expect(selection.mode).toBe("full");
    expect(consumerSnapshot(store)!.forceFull).toBe(true);
    commitOk(store, selection);
    expect(consumerSnapshot(store)!.forceFull).toBe(false);
    clock.advance(1);
  });

  it("forces Full for every consumer of one owner", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const facts = makeFacts(makeView({ transcript: makeTranscript(1, 2), captureSeq: 1 }));
    commitOk(store, beginOk(store, facts, "consumer-a"));
    commitOk(store, beginOk(store, facts, "consumer-b"));

    store.invalidate({ owner: "owner-a" });

    expect(beginOk(store, facts, "consumer-a").mode).toBe("full");
    expect(beginOk(store, facts, "consumer-b").mode).toBe("full");
  });

  it("forces Full for a consumer name across owners", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const factsA = makeFacts(makeView({ transcript: makeTranscript(1, 2), captureSeq: 1 }));
    const factsB = makeFacts(makeView({ owner: "owner-b", transcript: makeTranscript(1, 2), captureSeq: 1 }));
    commitOk(store, beginOk(store, factsA, "consumer-shared"));
    commitOk(store, beginOk(store, factsB, "consumer-shared", { }));
    commitOk(store, beginOk(store, factsA, "consumer-only-a"));

    store.invalidate({ consumer: "consumer-shared" });

    expect(beginOk(store, factsA, "consumer-shared").mode).toBe("full");
    expect(beginOk(store, factsB, "consumer-shared").mode).toBe("full");
    expect(beginOk(store, factsA, "consumer-only-a").mode).toBe("delta");
  });

  it("forces Full for every consumer when nothing is specified", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const factsA = makeFacts(makeView({ transcript: makeTranscript(1, 2), captureSeq: 1 }));
    const factsB = makeFacts(makeView({ owner: "owner-b", transcript: makeTranscript(1, 2), captureSeq: 1 }));
    commitOk(store, beginOk(store, factsA, "consumer-a"));
    commitOk(store, beginOk(store, factsB, "consumer-b"));

    store.invalidate();

    expect(store.state().every((entry) => entry.forceFull)).toBe(true);
    expect(beginOk(store, factsA, "consumer-a").mode).toBe("full");
    expect(beginOk(store, factsB, "consumer-b").mode).toBe("full");
  });

  it("ignores an unknown owner or consumer", () => {
    const { store } = committedStore();
    store.invalidate({ owner: "owner-unknown" });
    store.invalidate({ consumer: "consumer-unknown" });
    store.invalidate({ owner: "owner-a", consumer: "consumer-unknown" });

    expect(consumerSnapshot(store)!.forceFull).toBe(false);
    expect(beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 3), captureSeq: 2 }))).mode).toBe("delta");
  });
});

describe("readable-but-not-installable snapshots", () => {
  function versionFields(snapshot: ReviewerContextConsumerState): Omit<ReviewerContextConsumerState, "lastUsedAt"> {
    const { lastUsedAt: _lastUsedAt, ...rest } = snapshot;
    return rest;
  }

  it("serves a Full non-installable read for a snapshot older by capture sequence", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const oldView = makeView({ transcript: makeTranscript(1, 2), captureSeq: 1 });
    commitOk(store, beginOk(store, makeFacts(oldView)));
    const newerView = makeView({ transcript: makeTranscript(1, 4), captureSeq: 2 });
    commitOk(store, beginOk(store, makeFacts(newerView)));
    const before = consumerSnapshot(store)!;

    const selection = beginOk(store, makeFacts(oldView));

    expect(selection.mode).toBe("full");
    expect(selection.installable).toBe(false);
    expect(selection.readCount).toBe(2);
    expect(selection.generation).toBe(1);
    expect(selection.evidence).toEqual(projectFullEvidence(oldView).evidence);
    expect(versionFields(consumerSnapshot(store)!)).toEqual(versionFields(before));
    expect(commitFailure(store, selection)).toBe("not-installable");
    expect(versionFields(consumerSnapshot(store)!)).toEqual(versionFields(before));
  });

  it("serves a Full non-installable read for a snapshot older by history version", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const oldView = makeView({ transcript: makeTranscript(1, 3), historyVersion: 1, captureSeq: 2 });
    commitOk(store, beginOk(store, makeFacts(oldView)));
    const newerView = makeView({ transcript: makeTranscript(1, 3), historyVersion: 2, captureSeq: 3 });
    commitOk(store, beginOk(store, makeFacts(newerView)));

    const selection = beginOk(store, makeFacts(oldView));

    expect(selection.mode).toBe("full");
    expect(selection.installable).toBe(false);
    expect(consumerSnapshot(store)!.historyVersion).toBe(2);
    expect(consumerSnapshot(store)!.captureSeq).toBe(3);
  });

  it("serves a Full non-installable read when the consumed prefix digest was revised", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const firstView = makeView({ transcript: makeTranscript(1, 3), captureSeq: 1 });
    commitOk(store, beginOk(store, makeFacts(firstView)));
    const before = consumerSnapshot(store)!;

    const revisedView = makeView({
      transcript: [makeEntry("e1"), makeEntry("e2", { content: "rewritten" }), makeEntry("e3")],
      captureSeq: 2,
    });
    const selection = beginOk(store, makeFacts(revisedView));

    expect(selection.mode).toBe("full");
    expect(selection.installable).toBe(false);
    expect(selection.generation).toBe(1);
    expect(versionFields(consumerSnapshot(store)!)).toEqual(versionFields(before));
    expect(commitFailure(store, selection)).toBe("not-installable");
  });

  it("serves a Full installable read for an out-of-bounds cursor instead of a revised prefix", () => {
    const clock = createClock();
    const store = makeStore(clock);
    commitOk(store, beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 4), captureSeq: 1 }))));
    const shrunkView = makeView({ transcript: makeTranscript(1, 2), captureSeq: 2 });

    const selection = beginOk(store, makeFacts(shrunkView));

    expect(selection.mode).toBe("full");
    expect(selection.installable).toBe(true);
    expect(commitOk(store, selection)).toBe(2);
    expect(consumerSnapshot(store)!.cursor).toBe(2);
  });
});

describe("prefix digests", () => {
  it("stores the consumed prefix digest of the transcript at the committed cursor", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const view = makeView({ transcript: makeTranscript(1, 4), captureSeq: 1 });
    commitOk(store, beginOk(store, makeFacts(view)));
    const consumedPrefix = transcriptPrefixDigest(view, 4);
    expect(consumerSnapshot(store)!.prefixDigest).toBe(consumedPrefix);
    expect(consumedPrefix).not.toBe(transcriptPrefixDigest(view, 2));

    const appended = makeView({ transcript: makeTranscript(1, 5), captureSeq: 2 });
    const delta = beginOk(store, makeFacts(appended));
    // A Delta selection covers the whole new transcript prefix, while the
    // stored digest still covers exactly the entries the consumer consumed.
    expect(delta.prefixDigest).toBe(transcriptPrefixDigest(appended, 5));
    expect(delta.prefixDigest).not.toBe(consumedPrefix);
    expect(consumerSnapshot(store)!.prefixDigest).toBe(transcriptPrefixDigest(appended, 4));

    commitOk(store, delta);
    expect(consumerSnapshot(store)!.prefixDigest).toBe(transcriptPrefixDigest(appended, 5));
  });
});

describe("commit: validation and stop conditions", () => {
  function committedSelection(): {
    clock: TestClock;
    store: ReviewerContextStore;
    selection: ContextSelection;
  } {
    const clock = createClock();
    const store = makeStore(clock);
    const view = makeView({ transcript: makeTranscript(1, 2), captureSeq: 1 });
    commitOk(store, beginOk(store, makeFacts(view)));
    const selection = beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 3), captureSeq: 2 })));
    return { clock, store, selection };
  }

  it("fails disposed after the store was disposed", () => {
    const { store, selection } = committedSelection();
    store.dispose();
    expect(commitFailure(store, selection)).toBe("disposed");
  });

  it("fails cancelled for an aborted stop signal", () => {
    const { store, selection } = committedSelection();
    const controller = new AbortController();
    controller.abort();
    expect(commitFailure(store, selection, { signal: controller.signal })).toBe("cancelled");
    expect(commitOk(store, selection)).toBe(1);
  });

  it("fails deadline when the injected clock reached a finite deadline", () => {
    const { clock, store, selection } = committedSelection();
    expect(commitFailure(store, selection, { deadline: clock.now() })).toBe("deadline");
    expect(commitFailure(store, selection, { deadline: clock.now() - 1 })).toBe("deadline");
    expect(commitFailure(store, selection, { deadline: Number.NaN })).toBe("deadline");
    expect(commitFailure(store, selection, { deadline: Number.POSITIVE_INFINITY })).toBe("deadline");
    expect(commitOk(store, selection, { deadline: clock.now() + 1 })).toBe(1);
  });

  it("treats a null or absent stop deadline as no deadline", () => {
    const { store, selection } = committedSelection();
    expect(commitOk(store, selection, { deadline: null })).toBe(1);
  });

  it("fails unknown-consumer for an owner or consumer the store never saw", () => {
    const { store, selection } = committedSelection();
    const unknownConsumer = { ...selection, consumer: "consumer-unknown" } as ContextSelection;
    const unknownOwner = { ...selection, owner: "owner-unknown" } as ContextSelection;
    expect(commitFailure(store, unknownConsumer)).toBe("unknown-consumer");
    expect(commitFailure(store, unknownOwner)).toBe("unknown-consumer");
    expect(commitOk(store, selection)).toBe(1);
  });

  it("checks unknown-consumer before malformed-selection fields", () => {
    const { store, selection } = committedSelection();
    const forged = { ...selection, consumer: "consumer-unknown", mode: "partial" } as unknown as ContextSelection;
    expect(commitFailure(store, forged)).toBe("unknown-consumer");
  });

  it("fails invalid-selection for a selection that is not a selection object", () => {
    const { store } = committedSelection();
    for (const forged of [null, undefined, "selection", 42, {}, [], { owner: "owner-a" }]) {
      expect(commitFailure(store, forged as unknown as ContextSelection)).toBe("invalid-selection");
    }
  });

  it("fails invalid-selection for malformed selection fields", () => {
    const { store, selection } = committedSelection();
    const mutations: Array<Record<string, unknown>> = [
      { owner: 42 },
      { consumer: 42 },
      { view: null },
      { view: { ...selection.view, transcript: "transcript" } },
      { view: { ...selection.view, owner: "owner-other" } },
      { revisions: null },
      { revisions: { ...selection.revisions, owner: -1 } },
      { mode: "partial" },
      { generation: -1 },
      { generation: 1.5 },
      { historyVersion: Number.NaN },
      { captureSeq: -2 },
      { readCount: -1 },
      { prefixDigest: 42 },
      { prefixDigest: "tampered" },
      { installable: "yes" },
      { authorization: null },
      { evidence: "evidence" },
    ];
    for (const mutation of mutations) {
      const forged = { ...selection, ...mutation } as unknown as ContextSelection;
      expect(commitFailure(store, forged)).toBe("invalid-selection");
    }
    expect(commitOk(store, selection)).toBe(1);
  });

  it("fails not-installable before checking staleness", () => {
    const { store, selection } = committedSelection();
    const forged = {
      ...selection,
      installable: false,
      generation: selection.generation + 1,
    } as ContextSelection;
    expect(commitFailure(store, forged)).toBe("not-installable");
    expect(commitOk(store, selection)).toBe(1);
  });
});

describe("commit: staleness", () => {
  function versionFields(snapshot: ReviewerContextConsumerState): Omit<ReviewerContextConsumerState, "lastUsedAt"> {
    const { lastUsedAt: _lastUsedAt, ...rest } = snapshot;
    return rest;
  }

  it("rejects committing the same Delta selection twice", () => {
    const clock = createClock();
    const store = makeStore(clock);
    commitOk(store, beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 2), captureSeq: 1 }))));
    const delta = beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 3), captureSeq: 2 })));
    const installed = consumerSnapshot(store)!;

    expect(commitOk(store, delta)).toBe(1);
    const afterFirst = consumerSnapshot(store)!;
    expect(commitFailure(store, delta)).toBe("stale");
    expect(versionFields(consumerSnapshot(store)!)).toEqual(versionFields(afterFirst));
    expect(afterFirst.cursor).not.toBe(installed.cursor);
  });

  it("rejects committing the same Full selection twice", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const selection = beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 2), captureSeq: 1 })));
    expect(commitOk(store, selection)).toBe(1);

    expect(commitFailure(store, selection)).toBe("stale");
    expect(consumerSnapshot(store)!.generation).toBe(1);
    expect(consumerSnapshot(store)!.cursor).toBe(2);
  });

  it("rejects a Delta selection once its generation changed", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const view = makeView({ transcript: makeTranscript(1, 2), captureSeq: 1 });
    commitOk(store, beginOk(store, makeFacts(view)));
    const delta = beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 3), captureSeq: 2 })));

    beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 3), captureSeq: 2 }), {
      revisions: { authorization: 2 },
    }));
    const before = consumerSnapshot(store)!;

    expect(commitFailure(store, delta)).toBe("stale");
    expect(versionFields(consumerSnapshot(store)!)).toEqual(versionFields(before));
  });

  it("rejects a Delta selection once the history version changed", () => {
    const clock = createClock();
    const store = makeStore(clock);
    commitOk(store, beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 2), captureSeq: 1 }))));
    const delta = beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 3), captureSeq: 2 })));

    beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 3), historyVersion: 2, captureSeq: 3 })));

    expect(commitFailure(store, delta)).toBe("stale");
    // The history change already reset the shared cursor to the new history.
    expect(consumerSnapshot(store)!.cursor).toBe(0);
    expect(consumerSnapshot(store)!.generation).toBe(2);
  });

  it("rejects a selection once a newer capture was observed", () => {
    const clock = createClock();
    const store = makeStore(clock);
    commitOk(store, beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 2), captureSeq: 1 }))));
    const delta = beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 3), captureSeq: 2 })));

    beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 3), captureSeq: 3 })));

    expect(commitFailure(store, delta)).toBe("stale");
    expect(consumerSnapshot(store)!.captureSeq).toBe(3);
    expect(consumerSnapshot(store)!.cursor).toBe(2);
  });

  it("rejects the second of two selections begun from the same snapshot after the first installs", () => {
    const clock = createClock();
    const store = makeStore(clock);
    commitOk(store, beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 2), captureSeq: 1 }))));
    const upcoming = makeFacts(makeView({ transcript: makeTranscript(1, 4), captureSeq: 2 }));
    const first = beginOk(store, upcoming);
    const second = beginOk(store, upcoming);

    expect(commitOk(store, first)).toBe(1);
    expect(commitFailure(store, second)).toBe("stale");
    expect(consumerSnapshot(store)!.cursor).toBe(4);
  });

  it("rejects a selection whose read count no longer describes the transcript slice", () => {
    const clock = createClock();
    const store = makeStore(clock);
    commitOk(store, beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 2), captureSeq: 1 }))));
    const delta = beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 5), captureSeq: 2 })));
    const before = consumerSnapshot(store)!;

    expect(commitFailure(store, { ...delta, readCount: delta.readCount + 1 } as ContextSelection)).toBe("stale");
    expect(versionFields(consumerSnapshot(store)!)).toEqual(versionFields(before));
    expect(commitOk(store, delta)).toBe(1);
  });

  it("rejects a Full selection whose read count no longer covers the transcript", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const selection = beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 4), captureSeq: 1 })));

    expect(commitFailure(store, { ...selection, readCount: 2 } as ContextSelection)).toBe("stale");
    expect(commitOk(store, selection)).toBe(1);
  });
});

describe("retention eviction", () => {
  it("keeps an entry that is still inside the retention window", () => {
    const clock = createClock();
    const store = makeStore(clock, { retentionMs: 100 });
    const view = makeView({ transcript: makeTranscript(1, 2), captureSeq: 1 });
    commitOk(store, beginOk(store, makeFacts(view)));

    clock.advance(99);
    const selection = beginOk(store, makeFacts(view));

    expect(selection.mode).toBe("delta");
    expect(consumerSnapshot(store)!.generation).toBe(1);
  });

  it("evicts an idle consumer at exactly the retention boundary and starts it fresh", () => {
    const clock = createClock();
    const store = makeStore(clock, { retentionMs: 100 });
    const view = makeView({ transcript: makeTranscript(1, 2), captureSeq: 1 });
    commitOk(store, beginOk(store, makeFacts(view)));
    expect(consumerSnapshot(store)!.generation).toBe(1);

    clock.advance(100);
    const selection = beginOk(store, makeFacts(view));

    expect(selection.mode).toBe("full");
    expect(selection.generation).toBe(0);
    expect(consumerSnapshot(store)!.generation).toBe(0);
    expect(consumerSnapshot(store)!.cursor).toBe(0);
    expect(consumerSnapshot(store)!.prefixDigest).toBeNull();
    expect(consumerSnapshot(store)!.lastUsedAt).toBe(CLOCK_START + 100);
  });

  it("evicts the whole owner group once its idle consumers are gone", () => {
    const clock = createClock();
    const store = makeStore(clock, { retentionMs: 100 });
    const factsA = makeFacts(makeView({ transcript: makeTranscript(1, 1), captureSeq: 1 }));
    const factsB = makeFacts(makeView({ owner: "owner-b", transcript: makeTranscript(1, 1), captureSeq: 1 }));
    commitOk(store, beginOk(store, factsA));
    commitOk(store, beginOk(store, factsB));
    expect(store.state().length).toBe(2);

    clock.advance(100);
    beginOk(store, factsB);

    expect(store.state().map((entry) => entry.owner)).toEqual(["owner-b"]);
  });

  it("evicts idle entries before enforcing the owner capacity", () => {
    const clock = createClock();
    const store = makeStore(clock, { retentionMs: 100, maxOwners: 2 });
    const factsA = makeFacts(makeView({ transcript: makeTranscript(1, 1), captureSeq: 1 }));
    const factsB = makeFacts(makeView({ owner: "owner-b", transcript: makeTranscript(1, 1), captureSeq: 1 }));
    const factsC = makeFacts(makeView({ owner: "owner-c", transcript: makeTranscript(1, 1), captureSeq: 1 }));
    beginOk(store, factsA);
    beginOk(store, factsB);

    clock.advance(100);
    beginOk(store, factsC);

    expect(store.state().map((entry) => entry.owner)).toEqual(["owner-c"]);
  });

  it("treats a zero retention window as immediately idle", () => {
    const clock = createClock();
    const store = makeStore(clock, { retentionMs: 0 });
    const facts = makeFacts(makeView({ transcript: makeTranscript(1, 1), captureSeq: 1 }));
    expect(beginOk(store, facts).mode).toBe("full");
    expect(beginOk(store, facts).mode).toBe("full");
  });
});

describe("capacity eviction", () => {
  function factsFor(owner: string, consumer: string): ReviewerSessionFacts {
    return makeFacts(makeView({ owner, transcript: makeTranscript(1, 1), captureSeq: 1 }));
  }

  it("evicts the least-recently-used owner whole when the owner cap is reached", () => {
    const clock = createClock();
    const store = makeStore(clock, { maxOwners: 2 });
    beginOk(store, factsFor("owner-a", "consumer-1"));
    clock.advance(1);
    beginOk(store, factsFor("owner-b", "consumer-1"));
    clock.advance(1);
    // Touching owner-b makes owner-a the least-recently-used owner.
    beginOk(store, factsFor("owner-b", "consumer-1"));
    clock.advance(1);
    beginOk(store, factsFor("owner-c", "consumer-1"));

    expect(store.state().map((entry) => entry.owner)).toEqual(["owner-b", "owner-c"]);

    clock.advance(1);
    beginOk(store, factsFor("owner-a", "consumer-1"));
    expect(store.state().map((entry) => entry.owner)).toEqual(["owner-c", "owner-a"]);
  });

  it("evicts the least-recently-used consumer inside one owner", () => {
    const clock = createClock();
    const store = makeStore(clock, { maxConsumersPerOwner: 2 });
    const facts = factsFor("owner-a", "consumer-1");
    beginOk(store, facts, "consumer-1");
    clock.advance(1);
    beginOk(store, facts, "consumer-2");
    clock.advance(1);
    beginOk(store, facts, "consumer-1");
    clock.advance(1);
    beginOk(store, facts, "consumer-3");

    expect(store.state().map((entry) => entry.consumer)).toEqual(["consumer-1", "consumer-3"]);
    expect(consumerSnapshot(store, "consumer-2")).toBeUndefined();
  });

  it("never exceeds the per-owner consumer cap when re-touching an existing consumer", () => {
    const clock = createClock();
    const store = makeStore(clock, { maxConsumersPerOwner: 1 });
    const facts = factsFor("owner-a", "consumer-1");
    beginOk(store, facts, "consumer-1");
    beginOk(store, facts, "consumer-1");
    beginOk(store, facts, "consumer-1");

    expect(store.state().length).toBe(1);
  });

  it("clamps configured capacities to the hard caps", () => {
    const clock = createClock();
    const ownersStore = makeStore(clock, { maxOwners: 1_000 });
    for (let index = 0; index < 70; index += 1) {
      beginOk(ownersStore, factsFor(`owner-${index}`, "consumer-1"));
    }
    const owners = ownersStore.state().map((entry) => entry.owner);
    expect(owners.length).toBe(64);
    expect(owners).toContain("owner-69");
    expect(owners).not.toContain("owner-0");

    const consumersStore = makeStore(clock, { maxConsumersPerOwner: 1_000 });
    for (let index = 0; index < 40; index += 1) {
      beginOk(consumersStore, factsFor("owner-a", "consumer-1"), `consumer-${index}`);
    }
    const consumers = consumersStore.state().map((entry) => entry.consumer);
    expect(consumers.length).toBe(32);
    expect(consumers).toContain("consumer-39");
    expect(consumers).not.toContain("consumer-0");
  });

  it("falls back to the default capacities for unusable overrides", () => {
    const clock = createClock();
    const store = makeStore(clock, { maxOwners: 0 });
    for (let index = 0; index < 33; index += 1) {
      beginOk(store, factsFor(`owner-${index}`, "consumer-1"));
    }
    expect(store.state().length).toBe(32);
  });

  it("keeps the committed cursor of a surviving owner while evicting a sibling", () => {
    const clock = createClock();
    const store = makeStore(clock, { maxOwners: 2 });
    const factsA = factsFor("owner-a", "consumer-1");
    const viewA = makeView({ transcript: makeTranscript(1, 2), captureSeq: 1 });
    commitOk(store, beginOk(store, makeFacts(viewA)));
    beginOk(store, factsFor("owner-b", "consumer-1"));
    // Touching owner-a again makes owner-b the least-recently-used owner.
    beginOk(store, makeFacts(viewA));
    beginOk(store, factsFor("owner-c", "consumer-1"));

    expect(store.state().map((entry) => entry.owner)).toEqual(["owner-a", "owner-c"]);
    expect(consumerSnapshot(store, "consumer-1", "owner-a")!.cursor).toBe(2);
    expect(consumerSnapshot(store, "consumer-1", "owner-a")!.generation).toBe(1);
  });
});

describe("state snapshots", () => {
  it("is frozen and read-only", () => {
    const clock = createClock();
    const store = makeStore(clock);
    commitOk(store, beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 2) }))));
    const snapshots = store.state();

    expect(Object.isFrozen(snapshots)).toBe(true);
    expect(Object.isFrozen(snapshots[0])).toBe(true);
    expect(() => {
      (snapshots as ReviewerContextConsumerState[]).push({} as ReviewerContextConsumerState);
    }).toThrow();
    expect(() => {
      (snapshots[0] as { cursor: number }).cursor = 99;
    }).toThrow();
    expect(consumerSnapshot(store)!.cursor).toBe(2);
  });

  it("reports every owner and consumer the store keeps", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const factsA = makeFacts(makeView({ transcript: makeTranscript(1, 1) }));
    const factsB = makeFacts(makeView({ owner: "owner-b", transcript: makeTranscript(1, 1) }));
    beginOk(store, factsA, "consumer-a");
    beginOk(store, factsA, "consumer-b");
    beginOk(store, factsB, "consumer-a");

    const snapshots = store.state();
    expect(snapshots.length).toBe(3);
    expect(snapshots.map((entry) => `${entry.owner}/${entry.consumer}`).sort()).toEqual([
      "owner-a/consumer-a",
      "owner-a/consumer-b",
      "owner-b/consumer-a",
    ]);
  });

  it("is empty before the first begin and after dispose", () => {
    const clock = createClock();
    const store = makeStore(clock);
    expect(store.state()).toEqual([]);
    beginOk(store, makeFacts(makeView()));
    expect(store.state().length).toBe(1);
    store.dispose();
    expect(store.state()).toEqual([]);
  });
});

describe("dispose", () => {
  it("clears all entries, reports disposed and is idempotent", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const selection = beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 2) })));
    expect(store.disposed).toBe(false);

    store.dispose();
    expect(store.disposed).toBe(true);
    expect(store.state()).toEqual([]);
    store.dispose();
    expect(store.disposed).toBe(true);
    expect(commitFailure(store, selection)).toBe("disposed");
  });

  it("makes invalidate a no-op after dispose", () => {
    const clock = createClock();
    const store = makeStore(clock);
    beginOk(store, makeFacts(makeView()));
    store.dispose();
    expect(() => store.invalidate()).not.toThrow();
    expect(store.state()).toEqual([]);
  });
});

describe("stop-state priority", () => {
  it("reports disposed before an aborted signal on begin and commit", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const selection = beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 1) })));
    store.dispose();
    const controller = new AbortController();
    controller.abort();
    expect(beginFailure(store, {
      facts: makeFacts(makeView()),
      consumer: "consumer-1",
      signal: controller.signal,
    })).toBe("disposed");
    expect(commitFailure(store, selection, { signal: controller.signal })).toBe("disposed");
  });

  it("checks the stop state before validating the begin input", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const controller = new AbortController();
    controller.abort();
    expect(beginFailure(store, {
      facts: undefined as unknown as ReviewerSessionFacts,
      consumer: "",
      signal: controller.signal,
    })).toBe("cancelled");
    expect(beginFailure(store, {
      facts: undefined as unknown as ReviewerSessionFacts,
      consumer: "",
      deadline: Number.NaN,
    })).toBe("deadline");
  });

  it("checks the commit stop state before looking up the consumer", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const controller = new AbortController();
    controller.abort();
    const forged = { owner: "nobody", consumer: "nobody" } as unknown as ContextSelection;
    expect(commitFailure(store, forged, { signal: controller.signal })).toBe("cancelled");
    expect(commitFailure(store, forged, { deadline: CLOCK_START })).toBe("deadline");
  });
});

describe("default limits", () => {
  it("defaults to a 30 minute retention window", () => {
    const boundaryClock = createClock();
    const boundaryStore = makeStore(boundaryClock);
    const view = makeView({ transcript: makeTranscript(1, 2), captureSeq: 1 });
    commitOk(boundaryStore, beginOk(boundaryStore, makeFacts(view)));
    boundaryClock.advance(30 * 60_000);
    expect(beginOk(boundaryStore, makeFacts(view)).mode).toBe("full");

    const insideClock = createClock();
    const insideStore = makeStore(insideClock);
    commitOk(insideStore, beginOk(insideStore, makeFacts(view)));
    insideClock.advance(30 * 60_000 - 1);
    expect(beginOk(insideStore, makeFacts(view)).mode).toBe("delta");
  });

  it("defaults to eight consumers per owner", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const facts = makeFacts(makeView({ transcript: makeTranscript(1, 1) }));
    for (let index = 0; index < 9; index += 1) {
      beginOk(store, facts, `consumer-${index}`);
    }
    expect(store.state().length).toBe(8);
    expect(consumerSnapshot(store, "consumer-8")).toBeDefined();
    expect(consumerSnapshot(store, "consumer-0")).toBeUndefined();
  });

  it("evicts deterministically by access order when the injected clock does not advance", () => {
    const clock = createClock();
    const store = makeStore(clock, { maxOwners: 2 });
    beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 1) })));
    beginOk(store, makeFacts(makeView({ owner: "owner-b", transcript: makeTranscript(1, 1) })));
    beginOk(store, makeFacts(makeView({ owner: "owner-c", transcript: makeTranscript(1, 1) })));

    expect(store.state().map((entry) => entry.owner)).toEqual(["owner-b", "owner-c"]);
  });
});

describe("authorization in Delta reads", () => {
  it("always returns the full authorization list while the evidence region stays incremental", () => {
    const clock = createClock();
    const store = makeStore(clock);
    const authorization = [makeAuthorization("auth:1", "please change the config")];
    const firstView = makeView({ transcript: makeTranscript(1, 2), authorization, captureSeq: 1 });
    commitOk(store, beginOk(store, makeFacts(firstView)));

    const appendedView = makeView({ transcript: makeTranscript(1, 3), authorization, captureSeq: 2 });
    const delta = beginOk(store, makeFacts(appendedView));

    expect(delta.mode).toBe("delta");
    expect(delta.authorization).toEqual([{ sourceEntryId: "source-auth:1", text: "please change the config" }]);
    expect(delta.authorization).toEqual(projectDeltaEvidence(appendedView, 2).authorization);
    expect(delta.evidence.map((item) => item.id)).toEqual(["e3"]);
  });
});

describe("commit staleness: revision digest", () => {
  it("rejects a selection made against different revisions", () => {
    const clock = createClock();
    const store = makeStore(clock);
    commitOk(store, beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 2), captureSeq: 1 }))));
    const delta = beginOk(store, makeFacts(makeView({ transcript: makeTranscript(1, 3), captureSeq: 2 })));

    const forged = {
      ...delta,
      revisions: { ...delta.revisions, projectRules: delta.revisions.projectRules + 1 },
    } as ContextSelection;

    expect(commitFailure(store, forged)).toBe("stale");
    expect(commitOk(store, delta)).toBe(1);
  });
});
