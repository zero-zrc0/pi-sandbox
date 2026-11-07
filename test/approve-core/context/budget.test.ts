import { describe, expect, it } from "vitest";
import {
  checkProviderBudget,
  decisionBudget,
  estimateJsonStringContentTokenQuarters,
  estimateTextTokens,
  hasUnpairedToolResults,
  historySelectableEvidence,
  measureRequestTokens,
  measureRequestTokenQuarters,
  selectBudgetedEvidence,
  selectBudgetedEvidenceByCost,
  type BudgetedEvidence,
  type DecisionBudget,
  type ProviderBudgetInput,
} from "#approve-core/context/budget";
import type { ApprovalEvidence } from "#approve-core/context/types";
import { renderEvidence } from "#approve-core/context/projection";
import { renderMaterial, serializeMaterialEvidenceEntry } from "#approve-core/nodes/llm-approver/protocol";
import { prepareDecisionMaterial } from "#approve-core/nodes/decision-approver/material";

function evidence(id: string, overrides: Partial<ApprovalEvidence> = {}): ApprovalEvidence {
  return { id, source: "summary", text: `text:${id}`, digest: `digest:${id}`, ...overrides };
}

function userEvidence(id: string): ApprovalEvidence {
  return evidence(id, { source: "user" });
}

function assistantEvidence(id: string): ApprovalEvidence {
  return evidence(id, { source: "assistant" });
}

function toolCallEvidence(id: string, toolCallId: string): ApprovalEvidence {
  return evidence(id, { source: "tool", toolPart: "call", toolCallId });
}

function toolResultEvidence(id: string, toolCallId: string): ApprovalEvidence {
  return evidence(id, { source: "tool", toolPart: "result", toolCallId });
}

describe("decisionBudget", () => {
  it("defaults to the 32768 hard cap with an 80% packing target", () => {
    expect(decisionBudget()).toEqual({ max: 32768, target: 26214 });
  });

  it("uses a legal configured cap and derives the 80% target from it", () => {
    expect(decisionBudget(1000)).toEqual({ max: 1000, target: 800 });
    expect(decisionBudget(65536)).toEqual({ max: 65536, target: 52428 });
  });

  it("floors the target at 500 without ever exceeding a smaller cap", () => {
    // A cap below the floor cannot honour both rules; the cap is a hard limit,
    // so the target stays at the cap instead of rising above it.
    expect(decisionBudget(400).target).toBe(400);
    expect(decisionBudget(624).target).toBe(500);
    expect(decisionBudget(625).target).toBe(500);
    expect(decisionBudget(1000).target).toBe(800);
    for (const max of [1, 400, 500, 625, 1000, 65536, 32768]) {
      expect(decisionBudget(max).target).toBeLessThanOrEqual(max);
    }
  });

  it("falls back to the default cap for anything that is not a positive safe integer", () => {
    const defaults: DecisionBudget = { max: 32768, target: 26214 };
    const invalidInputs: unknown[] = [
      null,
      undefined,
      0,
      -1,
      1.5,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      Number.NEGATIVE_INFINITY,
      Number.MAX_SAFE_INTEGER + 2,
      "4096",
      true,
      {},
    ];
    for (const value of invalidInputs) {
      expect(decisionBudget(value as number)).toEqual(defaults);
    }
  });
});

describe("estimateTextTokens", () => {
  it("charges a quarter token per non-CJK code point and rounds the total up", () => {
    expect(estimateTextTokens("")).toBe(0);
    expect(estimateTextTokens("a")).toBe(1);
    expect(estimateTextTokens("abcd")).toBe(1);
    expect(estimateTextTokens("abcde")).toBe(2);
    expect(estimateTextTokens("abcdefgh")).toBe(2);
    expect(estimateTextTokens("abcdefghi")).toBe(3);
  });

  it("charges one token per CJK unified ideograph in mixed text", () => {
    expect(estimateTextTokens("你好")).toBe(2);
    expect(estimateTextTokens("中文abc")).toBe(3);
    expect(estimateTextTokens("中abcd")).toBe(2);
  });

  it("covers every spec CJK range and iterates astral code points, not UTF-16 units", () => {
    const cjkExamples = [
      "\u3002", // CJK Symbols and Punctuation
      "\u3042", // Hiragana
      "\u30a2", // Katakana
      "\u3400", // CJK Unified Ideographs Extension A
      "\u4e00", // CJK Unified Ideographs
      "\uf900", // CJK Compatibility Ideographs
      "\uff21", // Fullwidth Forms
      "\u1100", // Hangul Jamo
      "\u3131", // Hangul Compatibility Jamo
      "\ua960", // Hangul Jamo Extended-A
      "\ud55c", // Hangul Syllables
      "\u{20000}", // CJK Unified Ideographs Extension B
    ];
    for (const character of cjkExamples) {
      expect(estimateTextTokens(character)).toBe(1);
    }

    // Two ext-B ideographs are two code points (four UTF-16 units), so 2 tokens.
    expect(estimateTextTokens("\u{20000}\u{20000}")).toBe(2);
    // Ten astral non-CJK code points are 2.5 tokens before rounding up.
    expect(estimateTextTokens("\u{1f600}".repeat(10))).toBe(3);
    expect(estimateTextTokens("\u{1d400}")).toBe(1);
    // 0.25 + 1 = 1.25, rounded up.
    expect(estimateTextTokens("a\u3002")).toBe(2);
    // Four code points just below the punctuation block stay at a quarter token each.
    expect(estimateTextTokens("\u2fff\u2fff\u2fff\u2fff")).toBe(1);
  });

  it("rejects non-string input with a TypeError", () => {
    const invalidInputs: unknown[] = [42, null, undefined, ["a"], { length: 1 }, true];
    for (const value of invalidInputs) {
      expect(() => estimateTextTokens(value as string)).toThrow(TypeError);
    }
  });
});

describe("measureRequestTokens", () => {
  it("measures the complete rendered request JSON, including JSON punctuation", () => {
    expect(measureRequestTokens({ hello: "world" })).toBe(5);
    expect(measureRequestTokens([1, 2, 3])).toBe(2);
    expect(measureRequestTokens("hi")).toBe(1);
    expect(measureRequestTokens(42)).toBe(1);
    // 10 ASCII code points of JSON plus two CJK code points: 2.5 + 2 = 4.5, up to 5.
    expect(measureRequestTokens({ msg: "你好" })).toBe(5);
  });

  it("throws an Error when the request cannot be serialized", () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => measureRequestTokens(cyclic)).toThrow(Error);
    expect(() => measureRequestTokens(10n)).toThrow(Error);
    // JSON.stringify(undefined) is undefined rather than JSON text.
    expect(() => measureRequestTokens(undefined)).toThrow(Error);
  });
});

const providerBase: ProviderBudgetInput = {
  context: { a: 1 }, // rendered JSON '{"a":1}' is 7 code points: 1.75 tokens, up to 2
  outputTokens: 100,
  maxOutputTokens: 500,
  contextWindowTokens: 1000,
};

describe("checkProviderBudget", () => {
  it("accepts a request inside the window and reports actual output plus measured input", () => {
    expect(checkProviderBudget(providerBase)).toEqual({ ok: true, outputTokens: 100, inputTokens: 2 });
  });

  it("rejects an unknown or non-positive window, model output limit and requested output", () => {
    for (const contextWindowTokens of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(checkProviderBudget({ ...providerBase, contextWindowTokens }))
        .toEqual({ ok: false, reason: "invalid-context-window" });
    }
    for (const maxOutputTokens of [0, -500, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(checkProviderBudget({ ...providerBase, maxOutputTokens }))
        .toEqual({ ok: false, reason: "invalid-output-limit" });
    }
    for (const outputTokens of [0, -10, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(checkProviderBudget({ ...providerBase, outputTokens }))
        .toEqual({ ok: false, reason: "invalid-output-budget" });
    }
  });

  it("rejects an estimator that was supplied but is not a function", () => {
    for (const estimateTokens of [42, null]) {
      const result = checkProviderBudget({
        ...providerBase,
        estimateTokens: estimateTokens as unknown as (text: string) => number,
      });
      expect(result).toEqual({ ok: false, reason: "invalid-estimator" });
    }
  });

  it("uses an injected estimator over the complete rendered request JSON", () => {
    const measured: string[] = [];
    const result = checkProviderBudget({
      ...providerBase,
      context: { a: "b" },
      outputTokens: 25,
      maxOutputTokens: 100,
      estimateTokens: (text) => {
        measured.push(text);
        return text.length;
      },
    });

    expect(measured).toEqual(['{"a":"b"}']);
    expect(result).toEqual({ ok: true, outputTokens: 25, inputTokens: 9 });
  });

  it("fails when the context cannot be serialized into the request", () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    for (const context of [cyclic, 10n]) {
      expect(checkProviderBudget({ ...providerBase, context }))
        .toEqual({ ok: false, reason: "context-not-serializable" });
    }
  });

  it("keeps room for the framing margin and treats an unusable margin as zero", () => {
    // '"' + 400 x + '"' is 402 code points: 100.5 tokens, rounded up to 101.
    const context = "x".repeat(400);
    const budget = { context, outputTokens: 50, maxOutputTokens: 1000 } as const;

    expect(checkProviderBudget({ ...budget, contextWindowTokens: 200, framingMarginTokens: 50 }))
      .toEqual({ ok: false, reason: "context-window-exceeded" });
    // 101 + 50 + 50 lands exactly on the window and therefore passes.
    expect(checkProviderBudget({ ...budget, contextWindowTokens: 201, framingMarginTokens: 50 }))
      .toEqual({ ok: true, outputTokens: 50, inputTokens: 101 });

    for (const framingMarginTokens of [Number.NaN, -10, Number.POSITIVE_INFINITY]) {
      expect(checkProviderBudget({ ...budget, contextWindowTokens: 151, framingMarginTokens }))
        .toEqual({ ok: true, outputTokens: 50, inputTokens: 101 });
    }
  });

  it("takes the smaller of the requested and model output budgets without raising either", () => {
    expect(checkProviderBudget({
      ...providerBase,
      outputTokens: 8000,
      maxOutputTokens: 4000,
      contextWindowTokens: 100_000,
    })).toEqual({ ok: true, outputTokens: 4000, inputTokens: 2 });

    expect(checkProviderBudget({ ...providerBase, outputTokens: 10, maxOutputTokens: 4000 }))
      .toEqual({ ok: true, outputTokens: 10, inputTokens: 2 });
  });
});

describe("historySelectableEvidence", () => {
  it("drops user authorization evidence, keeps history order and freezes the result", () => {
    const input: ApprovalEvidence[] = [
      userEvidence("auth-1"),
      assistantEvidence("a-1"),
      toolCallEvidence("call-1", "call-1"),
      toolResultEvidence("result-1", "call-1"),
      userEvidence("auth-2"),
    ];

    const selectable = historySelectableEvidence(input);

    expect(selectable.map((item) => item.id)).toEqual(["a-1", "call-1", "result-1"]);
    expect(Object.isFrozen(selectable)).toBe(true);
    // The caller's list is never rewritten.
    expect(input).toHaveLength(5);
    expect(input[0]?.source).toBe("user");

    expect(historySelectableEvidence([])).toEqual([]);
    expect(Object.isFrozen(historySelectableEvidence([]))).toBe(true);
    expect(historySelectableEvidence([userEvidence("auth-only")])).toEqual([]);
  });
});

describe("hasUnpairedToolResults", () => {
  it("reports an id whose results outnumber its calls", () => {
    expect(hasUnpairedToolResults([
      toolCallEvidence("call-1", "call-1"),
      toolResultEvidence("result-1", "call-1"),
      toolResultEvidence("result-2", "call-1"),
    ])).toBe(true);

    expect(hasUnpairedToolResults([toolResultEvidence("orphan", "call-9")])).toBe(true);

    expect(hasUnpairedToolResults([
      toolCallEvidence("call-1", "call-1"),
      toolResultEvidence("result-1", "call-1"),
      toolCallEvidence("call-2", "call-2"),
      toolResultEvidence("result-2", "call-2"),
      toolResultEvidence("result-3", "call-2"),
    ])).toBe(true);
  });

  it("accepts balanced or call-heavy histories and ignores entries without a tool identity", () => {
    expect(hasUnpairedToolResults([])).toBe(false);
    expect(hasUnpairedToolResults([
      toolCallEvidence("call-1", "call-1"),
      toolResultEvidence("result-1", "call-1"),
    ])).toBe(false);
    // A call without its result is not an unpaired result.
    expect(hasUnpairedToolResults([toolCallEvidence("call-1", "call-1")])).toBe(false);
    expect(hasUnpairedToolResults([assistantEvidence("a-1")])).toBe(false);
    expect(hasUnpairedToolResults([evidence("no-id", { source: "tool", toolPart: "result" })])).toBe(false);
    expect(hasUnpairedToolResults([evidence("id-only", { toolCallId: "call-1" })])).toBe(false);
  });
});

function evidenceIds(result: BudgetedEvidence | undefined): readonly string[] | undefined {
  return result?.evidence.map((item) => item.id);
}

function fitsWithin(limit: number) {
  return (candidate: readonly ApprovalEvidence[], omitted: boolean): boolean =>
    omitted && candidate.length <= limit;
}

describe("selectBudgetedEvidence", () => {
  it("returns the evidence unchanged when the full list fits without the omitted flag", () => {
    const list = [assistantEvidence("a-1"), toolCallEvidence("call-1", "call-1")];
    const consulted: { readonly ids: readonly string[]; readonly omitted: boolean }[] = [];
    const result = selectBudgetedEvidence(list, (candidate, omitted) => {
      consulted.push({ ids: candidate.map((item) => item.id), omitted });
      return candidate.length <= 10;
    });

    expect(result?.evidence).toBe(list);
    expect(result?.omitted).toBe(false);
    expect(consulted[0]).toEqual({ ids: ["a-1", "call-1"], omitted: false });

    expect(selectBudgetedEvidence([], () => true)).toEqual({ evidence: [], omitted: false });
  });

  it("omits a standalone assistant group while keeping every mandatory entry", () => {
    const list = [
      evidence("summary-1"),
      assistantEvidence("a-1"),
      evidence("environment-1", { source: "environment" }),
    ];

    const result = selectBudgetedEvidence(list, fitsWithin(2));

    expect(evidenceIds(result)).toEqual(["summary-1", "environment-1"]);
    expect(result?.omitted).toBe(true);
  });

  it("omits an assistant together with the complete tool pair that follows it", () => {
    const list = [
      assistantEvidence("a-1"),
      toolCallEvidence("call-1", "call-1"),
      toolResultEvidence("result-1", "call-1"),
      evidence("summary-1"),
    ];

    // Room for the mandatory summary plus either the assistant or the pair,
    // never for all three grouped entries: grouping decides the outcome.
    const result = selectBudgetedEvidence(list, fitsWithin(3));

    expect(evidenceIds(result)).toEqual(["summary-1"]);
    expect(result?.omitted).toBe(true);
  });

  it("drops a complete tool pair that stands alone as its own group", () => {
    const list = [
      evidence("summary-1"),
      toolCallEvidence("call-1", "call-1"),
      toolResultEvidence("result-1", "call-1"),
    ];

    const result = selectBudgetedEvidence(list, fitsWithin(1));

    expect(evidenceIds(result)).toEqual(["summary-1"]);
    expect(result?.omitted).toBe(true);
  });

  it("fills the budget from the newest group backwards", () => {
    const list = [
      assistantEvidence("a-old"),
      evidence("summary-1"),
      assistantEvidence("a-new"),
      evidence("environment-1", { source: "environment" }),
    ];

    // Two mandatory entries plus one of the two one-entry assistant groups.
    const result = selectBudgetedEvidence(list, fitsWithin(3));

    expect(evidenceIds(result)).toEqual(["summary-1", "a-new", "environment-1"]);
    expect(result?.omitted).toBe(true);
  });

  it("returns undefined when the mandatory entries alone do not fit", () => {
    const list = [
      assistantEvidence("a-1"),
      evidence("summary-1"),
      evidence("environment-1", { source: "environment" }),
    ];

    expect(selectBudgetedEvidence(list, fitsWithin(1))).toBeUndefined();
  });

  it("returns undefined when the history has no droppable group at all", () => {
    // A result before its call is not a complete pair, so nothing may be dropped.
    const list = [
      toolResultEvidence("result-1", "call-1"),
      toolCallEvidence("call-1", "call-1"),
      evidence("summary-1"),
    ];

    expect(selectBudgetedEvidence(list, fitsWithin(3))).toBeUndefined();
  });

  it("keeps duplicated and out-of-order tool identities mandatory", () => {
    // The same call id appears with two results, so neither pair is complete.
    const duplicated = [
      assistantEvidence("a-1"),
      toolCallEvidence("call-1", "call-1"),
      toolResultEvidence("result-1", "call-1"),
      toolResultEvidence("result-2", "call-1"),
    ];
    expect(selectBudgetedEvidence(duplicated, fitsWithin(2))).toBeUndefined();

    // A result that precedes its call is not a pair either; only the assistant
    // is droppable, and both tool entries stay in their original order.
    const outOfOrder = [
      assistantEvidence("a-1"),
      toolResultEvidence("result-1", "call-1"),
      toolCallEvidence("call-1", "call-1"),
    ];
    const result = selectBudgetedEvidence(outOfOrder, fitsWithin(2));

    expect(evidenceIds(result)).toEqual(["result-1", "call-1"]);
    expect(result?.omitted).toBe(true);
  });

  it("does not treat isolated results or calls without results as droppable pairs", () => {
    const isolatedResult = [assistantEvidence("a-1"), toolResultEvidence("result-1", "call-1")];
    const keptResult = selectBudgetedEvidence(isolatedResult, fitsWithin(1));
    expect(evidenceIds(keptResult)).toEqual(["result-1"]);
    expect(keptResult?.omitted).toBe(true);

    const pendingCall = [assistantEvidence("a-1"), toolCallEvidence("call-1", "call-1")];
    const keptCall = selectBudgetedEvidence(pendingCall, fitsWithin(1));
    expect(evidenceIds(keptCall)).toEqual(["call-1"]);
    expect(keptCall?.omitted).toBe(true);
  });

  it("keeps every following complete pair in the assistant group it belongs to", () => {
    const list = [
      assistantEvidence("a-1"),
      toolCallEvidence("call-1", "call-1"),
      toolResultEvidence("result-1", "call-1"),
      toolCallEvidence("call-2", "call-2"),
      toolResultEvidence("result-2", "call-2"),
      evidence("summary-1"),
    ];

    // The assistant group is five entries; only the summary is mandatory.
    const result = selectBudgetedEvidence(list, fitsWithin(1));

    expect(evidenceIds(result)).toEqual(["summary-1"]);
    expect(result?.omitted).toBe(true);
  });

  it("preserves the original order when a kept group interleaves with mandatory entries", () => {
    const list = [
      evidence("summary-1"),
      assistantEvidence("a-1"),
      evidence("environment-1", { source: "environment" }),
    ];

    const result = selectBudgetedEvidence(list, fitsWithin(3));

    expect(evidenceIds(result)).toEqual(["summary-1", "a-1", "environment-1"]);
    expect(result?.omitted).toBe(true);
  });

  it("marks the result omitted even when every group is kept under the omitted flag", () => {
    const list = [assistantEvidence("a-1"), evidence("summary-1")];
    let fullListRejected = false;
    const result = selectBudgetedEvidence(list, (candidate, omitted) => {
      if (!omitted) fullListRejected = true;
      return omitted && candidate.length <= 2;
    });

    expect(fullListRejected).toBe(true);
    expect(evidenceIds(result)).toEqual(["a-1", "summary-1"]);
    expect(result?.omitted).toBe(true);
  });

  it("uses additive costs that match complete nested LLM request serialization", () => {
    const list = [
      evidence("old", { source: "assistant", text: "中文😀 quote: \"a\\b\"\nnext line" }),
      evidence("mandatory", { source: "environment", text: "固定值" }),
      evidence("large", { source: "assistant", text: "x".repeat(600) }),
      evidence("new", { source: "assistant", text: "émoji 🌐 and\\slashes" }),
    ];
    const request = (historyEvidence: readonly ApprovalEvidence[], historyOmitted: boolean) => ({
      messages: [
        { role: "system", content: "fixed rubric \"quoted\"", timestamp: 1 },
        {
          role: "user",
          content: renderMaterial({
            owner: "owner",
            historyVersion: 1,
            captureSeq: 2,
            revision: 3,
            representation: "full",
            mode: "default",
            authorization: [{ sourceEntryId: "auth", text: "user authorization" }],
            guidance: [],
            historyEvidence,
            historyOmitted,
            calls: [],
          }),
          timestamp: 1,
        },
      ],
    });
    const target = [list[0]!, list[1]!, list[3]!];
    const targetQuarters = measureRequestTokenQuarters(request(target, true));
    const costs = {
      limitQuarterTokens: Math.ceil(targetQuarters / 4) * 4,
      baseQuarterTokens: {
        all: measureRequestTokenQuarters(request([], false)),
        omitted: measureRequestTokenQuarters(request([], true)),
      },
      entryQuarterTokens: list.map((entry) => estimateJsonStringContentTokenQuarters(
        serializeMaterialEvidenceEntry(entry),
      )),
      separatorQuarterTokens: estimateJsonStringContentTokenQuarters(","),
      emptyPlaceholderQuarterTokens: 0,
    };
    const fullTokens = measureRequestTokens(request(list, false));
    const limit = Math.ceil(targetQuarters / 4);
    expect(fullTokens).toBeGreaterThan(limit);
    expect(targetQuarters).toBe(
      costs.baseQuarterTokens.omitted +
      costs.entryQuarterTokens[0]! +
      costs.entryQuarterTokens[1]! +
      costs.entryQuarterTokens[3]! +
      costs.separatorQuarterTokens * 2,
    );

    const exact = selectBudgetedEvidence(list, (candidate, omitted) =>
      measureRequestTokens(request(candidate, omitted)) <= limit,
    );
    const incremental = selectBudgetedEvidenceByCost(list, { ...costs, limitQuarterTokens: limit * 4 });

    expect(incremental?.evidence.map((entry) => entry.id)).toEqual(exact?.evidence.map((entry) => entry.id));
    expect(incremental?.evidence.map((entry) => entry.id)).toEqual(["old", "mandatory", "new"]);
    expect(incremental?.omitted).toBe(true);
  });

  it("accounts for decision text, omission notices, and JSON string escaping exactly", () => {
    const list = [
      evidence("one", { source: "assistant", text: "中文😀 \"quoted\" \\\nnext" }),
      evidence("two", { source: "environment", text: "accent é and tab\t" }),
      evidence("three", { source: "tool", toolPart: "result", toolCallId: "c1", text: "C:\\path" }),
    ];
    const call = {
      toolCallId: "call-1",
      toolName: "bash",
      arguments: { command: "echo" },
      argumentsDigest: "digest",
      digest: "digest",
      units: [],
    };
    const request = (historyEvidence: readonly ApprovalEvidence[], historyOmitted: boolean) => ({
      state: {
        rubric: "固定评审规则\n",
        permissionReview: prepareDecisionMaterial({
          selection: { authorization: [], mode: "full" },
          call,
          guidance: { included: [] },
          historyEvidence,
          historyOmitted,
        }),
      },
      questions: { verdict: { type: "choice", instructions: "选择结果" } },
    });
    const baseQuarterTokens = {
      all: measureRequestTokenQuarters(request([], false)),
      omitted: measureRequestTokenQuarters(request([], true)),
    };
    const entryQuarterTokens = list.map((entry) =>
      estimateJsonStringContentTokenQuarters(renderEvidence([entry])),
    );
    const separatorQuarterTokens = estimateJsonStringContentTokenQuarters("\n");
    const emptyPlaceholderQuarterTokens = estimateJsonStringContentTokenQuarters("(none)");

    for (const omitted of [false, true]) {
      for (let mask = 0; mask < 1 << list.length; mask += 1) {
        const selected = list.filter((_, index) => (mask & (1 << index)) !== 0);
        const expected = selected.length === 0
          ? baseQuarterTokens[omitted ? "omitted" : "all"]
          : baseQuarterTokens[omitted ? "omitted" : "all"] - emptyPlaceholderQuarterTokens +
            selected.reduce((total, entry) => total + entryQuarterTokens[list.indexOf(entry)]!, 0) +
            separatorQuarterTokens * (selected.length - 1);
        expect(measureRequestTokenQuarters(request(selected, omitted))).toBe(expected);
      }
    }
  });
});
