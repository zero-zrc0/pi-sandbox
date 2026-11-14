import { describe, expect, it } from "vitest";
import {
  LEARNING_REJECTION_REASONS,
  LearningCandidateCollector,
  type LearningCandidate,
  type StagedLearningData,
} from "#approve-core/policy/project-rules/candidates";

const ATTEMPT = "attempt-fixed";
const REQUEST = "req-1";

const delay = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

function newCollector(options?: ConstructorParameters<typeof LearningCandidateCollector>[0]): LearningCandidateCollector {
  return new LearningCandidateCollector(options);
}

function explicit(attemptId: string, requestId: string): { attemptId: string; requestId: string } {
  return { attemptId, requestId };
}

function emptyStage(): StagedLearningData {
  return { candidates: [], rejections: [] };
}

function valuesOf(candidates: readonly LearningCandidate[]): Array<Record<string, unknown>> {
  return candidates.map((candidate) => candidate.value as Record<string, unknown>);
}

describe("rejection reasons", () => {
  it("exposes stable reason strings", () => {
    expect(LEARNING_REJECTION_REASONS).toEqual({
      unknownField: "unknown-field",
      fieldNotArray: "field-not-array",
      invalidCandidate: "invalid-candidate",
      candidateLimit: "candidate-limit",
      bucketCapacity: "bucket-capacity",
    });
  });
});

describe("runAttempt implicit context", () => {
  it("assigns monotonically increasing attempt ids", () => {
    const collector = newCollector();
    expect(collector.runAttempt((attemptId) => attemptId)).toBe("attempt-1");
    expect(collector.runAttempt((attemptId) => attemptId)).toBe("attempt-2");
    expect(collector.runAttempt((attemptId) => attemptId)).toBe("attempt-3");
  });

  it("exposes the current attempt only inside runAttempt", () => {
    const collector = newCollector();
    expect(collector.currentAttemptId()).toBeUndefined();
    expect(collector.runAttempt(() => collector.currentAttemptId())).toBe("attempt-1");
    expect(collector.currentAttemptId()).toBeUndefined();
  });

  it("returns the work result and restores the outer attempt after nesting", () => {
    const collector = newCollector();
    const observed = collector.runAttempt((outerAttemptId) => {
      const inner = collector.runAttempt((innerAttemptId) => {
        collector.parse({ create: [{ from: innerAttemptId }] }, { requestId: "shared" });
        return { innerAttemptId, innerCurrent: collector.currentAttemptId() };
      });
      collector.parse({ create: [{ from: outerAttemptId }] }, { requestId: "shared" });
      return {
        outerAttemptId,
        innerAttemptId: inner.innerAttemptId,
        innerCurrent: inner.innerCurrent,
        restored: collector.currentAttemptId(),
      };
    });

    expect(observed).toEqual({
      outerAttemptId: "attempt-1",
      innerAttemptId: "attempt-2",
      innerCurrent: "attempt-2",
      restored: "attempt-1",
    });
    expect(valuesOf(collector.take("attempt-1", ["shared"]).candidates)).toEqual([{ from: "attempt-1" }]);
    expect(valuesOf(collector.take("attempt-2", ["shared"]).candidates)).toEqual([{ from: "attempt-2" }]);
  });

  it("restores the context when the work throws", () => {
    const collector = newCollector();
    expect(() =>
      collector.runAttempt(() => {
        throw new Error("review failed");
      }),
    ).toThrow("review failed");
    expect(collector.currentAttemptId()).toBeUndefined();
    expect(collector.runAttempt((attemptId) => attemptId)).toBe("attempt-2");
  });

  it("keeps the async context across awaits", async () => {
    const collector = newCollector();
    const observed = await Promise.all([
      collector.runAttempt(async () => {
        await delay(6);
        return collector.currentAttemptId();
      }),
      collector.runAttempt(async () => {
        await delay(1);
        return collector.currentAttemptId();
      }),
    ]);
    expect(observed).toEqual(["attempt-1", "attempt-2"]);
  });

  it("isolates interleaved async attempts that share a request id", async () => {
    const collector = newCollector();
    await Promise.all([
      collector.runAttempt(async (attemptId) => {
        await delay(6);
        collector.parse({ create: [{ owner: attemptId }] }, { requestId: "shared" });
      }),
      collector.runAttempt(async (attemptId) => {
        await delay(1);
        collector.parse({ create: [{ owner: attemptId }] }, { requestId: "shared" });
      }),
    ]);

    expect(valuesOf(collector.take("attempt-1", ["shared"]).candidates)).toEqual([{ owner: "attempt-1" }]);
    expect(valuesOf(collector.take("attempt-2", ["shared"]).candidates)).toEqual([{ owner: "attempt-2" }]);
  });

  it("stages under an explicit attempt id when one is given", () => {
    const collector = newCollector();
    const result = collector.parse({ create: [{ command: "ls" }] }, explicit("attempt-explicit", REQUEST));
    expect(result.candidates.map((candidate) => candidate.attemptId)).toEqual(["attempt-explicit"]);
    expect(collector.hasStagedData("attempt-explicit")).toBe(true);
    expect(collector.hasStagedData("attempt-1")).toBe(false);
  });

  it("stages under the implicit attempt id", () => {
    const collector = newCollector();
    const attemptId = collector.runAttempt((generated) => {
      collector.parse({ create: [{ marker: 1 }] }, { requestId: REQUEST });
      return generated;
    });
    expect(valuesOf(collector.take(attemptId, [REQUEST]).candidates)).toEqual([{ marker: 1 }]);
  });

  it("prefers an explicit attempt id over the implicit context", () => {
    const collector = newCollector();
    collector.runAttempt(() => {
      collector.parse({ create: [{ marker: "explicit" }] }, explicit("attempt-explicit", REQUEST));
    });
    expect(collector.take("attempt-1", [REQUEST])).toEqual(emptyStage());
    expect(valuesOf(collector.take("attempt-explicit", [REQUEST]).candidates)).toEqual([{ marker: "explicit" }]);
  });

  it("ignores parse calls without an attempt context", () => {
    const collector = newCollector();
    expect(collector.parse({ create: [{ command: "ls" }] }, { requestId: REQUEST })).toEqual(emptyStage());
    expect(collector.parse({ create: [{ command: "ls" }] })).toEqual(emptyStage());
    expect(collector.hasStagedData()).toBe(false);
    expect(collector.pendingRequestCount()).toBe(0);
  });

  it("ignores parse calls with an unusable attempt or request id", () => {
    const collector = newCollector();
    expect(collector.parse({ create: [{ command: "ls" }] }, { attemptId: "", requestId: REQUEST })).toEqual(emptyStage());
    expect(collector.parse({ create: [{ command: "ls" }] }, explicit(ATTEMPT, ""))).toEqual(emptyStage());
    expect(collector.hasStagedData()).toBe(false);
  });
});

describe("parse input shape", () => {
  it("ignores non plain-object inputs", () => {
    const collector = newCollector();
    const inputs: unknown[] = [
      null,
      undefined,
      42,
      "text",
      true,
      [],
      [{ create: [{ command: "ls" }] }],
      new Date(0),
      new Map(),
      new (class Sample {})(),
      () => ({ create: [{}] }),
    ];
    for (const input of inputs) {
      expect(collector.parse(input, explicit(ATTEMPT, REQUEST))).toEqual(emptyStage());
    }
    expect(collector.hasStagedData()).toBe(false);
  });

  it("ignores payloads without a create or revoke key", () => {
    const collector = newCollector();
    expect(collector.parse({}, explicit(ATTEMPT, REQUEST))).toEqual(emptyStage());
    expect(collector.parse({ mystery: true }, explicit(ATTEMPT, REQUEST))).toEqual(emptyStage());
    expect(collector.parse({ create: undefined }, explicit(ATTEMPT, REQUEST))).not.toEqual(emptyStage());
    collector.clear();
    expect(collector.parse({ create: [] }, explicit(ATTEMPT, REQUEST))).toEqual(emptyStage());
    expect(collector.hasStagedData()).toBe(false);
    expect(collector.pendingRequestCount()).toBe(0);
  });

  it("accepts a null-prototype data object", () => {
    const collector = newCollector();
    const input = Object.assign(Object.create(null) as Record<string, unknown>, {
      create: [{ command: "ls" }],
    });
    expect(valuesOf(collector.parse(input, explicit(ATTEMPT, REQUEST)).candidates)).toEqual([{ command: "ls" }]);
  });

  it("stages only unknown-field rejections alongside a legal key", () => {
    const collector = newCollector();
    const result = collector.parse(
      { create: [{ command: "ls" }], mystery: true, extra: 1 },
      explicit(ATTEMPT, REQUEST),
    );
    expect(valuesOf(result.candidates)).toEqual([{ command: "ls" }]);
    expect(result.rejections).toEqual([
      { attemptId: ATTEMPT, requestId: REQUEST, reason: "unknown-field" },
      { attemptId: ATTEMPT, requestId: REQUEST, reason: "unknown-field" },
    ]);
    expect(collector.hasStagedData()).toBe(true);
  });

  it("treats symbol-keyed properties as unknown fields alongside a legal key", () => {
    const collector = newCollector();
    const input = { create: [{ command: "ls" }], [Symbol("hidden")]: 1 };
    expect(collector.parse(input, explicit(ATTEMPT, REQUEST)).rejections).toEqual([
      { attemptId: ATTEMPT, requestId: REQUEST, reason: "unknown-field" },
    ]);
  });

  it("ignores a symbol-only payload without a legal key", () => {
    const collector = newCollector();
    expect(collector.parse({ [Symbol("hidden")]: 1 }, explicit(ATTEMPT, REQUEST))).toEqual(emptyStage());
    expect(collector.hasStagedData()).toBe(false);
  });

  it("rejects legal keys whose values are not arrays", () => {
    const collector = newCollector();
    const result = collector.parse(
      { create: { command: "ls" }, revoke: "rule-0000000000000001" },
      explicit(ATTEMPT, REQUEST),
    );
    expect(result.candidates).toEqual([]);
    expect(result.rejections).toEqual([
      { attemptId: ATTEMPT, requestId: REQUEST, field: "create", reason: "field-not-array" },
      { attemptId: ATTEMPT, requestId: REQUEST, field: "revoke", reason: "field-not-array" },
    ]);
  });

  it("never throws and stages nothing for accessor-backed payloads", () => {
    const collector = newCollector();
    const input: Record<string, unknown> = {};
    Object.defineProperty(input, "create", {
      enumerable: true,
      get() {
        throw new Error("unreadable input");
      },
    });
    expect(() => collector.parse(input, explicit(ATTEMPT, REQUEST))).not.toThrow();
    expect(collector.hasStagedData()).toBe(false);
  });
});

describe("parse candidates", () => {
  it("stages create and revoke candidates with field, index, attempt and request", () => {
    const collector = newCollector();
    const result = collector.parse(
      {
        create: [{ command: "ls" }, { command: "git status" }],
        revoke: [{ ruleId: "rule-1" }],
      },
      explicit(ATTEMPT, REQUEST),
    );
    expect(result.candidates).toEqual([
      { attemptId: ATTEMPT, requestId: REQUEST, field: "create", index: 0, value: { command: "ls" } },
      { attemptId: ATTEMPT, requestId: REQUEST, field: "create", index: 1, value: { command: "git status" } },
      { attemptId: ATTEMPT, requestId: REQUEST, field: "revoke", index: 0, value: { ruleId: "rule-1" } },
    ]);
    expect(result.rejections).toEqual([]);
  });

  it("keeps a revoke-only payload", () => {
    const collector = newCollector();
    const result = collector.parse({ revoke: [{ ruleId: "rule-1" }] }, explicit(ATTEMPT, REQUEST));
    expect(result.candidates.map((candidate) => candidate.field)).toEqual(["revoke"]);
  });

  it("returns only newly staged data from each parse call", () => {
    const collector = newCollector();
    collector.parse({ create: [{ command: "ls" }] }, explicit(ATTEMPT, REQUEST));
    const second = collector.parse({ create: [{ command: "pwd" }] }, explicit(ATTEMPT, REQUEST));
    expect(second.candidates).toHaveLength(1);
    expect(valuesOf(second.candidates)).toEqual([{ command: "pwd" }]);
    expect(collector.take(ATTEMPT, [REQUEST]).candidates).toHaveLength(2);
  });

  it("accepts null and nested containers inside a candidate object", () => {
    const collector = newCollector();
    const value = { command: "ls", flags: null, nested: { list: [1, true, "x"] }, empty: {} };
    expect(valuesOf(collector.parse({ create: [value] }, explicit(ATTEMPT, REQUEST)).candidates)).toEqual([value]);
  });

  it("accepts one object referenced twice without treating it as a cycle", () => {
    const collector = newCollector();
    const shared = { command: "ls" };
    const result = collector.parse({ create: [{ first: shared, second: shared }] }, explicit(ATTEMPT, REQUEST));
    expect(result.candidates).toHaveLength(1);
    expect(result.candidates[0]!.value).toEqual({ first: shared, second: shared });
  });

  it("keeps a __proto__ data key as an own property without touching prototypes", () => {
    const collector = newCollector();
    const value: Record<string, unknown> = {};
    Object.defineProperty(value, "__proto__", {
      value: { polluted: true },
      enumerable: true,
      configurable: true,
    });
    const result = collector.parse({ create: [value] }, explicit(ATTEMPT, REQUEST));
    expect(result.candidates).toHaveLength(1);
    const frozenValue = result.candidates[0]!.value;
    expect(Object.getPrototypeOf(frozenValue)).toBe(Object.prototype);
    expect(Object.prototype).not.toHaveProperty("polluted");
    expect(Object.prototype.hasOwnProperty.call(frozenValue, "__proto__")).toBe(true);
    expect(frozenValue["__proto__"]).toEqual({ polluted: true });
  });
});

describe("parse invalid candidates", () => {
  const cyclic: Record<string, unknown> = { command: "ls" };
  cyclic.self = cyclic;

  const INVALID_ITEMS: Array<[string, unknown]> = [
    ["undefined", undefined],
    ["null", null],
    ["a function", () => 1],
    ["a string", "text"],
    ["a number", 1],
    ["an array", []],
    ["a Date", new Date(0)],
    ["a Map", new Map()],
    ["a class instance", new (class Sample {})()],
    ["a nested function", { handler: () => 1 }],
    ["a nested undefined", { value: undefined }],
    ["a nested bigint", { value: 1n }],
    ["a nested NaN", { value: Number.NaN }],
    ["a nested Infinity", { value: Number.POSITIVE_INFINITY }],
    ["a nested symbol key", { [Symbol("hidden")]: 1 }],
    ["a cyclic reference", cyclic],
  ];

  it.each(INVALID_ITEMS)("rejects %s as invalid-candidate", (_label: string, item: unknown) => {
    const collector = newCollector();
    const result = collector.parse(
      { create: [{ command: "ls" }, item] },
      explicit(ATTEMPT, REQUEST),
    );
    expect(valuesOf(result.candidates)).toEqual([{ command: "ls" }]);
    expect(result.rejections).toEqual([
      { attemptId: ATTEMPT, requestId: REQUEST, field: "create", index: 1, reason: "invalid-candidate" },
    ]);
  });

  it("rejects a top-level array candidate", () => {
    const collector = newCollector();
    const result = collector.parse({ create: [[1, 2]] }, explicit(ATTEMPT, REQUEST));
    expect(result.candidates).toEqual([]);
    expect(result.rejections).toEqual([
      { attemptId: ATTEMPT, requestId: REQUEST, field: "create", index: 0, reason: "invalid-candidate" },
    ]);
  });

  it("never throws for accessor-backed candidate values or field items", () => {
    const collector = newCollector();
    const nested: Record<string, unknown> = {};
    Object.defineProperty(nested, "value", {
      enumerable: true,
      get() {
        throw new Error("unreadable candidate");
      },
    });
    expect(() => collector.parse({ create: [{ nested }] }, explicit(ATTEMPT, REQUEST))).not.toThrow();
    expect(collector.take(ATTEMPT, [REQUEST]).rejections).toEqual([
      { attemptId: ATTEMPT, requestId: REQUEST, field: "create", index: 0, reason: "invalid-candidate" },
    ]);

    collector.clear();
    const items: unknown[] = [{ command: "ls" }];
    Object.defineProperty(items, "1", {
      enumerable: true,
      get() {
        throw new Error("unreadable item");
      },
    });
    expect(() => collector.parse({ create: items }, explicit(ATTEMPT, REQUEST))).not.toThrow();
    const staged = collector.take(ATTEMPT, [REQUEST]);
    expect(valuesOf(staged.candidates)).toEqual([{ command: "ls" }]);
    expect(staged.rejections).toEqual([
      { attemptId: ATTEMPT, requestId: REQUEST, field: "create", index: 1, reason: "invalid-candidate" },
    ]);
  });
});

describe("parse limits", () => {
  const items = (count: number, start = 0): Array<Record<string, number>> =>
    Array.from({ length: count }, (_, index) => ({ index: start + index }));

  it("reads at most 32 items per field", () => {
    const collector = newCollector();
    const result = collector.parse(
      { create: items(40), revoke: items(40, 100) },
      explicit(ATTEMPT, REQUEST),
    );
    expect(result.candidates).toHaveLength(64);
    expect(result.candidates.filter((candidate) => candidate.field === "create").map((candidate) => candidate.index)).toEqual(
      Array.from({ length: 32 }, (_, index) => index),
    );
    expect(result.candidates.filter((candidate) => candidate.field === "revoke").map((candidate) => candidate.index)).toEqual(
      Array.from({ length: 32 }, (_, index) => index),
    );
    expect(result.rejections).toEqual([]);
  });

  it("honors a lower maxInputsPerField", () => {
    const collector = newCollector({ maxInputsPerField: 2 });
    const result = collector.parse({ create: items(5) }, explicit(ATTEMPT, REQUEST));
    expect(result.candidates).toHaveLength(2);
  });

  it("rejects candidates beyond maxCandidatesPerRequest", () => {
    const collector = newCollector({ maxCandidatesPerRequest: 2 });
    const result = collector.parse({ create: items(4) }, explicit(ATTEMPT, REQUEST));
    expect(valuesOf(result.candidates)).toEqual([{ index: 0 }, { index: 1 }]);
    expect(result.rejections).toEqual([
      { attemptId: ATTEMPT, requestId: REQUEST, field: "create", index: 2, reason: "candidate-limit" },
      { attemptId: ATTEMPT, requestId: REQUEST, field: "create", index: 3, reason: "candidate-limit" },
    ]);
  });

  it("caps the staged rejections at maxRejections", () => {
    const collector = newCollector({ maxRejections: 2 });
    const invalid = Array.from({ length: 5 }, () => () => 1);
    const result = collector.parse({ create: invalid }, explicit(ATTEMPT, REQUEST));
    expect(result.candidates).toEqual([]);
    expect(result.rejections).toHaveLength(2);
    expect(result.rejections.map((rejection) => rejection.index)).toEqual([0, 1]);
    expect(collector.take(ATTEMPT, [REQUEST]).rejections).toHaveLength(2);
  });

  it("keeps at most 64 rejections per request by default", () => {
    const collector = newCollector();
    const input: Record<string, unknown> = { create: [{ command: "ls" }] };
    for (let index = 0; index < 100; index += 1) input[`unknown${index}`] = index;
    const result = collector.parse(input, explicit(ATTEMPT, REQUEST));
    expect(valuesOf(result.candidates)).toEqual([{ command: "ls" }]);
    expect(result.rejections).toHaveLength(64);
    expect(result.rejections.every((rejection) => rejection.reason === "unknown-field")).toBe(true);
  });

  it("shares the candidate cap across repeated parses of one request", () => {
    const collector = newCollector({ maxCandidatesPerRequest: 2 });
    expect(collector.parse({ create: [{ n: 0 }] }, explicit(ATTEMPT, REQUEST)).candidates).toHaveLength(1);
    expect(collector.parse({ create: [{ n: 1 }] }, explicit(ATTEMPT, REQUEST)).candidates).toHaveLength(1);
    const overflow = collector.parse({ create: [{ n: 2 }] }, explicit(ATTEMPT, REQUEST));
    expect(overflow.candidates).toEqual([]);
    expect(overflow.rejections).toEqual([
      { attemptId: ATTEMPT, requestId: REQUEST, field: "create", index: 0, reason: "candidate-limit" },
    ]);
    expect(collector.take(ATTEMPT, [REQUEST]).candidates).toHaveLength(2);
  });

  it("shares the rejection cap across repeated parses of one request", () => {
    const collector = newCollector({ maxRejections: 2 });
    expect(collector.parse({ create: [() => 1, () => 2] }, explicit(ATTEMPT, REQUEST)).rejections).toHaveLength(2);
    expect(collector.parse({ create: [() => 3] }, explicit(ATTEMPT, REQUEST))).toEqual(emptyStage());
    expect(collector.take(ATTEMPT, [REQUEST]).rejections).toHaveLength(2);
  });

  it("ignores non-positive and non-finite option overrides", () => {
    const collector = newCollector({ maxActiveBuckets: 0, maxCandidatesPerRequest: Number.NaN, maxInputsPerField: -1 });
    expect(collector.parse({ create: items(3) }, explicit(ATTEMPT, REQUEST)).candidates).toHaveLength(2 + 1);
  });

  it("does not stage anything when a request only has empty fields", () => {
    const collector = newCollector();
    expect(collector.parse({ create: [], revoke: [] }, explicit(ATTEMPT, REQUEST))).toEqual(emptyStage());
    expect(collector.pendingRequestCount()).toBe(0);
    expect(collector.hasStagedData()).toBe(false);
  });
});

describe("active request bucket capacity", () => {
  it("admits at most 8 active request buckets by default", () => {
    const collector = newCollector();
    for (let index = 0; index < 8; index += 1) {
      const staged = collector.parse(
        { create: [{ index }] },
        explicit(ATTEMPT, `req-${index}`),
      );
      expect(staged.candidates).toHaveLength(1);
    }
    expect(collector.pendingRequestCount()).toBe(8);

    const overflow = collector.parse({ create: [{ index: 8 }] }, explicit(ATTEMPT, "req-8"));
    expect(overflow).toEqual({
      candidates: [],
      rejections: [{ attemptId: ATTEMPT, requestId: "req-8", reason: "bucket-capacity" }],
    });
    expect(collector.pendingRequestCount()).toBe(8);
    expect(collector.take(ATTEMPT, ["req-8"]).candidates).toEqual([]);
    expect(collector.hasStagedData()).toBe(true);
  });

  it("shares the capacity across attempts and does not overwrite existing buckets", () => {
    const collector = newCollector({ maxActiveBuckets: 2 });
    collector.parse({ create: [{ marker: "first" }] }, explicit("attempt-a", "req-1"));
    collector.parse({ create: [{ marker: "second" }] }, explicit("attempt-b", "req-1"));
    const overflow = collector.parse({ create: [{ marker: "third" }] }, explicit("attempt-c", "req-1"));
    expect(overflow.rejections).toEqual([
      { attemptId: "attempt-c", requestId: "req-1", reason: "bucket-capacity" },
    ]);
    expect(valuesOf(collector.take("attempt-a", ["req-1"]).candidates)).toEqual([{ marker: "first" }]);
    expect(valuesOf(collector.take("attempt-b", ["req-1"]).candidates)).toEqual([{ marker: "second" }]);
    expect(collector.pendingRequestCount()).toBe(0);
  });

  it("does not consume capacity for an existing bucket", () => {
    const collector = newCollector({ maxActiveBuckets: 1 });
    collector.parse({ create: [{ index: 0 }] }, explicit(ATTEMPT, REQUEST));
    expect(collector.parse({ create: [{ index: 1 }] }, explicit(ATTEMPT, REQUEST)).candidates).toHaveLength(1);
    expect(collector.pendingRequestCount()).toBe(1);
  });

  it("counts a rejection-only bucket toward capacity", () => {
    const collector = newCollector({ maxActiveBuckets: 1 });
    collector.parse({ create: "not-an-array" }, explicit(ATTEMPT, REQUEST));
    expect(collector.pendingRequestCount()).toBe(1);
    expect(collector.parse({ create: [{}] }, explicit(ATTEMPT, "req-2")).rejections).toEqual([
      { attemptId: ATTEMPT, requestId: "req-2", reason: "bucket-capacity" },
    ]);
  });
});

describe("take", () => {
  it("extracts and deletes only the requested buckets", () => {
    const collector = newCollector();
    collector.parse({ create: [{ marker: 1 }] }, explicit(ATTEMPT, "req-1"));
    collector.parse({ create: [{ marker: 2 }] }, explicit(ATTEMPT, "req-2"));
    collector.parse({ create: [{ marker: 3 }] }, explicit("attempt-other", "req-1"));

    const taken = collector.take(ATTEMPT, ["req-1"]);
    expect(valuesOf(taken.candidates)).toEqual([{ marker: 1 }]);
    expect(collector.pendingRequestCount()).toBe(2);
    expect(collector.take(ATTEMPT, ["req-1"])).toEqual(emptyStage());
    expect(valuesOf(collector.take(ATTEMPT, ["req-2"]).candidates)).toEqual([{ marker: 2 }]);
    expect(valuesOf(collector.take("attempt-other", ["req-1"]).candidates)).toEqual([{ marker: 3 }]);
    expect(collector.pendingRequestCount()).toBe(0);
    expect(collector.hasStagedData()).toBe(false);
  });

  it("returns candidates and rejections together", () => {
    const collector = newCollector();
    collector.parse({ create: [{ command: "ls" }, 42] }, explicit(ATTEMPT, REQUEST));
    const taken = collector.take(ATTEMPT, [REQUEST]);
    expect(valuesOf(taken.candidates)).toEqual([{ command: "ls" }]);
    expect(taken.rejections).toEqual([
      { attemptId: ATTEMPT, requestId: REQUEST, field: "create", index: 1, reason: "invalid-candidate" },
    ]);
  });

  it("does not extract the same request id twice", () => {
    const collector = newCollector();
    collector.parse({ create: [{ command: "ls" }] }, explicit(ATTEMPT, REQUEST));
    const taken = collector.take(ATTEMPT, [REQUEST, REQUEST, REQUEST]);
    expect(taken.candidates).toHaveLength(1);
  });

  it("returns a frozen empty view for unknown attempts or requests", () => {
    const collector = newCollector();
    const taken = collector.take("attempt-missing", ["req-missing"]);
    expect(taken).toEqual(emptyStage());
    expect(Object.isFrozen(taken)).toBe(true);
    expect(Object.isFrozen(taken.candidates)).toBe(true);
    expect(Object.isFrozen(taken.rejections)).toBe(true);
  });
});

describe("hasStagedData", () => {
  it("observes candidates and rejections", () => {
    const collector = newCollector();
    expect(collector.hasStagedData()).toBe(false);
    collector.parse({ create: [{ command: "ls" }] }, explicit(ATTEMPT, REQUEST));
    expect(collector.hasStagedData()).toBe(true);
    collector.clear();

    collector.parse({ create: "not-an-array" }, explicit(ATTEMPT, REQUEST));
    expect(collector.hasStagedData()).toBe(true);
  });

  it("filters by attempt id", () => {
    const collector = newCollector();
    collector.parse({ create: [{ command: "ls" }] }, explicit(ATTEMPT, REQUEST));
    expect(collector.hasStagedData(ATTEMPT)).toBe(true);
    expect(collector.hasStagedData("attempt-other")).toBe(false);
    expect(collector.hasStagedData()).toBe(true);
  });
});

describe("discard, discardAttempt and clear", () => {
  it("discards one request bucket without touching the others", () => {
    const collector = newCollector();
    collector.parse({ create: [{ marker: 1 }] }, explicit(ATTEMPT, "req-1"));
    collector.parse({ create: [{ marker: 2 }] }, explicit(ATTEMPT, "req-2"));
    collector.discard(ATTEMPT, "req-1");
    expect(collector.pendingRequestCount()).toBe(1);
    expect(collector.take(ATTEMPT, ["req-1"])).toEqual(emptyStage());
    expect(valuesOf(collector.take(ATTEMPT, ["req-2"]).candidates)).toEqual([{ marker: 2 }]);
  });

  it("ignores a discard for an unknown bucket", () => {
    const collector = newCollector();
    expect(() => collector.discard(ATTEMPT, "req-missing")).not.toThrow();
    expect(() => collector.discard("", "")).not.toThrow();
    expect(collector.pendingRequestCount()).toBe(0);
  });

  it("discards every bucket of one attempt", () => {
    const collector = newCollector();
    collector.parse({ create: [{ marker: 1 }] }, explicit(ATTEMPT, "req-1"));
    collector.parse({ create: [{ marker: 2 }] }, explicit(ATTEMPT, "req-2"));
    collector.parse({ create: [{ marker: 3 }] }, explicit("attempt-other", "req-1"));
    collector.discardAttempt(ATTEMPT);
    expect(collector.pendingRequestCount(ATTEMPT)).toBe(0);
    expect(collector.pendingRequestCount()).toBe(1);
    expect(collector.hasStagedData(ATTEMPT)).toBe(false);
    expect(collector.hasStagedData("attempt-other")).toBe(true);
  });

  it("clears every staged bucket", () => {
    const collector = newCollector();
    collector.parse({ create: [{ marker: 1 }] }, explicit(ATTEMPT, "req-1"));
    collector.parse({ create: [{ marker: 2 }] }, explicit("attempt-other", "req-2"));
    collector.clear();
    expect(collector.pendingRequestCount()).toBe(0);
    expect(collector.hasStagedData()).toBe(false);
    expect(collector.take(ATTEMPT, ["req-1"])).toEqual(emptyStage());
  });
});

describe("pendingRequestCount", () => {
  it("counts active buckets globally and per attempt", () => {
    const collector = newCollector();
    collector.parse({ create: [{ marker: 1 }] }, explicit(ATTEMPT, "req-1"));
    collector.parse({ create: [{ marker: 2 }] }, explicit(ATTEMPT, "req-2"));
    collector.parse({ create: [{ marker: 3 }] }, explicit("attempt-other", "req-1"));
    expect(collector.pendingRequestCount()).toBe(3);
    expect(collector.pendingRequestCount(ATTEMPT)).toBe(2);
    expect(collector.pendingRequestCount("attempt-missing")).toBe(0);
  });

  it("does not count attempts without staged data", () => {
    const collector = newCollector();
    collector.runAttempt(() => undefined);
    expect(collector.pendingRequestCount()).toBe(0);
  });
});

describe("frozen views", () => {
  it("freezes every returned object, array and candidate value", () => {
    const collector = newCollector();
    const result = collector.parse(
      { create: [{ command: "ls", nested: { list: [1, 2] } }, 42] },
      explicit(ATTEMPT, REQUEST),
    );
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.candidates)).toBe(true);
    expect(Object.isFrozen(result.rejections)).toBe(true);

    const candidate = result.candidates[0]!;
    expect(Object.isFrozen(candidate)).toBe(true);
    expect(Object.isFrozen(candidate.value)).toBe(true);
    const nested = candidate.value.nested as Record<string, unknown>;
    expect(Object.isFrozen(nested)).toBe(true);
    expect(Object.isFrozen(nested.list)).toBe(true);
    expect(Object.isFrozen(result.rejections[0])).toBe(true);
  });

  it("freezes the empty view", () => {
    const collector = newCollector();
    const result = collector.parse({ mystery: true }, explicit(ATTEMPT, REQUEST));
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.candidates)).toBe(true);
    expect(Object.isFrozen(result.rejections)).toBe(true);
  });

  it("prevents mutating staged candidates and their values", () => {
    const collector = newCollector();
    const result = collector.parse({ create: [{ command: "ls" }] }, explicit(ATTEMPT, REQUEST));
    const candidates = result.candidates as LearningCandidate[];
    expect(() => candidates.push(result.candidates[0]!)).toThrow(TypeError);
    const value = result.candidates[0]!.value as Record<string, unknown>;
    expect(() => {
      value.command = "rm -rf /";
    }).toThrow(TypeError);
  });

  it("keeps taken arrays frozen as well", () => {
    const collector = newCollector();
    collector.parse({ create: [{ command: "ls" }, 42] }, explicit(ATTEMPT, REQUEST));
    const taken = collector.take(ATTEMPT, [REQUEST]);
    expect(Object.isFrozen(taken)).toBe(true);
    expect(Object.isFrozen(taken.candidates)).toBe(true);
    expect(Object.isFrozen(taken.rejections)).toBe(true);
    expect(Object.isFrozen(taken.rejections[0])).toBe(true);
  });
});
