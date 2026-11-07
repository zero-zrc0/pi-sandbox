/**
 * Contract tests for the approver configuration schema (spec section 5).
 *
 * Every schema is exercised through table-driven valid/invalid fixtures, so the
 * published JSON schema and the runtime checks stay in sync. The pi-model judge
 * is the one documented compatibility exception: its extra keys are accepted
 * and then stripped.
 */
import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
  APPROVER_JUDGE_KINDS,
  DECISION_CONTEXT_ACQUISITIONS,
  DEFAULT_APPROVER_TIMEOUT_MS,
  DEFAULT_CLASSIFIER_ALLOW_THRESHOLD,
  DEFAULT_CLASSIFIER_CONTEXT_BUDGET_TOKENS,
  DEFAULT_CLASSIFIER_DENY_THRESHOLD,
  approverConfigSchema,
  approverJudgeSchema,
  piClassifierJudgeSchema,
  piModelJudgeSchema,
} from "#config/approver-schema";
import type {
  ApproverConfig,
  ApproverJudge,
  DecisionContextAcquisition,
  PiClassifierJudge,
  PiModelJudge,
} from "#config/approver-schema";
import { issuesFromZodError } from "#config/config-schema";

/** Minimal surface shared by every schema under test. */
function accept(schema: z.ZodType, value: unknown): boolean {
  return schema.safeParse(value).success;
}

/** Dotted field paths of every issue reported for an invalid fixture. */
function issuePaths(schema: z.ZodType, value: unknown): readonly string[] {
  const result = schema.safeParse(value);
  if (result.success) return [];
  return issuesFromZodError(result.error).map((issue) => issue.path);
}

const JSON_SCHEMA_OPTIONS = { target: "draft-2020-12", io: "input" } as const;

describe("approver schema constants", () => {
  it("publishes the two judge kinds and the two context acquisitions", () => {
    expect(APPROVER_JUDGE_KINDS).toEqual(["pi-model", "pi-classifier", "custom"]);
    expect(DECISION_CONTEXT_ACQUISITIONS).toEqual(["llm", "decision"]);
  });

  it("publishes the documented defaults", () => {
    expect(DEFAULT_APPROVER_TIMEOUT_MS).toBe(15000);
    expect(DEFAULT_CLASSIFIER_CONTEXT_BUDGET_TOKENS).toBe(32768);
    expect(DEFAULT_CLASSIFIER_ALLOW_THRESHOLD).toBe(0.9);
    expect(DEFAULT_CLASSIFIER_DENY_THRESHOLD).toBe(0.8);
  });
});

describe("approver common fields", () => {
  it("applies the timeout and context acquisition defaults to an empty config", () => {
    const parsed = approverConfigSchema.parse({});
    expect(parsed).toEqual({ timeoutMs: 15000, decisionContextAcquisition: "llm" });
    expect("judge" in parsed).toBe(false);
    expect("provider" in parsed).toBe(false);
    expect("queueTimeoutMs" in parsed).toBe(false);
  });

  it("keeps the values the user supplied and leaves unset optional keys absent", () => {
    const parsed = approverConfigSchema.parse({
      provider: "acme",
      model: "judge",
      timeoutMs: 2500,
      decisionContextAcquisition: "decision",
    });
    expect(parsed).toEqual({
      provider: "acme",
      model: "judge",
      timeoutMs: 2500,
      decisionContextAcquisition: "decision",
    });
  });

  it("accepts a paired provider and model", () => {
    expect(accept(approverConfigSchema, { provider: "acme", model: "judge" })).toBe(true);
  });

  it("rejects a half-configured provider/model pair and blames the missing field", () => {
    expect(accept(approverConfigSchema, { provider: "acme" })).toBe(false);
    expect(issuePaths(approverConfigSchema, { provider: "acme" })).toEqual(["model"]);
    expect(accept(approverConfigSchema, { model: "judge" })).toBe(false);
    expect(issuePaths(approverConfigSchema, { model: "judge" })).toEqual(["provider"]);
  });

  it("rejects empty provider and model strings", () => {
    expect(accept(approverConfigSchema, { provider: "", model: "judge" })).toBe(false);
    expect(accept(approverConfigSchema, { provider: "acme", model: "   " })).toBe(false);
  });

  it("accepts a non-empty instructions string and rejects empty or non-string values", () => {
    expect(accept(approverConfigSchema, { instructions: "review carefully" })).toBe(true);
    for (const instructions of ["", "   ", 7, null, ["x"]]) {
      expect(accept(approverConfigSchema, { instructions })).toBe(false);
    }
  });

  it("accepts a surfaces list of non-empty strings and the empty list", () => {
    expect(accept(approverConfigSchema, { surfaces: [] })).toBe(true);
    expect(accept(approverConfigSchema, { surfaces: ["cli", "tui"] })).toBe(true);
  });

  it("rejects surfaces that are not a list of non-empty strings", () => {
    for (const surfaces of [["ok", ""], ["   "], "cli", 3, null, [1]]) {
      expect(accept(approverConfigSchema, { surfaces })).toBe(false);
    }
  });

  it("accepts positive integer timeouts", () => {
    for (const timeoutMs of [1, 5000, Number.MAX_SAFE_INTEGER]) {
      expect(accept(approverConfigSchema, { timeoutMs })).toBe(true);
      expect(accept(approverConfigSchema, { queueTimeoutMs: timeoutMs })).toBe(true);
    }
  });

  it("rejects zero, negative, fractional, string and non-finite timeouts", () => {
    for (const timeoutMs of [0, -1, -5000, 1.5, "5000", null, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(accept(approverConfigSchema, { timeoutMs })).toBe(false);
      expect(accept(approverConfigSchema, { queueTimeoutMs: timeoutMs })).toBe(false);
    }
    expect(issuePaths(approverConfigSchema, { timeoutMs: 0 })).toEqual(["timeoutMs"]);
    expect(issuePaths(approverConfigSchema, { queueTimeoutMs: -1 })).toEqual(["queueTimeoutMs"]);
  });

  it("accepts the two decision context acquisition values", () => {
    for (const value of DECISION_CONTEXT_ACQUISITIONS) {
      expect(approverConfigSchema.parse({ decisionContextAcquisition: value }).decisionContextAcquisition)
        .toBe(value);
    }
  });

  it("rejects unknown decision context acquisition values", () => {
    for (const value of ["LLM", "decision-context", "", 1, null]) {
      expect(accept(approverConfigSchema, { decisionContextAcquisition: value })).toBe(false);
    }
  });

  it("rejects unknown top-level fields and points at the offending key", () => {
    expect(accept(approverConfigSchema, { extra: true })).toBe(false);
    expect(issuePaths(approverConfigSchema, { extra: true })).toEqual(["extra"]);
  });

  it("rejects non-object input", () => {
    for (const value of [null, [], "config", 1]) {
      expect(accept(approverConfigSchema, value)).toBe(false);
    }
  });
});

describe("pi-model judge", () => {
  it("accepts the bare type and a fully configured pair", () => {
    expect(piModelJudgeSchema.parse({ type: "pi-model" })).toEqual({ type: "pi-model" });
    expect(
      piModelJudgeSchema.parse({
        type: "pi-model",
        provider: "acme",
        model: "judge",
        timeoutMs: 100,
      }),
    ).toEqual({ type: "pi-model", provider: "acme", model: "judge", timeoutMs: 100 });
  });

  it("requires the judge provider and model to be paired", () => {
    expect(accept(piModelJudgeSchema, { type: "pi-model", provider: "acme" })).toBe(false);
    expect(issuePaths(piModelJudgeSchema, { type: "pi-model", provider: "acme" })).toEqual(["model"]);
    expect(accept(piModelJudgeSchema, { type: "pi-model", model: "judge" })).toBe(false);
    expect(issuePaths(piModelJudgeSchema, { type: "pi-model", model: "judge" })).toEqual(["provider"]);
    expect(accept(piModelJudgeSchema, { type: "pi-model", provider: "acme", model: "judge" })).toBe(true);
  });

  it("strips unknown keys instead of rejecting them", () => {
    const parsed = piModelJudgeSchema.parse({
      type: "pi-model",
      extra: { nested: true },
      rubric: "x",
    });
    expect(parsed).toEqual({ type: "pi-model" });
    expect("extra" in parsed).toBe(false);
    expect("rubric" in parsed).toBe(false);
  });

  it("strips unknown judge keys when nested in the approver config", () => {
    const parsed = approverConfigSchema.parse({
      judge: { type: "pi-model", provider: "acme", model: "judge", temperature: 0.2 },
    });
    expect(parsed.judge).toEqual({ type: "pi-model", provider: "acme", model: "judge" });
    expect(parsed.judge).not.toHaveProperty("temperature");
  });

  it("accepts only positive integer timeouts", () => {
    for (const timeoutMs of [1, 2500]) {
      expect(accept(piModelJudgeSchema, { type: "pi-model", timeoutMs })).toBe(true);
    }
    for (const timeoutMs of [0, -1, 1.5, "100", null]) {
      expect(accept(piModelJudgeSchema, { type: "pi-model", timeoutMs })).toBe(false);
    }
  });

  it("rejects empty provider or model strings", () => {
    expect(accept(piModelJudgeSchema, { type: "pi-model", provider: "", model: "judge" })).toBe(false);
    expect(accept(piModelJudgeSchema, { type: "pi-model", provider: "acme", model: "   " })).toBe(false);
  });
});

describe("pi-classifier judge", () => {
  it("requires provider and model", () => {
    for (const judge of [
      { type: "pi-classifier" },
      { type: "pi-classifier", provider: "acme" },
      { type: "pi-classifier", model: "classifier" },
    ]) {
      expect(accept(piClassifierJudgeSchema, judge)).toBe(false);
    }
    expect(accept(piClassifierJudgeSchema, { type: "pi-classifier", provider: "acme", model: "classifier" }))
      .toBe(true);
  });

  it("fills every classifier default when only the required fields are given", () => {
    expect(piClassifierJudgeSchema.parse({ type: "pi-classifier", provider: "acme", model: "classifier" }))
      .toEqual({
        type: "pi-classifier",
        provider: "acme",
        model: "classifier",
        timeoutMs: 15000,
        contextBudgetTokens: 32768,
        allowThreshold: 0.9,
        denyThreshold: 0.8,
      });
  });

  it("accepts threshold boundaries and rejects values outside the unit interval", () => {
    for (const threshold of [0, 0.5, 1]) {
      expect(accept(piClassifierJudgeSchema, {
        type: "pi-classifier",
        provider: "acme",
        model: "classifier",
        allowThreshold: threshold,
        denyThreshold: threshold,
      })).toBe(true);
    }
    for (const threshold of [-0.01, 1.01, Number.NaN, Number.POSITIVE_INFINITY, "0.5"]) {
      expect(accept(piClassifierJudgeSchema, {
        type: "pi-classifier",
        provider: "acme",
        model: "classifier",
        allowThreshold: threshold,
      })).toBe(false);
      expect(accept(piClassifierJudgeSchema, {
        type: "pi-classifier",
        provider: "acme",
        model: "classifier",
        denyThreshold: threshold,
      })).toBe(false);
    }
  });

  it("accepts positive integer context budgets and rejects invalid ones", () => {
    for (const contextBudgetTokens of [1, 32768, Number.MAX_SAFE_INTEGER]) {
      expect(accept(piClassifierJudgeSchema, {
        type: "pi-classifier",
        provider: "acme",
        model: "classifier",
        contextBudgetTokens,
      })).toBe(true);
    }
    for (const contextBudgetTokens of [0, -1, 1.5, "32768", null]) {
      expect(accept(piClassifierJudgeSchema, {
        type: "pi-classifier",
        provider: "acme",
        model: "classifier",
        contextBudgetTokens,
      })).toBe(false);
    }
  });

  it("accepts positive integer timeouts and rejects invalid ones", () => {
    for (const timeoutMs of [1, 5000]) {
      expect(accept(piClassifierJudgeSchema, {
        type: "pi-classifier",
        provider: "acme",
        model: "classifier",
        timeoutMs,
      })).toBe(true);
    }
    for (const timeoutMs of [0, -1, 1.5, "5000"]) {
      expect(accept(piClassifierJudgeSchema, {
        type: "pi-classifier",
        provider: "acme",
        model: "classifier",
        timeoutMs,
      })).toBe(false);
    }
  });

  it("rejects empty provider and model strings", () => {
    expect(accept(piClassifierJudgeSchema, { type: "pi-classifier", provider: "", model: "classifier" }))
      .toBe(false);
    expect(accept(piClassifierJudgeSchema, { type: "pi-classifier", provider: "acme", model: "" }))
      .toBe(false);
  });

  it("rejects unknown keys", () => {
    const judge = { type: "pi-classifier", provider: "acme", model: "classifier", extra: true };
    expect(accept(piClassifierJudgeSchema, judge)).toBe(false);
    expect(issuePaths(piClassifierJudgeSchema, judge)).toEqual(["extra"]);
    expect(accept(piClassifierJudgeSchema, {
      type: "pi-classifier",
      provider: "acme",
      model: "classifier",
      allowConfidenceThreshold: 0.5,
    })).toBe(false);
  });
});

describe("approver judge union", () => {
  it("accepts both discriminated judge kinds", () => {
    expect(accept(approverJudgeSchema, { type: "pi-model" })).toBe(true);
    expect(accept(approverJudgeSchema, { type: "pi-classifier", provider: "acme", model: "classifier" }))
      .toBe(true);
  });

  it("rejects the retired endpoint and profile judge kinds", () => {
    for (const judge of [
      { type: "endpoint", provider: "p", model: "m" },
      { type: "profile", provider: "p", model: "m" },
      { type: "model" },
      {},
      null,
      "pi-model",
    ]) {
      expect(accept(approverJudgeSchema, judge)).toBe(false);
    }
  });
});

describe("common provider/model pair rule next to a judge", () => {
  it("still enforces the common pair when the judge is pi-model", () => {
    expect(accept(approverConfigSchema, { provider: "acme", judge: { type: "pi-model" } })).toBe(false);
    expect(issuePaths(approverConfigSchema, { provider: "acme", judge: { type: "pi-model" } }))
      .toEqual(["model"]);
    expect(accept(approverConfigSchema, {
      provider: "acme",
      model: "judge",
      judge: { type: "pi-model" },
    })).toBe(true);
  });

  it("does not apply the common pair rule when the judge is pi-classifier", () => {
    const classifier = { type: "pi-classifier", provider: "acme", model: "classifier" };
    expect(accept(approverConfigSchema, { provider: "acme", judge: classifier })).toBe(true);
    expect(accept(approverConfigSchema, { model: "judge", judge: classifier })).toBe(true);
  });
});

describe("exported types", () => {
  it("describes the parsed shapes", () => {
    const config: ApproverConfig = approverConfigSchema.parse({
      timeoutMs: 25,
      decisionContextAcquisition: "decision",
    });
    expect(config.timeoutMs).toBe(25);
    expect(config.decisionContextAcquisition).toBe("decision");

    const acquisition: DecisionContextAcquisition = "decision";
    expect(DECISION_CONTEXT_ACQUISITIONS).toContain(acquisition);

    const modelJudge: PiModelJudge = piModelJudgeSchema.parse({ type: "pi-model" });
    expect(modelJudge.type).toBe("pi-model");

    const classifierJudge: PiClassifierJudge = piClassifierJudgeSchema.parse({
      type: "pi-classifier",
      provider: "acme",
      model: "classifier",
    });
    expect(classifierJudge.type).toBe("pi-classifier");

    const judge: ApproverJudge = modelJudge;
    expect(judge.type).toBe("pi-model");
  });
});

describe("JSON Schema export", () => {
  it("generates a draft 2020-12 schema for every exported schema without throwing", () => {
    for (const schema of [
      piModelJudgeSchema,
      piClassifierJudgeSchema,
      approverJudgeSchema,
      approverConfigSchema,
    ]) {
      const jsonSchema = z.toJSONSchema(schema, JSON_SCHEMA_OPTIONS) as Record<string, unknown>;
      expect(jsonSchema["$schema"]).toBe("https://json-schema.org/draft/2020-12/schema");
    }
    for (const schema of [piModelJudgeSchema, piClassifierJudgeSchema, approverConfigSchema]) {
      const jsonSchema = z.toJSONSchema(schema, JSON_SCHEMA_OPTIONS) as Record<string, unknown>;
      expect(jsonSchema.type).toBe("object");
    }
  });

  it("keeps the pi-model judge input schema open for the compatibility exception", () => {
    const jsonSchema = z.toJSONSchema(piModelJudgeSchema, JSON_SCHEMA_OPTIONS) as Record<string, unknown>;
    expect(jsonSchema.type).toBe("object");
    expect(jsonSchema.additionalProperties).not.toBe(false);
  });

  it("publishes both judge alternatives and a strict approver object", () => {
    const judgeSchema = z.toJSONSchema(approverJudgeSchema, JSON_SCHEMA_OPTIONS) as Record<string, unknown>;
    expect(Array.isArray(judgeSchema.anyOf)).toBe(true);
    expect((judgeSchema.anyOf as readonly unknown[])).toHaveLength(3);

    const configSchema = z.toJSONSchema(approverConfigSchema, JSON_SCHEMA_OPTIONS) as Record<string, unknown>;
    expect(configSchema.type).toBe("object");
    expect(configSchema.additionalProperties).toBe(false);
    expect(Object.keys(configSchema.properties as Record<string, unknown>).sort()).toEqual([
      "decisionContextAcquisition",
      "instructions",
      "judge",
      "model",
      "provider",
      "queueTimeoutMs",
      "surfaces",
      "timeoutMs",
    ]);
  });
});
