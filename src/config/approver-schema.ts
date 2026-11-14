/**
 * Approver configuration schema (spec section 5).
 *
 * An approver selects the model that reviews tool calls, optionally through a
 * model judge. The schema is strict: only the documented fields are accepted.
 * The single compatibility exception is the `pi-model` judge, which accepts and
 * strips unknown keys so older judge declarations keep loading.
 *
 * The same declaration drives runtime validation and the published JSON Schema;
 * therefore no schema here relies on constructs that cannot be exported.
 */
import { z } from "zod";
import {
  nonEmptyStringListSchema,
  nonEmptyStringSchema,
  positiveIntegerSchema,
  ratioSchema,
} from "./config-schema";

/** Judge kinds the approver accepts; retired endpoint/profile kinds are not part of the model. */
export const APPROVER_JUDGE_KINDS = ["pi-model", "pi-classifier", "custom"] as const;

/** How the decision approver acquires reviewer context. */
export const DECISION_CONTEXT_ACQUISITIONS = ["llm", "decision"] as const;

/** Default evaluation timeout for the approver, in milliseconds. */
export const DEFAULT_APPROVER_TIMEOUT_MS = 15000;

/** Default context budget of a `pi-classifier` judge, in tokens. */
export const DEFAULT_CLASSIFIER_CONTEXT_BUDGET_TOKENS = 32768;

/** Default minimum confidence a `pi-classifier` judge needs to allow a call. */
export const DEFAULT_CLASSIFIER_ALLOW_THRESHOLD = 0.9;

/** Default minimum confidence a `pi-classifier` judge needs to deny a call. */
export const DEFAULT_CLASSIFIER_DENY_THRESHOLD = 0.8;

/** A model selection: either both halves are set or both are omitted. */
interface ModelSelection {
  readonly provider?: string;
  readonly model?: string;
}

/**
 * Reject a half-configured model pair at its missing field. A partial pair
 * would silently fall back to another model, so it must not load at all.
 */
function addMissingModelPairIssue(value: ModelSelection, ctx: z.RefinementCtx): void {
  const hasProvider = value.provider !== undefined;
  const hasModel = value.model !== undefined;
  if (hasProvider === hasModel) return;
  ctx.addIssue({
    code: "custom",
    message: "provider and model must be configured together",
    path: [hasProvider ? "model" : "provider"],
  });
}

/**
 * Judge that delegates to a Pi model.
 *
 * This is the documented exception to the strict-object rule: unknown keys are
 * accepted and then stripped, so a declaration may carry extra judge options
 * that a later phase understands. The declared provider/model pair overrides the
 * approver pair and must be complete on its own.
 */
export const piModelJudgeSchema = z
  .looseObject({
    type: z.literal("pi-model"),
    provider: nonEmptyStringSchema.optional(),
    model: nonEmptyStringSchema.optional(),
    timeoutMs: positiveIntegerSchema.optional(),
  })
  .superRefine((value, ctx) => addMissingModelPairIssue(value, ctx))
  .transform((value) => ({
    type: "pi-model" as const,
    ...(value.provider === undefined ? {} : { provider: value.provider }),
    ...(value.model === undefined ? {} : { model: value.model }),
    ...(value.timeoutMs === undefined ? {} : { timeoutMs: value.timeoutMs }),
  }));

export type PiModelJudge = z.infer<typeof piModelJudgeSchema>;

/**
 * Judge that delegates to a Pi classifier. The model pair is required; every
 * other field has a documented default so the parsed result is ready to use.
 */
export const piClassifierJudgeSchema = z.strictObject({
  type: z.literal("pi-classifier"),
  provider: nonEmptyStringSchema,
  model: nonEmptyStringSchema,
  timeoutMs: positiveIntegerSchema.default(DEFAULT_APPROVER_TIMEOUT_MS),
  contextBudgetTokens: positiveIntegerSchema.default(DEFAULT_CLASSIFIER_CONTEXT_BUDGET_TOKENS),
  allowThreshold: ratioSchema.default(DEFAULT_CLASSIFIER_ALLOW_THRESHOLD),
  denyThreshold: ratioSchema.default(DEFAULT_CLASSIFIER_DENY_THRESHOLD),
});

export type PiClassifierJudge = z.infer<typeof piClassifierJudgeSchema>;

/**
 * Judge that delegates to a user-owned backend. The request is issued
 * directly by pi-sandbox (bypassing Pi's classifier registry) using the
 * classifier request shape; the backend is expected to return an
 * `answers.verdict` choice/confidence payload.
 */
export const customJudgeSchema = z.strictObject({
  type: z.literal("custom"),
  baseUrl: nonEmptyStringSchema,
  model: nonEmptyStringSchema,
  apiKey: nonEmptyStringSchema.optional(),
  timeoutMs: positiveIntegerSchema.default(DEFAULT_APPROVER_TIMEOUT_MS),
  contextBudgetTokens: positiveIntegerSchema.default(DEFAULT_CLASSIFIER_CONTEXT_BUDGET_TOKENS),
  allowThreshold: ratioSchema.default(DEFAULT_CLASSIFIER_ALLOW_THRESHOLD),
  denyThreshold: ratioSchema.default(DEFAULT_CLASSIFIER_DENY_THRESHOLD),
});

export type CustomJudge = z.infer<typeof customJudgeSchema>;

/** The supported judge kinds, discriminated by their `type` tag. */
export const approverJudgeSchema = z.union([piModelJudgeSchema, piClassifierJudgeSchema, customJudgeSchema]);

export type ApproverJudge = z.infer<typeof approverJudgeSchema>;

/**
 * Approver configuration shared by every approval chain node that needs a model.
 *
 * The common provider/model pair is required for a plain config and next to a
 * `pi-model` judge. A `pi-classifier` judge brings its own required model pair,
 * so the common pair is not imposed in that case.
 */
export const approverConfigSchema = z
  .strictObject({
    provider: nonEmptyStringSchema.optional(),
    model: nonEmptyStringSchema.optional(),
    instructions: nonEmptyStringSchema.optional(),
    surfaces: nonEmptyStringListSchema.optional(),
    judge: approverJudgeSchema.optional(),
    timeoutMs: positiveIntegerSchema.default(DEFAULT_APPROVER_TIMEOUT_MS),
    queueTimeoutMs: positiveIntegerSchema.optional(),
    decisionContextAcquisition: z.enum(DECISION_CONTEXT_ACQUISITIONS).default("llm"),
  })
  .superRefine((value, ctx) => {
    if (value.judge?.type === "pi-classifier" || value.judge?.type === "custom") return;
    addMissingModelPairIssue(value, ctx);
  });

export type ApproverConfig = z.infer<typeof approverConfigSchema>;

/** One parsed decision-context acquisition strategy. */
export type DecisionContextAcquisition = (typeof DECISION_CONTEXT_ACQUISITIONS)[number];
