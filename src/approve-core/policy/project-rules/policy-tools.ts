/**
 * Restricted project-rule policy tools (specs/project-rule-learning.md §8).
 *
 * The model may only list this project's rules and propose a revoke. Neither
 * tool can touch the rule file: `list` reads through the service and returns a
 * safe summary, `revoke` validates the proposal and stages it in the collector.
 * The staged candidate is durable only when the learning transaction later
 * proves it, so a tool result never claims a rule was revoked.
 */
import type { LearningCandidate, LearningCandidateCollector, LearningRejection } from "./candidates";
import type { LearningLifecyclePort } from "./learning";
import type {
  ProjectRulesListResult,
  ProjectRulesRuleSummary,
  ProjectRulesService,
  ProjectRulesSuspension,
} from "./service";
import type { ProjectRulesUnavailableCategory } from "./storage";
import { PROJECT_RULES_LIMITS, isRuleId, type RuleEffect, type RuleScope, type RuleStatus } from "./types";

export type { LearningLifecyclePort } from "./learning";

/** The service surface the tools consume; the real service is assignable. */
export type ProjectRuleServicePort = Pick<
  ProjectRulesService,
  "list" | "revoke" | "isSuspended" | "suspendRuleIds"
>;

/** The collector surface `revoke` stages through. */
export type LearningStagePort = Pick<LearningCandidateCollector, "parse" | "currentAttemptId" | "hasStagedData">;

export const PROJECT_RULE_POLICY_TOOL_NAMES = Object.freeze({
  list: "project_rules_list",
  revoke: "project_rules_revoke",
} as const);

export type ProjectRulePolicyToolName =
  typeof PROJECT_RULE_POLICY_TOOL_NAMES[keyof typeof PROJECT_RULE_POLICY_TOOL_NAMES];

/** Safe list entry: stable facts only, never full arguments or env values. */
export interface ProjectRulePolicyRuleSummary {
  readonly id: string;
  readonly effect: RuleEffect;
  readonly status: RuleStatus;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly provenance: {
    readonly quote: string;
    readonly confidence?: number;
    readonly judge?: string;
    readonly actor: string;
  };
  readonly tool: { readonly name: string; readonly origin: string; readonly definitionRevision: string };
  readonly cwd: string;
  readonly requiredScopes: readonly RuleScope[];
  readonly suspension?: ProjectRulesSuspension;
}

export type ProjectRulePolicyListResult =
  | {
      readonly ok: true;
      readonly state: "available" | "missing";
      readonly revision: number;
      readonly rules: readonly ProjectRulePolicyRuleSummary[];
    }
  | {
      readonly ok: false;
      readonly state: "unavailable";
      readonly reason: "unavailable";
      readonly category: ProjectRulesUnavailableCategory;
    }
  | { readonly ok: false; readonly state: "failed"; readonly reason: "invalid-input" };

/** The complete model-proposed revoke: rule, confidence, reason and evidence. */
export interface ProjectRuleRevokeToolInput {
  readonly ruleId: string;
  readonly confidence: number;
  readonly reason: string;
  readonly expectedRevision: number;
  /** Capture bucket for the staged candidate; defaults to a stable id. */
  readonly requestId?: string;
  readonly evidence: {
    readonly sourceEntryId: string;
    readonly quote: string;
    readonly confidence: number;
    readonly judge: string;
    readonly sessionId: string;
    readonly actor: string;
  };
}

export type ProjectRulePolicyRevokeFailureReason =
  | "invalid-input"
  | "unknown-rule"
  | "inactive-rule"
  | "revision-mismatch"
  | "unavailable"
  | "disposed"
  | "no-attempt"
  | "stage-failed";

export type ProjectRulePolicyRevokeResult =
  | {
      readonly ok: true;
      readonly staged: true;
      readonly durable: false;
      readonly ruleId: string;
      readonly requestId: string;
      readonly stagedAt: string;
      readonly rejections: readonly LearningRejection[];
    }
  | {
      readonly ok: false;
      readonly staged: false;
      readonly durable: false;
      readonly reason: ProjectRulePolicyRevokeFailureReason;
      readonly rejections?: readonly LearningRejection[];
    };

export type ProjectRulePolicyDispatchResult =
  | { readonly ok: true; readonly tool: "list"; readonly result: ProjectRulePolicyListResult }
  | { readonly ok: true; readonly tool: "revoke"; readonly result: ProjectRulePolicyRevokeResult }
  | { readonly ok: false; readonly reason: "unknown-tool" };

export interface ProjectRulePolicyTools {
  readonly list: (input: unknown) => Promise<ProjectRulePolicyListResult>;
  readonly revoke: (input: unknown) => Promise<ProjectRulePolicyRevokeResult>;
  /** Name-based entry point: unknown names fail without touching the store. */
  readonly dispatch: (name: string, input: unknown) => Promise<ProjectRulePolicyDispatchResult>;
}

export interface ProjectRulePolicyToolsOptions {
  readonly service: ProjectRuleServicePort;
  readonly collector: LearningStagePort;
  readonly learning?: LearningLifecyclePort;
  readonly now?: () => Date;
  /**
   * The reviewed action's request id. The host wires this so a staged revoke
   * lands in the same collector bucket the learning transaction extracts;
   * without it the tool uses `input.requestId` or a stable per-rule id.
   */
  readonly requestId?: () => string | undefined;
}

const MIN_CONFIDENCE = PROJECT_RULES_LIMITS.minConfidence;
const MAX_REASON_CHARS = PROJECT_RULES_LIMITS.maxQuoteChars;

type DataRecord = Record<string, unknown>;

interface ReadResult<T> {
  readonly ok: true;
  readonly value: T;
}
interface ReadFailure {
  readonly ok: false;
}

function plainDataObject(value: unknown): value is DataRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  if (Object.getOwnPropertySymbols(value).length > 0) return false;
  for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) {
    if (!("value" in descriptor)) return false;
  }
  return true;
}

function closedObject(value: unknown, required: readonly string[], optional: readonly string[] = []): DataRecord | undefined {
  if (!plainDataObject(value)) return undefined;
  const names = Object.keys(Object.getOwnPropertyDescriptors(value));
  for (const name of names) {
    if (!required.includes(name) && !optional.includes(name)) return undefined;
  }
  for (const name of required) {
    if (!names.includes(name)) return undefined;
  }
  return value;
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function validConfidence(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= MIN_CONFIDENCE && value <= 1;
}

function readEvidence(value: unknown): ReadResult<ProjectRuleRevokeToolInput["evidence"]> | ReadFailure {
  const record = closedObject(value, ["sourceEntryId", "quote", "confidence", "judge", "sessionId", "actor"]);
  if (record === undefined) return { ok: false };
  if (!nonEmptyString(record.sourceEntryId) || !nonEmptyString(record.quote) ||
    !nonEmptyString(record.judge) || !nonEmptyString(record.sessionId) || !nonEmptyString(record.actor)) {
    return { ok: false };
  }
  if (record.quote.length > MAX_REASON_CHARS) return { ok: false };
  if (!validConfidence(record.confidence)) return { ok: false };
  return {
    ok: true,
    value: {
      sourceEntryId: record.sourceEntryId,
      quote: record.quote,
      confidence: record.confidence,
      judge: record.judge,
      sessionId: record.sessionId,
      actor: record.actor,
    },
  };
}

function readRevokeInput(input: unknown): ReadResult<ProjectRuleRevokeToolInput> | ReadFailure {
  const record = closedObject(input, ["ruleId", "confidence", "reason", "expectedRevision", "evidence"], ["requestId"]);
  if (record === undefined) return { ok: false };
  if (!isRuleId(record.ruleId)) return { ok: false };
  if (!validConfidence(record.confidence)) return { ok: false };
  if (!nonEmptyString(record.reason) || record.reason.length > MAX_REASON_CHARS) return { ok: false };
  if (typeof record.expectedRevision !== "number" || !Number.isSafeInteger(record.expectedRevision) ||
    record.expectedRevision < 0) {
    return { ok: false };
  }
  if (record.requestId !== undefined && !nonEmptyString(record.requestId)) return { ok: false };
  const evidence = readEvidence(record.evidence);
  if (!evidence.ok) return { ok: false };
  return {
    ok: true,
    value: {
      ruleId: record.ruleId,
      confidence: record.confidence,
      reason: record.reason,
      expectedRevision: record.expectedRevision,
      ...(record.requestId === undefined ? {} : { requestId: record.requestId }),
      evidence: evidence.value,
    },
  };
}

/** Strip everything a model never needs: no arguments, no environment values. */
function summarize(rule: ProjectRulesRuleSummary): ProjectRulePolicyRuleSummary {
  return Object.freeze({
    id: rule.id,
    effect: rule.effect,
    status: rule.status,
    createdAt: rule.createdAt,
    updatedAt: rule.updatedAt,
    provenance: Object.freeze({
      quote: rule.provenance.quote,
      actor: rule.provenance.actor,
      ...(rule.provenance.confidence === undefined ? {} : { confidence: rule.provenance.confidence }),
      ...(rule.provenance.judge === undefined ? {} : { judge: rule.provenance.judge }),
    }),
    tool: Object.freeze({ ...rule.tool }),
    cwd: rule.cwd,
    requiredScopes: Object.freeze(rule.requiredScopes.map((scope) => Object.freeze({ ...scope }))),
    ...(rule.suspension === undefined ? {} : { suspension: rule.suspension }),
  });
}

function stagedCandidateValue(input: ProjectRuleRevokeToolInput): Readonly<Record<string, unknown>> {
  // Only the proposal fields are staged; the judge/session/actor come from the
  // host-verified learning admission when the candidate is committed.
  return Object.freeze({
    ruleId: input.ruleId,
    sourceEntryId: input.evidence.sourceEntryId,
    quote: input.evidence.quote,
    confidence: input.evidence.confidence,
    reason: input.reason,
  });
}

function revokeFailure(reason: ProjectRulePolicyRevokeFailureReason, rejections?: readonly LearningRejection[]): ProjectRulePolicyRevokeResult {
  return {
    ok: false,
    staged: false,
    durable: false,
    reason,
    ...(rejections === undefined ? {} : { rejections }),
  };
}

/**
 * Build the two restricted tools. Both are closed-world: unknown fields,
 * unknown rule names and stale revisions fail before anything is staged.
 */
export function createProjectRulePolicyTools(options: ProjectRulePolicyToolsOptions): ProjectRulePolicyTools {
  const now = options.now ?? (() => new Date());

  const list = async (input: unknown): Promise<ProjectRulePolicyListResult> => {
    if (input !== undefined && (closedObject(input, []) === undefined)) {
      return { ok: false, state: "failed", reason: "invalid-input" };
    }
    const listed: ProjectRulesListResult = await options.service.list();
    if (listed.kind === "unavailable") {
      return { ok: false, state: "unavailable", reason: "unavailable", category: listed.category };
    }
    return {
      ok: true,
      state: listed.kind,
      revision: listed.revision,
      rules: Object.freeze(listed.rules.map(summarize)),
    };
  };

  const revoke = async (input: unknown): Promise<ProjectRulePolicyRevokeResult> => {
    if (options.learning?.disposed === true) return revokeFailure("disposed");
    const parsed = readRevokeInput(input);
    if (!parsed.ok) return revokeFailure("invalid-input");
    const value = parsed.value;

    const attempt = options.collector.currentAttemptId();
    if (attempt === undefined) return revokeFailure("no-attempt");

    const listed = await options.service.list();
    if (listed.kind === "unavailable") return revokeFailure("unavailable");
    const revision = listed.kind === "missing" ? 0 : listed.revision;
    if (value.expectedRevision !== revision) return revokeFailure("revision-mismatch");
    const target = listed.kind === "missing" ? undefined : listed.rules.find((rule) => rule.id === value.ruleId);
    if (target === undefined) return revokeFailure("unknown-rule");
    if (target.status !== "active") return revokeFailure("inactive-rule");

    const requestId = value.requestId ?? options.requestId?.() ?? `policy-revoke-${value.ruleId}`;
    if (!nonEmptyString(requestId)) return revokeFailure("invalid-input");
    const staged = options.collector.parse(
      { revoke: [stagedCandidateValue(value)] },
      { attemptId: attempt, requestId },
    );
    if (staged.candidates.length === 0) return revokeFailure("stage-failed", staged.rejections);
    return {
      ok: true,
      staged: true,
      durable: false,
      ruleId: value.ruleId,
      requestId,
      stagedAt: now().toISOString(),
      rejections: staged.rejections,
    };
  };

  const dispatch = async (name: string, input: unknown): Promise<ProjectRulePolicyDispatchResult> => {
    if (name === PROJECT_RULE_POLICY_TOOL_NAMES.list) {
      return { ok: true, tool: "list", result: await list(input) };
    }
    if (name === PROJECT_RULE_POLICY_TOOL_NAMES.revoke) {
      return { ok: true, tool: "revoke", result: await revoke(input) };
    }
    return { ok: false, reason: "unknown-tool" };
  };

  return Object.freeze({ list, revoke, dispatch });
}

/** Unused candidate type re-export keeps the staged shape visible to Phase 10. */
export type { LearningCandidate };
