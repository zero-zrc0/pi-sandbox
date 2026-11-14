/**
 * Model-node assembly (specs/host-integration.md §5).
 *
 * A publication generation owns at most two model nodes: the LLM approver and
 * the Decision classifier. The assembly is a composition seam only: node
 * factories, the model registry, the context store and the completion seams are
 * injected, so this module never loads a node implementation, a config parser
 * or a transport. Enabled state and order come from the effective node
 * configuration; everything that depends on the current mode/view is resolved
 * lazily, when a node evaluates a step.
 */
import type {
  Api,
  ClassifierApi,
  ClassifierContext,
  ClassifierModel,
  ClassifierResult,
  Model,
  ModelsClassifierOptions,
} from "@earendil-works/pi-ai";
import type { EffectiveNode } from "#approve-core/contracts";
import type { ChainNode, NodeBinding } from "#approve-core/runtime";
import type {
  ReviewerContextStore,
  ReviewerLearningLifecycle,
  ReviewerMode,
  ReviewRevisions,
  ReviewView,
} from "#approve-core/context";
import type {
  LlmApproverNodeDependencies,
  LlmCompleteFn,
  LlmGuidance,
  LlmNodeEvent,
  LlmProjectRulesSnapshot,
} from "#approve-core/nodes/llm-approver/types";
import type {
  DecisionApproverNodeDependencies,
  DecisionNodeEvent,
} from "#approve-core/nodes/decision-approver/types";
import { DEFAULT_INSTRUCTIONS } from "#approve-core/nodes/llm-approver/instructions";
import { reviewDigest } from "#approve-core/context/types";

const LLM_APPROVER_NODE_ID = "builtin/llm-approver";
const DECISION_APPROVER_NODE_ID = "builtin/decision-approver";

/**
 * Hard cap on the output budget this host requests from a judge. The config
 * schema has no output-budget field yet, so a publication can only reserve this
 * default request; the actual reserved output is additionally clamped by the
 * model's own output limit below.
 */
const MAX_RESERVED_OUTPUT_TOKENS = 4_096;

/** Classifier defaults the config schema documents for a pi-classifier judge. */
const DEFAULT_CLASSIFIER_TIMEOUT_MS = 15_000;
const DEFAULT_CLASSIFIER_CONTEXT_BUDGET_TOKENS = 32_768;
const DEFAULT_CLASSIFIER_ALLOW_THRESHOLD = 0.9;
const DEFAULT_CLASSIFIER_DENY_THRESHOLD = 0.8;

/** Read-only model registry slice a publication generation can consult. */
export interface ModelRegistryPort {
  find(provider: string, modelId: string): Model<Api> | undefined;
  findClassifier(
    provider: string,
    modelId: string,
  ): ClassifierModel<ClassifierApi> | undefined;
}

/** Project-rule snapshot seam; resolves at evaluation time, never at assembly. */
export interface ProjectRulesPort {
  snapshot(input: {
    readonly owner: string;
    readonly mode: ReviewerMode;
    readonly view: ReviewView;
    readonly revisions: ReviewRevisions;
    readonly signal?: AbortSignal;
  }): LlmProjectRulesSnapshot | undefined | Promise<LlmProjectRulesSnapshot | undefined>;
}

export type LlmNodeFactory = (
  deps: LlmApproverNodeDependencies,
) => ChainNode & { dispose?: () => void };

export type DecisionNodeFactory = (
  deps: DecisionApproverNodeDependencies,
) => ChainNode & { dispose?: () => void };

export type ModelJudgeConfig =
  | {
      readonly kind: "pi-model";
      readonly provider?: string;
      readonly modelId?: string;
      readonly timeoutMs?: number;
    }
  | {
      readonly kind: "pi-classifier";
      readonly provider: string;
      readonly modelId: string;
      readonly timeoutMs?: number;
      readonly contextBudgetTokens?: number;
      readonly allowConfidenceThreshold?: number;
      readonly denyConfidenceThreshold?: number;
    }
  | {
      readonly kind: "custom";
      readonly baseUrl: string;
      readonly modelId: string;
      readonly apiKey?: string;
      readonly timeoutMs?: number;
      readonly contextBudgetTokens?: number;
      readonly allowConfidenceThreshold?: number;
      readonly denyConfidenceThreshold?: number;
    };

export interface ApproverConfig {
  readonly provider?: string;
  readonly modelId?: string;
  readonly instructions?: string;
  readonly judge?: ModelJudgeConfig;
  readonly timeoutMs?: number;
  readonly queueTimeoutMs?: number;
  readonly decisionContextAcquisition?: "llm" | "decision";
}

/** One node audit event tagged with the publication generation that owns it. */
export type ModelNodeEvent = (LlmNodeEvent | DecisionNodeEvent) & {
  readonly generation: number;
};

export interface ModelAssemblyInput {
  readonly generation: number;
  readonly effectiveNodes: readonly EffectiveNode[];
  readonly approver: ApproverConfig;
  readonly registry: ModelRegistryPort;
  readonly context: ReviewerContextStore;
  readonly resolveSession: LlmApproverNodeDependencies["resolveSession"];
  readonly verifyFacts: LlmApproverNodeDependencies["verifyFacts"];
  readonly learning?: ReviewerLearningLifecycle;
  readonly projectRules?: ProjectRulesPort;
  readonly complete: LlmCompleteFn;
  readonly classify: (
    model: ClassifierModel<ClassifierApi>,
    context: ClassifierContext,
    options?: ModelsClassifierOptions,
  ) => Promise<ClassifierResult>;
  readonly fetch?: typeof fetch;
  readonly now?: () => number;
  readonly guidance?: readonly LlmGuidance[];
  readonly rubric?: string;
  readonly onEvent?: (event: ModelNodeEvent) => void;
  readonly createLlmNode: LlmNodeFactory;
  readonly createDecisionNode: DecisionNodeFactory;
  /** Host "current model" identity used as the last LLM judge fallback. */
  readonly currentModel?: { readonly provider: string; readonly modelId: string };
}

export interface ModelNodeAssembly {
  readonly generation: number;
  readonly nodes: readonly NodeBinding[];
  /** Disposes both nodes once; idempotent. */
  dispose(): void;
}

function nonEmpty(value: string | undefined): value is string {
  return typeof value === "string" && value.trim() !== "";
}

function positiveSafeInteger(value: number | undefined, fallback: number): number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0
    ? value
    : fallback;
}

function unitInterval(value: number | undefined, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1
    ? value
    : fallback;
}

interface ModelPair {
  readonly provider: string;
  readonly modelId: string;
}

/**
 * Judge provider/model precedence: an explicit `pi-model` judge pair, then the
 * approver pair, then the host current model. Every pair is looked up as a
 * unit; a half-configured pair falls through to the next source.
 */
function configuredModelPair(input: ModelAssemblyInput): ModelPair | undefined {
  const judge = input.approver.judge;
  if (judge !== undefined && judge.kind === "pi-model") {
    if (nonEmpty(judge.provider) && nonEmpty(judge.modelId)) {
      return { provider: judge.provider, modelId: judge.modelId };
    }
  }
  if (nonEmpty(input.approver.provider) && nonEmpty(input.approver.modelId)) {
    return { provider: input.approver.provider, modelId: input.approver.modelId };
  }
  const current = input.currentModel;
  if (current !== undefined && nonEmpty(current.provider) && nonEmpty(current.modelId)) {
    return { provider: current.provider, modelId: current.modelId };
  }
  return undefined;
}

/**
 * Audit events are bound to the generation of the assembly that created the
 * node. A later reload builds a new assembly, so it can never rewrite the
 * generation an already-recorded event belongs to.
 */
function taggedEventSink(
  input: ModelAssemblyInput,
): ((event: LlmNodeEvent | DecisionNodeEvent) => void) | undefined {
  const onEvent = input.onEvent;
  if (onEvent === undefined) return undefined;
  return (event) => {
    onEvent({ ...event, generation: input.generation });
  };
}

function llmDependencies(input: ModelAssemblyInput): LlmApproverNodeDependencies {
  const onEvent = taggedEventSink(input);
  return {
    context: input.context,
    resolveSession: input.resolveSession,
    resolveProfile: () => {
      const pair = configuredModelPair(input);
      if (pair === undefined) return undefined;
      const model = input.registry.find(pair.provider, pair.modelId);
      if (model === undefined) return undefined;
      if (!Number.isSafeInteger(model.contextWindow) || model.contextWindow <= 0) {
        return undefined;
      }
      const modelMaxTokens = model.maxTokens;
      if (!Number.isSafeInteger(modelMaxTokens) || modelMaxTokens <= 0) {
        // The llm node's own model capture requires an integer output limit at
        // least as large as the profile's `maxOutputTokens`, so a model without
        // one cannot be used as a judge at all: fail closed and let the node
        // fall back instead of fabricating a limit the node would reject.
        return undefined;
      }
      return {
        provider: pair.provider,
        modelId: pair.modelId,
        contextWindowTokens: model.contextWindow,
        maxOutputTokens: modelMaxTokens,
        outputTokens: Math.min(modelMaxTokens, MAX_RESERVED_OUTPUT_TOKENS),
        endpointRevision: reviewDigest({ api: model.api, baseUrl: model.baseUrl }),
        authSubjectRevision: reviewDigest({
          provider: pair.provider,
          modelId: pair.modelId,
        }),
        protocolRevision: reviewDigest({ api: model.api }),
        projectionRevision: reviewDigest({
          contextWindow: model.contextWindow,
          maxTokens: model.maxTokens,
        }),
        rubric: input.rubric ?? DEFAULT_INSTRUCTIONS,
        guidance: input.guidance ?? [],
        framingMarginTokens: 0,
      };
    },
    resolveModel: (profile) => input.registry.find(profile.provider, profile.modelId),
    complete: input.complete,
    verifyFacts: input.verifyFacts,
    ...(input.projectRules === undefined
      ? {}
      : { resolveProjectRules: (request) => input.projectRules?.snapshot(request) }),
    ...(input.learning === undefined ? {} : { learning: input.learning }),
    ...(input.now === undefined ? {} : { now: input.now }),
    ...(onEvent === undefined ? {} : { onEvent }),
  };
}

function decisionDependencies(
  input: ModelAssemblyInput,
): DecisionApproverNodeDependencies {
  const onEvent = taggedEventSink(input);
  return {
    context: input.context,
    resolveSession: input.resolveSession,
    resolveProfile: () => {
      const judge = input.approver.judge;
      if (judge === undefined) return undefined;
      if (judge.kind === "custom") {
        return {
          kind: "custom",
          baseUrl: judge.baseUrl,
          modelId: judge.modelId,
          apiKey: judge.apiKey,
          timeoutMs: positiveSafeInteger(
            judge.timeoutMs ?? input.approver.timeoutMs,
            DEFAULT_CLASSIFIER_TIMEOUT_MS,
          ),
          contextBudgetTokens: positiveSafeInteger(
            judge.contextBudgetTokens,
            DEFAULT_CLASSIFIER_CONTEXT_BUDGET_TOKENS,
          ),
          allowConfidenceThreshold: unitInterval(
            judge.allowConfidenceThreshold,
            DEFAULT_CLASSIFIER_ALLOW_THRESHOLD,
          ),
          denyConfidenceThreshold: unitInterval(
            judge.denyConfidenceThreshold,
            DEFAULT_CLASSIFIER_DENY_THRESHOLD,
          ),
        };
      }
      // The classifier path is exclusive to an explicit pi-classifier judge.
      if (judge.kind !== "pi-classifier") return undefined;
      const model = input.registry.findClassifier(judge.provider, judge.modelId);
      if (model === undefined) return undefined;
      return {
        kind: "pi-classifier",
        model,
        timeoutMs: positiveSafeInteger(
          judge.timeoutMs ?? input.approver.timeoutMs,
          DEFAULT_CLASSIFIER_TIMEOUT_MS,
        ),
        contextBudgetTokens: positiveSafeInteger(
          judge.contextBudgetTokens,
          DEFAULT_CLASSIFIER_CONTEXT_BUDGET_TOKENS,
        ),
        allowConfidenceThreshold: unitInterval(
          judge.allowConfidenceThreshold,
          DEFAULT_CLASSIFIER_ALLOW_THRESHOLD,
        ),
        denyConfidenceThreshold: unitInterval(
          judge.denyConfidenceThreshold,
          DEFAULT_CLASSIFIER_DENY_THRESHOLD,
        ),
      };
    },
    classify: input.classify,
    verifyFacts: input.verifyFacts,
    ...(input.rubric === undefined ? {} : { rubric: input.rubric }),
    ...(input.approver.decisionContextAcquisition === undefined
      ? {}
      : { contextAcquisition: input.approver.decisionContextAcquisition }),
    ...(input.fetch === undefined ? {} : { fetch: input.fetch }),
    ...(input.now === undefined ? {} : { now: input.now }),
    ...(onEvent === undefined ? {} : { onEvent }),
  };
}

export function assembleModelNodes(input: ModelAssemblyInput): ModelNodeAssembly {
  const bindings: NodeBinding[] = [];
  const nodes: (ChainNode & { dispose?: () => void })[] = [];

  for (const entry of input.effectiveNodes) {
    if (entry.enabled !== true) continue;
    if (entry.id === LLM_APPROVER_NODE_ID) {
      const node = input.createLlmNode(llmDependencies(input));
      nodes.push(node);
      bindings.push({ node, position: "post", priority: null });
    } else if (entry.id === DECISION_APPROVER_NODE_ID) {
      const node = input.createDecisionNode(decisionDependencies(input));
      nodes.push(node);
      bindings.push({ node, position: "post", priority: null });
    }
  }

  let disposed = false;
  return {
    generation: input.generation,
    nodes: bindings,
    dispose(): void {
      if (disposed) return;
      disposed = true;
      for (const node of nodes) {
        try {
          node.dispose?.();
        } catch {
          // A release failure never changes a decided result or blocks the peer.
        }
      }
    },
  };
}
