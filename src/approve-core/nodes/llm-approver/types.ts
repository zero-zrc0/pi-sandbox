import type {
  Api,
  AssistantMessage,
  Context,
  Model,
} from "@earendil-works/pi-ai";
import type { CallState } from "#approve-core/contracts";
import type { StepContext } from "#approve-core/runtime";
import type { PermissionMode, ReviewRevisions, ReviewView } from "../../../contracts";
import type {
  ChainCallMaterial,
  ReviewerContextStore,
  ReviewerLearningLifecycle,
  ReviewerSessionFacts,
} from "#approve-core/context";
import { type JsonObject } from "../../../json";

/**
 * Injected completion seam, structurally the public Pi `complete` call. The
 * node never imports a transport and never exposes an execution tool to the
 * judge; the judge answers in message text, so no tool choice is forced.
 */
export type LlmCompleteFn = (
  model: Model<Api>,
  context: Context,
  options?: {
    readonly signal?: AbortSignal;
    readonly apiKey?: string;
    readonly headers?: Record<string, string | null>;
    readonly maxTokens?: number;
  },
) => Promise<AssistantMessage>;

export interface LlmGuidance {
  readonly path: string;
  readonly content: string;
  readonly trusted: boolean;
  readonly digest: string;
}

export interface LlmProjectRule {
  readonly id: string;
  readonly effect: "allow" | "deny";
  readonly status: "active" | "needs_review" | "revoked";
  readonly applicable: boolean;
  readonly match: JsonObject;
}

export interface LlmProjectRulesSnapshot {
  readonly rulesRevision: number;
  readonly intentRevision: number;
  readonly rules: readonly LlmProjectRule[];
}

export interface LlmReviewerProfile {
  readonly provider: string;
  readonly modelId: string;
  readonly contextWindowTokens: number;
  readonly maxOutputTokens: number;
  readonly outputTokens: number;
  readonly endpointRevision: string;
  readonly authSubjectRevision: string;
  readonly protocolRevision: string;
  readonly projectionRevision: string;
  readonly rubric: string;
  readonly guidance: readonly LlmGuidance[];
  readonly framingMarginTokens: number;
}

export interface LlmProfileRequest {
  readonly owner: string;
  readonly mode: PermissionMode;
  readonly view: ReviewView;
}

export interface LlmNodeBounds {
  readonly maxReviewers?: number;
  readonly maxQueueLength?: number;
  readonly queueWaitMs?: number;
  readonly maxConversationRounds?: number;
  readonly retentionMs?: number;
  /** Physical model completions allowed unsettled across the process. */
  readonly maxUnsettledCompletions?: number;
}

export interface LlmTransportEvent {
  readonly kind: "llm";
  readonly nodeId: "builtin/llm-approver";
  readonly owner: string;
  readonly requests: 1;
  readonly outcome: "sent" | "failed";
}

export type LlmNodeEvent = LlmTransportEvent;

export interface LlmApproverNodeDependencies {
  readonly context: ReviewerContextStore;
  readonly resolveSession: (
    context: StepContext,
  ) => ReviewerSessionFacts | undefined | Promise<ReviewerSessionFacts | undefined>;
  readonly resolveProfile: (input: LlmProfileRequest) => LlmReviewerProfile | undefined;
  readonly resolveModel: (profile: LlmReviewerProfile) => Model<Api> | undefined;
  readonly complete: LlmCompleteFn;
  readonly resolveProjectRules?: (input: {
    readonly owner: string;
    readonly mode: PermissionMode;
    readonly view: ReviewView;
    readonly revisions: ReviewRevisions;
    readonly signal?: AbortSignal;
  }) => LlmProjectRulesSnapshot | undefined | Promise<LlmProjectRulesSnapshot | undefined>;
  readonly verifyFacts: (input: {
    readonly owner: string;
    readonly mode: PermissionMode;
    readonly view: ReviewView;
    readonly revisions: ReviewRevisions;
    readonly calls: readonly {
      readonly toolCallId: string;
      readonly actionDigest: string;
      readonly call: CallState;
    }[];
  }) => boolean;
  readonly learning?: ReviewerLearningLifecycle;
  readonly now?: () => number;
  readonly estimateTokens?: (text: string) => number;
  readonly bounds?: LlmNodeBounds;
  readonly onEvent?: (event: LlmNodeEvent) => void;
}

export interface LlmMaterialCall extends ChainCallMaterial {}
