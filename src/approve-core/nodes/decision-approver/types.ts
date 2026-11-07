import type { CallState } from "#approve-core/contracts";
import type { StepContext } from "#approve-core/runtime";
import type { ReviewRevisions, ReviewView } from "../../../contracts";
import type {
  ReviewerContextStore,
  ReviewerSessionFacts,
} from "#approve-core/context";
import type {
  ClassifierApi,
  ClassifierContext,
  ClassifierModel,
  ClassifierResult,
  ModelsClassifierOptions,
} from "@earendil-works/pi-ai";
import type { DecisionClassifierProfile } from "#approve-core/nodes/decision-approver/model";

export interface DecisionGuidanceEntry {
  readonly path: string;
  readonly content: string;
  readonly isGlobal: boolean;
}

export interface DecisionGuidanceSelection {
  readonly included: readonly DecisionGuidanceEntry[];
  readonly dropped?: readonly {
    readonly path: string;
    readonly bytes: number;
    readonly reason: string;
  }[];
}

export interface DecisionClassifierEvent {
  readonly kind: "decision";
  readonly nodeId: "builtin/decision-approver";
  readonly owner: string;
  readonly requests: number;
  readonly outcome: "sent" | "failed";
}

export type DecisionNodeEvent = DecisionClassifierEvent;

/**
 * How the node acquires reviewer context. Experimental and subject to change.
 * `llm` mirrors the LLM approver's cursor discipline (delta reads after a
 * committed read, commit on a fully accepted batch, invalidate on failure);
 * `decision` keeps the legacy full re-read without cursor advancement.
 */
export type DecisionContextAcquisition = "llm" | "decision";

export interface DecisionApproverNodeDependencies {
  readonly context: ReviewerContextStore;
  readonly contextAcquisition?: DecisionContextAcquisition;
  readonly resolveSession: (
    context: StepContext,
  ) => ReviewerSessionFacts | undefined | Promise<ReviewerSessionFacts | undefined>;
  readonly resolveProfile: (owner: string) => DecisionClassifierProfile | undefined;
  readonly classify: (
    model: ClassifierModel<ClassifierApi>,
    context: ClassifierContext,
    options?: ModelsClassifierOptions,
  ) => Promise<ClassifierResult>;
  readonly rubric?: string;
  readonly resolveGuidance?: (owner: string) => DecisionGuidanceSelection;
  readonly fetch?: typeof fetch;
  readonly now?: () => number;
  readonly packingContractVersion?: number;
  readonly verifyFacts: (input: {
    readonly owner: string;
    readonly mode: ReviewerSessionFacts["mode"];
    readonly view: ReviewView;
    readonly revisions: ReviewRevisions;
    readonly calls: readonly {
      readonly toolCallId: string;
      readonly actionDigest: string;
      readonly call: CallState;
    }[];
  }) => boolean;
  readonly onEvent?: (event: DecisionNodeEvent) => void;
}
