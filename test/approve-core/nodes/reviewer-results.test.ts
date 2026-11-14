import { describe, expect, it } from "vitest";
import type {
  Api,
  AssistantMessage,
  ClassifierApi,
  ClassifierModel,
  Model,
} from "@earendil-works/pi-ai";
import {
  applyNodeResult,
  captureStep,
  prepareStep,
  readyCallResults,
  type NodeResult,
} from "#approve-core/contracts";
import type {
  ContextSelection,
  ReviewRevisions,
  ReviewView,
  ReviewerContextStore,
  ReviewerSessionFacts,
} from "#approve-core/context/types";
import { reviewDigest } from "#approve-core/context/types";
import { createDecisionApproverNode } from "#approve-core/nodes/decision-approver/node";
import type { DecisionClassifierProfile } from "#approve-core/nodes/decision-approver/model";
import { createLlmApproverNode } from "#approve-core/nodes/llm-approver/node";
import type { LlmReviewerProfile } from "#approve-core/nodes/llm-approver/types";
import type { StepContext } from "#approve-core/runtime";

const CALL_ID = "review-call";
const UNIT_ID = "review-unit";
const OWNER = "review-owner";

const view: ReviewView = {
  owner: OWNER,
  sessionId: "review-session",
  historyVersion: 1,
  captureSeq: 1,
  leafId: "review-leaf",
  branchRootId: "review-root",
  transcript: [],
  authorization: [],
  degraded: false,
};

const revisions: ReviewRevisions = {
  owner: 1,
  navigation: 1,
  authorization: 1,
  projectRules: 1,
  intent: 1,
};

const facts: ReviewerSessionFacts = { view, revisions, mode: "auto-review" };

function contextStore(): ReviewerContextStore {
  const selection: ContextSelection = {
    owner: OWNER,
    consumer: "test-reviewer",
    view,
    revisions,
    mode: "full",
    generation: 1,
    historyVersion: view.historyVersion,
    captureSeq: view.captureSeq,
    readCount: 0,
    prefixDigest: reviewDigest([]),
    authorization: [],
    evidence: [],
    installable: true,
  };
  return {
    disposed: false,
    begin: () => ({ ok: true, selection }),
    commit: () => ({ ok: true, generation: 1 }),
    invalidate: () => undefined,
    state: () => [],
    dispose: () => undefined,
  };
}

function pendingStep(nodeId: string): StepContext {
  const args = { path: "report.txt", content: "data" };
  const captured = captureStep({
    stepKey: "review-step",
    sessionId: view.sessionId,
    sourceEntryId: "review-entry",
    manifestRevision: 1,
    complete: true,
    directCalls: [{
      toolCallId: CALL_ID,
      toolName: "write",
      arguments: args,
      argumentsDigest: reviewDigest(args),
    }],
  });
  if (!captured.ok) throw new Error(captured.reason);
  const prepared = prepareStep(captured.capture, [{
    toolCallId: CALL_ID,
    unitId: UNIT_ID,
    actionDigest: captured.capture.directCalls[0]!.digest,
    reason: "test-rule-ask",
  }]);
  if (!prepared.ok) throw new Error(prepared.reason);
  const asked = applyNodeResult(prepared.state, {
    node: { id: "builtin/decision", priority: null },
    evaluatedRevision: prepared.state.revision,
    result: {
      decisions: [{
        toolCallId: CALL_ID,
        unitId: UNIT_ID,
        decision: "ask",
        reason: "rules:global:ask:write:*",
      }],
    },
  });
  if (!asked.ok) throw new Error(asked.reason);
  return {
    capture: captured.capture,
    state: asked.state,
    node: { id: nodeId, position: "post", priority: null },
    signal: new AbortController().signal,
    deadlineAt: null,
  };
}

const classifier: ClassifierModel<ClassifierApi> = {
  id: "review-classifier",
  name: "Review classifier",
  type: "classifier",
  api: "typesafe-system-one",
  provider: "typesafe",
  baseUrl: "https://classifier.example.test",
  input: ["text"],
  cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
  contextWindow: 32_768,
};

const decisionProfile: DecisionClassifierProfile = {
  kind: "pi-classifier",
  model: classifier,
  timeoutMs: 1_000,
  contextBudgetTokens: 8_192,
  allowConfidenceThreshold: 0.8,
  denyConfidenceThreshold: 0.8,
};

const llmProfile: LlmReviewerProfile = {
  provider: "anthropic",
  modelId: "review-model",
  contextWindowTokens: 32_768,
  maxOutputTokens: 1_024,
  outputTokens: 1_024,
  endpointRevision: "endpoint-1",
  authSubjectRevision: "auth-1",
  protocolRevision: "protocol-1",
  projectionRevision: "projection-1",
  rubric: "Review the pending call.",
  guidance: [],
  framingMarginTokens: 0,
};

const llmModel: Model<Api> = {
  id: "review-model",
  name: "Review model",
  api: "anthropic-messages",
  provider: "anthropic",
  baseUrl: "https://review.example.test",
  input: ["text"],
  cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
  reasoning: false,
  contextWindow: 32_768,
  maxTokens: 1_024,
};

function nodeHost() {
  return { log: () => undefined };
}

describe("actual model reviewer nodes", () => {
  it.each(["approve", "deny"] as const)("Decision reviewer returns a separate %s review", async verdict => {
    const node = createDecisionApproverNode({
      context: contextStore(),
      contextAcquisition: "decision",
      resolveSession: () => facts,
      resolveProfile: () => decisionProfile,
      classify: async () => ({
        api: classifier.api,
        provider: classifier.provider,
        model: classifier.id,
        answers: {
          verdict: {
            type: "choice",
            choice: verdict,
            confidence: 1,
            probabilities: { [verdict]: 1 },
          },
        },
        stopReason: "stop",
        timestamp: 1,
      }),
      verifyFacts: () => true,
    });

    const step = pendingStep("builtin/decision-approver");
    const result: NodeResult = await node.evaluate(step, nodeHost());

    expect(result.decisions).toEqual([]);
    expect(result.reviews).toMatchObject([{
      toolCallId: CALL_ID,
      unitId: UNIT_ID,
      decision: verdict,
    }]);
    const applied = applyNodeResult(step.state, {
      node: { id: "builtin/decision-approver", priority: null },
      evaluatedRevision: step.state.revision,
      result,
    });
    expect(applied.ok).toBe(true);
    if (!applied.ok) throw new Error(applied.reason);
    expect(applied.state.calls[0]!.units[0]!.decision).toBe("ask");
    expect(readyCallResults(applied.state)[0]!.decision).toBe(verdict === "approve" ? "allow" : "deny");
    node.dispose();
  });

  it.each(["approve", "deny"] as const)("LLM reviewer returns a separate %s review", async verdict => {
    const step = pendingStep("builtin/llm-approver");
    const call = step.state.calls[0]!;
    const node = createLlmApproverNode({
      context: contextStore(),
      resolveSession: () => facts,
      resolveProfile: () => llmProfile,
      resolveModel: () => llmModel,
      complete: async () => ({
        role: "assistant",
        content: [{
          type: "text",
          text: JSON.stringify({ results: [{
            toolCallId: CALL_ID,
            actionDigest: call.digest,
            verdict,
          }] }),
        }],
        api: llmModel.api,
        provider: llmModel.provider,
        model: llmModel.id,
        usage: {
          input: 1,
          output: 1,
          cacheRead: 0,
          cacheWrite: 0,
          totalTokens: 2,
          cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
        },
        stopReason: "stop",
        timestamp: 1,
      } as AssistantMessage),
      verifyFacts: () => true,
      now: () => 1,
      estimateTokens: () => 1,
    });

    const result: NodeResult = await node.evaluate(step, nodeHost());

    expect(result.decisions).toEqual([]);
    expect(result.reviews).toMatchObject([{
      toolCallId: CALL_ID,
      unitId: UNIT_ID,
      decision: verdict,
    }]);
    const applied = applyNodeResult(step.state, {
      node: { id: "builtin/llm-approver", priority: null },
      evaluatedRevision: step.state.revision,
      result,
    });
    expect(applied.ok).toBe(true);
    if (!applied.ok) throw new Error(applied.reason);
    expect(applied.state.calls[0]!.units[0]!.decision).toBe("ask");
    expect(readyCallResults(applied.state)[0]!.decision).toBe(verdict === "approve" ? "allow" : "deny");
    node.dispose();
  });
});
