import type { Api, AssistantMessage, Context, Message, Model } from "@earendil-works/pi-ai";
import {
  MAX_REASON_LENGTH,
  applyNodeResult,
  mapCallReview,
  type CallState,
  type NodeResult,
  type UnitReview,
} from "#approve-core/contracts";
import type { ChainNode, NodeHost, StepContext } from "#approve-core/runtime";
import { pendingCalls } from "#approve-core/nodes/pending-calls";
import {
  checkProviderBudget,
  estimateJsonStringContentTokenQuarters,
  estimateTextTokenQuarters,
  estimateTextTokens,
  hasUnpairedToolResults,
  historySelectableEvidence,
  measureRequestTokenQuarters,
  selectBudgetedEvidence,
  selectBudgetedEvidenceByCost,
  type ChainCallMaterial,
  type ContextSelection,
  type ReviewerSessionFacts,
} from "#approve-core/context";
import {
  parseBatchVerdicts,
  renderMaterial,
  serializeMaterialEvidenceEntry,
  systemMessage,
  userMaterialMessage,
  type LlmVerdictItem,
} from "#approve-core/nodes/llm-approver/protocol";
import {
  boundedInteger,
  captureModel,
  captureProfile,
  captureProjectRules,
  compatibilityFingerprint,
} from "#approve-core/nodes/llm-approver/profile";
import {
  awaitSignal,
  conversationRounds,
  createConversationStore,
  createKeyedQueue,
  createSettlementAdmission,
  linkSignals,
  trackSettlement,
  type ConversationLease,
  type ReviewerConversation,
} from "#approve-core/nodes/llm-approver/runtime";
import type {
  LlmApproverNodeDependencies,
  LlmNodeEvent,
  LlmProjectRulesSnapshot,
  LlmReviewerProfile,
} from "#approve-core/nodes/llm-approver/types";
import { freezeJson } from "../../../json";

export const LLM_APPROVER_NODE_ID = "builtin/llm-approver";

const DEFAULT_MAX_REVIEWERS = 32;
const DEFAULT_REVIEWER_RETENTION_MS = 30 * 60_000;
const DEFAULT_MAX_QUEUE_LENGTH = 8;
const DEFAULT_QUEUE_WAIT_MS = 30_000;
const DEFAULT_MAX_CONVERSATION_ROUNDS = 8;
const DEFAULT_MAX_UNSETTLED_COMPLETIONS = 8;

export interface LlmApproverNode extends ChainNode {
  dispose(): void;
}

function callMaterial(call: CallState): ChainCallMaterial {
  const pendingUnitIds = call.units
    .filter((unit) => unit.decision === "ask")
    .map((unit) => unit.unitId);
  return {
    toolCallId: call.toolCallId,
    ...(call.parentToolCallId === undefined ? {} : { parentToolCallId: call.parentToolCallId }),
    toolName: call.toolName,
    arguments: call.arguments,
    ...(call.hostExecutionRequest === undefined
      ? {}
      : { hostExecutionRequest: call.hostExecutionRequest }),
    askFor: call.askFor ?? "allow",
    argumentsDigest: call.argumentsDigest,
    digest: call.digest,
    units: call.units.map((unit) => ({
      unitId: unit.unitId,
      decision: unit.decision,
      reason: unit.reason,
      source: unit.source,
      history: unit.history.map((record) => ({
        revision: record.revision,
        nodeId: record.nodeId,
        priority: record.priority,
        decision: record.decision,
        reason: record.reason,
      })),
    })),
    pendingUnitIds,
  };
}

function reasonFor(item: LlmVerdictItem): string {
  const fallback = item.verdict === "approve"
    ? "llm-approve"
    : item.verdict === "deny"
      ? "llm-deny"
      : "llm-ask";
  const reason = item.reason === undefined || item.reason.trim() === "" ? fallback : item.reason;
  if (reason.length > MAX_REASON_LENGTH) throw new Error("llm-invalid-reason");
  return reason;
}

/**
 * The recovery scope one failed round leaves behind, for the single recovery
 * owner to undo.
 */
interface RoundRecovery {
  owner?: string;
  consumer?: string;
  conversation?: { forceFull: boolean };
}

/** Facts every continuation round of one evaluation shares. */
interface RoundScope {
  readonly step: StepContext;
  readonly signal: AbortSignal;
  readonly facts: ReviewerSessionFacts;
  readonly calls: readonly CallState[];
  readonly profile: LlmReviewerProfile;
  readonly model: Model<Api>;
  readonly projectRules: LlmProjectRulesSnapshot | undefined;
  readonly consumer: string;
  readonly revision: number;
}

/** The request captured by the round's continuation-base selection. */
interface RoundRequest {
  readonly messages: readonly Message[];
  readonly outputTokens: number;
}

/**
 * One continuation round while it owns the consumer: the selection it will
 * commit, the conversation base it extends, both leases, and the captured
 * request. Queue use, Full selection, success install, failure recovery and
 * release all hang off this one object inside the node.
 */
interface ContinuationRound {
  readonly selection: ContextSelection;
  readonly conversation: ReviewerConversation;
  readonly conversationLease: ConversationLease;
  readonly queueRelease: () => void;
  readonly request: RoundRequest;
}

/**
 * Build the direct LLM approval node. It uses the chain's frozen state and the
 * shared reviewer context; there is no strategy resolver and no second action
 * capture. The judge answers with one JSON object as its message text, and the
 * batch is accepted only against the frozen pending calls. One legal
 * evaluation makes at most one judgement request whose history is selected
 * inside the full request budget; no plugin-generated summary request exists.
 */
export function createLlmApproverNode(
  deps: LlmApproverNodeDependencies,
): LlmApproverNode {
  const now = deps.now ?? Date.now;
  const estimateTokens = deps.estimateTokens ?? estimateTextTokens;
  const bounds = deps.bounds ?? {};
  const maxReviewers = boundedInteger(
    bounds.maxReviewers,
    DEFAULT_MAX_REVIEWERS,
    1,
    DEFAULT_MAX_REVIEWERS,
  );
  const maxQueueLength = boundedInteger(
    bounds.maxQueueLength,
    DEFAULT_MAX_QUEUE_LENGTH,
    0,
    DEFAULT_MAX_QUEUE_LENGTH,
  );
  const queueWaitMs = boundedInteger(
    bounds.queueWaitMs,
    DEFAULT_QUEUE_WAIT_MS,
    1,
    DEFAULT_QUEUE_WAIT_MS,
  );
  const maxConversationRounds = boundedInteger(
    bounds.maxConversationRounds,
    DEFAULT_MAX_CONVERSATION_ROUNDS,
    1,
    DEFAULT_MAX_CONVERSATION_ROUNDS,
  );
  const maxUnsettledCompletions = boundedInteger(
    bounds.maxUnsettledCompletions,
    DEFAULT_MAX_UNSETTLED_COMPLETIONS,
    1,
    32,
  );
  const retentionMs = boundedInteger(
    bounds.retentionMs,
    DEFAULT_REVIEWER_RETENTION_MS,
    1,
    DEFAULT_REVIEWER_RETENTION_MS,
  );

  const conversations = createConversationStore({
    maxReviewers,
    retentionMs,
    now,
  });
  const queue = createKeyedQueue({
    now,
    maxQueueLength,
    defaultWaitMs: queueWaitMs,
  });
  const completionAdmission = createSettlementAdmission(maxUnsettledCompletions);
  const lifetime = new AbortController();
  let disposed = false;

  function event(value: LlmNodeEvent): void {
    try {
      deps.onEvent?.(value);
    } catch {
      // A broken audit observer never changes the verdict.
    }
  }

  function stopReason(signal: AbortSignal, deadline: number | null): string | undefined {
    if (disposed) return "disposed";
    if (signal.aborted) return "cancelled";
    if (deadline !== null && (!Number.isFinite(deadline) || now() >= deadline)) {
      return "deadline-exceeded";
    }
    return undefined;
  }

  function verifyFacts(
    facts: ReviewerSessionFacts,
    calls: readonly CallState[],
  ): void {
    if (typeof deps.verifyFacts !== "function") throw new Error("stale-input");
    let current = false;
    try {
      current = deps.verifyFacts({
        owner: facts.view.owner,
        mode: facts.mode,
        view: facts.view,
        revisions: facts.revisions,
        calls: calls.map((call) => ({
          toolCallId: call.toolCallId,
          actionDigest: call.digest,
          call,
        })),
      }) === true;
    } catch {
      current = false;
    }
    if (!current) throw new Error("stale-input");
  }

  /**
   * The single failure-recovery owner for rounds: a technical failure forces
   * the next round to rebuild from Full, invalidates the consumer's context,
   * and lets the finally in the round release queue and conversation.
   */
  function recoverFailure(failure: RoundRecovery): void {
    if (failure.conversation !== undefined) failure.conversation.forceFull = true;
    if (failure.owner !== undefined || failure.consumer !== undefined) {
      deps.context.invalidate({
        ...(failure.owner === undefined ? {} : { owner: failure.owner }),
        ...(failure.consumer === undefined ? {} : { consumer: failure.consumer }),
      });
    }
  }

  function budgetFor(profile: LlmReviewerProfile, messages: readonly Message[]) {
    return checkProviderBudget({
      // The verdict arrives as message text; no tool declarations occupy the
      // request window.
      context: { messages: [...messages] } as Context,
      outputTokens: profile.outputTokens,
      maxOutputTokens: profile.maxOutputTokens,
      contextWindowTokens: profile.contextWindowTokens,
      framingMarginTokens: profile.framingMarginTokens,
      estimateTokens,
    });
  }

  function messagesFor(
    full: boolean,
    previous: readonly Message[],
    profile: LlmReviewerProfile,
    material: string,
    timestamp: number,
  ): Message[] {
    const base = full || previous.length === 0
      ? [systemMessage(profile.rubric, timestamp)]
      : [...previous];
    return [...base, userMaterialMessage(material, timestamp)];
  }

  function materialFor(input: {
    readonly selection: ContextSelection;
    readonly facts: ReviewerSessionFacts;
    readonly revision: number;
    readonly profile: LlmReviewerProfile;
    readonly projectRules: LlmProjectRulesSnapshot | undefined;
    readonly historyEvidence: ContextSelection["evidence"];
    readonly historyOmitted: boolean;
    readonly calls: readonly ChainCallMaterial[];
  }): string {
    return renderMaterial({
      owner: input.selection.owner,
      historyVersion: input.selection.historyVersion,
      captureSeq: input.selection.captureSeq,
      revision: input.revision,
      representation: input.selection.mode,
      mode: input.facts.mode,
      authorization: input.selection.authorization,
      guidance: input.profile.guidance,
      ...(input.projectRules === undefined ? {} : { projectRules: input.projectRules }),
      historyEvidence: input.historyEvidence,
      historyOmitted: input.historyOmitted,
      calls: input.calls,
    });
  }

  async function send(
    model: Model<Api>,
    context: Context,
    signal: AbortSignal,
    maxTokens: number,
    owner: string,
    key: string,
  ): Promise<AssistantMessage> {
    const release = completionAdmission.reserve(key);
    if (release === undefined) throw new Error("transport-capacity");
    let completion: Promise<AssistantMessage>;
    try {
      event({
        kind: "llm",
        nodeId: LLM_APPROVER_NODE_ID,
        owner,
        requests: 1,
        outcome: "sent",
      });
      completion = trackSettlement(
        deps.complete(model, context, { signal, maxTokens }),
        release,
      );
    } catch {
      release();
      event({
        kind: "llm",
        nodeId: LLM_APPROVER_NODE_ID,
        owner,
        requests: 1,
        outcome: "failed",
      });
      throw new Error("llm-transport-error");
    }
    try {
      const reply = await awaitSignal(completion, signal);
      if (signal.aborted) throw new Error("cancelled");
      return reply;
    } catch {
      event({
        kind: "llm",
        nodeId: LLM_APPROVER_NODE_ID,
        owner,
        requests: 1,
        outcome: "failed",
      });
      throw new Error("llm-transport-error");
    }
  }

  /**
   * Enter one continuation round: pick the continuation base (Full or the
   * accepted conversation), take the consumer's queue slot and a conversation
   * lease, then select the budgeted history and capture the exact request.
   * Everything acquired here is released again if entering fails.
   */
  async function enterRound(
    scope: RoundScope,
    failure: RoundRecovery,
  ): Promise<ContinuationRound> {
    failure.consumer = scope.consumer;
    const begun = deps.context.begin({
      facts: scope.facts,
      consumer: scope.consumer,
      signal: scope.signal,
      ...(scope.step.deadlineAt === null ? {} : { deadline: scope.step.deadlineAt }),
    });
    if (!begun.ok) throw new Error(`context-${begun.reason}`);
    let selection = begun.selection;

    const queueDeadline = scope.step.deadlineAt ?? (now() + queueWaitMs);
    const acquired = await queue.acquire(scope.consumer, {
      signal: scope.signal,
      deadline: queueDeadline,
    });
    if (!acquired.ok) throw new Error(acquired.reason);
    const conversationLease = conversations.acquire(scope.consumer, now());
    if (conversationLease === undefined) {
      acquired.release();
      throw new Error("reviewer-capacity");
    }
    const conversation = conversationLease.state;
    failure.consumer = scope.consumer;
    failure.conversation = conversation;
    try {
      const afterQueue = stopReason(scope.signal, scope.step.deadlineAt);
      if (afterQueue) throw new Error(afterQueue);

      let full = selection.mode === "full";
      if (
        !full && (
          conversation.messages.length === 0 ||
          conversation.forceFull ||
          conversation.generation !== selection.generation ||
          conversationRounds(conversation.messages) >= maxConversationRounds ||
          // A delta boundary that cuts a call/result pair cannot prove the
          // pairing against the accepted conversation; rebuild from Full
          // instead of sending an isolated result.
          hasUnpairedToolResults(selection.evidence)
        )
      ) {
        const forced = deps.context.begin({
          facts: scope.facts,
          consumer: scope.consumer,
          forceFull: true,
          signal: scope.signal,
          ...(scope.step.deadlineAt === null ? {} : { deadline: scope.step.deadlineAt }),
        });
        if (!forced.ok) throw new Error(`context-${forced.reason}`);
        selection = forced.selection;
        full = true;
      }

      const timestamp = now();
      const callMaterials = scope.calls.map(callMaterial);
      const buildRequest = (
        historyEvidence: ContextSelection["evidence"],
        historyOmitted: boolean,
      ) => {
        const material = materialFor({
          selection,
          facts: scope.facts,
          revision: scope.revision,
          profile: scope.profile,
          projectRules: scope.projectRules,
          historyEvidence,
          historyOmitted,
          calls: callMaterials,
        });
        const messages = messagesFor(full, conversation.messages, scope.profile, material, timestamp);
        const budget = budgetFor(scope.profile, messages);
        return { messages, budget };
      };

      const selectRequest = () => {
        const evidence = historySelectableEvidence(selection.evidence);
        const fullRequest = buildRequest(evidence, false);
        if (fullRequest.budget.ok) {
          return { request: { messages: fullRequest.messages, outputTokens: fullRequest.budget.outputTokens } };
        }

        if (estimateTokens === estimateTextTokens && fullRequest.budget.reason === "context-window-exceeded") {
          const profile = scope.profile;
          const margin = typeof profile.framingMarginTokens === "number" &&
              Number.isFinite(profile.framingMarginTokens) && profile.framingMarginTokens >= 0
            ? profile.framingMarginTokens
            : 0;
          if ([profile.contextWindowTokens, profile.maxOutputTokens, profile.outputTokens].every((value) =>
            Number.isFinite(value) && value > 0)) {
            const inputLimit = profile.contextWindowTokens - Math.min(profile.outputTokens, profile.maxOutputTokens) - margin;
            const base = (omitted: boolean) => buildRequest([], omitted).messages;
            const baseMessages = { all: base(false), omitted: base(true) };
            const packed = selectBudgetedEvidenceByCost(evidence, {
              limitQuarterTokens: Math.floor(inputLimit) * 4,
              baseQuarterTokens: {
                all: measureRequestTokenQuarters({ messages: [...baseMessages.all] }),
                omitted: measureRequestTokenQuarters({ messages: [...baseMessages.omitted] }),
              },
              entryQuarterTokens: evidence.map((item) => estimateJsonStringContentTokenQuarters(
                serializeMaterialEvidenceEntry(item),
              )),
              separatorQuarterTokens: estimateTextTokenQuarters(","),
              emptyPlaceholderQuarterTokens: 0,
            });
            if (packed !== undefined) {
              const selectedRequest = buildRequest(packed.evidence, packed.omitted);
              if (selectedRequest.budget.ok) {
                return { request: { messages: selectedRequest.messages, outputTokens: selectedRequest.budget.outputTokens } };
              }
            }
          }
        }

        const exact = selectBudgetedEvidence(evidence, (candidate, omitted) => {
          try {
            return buildRequest(candidate, omitted).budget.ok;
          } catch {
            return false;
          }
        });
        if (exact === undefined) return undefined;
        const selectedRequest = buildRequest(exact.evidence, exact.omitted);
        if (!selectedRequest.budget.ok) return undefined;
        return { request: { messages: selectedRequest.messages, outputTokens: selectedRequest.budget.outputTokens } };
      };
      let selectedRequest = selectRequest();
      if (selectedRequest === undefined && !full) {
        const forced = deps.context.begin({
          facts: scope.facts,
          consumer: scope.consumer,
          forceFull: true,
          signal: scope.signal,
          ...(scope.step.deadlineAt === null ? {} : { deadline: scope.step.deadlineAt }),
        });
        if (!forced.ok) throw new Error(`context-${forced.reason}`);
        selection = forced.selection;
        full = true;
        selectedRequest = selectRequest();
      }

      if (selectedRequest === undefined) throw new Error("llm-full-context-too-large");

      return {
        selection,
        conversation,
        conversationLease,
        queueRelease: acquired.release,
        request: selectedRequest.request,
      };
    } catch (error) {
      conversationLease.release(now());
      acquired.release();
      throw error;
    }
  }

  /**
   * Install a successful round: commit the context cursor and, in the same
   * synchronous section, install the accepted conversation so the two can
   * never drift apart. The continuation keeps the model's own plain assistant
   * JSON text message with its identity, usage and completion metadata — no
   * simulated tool call and no receipt is ever constructed.
   */
  function installRoundSuccess(
    round: ContinuationRound,
    scope: RoundScope,
    reply: AssistantMessage,
  ): void {
    const committed = deps.context.commit(round.selection, {
      signal: scope.signal,
      ...(scope.step.deadlineAt === null ? {} : { deadline: scope.step.deadlineAt }),
    });
    if (!committed.ok) throw new Error(committed.reason);
    round.conversation.messages = [
      ...round.request.messages,
      freezeJson(reply) as unknown as AssistantMessage,
    ];
    round.conversation.generation = committed.generation;
    round.conversation.forceFull = false;
    round.conversation.completedReviewCount += 1;
    round.conversation.lastUsedAt = now();
  }

  function acceptRoundLearning(scope: RoundScope, items: readonly LlmVerdictItem[]): void {
    if (deps.learning === undefined) return;
    for (const item of items) {
      const call = scope.calls.find((candidate) => candidate.toolCallId === item.toolCallId);
      if (call === undefined) continue;
      if (call.askFor === "escalate" || call.hostExecutionRequest !== undefined) continue;
      const attemptId = deps.learning.beginAttempt();
      let staged = 0;
      if (item.learning !== undefined) {
        try {
          staged = deps.learning.stage(attemptId, item.toolCallId, item.learning);
        } catch {
          staged = 0;
        }
      }
      if (staged === 0) {
        deps.learning.discardAttempt(attemptId);
        continue;
      }
      try {
        deps.learning.accept({
          attemptId,
          stepKey: scope.step.capture.stepKey,
          sessionId: scope.step.capture.sessionId,
          call,
          view: scope.facts.view,
          revisions: scope.facts.revisions,
          mode: scope.facts.mode,
          verdict: item.verdict === "approve"
            ? "allow"
            : item.verdict === "defer"
              ? "ask"
              : "deny",
        });
      } catch {
        deps.learning.discardAttempt(attemptId);
      }
    }
  }

  /**
   * Run one continuation round for an already-captured step: enter, send the
   * body-protocol request, reconcile the whole batch, map and preflight the
   * decisions, then commit context and conversation together. Any failure is
   * recovered by the single recovery owner; the finally releases the queue and
   * the conversation reference.
   */
  async function runRound(scope: RoundScope, failure: RoundRecovery): Promise<NodeResult> {
    const round = await enterRound(scope, failure);
    try {
      verifyFacts(scope.facts, scope.calls);
      const sendStop = stopReason(scope.signal, scope.step.deadlineAt);
      if (sendStop) throw new Error(sendStop);

      const reply = await send(
        scope.model,
        { messages: [...round.request.messages] },
        scope.signal,
        round.request.outputTokens,
        scope.facts.view.owner,
        scope.consumer,
      );

      const afterSend = stopReason(scope.signal, scope.step.deadlineAt);
      if (afterSend) throw new Error(afterSend);
      verifyFacts(scope.facts, scope.calls);

      const expected = scope.calls.map((call) => ({
        toolCallId: call.toolCallId,
        actionDigest: call.digest,
      }));
      const parsed = parseBatchVerdicts(reply, expected);
      if (!parsed.ok) throw new Error(parsed.reason);

      const node = { id: scope.step.node.id, priority: scope.step.node.priority };
      const reviews: UnitReview[] = [];
      for (const item of parsed.items) {
        const call = scope.calls.find((candidate) => candidate.toolCallId === item.toolCallId);
        if (call === undefined) throw new Error("llm-unknown-item");
        const mapped = mapCallReview(scope.step.state, node, {
          toolCallId: item.toolCallId,
          decision: item.verdict,
          reason: reasonFor(item),
        });
        if (!mapped.ok) throw new Error(mapped.reason);
        reviews.push(...(mapped.submission.result.reviews ?? []));
      }
      const result: NodeResult = { decisions: [], reviews };
      const preflight = applyNodeResult(scope.step.state, {
        node,
        evaluatedRevision: scope.step.state.revision,
        result,
      });
      if (!preflight.ok) throw new Error(preflight.reason);

      installRoundSuccess(round, scope, reply);
      acceptRoundLearning(scope, parsed.items);

      return result;
    } finally {
      round.conversationLease.release(now());
      round.queueRelease();
    }
  }

  return {
    apiVersion: "1",
    id: LLM_APPROVER_NODE_ID,

    async evaluate(step: StepContext, _host: NodeHost): Promise<NodeResult> {
      const calls = pendingCalls(step.state);
      if (calls.length === 0) return { decisions: [] };
      const linked = linkSignals(step.signal, lifetime.signal);
      const failure: RoundRecovery = {};
      try {
        const initialStop = stopReason(linked.signal, step.deadlineAt);
        if (initialStop) throw new Error(initialStop);

        let facts: ReviewerSessionFacts | undefined;
        try {
          facts = await Promise.resolve(deps.resolveSession(step));
        } catch {
          facts = undefined;
        }
        if (facts === undefined) throw new Error("session-context-unavailable");
        if (facts.mode !== "auto-review") return { decisions: [] };
        failure.owner = facts.view.owner;

        const afterResolve = stopReason(linked.signal, step.deadlineAt);
        if (afterResolve) throw new Error(afterResolve);

        const profile = captureProfile(deps.resolveProfile({
          owner: facts.view.owner,
          mode: facts.mode,
          view: facts.view,
        }));
        if (profile === undefined) throw new Error("reviewer-profile-unavailable");
        const model = captureModel(deps.resolveModel(profile), profile);
        if (model === undefined) throw new Error("judge-unavailable");

        let projectRules: LlmProjectRulesSnapshot | undefined;
        if (deps.resolveProjectRules !== undefined) {
          let resolved: LlmProjectRulesSnapshot | undefined;
          try {
            resolved = await awaitSignal(
              Promise.resolve(deps.resolveProjectRules({
                owner: facts.view.owner,
                mode: facts.mode,
                view: facts.view,
                revisions: facts.revisions,
                ...(linked.signal === undefined ? {} : { signal: linked.signal }),
              })),
              linked.signal,
            );
          } catch {
            throw new Error("project-rules-unavailable");
          }
          projectRules = captureProjectRules(resolved);
          if (projectRules === undefined) throw new Error("project-rules-invalid");
          if (
            projectRules.rulesRevision !== facts.revisions.projectRules ||
            projectRules.intentRevision !== facts.revisions.intent
          ) {
            throw new Error("stale-input");
          }
        }

        const fingerprint = compatibilityFingerprint(profile, projectRules);
        const consumer = `${LLM_APPROVER_NODE_ID}\u0000${fingerprint}`;

        return await runRound({
          step,
          signal: linked.signal,
          facts,
          calls,
          profile,
          model,
          projectRules,
          consumer,
          revision: step.state.revision,
        }, failure);
      } catch (error) {
        recoverFailure(failure);
        throw error;
      } finally {
        linked.dispose();
      }
    },

    dispose() {
      if (disposed) return;
      disposed = true;
      lifetime.abort();
      queue.dispose();
      conversations.clear();
    },
  };
}
