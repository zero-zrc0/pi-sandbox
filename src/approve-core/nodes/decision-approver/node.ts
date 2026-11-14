import {
  MAX_REASON_LENGTH,
  applyNodeResult,
  mapCallReview,
  type CallState,
  type NodeResult,
  type UnitReview,
} from "#approve-core/contracts";
import type { ClassifierContext, ClassifierResult } from "@earendil-works/pi-ai";
import type { ChainNode, NodeHost, StepContext } from "#approve-core/runtime";
import { pendingCalls } from "#approve-core/nodes/pending-calls";
import {
  decisionBudget,
  estimateJsonStringContentTokenQuarters,
  hasUnpairedToolResults,
  historySelectableEvidence,
  measureRequestTokens,
  measureRequestTokenQuarters,
  renderEvidence,
  selectBudgetedEvidence,
  selectBudgetedEvidenceByCost,
  type ApprovalEvidence,
  type ContextSelection,
  type ReviewerSessionFacts,
} from "#approve-core/context";
import { decisionClassifierIdentity } from "#approve-core/nodes/decision-approver/model";
import { classifyCustomJudge } from "#approve-core/nodes/decision-approver/custom";
import { prepareDecisionMaterial } from "#approve-core/nodes/decision-approver/material";
import type {
  DecisionApproverNodeDependencies,
  DecisionContextAcquisition,
  DecisionGuidanceSelection,
  DecisionNodeEvent,
} from "#approve-core/nodes/decision-approver/types";
import type { DecisionClassifierProfile } from "#approve-core/nodes/decision-approver/model";

export const DECISION_APPROVER_NODE_ID = "builtin/decision-approver";

export interface DecisionApproverNode extends ChainNode {
  dispose(): void;
}

interface DecisionOutcome {
  readonly verdict: "approve" | "deny" | "defer";
  readonly reason?: string;
  readonly deferReason?: "model-verdict" | "low-confidence";
}

type ClassifyResult =
  | { readonly kind: "result"; readonly result: ClassifierResult }
  | { readonly kind: "error"; readonly reason: string }
  | { readonly kind: "cancelled"; readonly reason: string };

const VERDICT_QUESTION: ClassifierContext["questions"][string] = {
  type: "choice",
  instructions:
    "Review the fixed askFor target in the permission facts. Approve only that target; do not change it. " +
    "Choose defer whenever evidence is incomplete, the action is ambiguous, or consequences are substantial.",
  criteria: {
    approve:
      "The fixed askFor target is clearly authorized under the rubric; every part of the complete call is safe.",
    deny:
      "The action clearly matches a never-allow item in the rubric, such as secret access, exfiltration, remote-code execution, force push, discarding work, or disabling safety controls.",
    defer:
      "The action is ambiguous, consequential, lacks enough evidence, or does not clearly qualify for allow or deny.",
  },
};

const GENERIC_DENY_REASON =
  "The decision model judged this action unsafe to run unattended. Explain the intent and ask the human, or take a safer route.";

function reasonFor(outcome: DecisionOutcome): string {
  const fallback = outcome.verdict === "approve"
    ? "decision-approve"
    : outcome.verdict === "deny"
      ? outcome.reason ?? "decision-deny"
      : "decision-ask";
  const reason = outcome.reason === undefined || outcome.reason.trim() === ""
    ? fallback
    : outcome.reason;
  if (reason.length > MAX_REASON_LENGTH) throw new Error("decision-invalid-reason");
  return reason;
}

function isLegalModelAsk(outcome: DecisionOutcome): boolean {
  return outcome.deferReason === "model-verdict" || outcome.deferReason === "low-confidence";
}

function outcomeFromClassifier(
  result: ClassifierResult,
  profile: DecisionClassifierProfile,
): DecisionOutcome {
  if (result.stopReason !== "stop") {
    throw new Error(result.stopReason === "aborted" ? "cancelled" : "classifier-call-failed");
  }
  const answer = result.answers?.verdict;
  if (typeof answer !== "object" || answer === null || Array.isArray(answer) ||
      answer.type !== "choice" || typeof answer.choice !== "string" ||
      typeof answer.confidence !== "number" || !Number.isFinite(answer.confidence) ||
      answer.confidence < 0 || answer.confidence > 1) {
    throw new Error("unrecognized-verdict");
  }
  if (answer.choice === "defer") {
    return { verdict: "defer", reason: "decision-ask", deferReason: "model-verdict" };
  }
  if (answer.choice !== "approve" && answer.choice !== "deny") {
    throw new Error("unrecognized-verdict");
  }
  const threshold = answer.choice === "deny"
    ? profile.denyConfidenceThreshold
    : profile.allowConfidenceThreshold;
  if (answer.confidence < threshold) {
    return { verdict: "defer", reason: "decision-ask", deferReason: "low-confidence" };
  }
  return {
    verdict: answer.choice,
    ...(answer.choice === "deny" ? { reason: GENERIC_DENY_REASON } : {}),
  };
}

/**
 * Build the Decision approval node. Every call that still has an ask at entry
 * gets one Pi classifier call, regardless of how many analysis units it
 * contains. The node maps the call-level answer onto units that are ask at
 * submission time.
 *
 * Context acquisition mirrors the LLM approver's cursor discipline by default
 * (`llm`): a committed read lets later evaluations read only appended
 * evidence, a fully accepted batch commits the cursor, and any failure
 * invalidates the consumer so the next evaluation rebuilds from Full. This
 * acquisition mode is experimental and may change; `decision` keeps the legacy
 * behavior of re-reading the full history for every request.
 */
export function createDecisionApproverNode(
  deps: DecisionApproverNodeDependencies,
): DecisionApproverNode {
  const now = deps.now ?? Date.now;
  const rubric = deps.rubric ?? "";
  const packingContractVersion = deps.packingContractVersion ?? 2;
  const acquisition: DecisionContextAcquisition =
    deps.contextAcquisition === "decision" ? "decision" : "llm";
  const activeClassifications = new Set<AbortController>();
  const lifetime = new AbortController();
  let disposed = false;

  function event(value: DecisionNodeEvent): void {
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

  function verifyFacts(facts: ReviewerSessionFacts, calls: readonly CallState[]): void {
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

  function guidanceFor(owner: string): DecisionGuidanceSelection {
    try {
      return deps.resolveGuidance?.(owner) ?? { included: [] };
    } catch {
      throw new Error("guidance-load-failed");
    }
  }

  function contextFor(input: {
    readonly selection: ContextSelection;
    readonly call: CallState;
    readonly mode: ReviewerSessionFacts["mode"];
    readonly profile: DecisionClassifierProfile;
    readonly guidance: DecisionGuidanceSelection;
  }): ClassifierContext {
    const budget = decisionBudget(input.profile.contextBudgetTokens);
    const build = (historyEvidence: readonly ApprovalEvidence[], historyOmitted: boolean): ClassifierContext => {
      const material = prepareDecisionMaterial({
        selection: input.selection,
        call: input.call,
        mode: input.mode,
        guidance: input.guidance,
        historyEvidence,
        historyOmitted,
        packingContractVersion,
      });
      const context: ClassifierContext = {
        state: { rubric, permissionReview: material },
        questions: { verdict: VERDICT_QUESTION },
      };
      return context;
    };
    const evidence = historySelectableEvidence(input.selection.evidence);
    const fullContext = build(evidence, false);
    if (measureRequestTokens(fullContext) <= budget.max) return fullContext;

    const baseQuarterTokens = {
      all: measureRequestTokenQuarters(build([], false)),
      omitted: measureRequestTokenQuarters(build([], true)),
    };
    const entryQuarterTokens = evidence.map((item) =>
      estimateJsonStringContentTokenQuarters(renderEvidence([item])),
    );
    const incremental = selectBudgetedEvidenceByCost(evidence, {
      limitQuarterTokens: budget.max * 4,
      baseQuarterTokens,
      entryQuarterTokens,
      separatorQuarterTokens: estimateJsonStringContentTokenQuarters("\n"),
      emptyPlaceholderQuarterTokens: estimateJsonStringContentTokenQuarters("(none)"),
    });
    if (incremental !== undefined) {
      const context = build(incremental.evidence, incremental.omitted);
      if (measureRequestTokens(context) <= budget.max) return context;
    }

    const exact = selectBudgetedEvidence(
      evidence,
      (candidate, omitted) => measureRequestTokens(build(candidate, omitted)) <= budget.max,
    );
    if (exact === undefined) throw new Error("decision-protected-context-too-large");
    const context = build(exact.evidence, exact.omitted);
    if (measureRequestTokens(context) > budget.max) throw new Error("decision-protected-context-too-large");
    return context;
  }

  async function classifyOnce(
    profile: DecisionClassifierProfile,
    context: ClassifierContext,
    signal: AbortSignal,
    deadline: number | null,
    owner: string,
  ): Promise<ClassifyResult> {
    const stop = stopReason(signal, deadline);
    if (stop) return { kind: "cancelled", reason: stop };

    const timeoutLimit = Math.max(
      1,
      Math.min(
        profile.timeoutMs,
        deadline === null ? Number.POSITIVE_INFINITY : Math.max(1, deadline - now()),
      ),
    );
    const controller = new AbortController();
    activeClassifications.add(controller);
    const onAbort = (): void => controller.abort();
    signal.addEventListener("abort", onAbort, { once: true });
    let timer: ReturnType<typeof setTimeout> | undefined;
    let timedOut = false;
    const timeout = new Promise<"timeout">((resolve) => {
      timer = setTimeout(() => {
        timedOut = true;
        controller.abort();
        resolve("timeout");
      }, timeoutLimit);
    });

    try {
      event({
        kind: "decision",
        nodeId: DECISION_APPROVER_NODE_ID,
        owner,
        requests: 1,
        outcome: "sent",
      });
      const classifyPromise = profile.kind === "custom"
        ? classifyCustomJudge(profile, context, {
            signal: controller.signal,
            timeoutMs: timeoutLimit,
            ...(deps.fetch === undefined ? {} : { fetch: deps.fetch }),
          })
        : deps.classify(profile.model, context, {
            signal: controller.signal,
            timeoutMs: timeoutLimit,
            ...(deps.fetch === undefined ? {} : { fetch: deps.fetch }),
          });
      const call = Promise.resolve().then(() => classifyPromise).then<ClassifyResult, ClassifyResult>(
        (result) => ({ kind: "result", result }),
        () => ({ kind: "error", reason: "classifier-call-failed" }),
      );
      const raced = await Promise.race([call, timeout]);
      if (raced === "timeout") {
        return signal.aborted
          ? { kind: "cancelled", reason: "cancelled" }
          : { kind: "error", reason: "timeout" };
      }
      if (raced.kind === "result" && raced.result.stopReason === "aborted") {
        return signal.aborted || disposed
          ? { kind: "cancelled", reason: stopReason(signal, deadline) ?? "cancelled" }
          : timedOut
            ? { kind: "error", reason: "timeout" }
            : { kind: "cancelled", reason: "cancelled" };
      }
      return raced;
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      signal.removeEventListener("abort", onAbort);
      controller.abort();
      activeClassifications.delete(controller);
    }
  }

  return {
    apiVersion: "1",
    id: DECISION_APPROVER_NODE_ID,

    async evaluate(step: StepContext, _host: NodeHost): Promise<NodeResult> {
      const calls = pendingCalls(step.state);
      if (calls.length === 0) return { decisions: [] };
      let requests = 0;
      const failure: { owner?: string; consumer?: string } = {};
      try {
        const initialStop = stopReason(step.signal, step.deadlineAt);
        if (initialStop) throw new Error(initialStop);

        let facts: ReviewerSessionFacts | undefined;
        try {
          facts = await Promise.resolve(deps.resolveSession(step));
        } catch {
          facts = undefined;
        }
        if (facts === undefined) throw new Error("session-context-unavailable");
        if (facts.mode !== "auto-review") return { decisions: [] };
        const afterResolve = stopReason(step.signal, step.deadlineAt);
        if (afterResolve) throw new Error(afterResolve);

        const profile = deps.resolveProfile(facts.view.owner);
        if (profile === undefined) throw new Error("classifier-unavailable");
        const guidance = guidanceFor(facts.view.owner);
        const consumer = `${DECISION_APPROVER_NODE_ID}\u0000${acquisition}\u0000${decisionClassifierIdentity(profile)}`;
        failure.owner = facts.view.owner;
        failure.consumer = consumer;
        const begun = deps.context.begin({
          facts,
          consumer,
          ...(acquisition === "decision" ? { forceFull: true } : {}),
          signal: step.signal,
          ...(step.deadlineAt === null ? {} : { deadline: step.deadlineAt }),
        });
        if (!begun.ok) throw new Error(`context-${begun.reason}`);
        let selection = begun.selection;
        // A delta boundary that cuts a tool call from its result cannot prove
        // the pairing inside a self-contained request; rebuild from Full.
        if (
          acquisition === "llm" &&
          selection.mode === "delta" &&
          hasUnpairedToolResults(selection.evidence)
        ) {
          const forced = deps.context.begin({
            facts,
            consumer,
            forceFull: true,
            signal: step.signal,
            ...(step.deadlineAt === null ? {} : { deadline: step.deadlineAt }),
          });
          if (!forced.ok) throw new Error(`context-${forced.reason}`);
          selection = forced.selection;
        }

        const node = { id: step.node.id, priority: step.node.priority };
        const reviews: UnitReview[] = [];
        for (const call of calls) {
          const stop = stopReason(step.signal, step.deadlineAt);
          if (stop) throw new Error(stop);
          verifyFacts(facts, calls);
          const classifierContext = contextFor({
            selection,
            call,
            mode: facts.mode,
            profile,
            guidance,
          });
          const response = await classifyOnce(
            profile,
            classifierContext,
            step.signal,
            step.deadlineAt,
            facts.view.owner,
          );
          requests += 1;
          if (response.kind === "cancelled") throw new Error(response.reason);
          if (response.kind === "error") throw new Error(response.reason);

          const outcome = outcomeFromClassifier(response.result, profile);
          let decision: "approve" | "deny" | "defer";
          if (outcome.verdict === "approve" || outcome.verdict === "deny") {
            decision = outcome.verdict;
          } else if (isLegalModelAsk(outcome)) {
            decision = "defer";
          } else {
            throw new Error(outcome.deferReason ?? "unrecognized-verdict");
          }
          verifyFacts(facts, calls);
          const mapped = mapCallReview(step.state, node, {
            toolCallId: call.toolCallId,
            decision,
            reason: reasonFor(outcome),
          });
          if (!mapped.ok) throw new Error(mapped.reason);
          reviews.push(...(mapped.submission.result.reviews ?? []));
        }

        const result: NodeResult = { decisions: [], reviews };
        const preflight = applyNodeResult(step.state, {
          node,
          evaluatedRevision: step.state.revision,
          result,
        });
        if (!preflight.ok) throw new Error(preflight.reason);
        // The cursor only advances after the whole batch was accepted; a
        // commit failure leaves the evaluation a whole-node fault with the
        // cursor untouched.
        if (acquisition === "llm") {
          const committed = deps.context.commit(selection, {
            signal: step.signal,
            ...(step.deadlineAt === null ? {} : { deadline: step.deadlineAt }),
          });
          if (!committed.ok) throw new Error(`context-${committed.reason}`);
        }
        return result;
      } catch (error) {
        if (
          acquisition === "llm" &&
          (failure.owner !== undefined || failure.consumer !== undefined)
        ) {
          deps.context.invalidate({
            ...(failure.owner === undefined ? {} : { owner: failure.owner }),
            ...(failure.consumer === undefined ? {} : { consumer: failure.consumer }),
          });
        }
        event({
          kind: "decision",
          nodeId: DECISION_APPROVER_NODE_ID,
          owner: "unknown",
          requests,
          outcome: "failed",
        });
        throw error;
      }
    },

    dispose() {
      if (disposed) return;
      disposed = true;
      lifetime.abort();
      for (const controller of activeClassifications) controller.abort();
      activeClassifications.clear();
    },
  };
}
