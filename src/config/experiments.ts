/**
 * Experiments dialog computation (specs/config-loading.md §10).
 *
 * Pure mapping from the checked experiments in the settings dialog to the next
 * approval-chain configuration, so the UI layer can stay thin and the policy
 * is testable without Pi UI.
 */
import type { ApprovalChainConfig } from "#config/schema";
import {
  DEFAULT_APPROVER_TIMEOUT_MS,
  DEFAULT_CLASSIFIER_ALLOW_THRESHOLD,
  DEFAULT_CLASSIFIER_CONTEXT_BUDGET_TOKENS,
  DEFAULT_CLASSIFIER_DENY_THRESHOLD,
} from "#config/approver-schema";

/** The experiments the settings dialog exposes as checkable items. */
export interface ExperimentSelection {
  /** Decision reviewer: on means the decision approver node, off the LLM approver. */
  readonly decision: boolean;
  readonly sandboxEnabled?: boolean;
  /** Per-mode approval default. `ask` is strict; `sandbox-run` is non-strict. */
  readonly strictApproval?: boolean;
  /** The active mode whose existing shell-policy default is being changed. */
  readonly mode?: ApprovalChainConfig["mode"];
}

/** A freshly chosen classifier judge (Pi classifier or self-owned endpoint). */
export type ExperimentJudge =
  | {
      readonly kind?: "pi-classifier";
      readonly provider: string;
      readonly model: string;
    }
  | {
      readonly kind: "custom";
      readonly baseUrl: string;
      readonly model: string;
      readonly apiKey?: string;
      readonly timeoutMs?: number;
      readonly contextBudgetTokens?: number;
      readonly allowThreshold?: number;
      readonly denyThreshold?: number;
    };

function isCustomJudge(judge: ExperimentJudge): judge is Extract<ExperimentJudge, { readonly kind: "custom" }> {
  return judge.kind === "custom" || "baseUrl" in judge;
}

/**
 * Compute the next configuration for the given selection.
 */
export function applyExperiments(
  current: ApprovalChainConfig,
  selection: ExperimentSelection,
  judge?: ExperimentJudge,
): ApprovalChainConfig {
  let nextJudge = current.approver.judge;
  if (judge !== undefined) {
    if (isCustomJudge(judge)) {
      nextJudge = {
        type: "custom" as const,
        baseUrl: judge.baseUrl,
        model: judge.model,
        ...(judge.apiKey === undefined ? {} : { apiKey: judge.apiKey }),
        timeoutMs: judge.timeoutMs ??
          (current.approver.judge?.type === "custom" ? current.approver.judge.timeoutMs : DEFAULT_APPROVER_TIMEOUT_MS),
        contextBudgetTokens: judge.contextBudgetTokens ??
          (current.approver.judge?.type === "custom" ? current.approver.judge.contextBudgetTokens : DEFAULT_CLASSIFIER_CONTEXT_BUDGET_TOKENS),
        allowThreshold: judge.allowThreshold ??
          (current.approver.judge?.type === "custom" ? current.approver.judge.allowThreshold : DEFAULT_CLASSIFIER_ALLOW_THRESHOLD),
        denyThreshold: judge.denyThreshold ??
          (current.approver.judge?.type === "custom" ? current.approver.judge.denyThreshold : DEFAULT_CLASSIFIER_DENY_THRESHOLD),
      };
    } else {
      const piJudge = judge as { readonly provider: string; readonly model: string };
      if (current.approver.judge?.type === "pi-classifier") {
        nextJudge = { ...current.approver.judge, provider: piJudge.provider, model: piJudge.model };
      } else {
        nextJudge = {
          type: "pi-classifier" as const,
          provider: piJudge.provider,
          model: piJudge.model,
          timeoutMs: DEFAULT_APPROVER_TIMEOUT_MS,
          contextBudgetTokens: DEFAULT_CLASSIFIER_CONTEXT_BUDGET_TOKENS,
          allowThreshold: DEFAULT_CLASSIFIER_ALLOW_THRESHOLD,
          denyThreshold: DEFAULT_CLASSIFIER_DENY_THRESHOLD,
        };
      }
    }
  }

  const mode = selection.mode ?? current.mode;
  const shellPolicy = selection.strictApproval === undefined ||
      (mode !== "default" && mode !== "auto-review")
    ? current.shellPolicy
    : {
        ...(current.shellPolicy ?? { version: 1 as const, rules: [] }),
        modes: {
          ...current.shellPolicy?.modes,
          [mode]: {
            ...current.shellPolicy?.modes?.[mode],
            defaultPolicy: selection.strictApproval ? "ask" as const : "sandbox-run" as const,
          },
        },
      };

  return {
    ...current,
    approver: {
      ...current.approver,
      judge: nextJudge,
    },
    experimental: {
      ...current.experimental,
      ...(selection.sandboxEnabled === undefined ? {} : { sandboxEnabled: selection.sandboxEnabled }),
    },
    ...(shellPolicy === undefined ? {} : { shellPolicy }),
    approval: {
      ...current.approval,
      nodes: {
        ...current.approval.nodes,
        "builtin/llm-approver": { enabled: !selection.decision },
        "builtin/decision-approver": { enabled: selection.decision },
      },
    },
  };
}
