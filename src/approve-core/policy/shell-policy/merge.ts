import type { ShellAnalysisLimits, ShellModePolicies, ShellPolicy } from "#config/shell-policy-schema";

export interface ShellPolicyMergeIssue {
  readonly code: "duplicate-project-rule" | "project-readonly-exception";
  readonly detail: string;
}

export interface ShellPolicyMergeResult {
  readonly policy?: ShellPolicy;
  readonly issues: readonly ShellPolicyMergeIssue[];
}

type Decision = "allow" | "ask" | "deny";

const DECISION_RANK: Readonly<Record<Decision, number>> = {
  allow: 0,
  ask: 1,
  deny: 2,
};

function restrictiveDecision<T extends Decision>(globalValue: T | undefined, projectValue: T | undefined): T | undefined {
  if (globalValue === undefined) return projectValue;
  if (projectValue === undefined) return globalValue;
  return DECISION_RANK[globalValue] >= DECISION_RANK[projectValue] ? globalValue : projectValue;
}

function minimum(value: number | undefined, projectValue: number | undefined): number | undefined {
  if (value === undefined) return projectValue;
  if (projectValue === undefined) return value;
  return Math.min(value, projectValue);
}

function mergeAnalysis(
  globalValue: ShellAnalysisLimits | undefined,
  projectValue: ShellAnalysisLimits | undefined,
): ShellAnalysisLimits | undefined {
  if (globalValue === undefined) return projectValue;
  if (projectValue === undefined) return globalValue;
  const analysis: ShellAnalysisLimits = {
    timeoutMs: minimum(globalValue.timeoutMs, projectValue.timeoutMs),
    maxInputBytes: minimum(globalValue.maxInputBytes, projectValue.maxInputBytes),
    maxOutputBytes: minimum(globalValue.maxOutputBytes, projectValue.maxOutputBytes),
    maxAstNodes: minimum(globalValue.maxAstNodes, projectValue.maxAstNodes),
    maxDepth: minimum(globalValue.maxDepth, projectValue.maxDepth),
  };
  return Object.values(analysis).some((value) => value !== undefined) ? analysis : undefined;
}

function mergeReadOnlyMode(
  globalValue: NonNullable<ShellModePolicies["read-only"]> | undefined,
  projectValue: NonNullable<ShellModePolicies["read-only"]> | undefined,
): NonNullable<ShellModePolicies["read-only"]> | undefined {
  if (globalValue === undefined) return projectValue === undefined ? undefined : {
    ...(projectValue.unmatched === undefined ? {} : { unmatched: projectValue.unmatched }),
    ...(projectValue.uncertain === undefined ? {} : { uncertain: projectValue.uncertain }),
    ...(projectValue.forbidEffects === undefined ? {} : { forbidEffects: projectValue.forbidEffects }),
  };
  if (projectValue === undefined) return globalValue;
  const unmatched = restrictiveDecision(globalValue.unmatched, projectValue.unmatched);
  const uncertain = restrictiveDecision(globalValue.uncertain, projectValue.uncertain);
  const forbidEffects = [...new Set([...(globalValue.forbidEffects ?? []), ...(projectValue.forbidEffects ?? [])])];
  return {
    ...(unmatched === undefined ? {} : { unmatched }),
    ...(uncertain === undefined ? {} : { uncertain }),
    ...(forbidEffects.length === 0 ? {} : { forbidEffects }),
    ...(globalValue.exceptions === undefined ? {} : { exceptions: globalValue.exceptions }),
  };
}

function mergeReviewMode(
  globalValue: NonNullable<ShellModePolicies["default"]> | undefined,
  projectValue: NonNullable<ShellModePolicies["default"]> | undefined,
): NonNullable<ShellModePolicies["default"]> | undefined {
  if (globalValue === undefined) {
    // A project configuration can require strict approval, never disable it.
    if (projectValue === undefined) return undefined;
    return {
      ...(projectValue.unmatched === undefined ? {} : { unmatched: projectValue.unmatched }),
      ...(projectValue.uncertain === undefined ? {} : { uncertain: projectValue.uncertain }),
      ...(projectValue.defaultPolicy === "ask" ? { defaultPolicy: "ask" as const } : {}),
    };
  }
  if (projectValue === undefined) return globalValue;
  const unmatched = restrictiveDecision(globalValue.unmatched, projectValue.unmatched);
  const uncertain = restrictiveDecision(globalValue.uncertain, projectValue.uncertain);
  // Strict approval is restrictive, so a project may only change this to `ask`.
  const defaultPolicy = projectValue.defaultPolicy === "ask"
    ? "ask" as const
    : globalValue.defaultPolicy;
  return {
    ...(unmatched === undefined ? {} : { unmatched }),
    ...(uncertain === undefined ? {} : { uncertain }),
    ...(defaultPolicy === undefined ? {} : { defaultPolicy }),
  };
}

function mergeFullAccessMode(
  globalValue: NonNullable<ShellModePolicies["full-access"]> | undefined,
  projectValue: NonNullable<ShellModePolicies["full-access"]> | undefined,
): NonNullable<ShellModePolicies["full-access"]> | undefined {
  if (globalValue === undefined) return projectValue;
  if (projectValue === undefined) return globalValue;
  const unmatched = restrictiveDecision(globalValue.unmatched, projectValue.unmatched);
  const uncertain = restrictiveDecision(globalValue.uncertain, projectValue.uncertain);
  return {
    ...(unmatched === undefined ? {} : { unmatched }),
    ...(uncertain === undefined ? {} : { uncertain }),
  };
}

function mergeModes(
  globalValue: ShellModePolicies | undefined,
  projectValue: ShellModePolicies | undefined,
): ShellModePolicies | undefined {
  if (globalValue === undefined) {
    if (projectValue === undefined) return undefined;
    const readOnly = projectValue["read-only"];
    // A project configuration can require strict approval, never disable it.
    const reviewMode = (
      value: NonNullable<ShellModePolicies["default"]> | undefined,
    ): NonNullable<ShellModePolicies["default"]> | undefined => value === undefined
      ? undefined
      : {
        ...(value.unmatched === undefined ? {} : { unmatched: value.unmatched }),
        ...(value.uncertain === undefined ? {} : { uncertain: value.uncertain }),
        ...(value.defaultPolicy === "ask" ? { defaultPolicy: "ask" as const } : {}),
      };
    const defaultMode = reviewMode(projectValue.default);
    const autoReview = reviewMode(projectValue["auto-review"]);
    return {
      ...(readOnly === undefined ? {} : {
        "read-only": {
          ...(readOnly.unmatched === undefined ? {} : { unmatched: readOnly.unmatched }),
          ...(readOnly.uncertain === undefined ? {} : { uncertain: readOnly.uncertain }),
          ...(readOnly.forbidEffects === undefined ? {} : { forbidEffects: readOnly.forbidEffects }),
        },
      }),
      ...(defaultMode === undefined ? {} : { default: defaultMode }),
      ...(autoReview === undefined ? {} : { "auto-review": autoReview }),
      ...(projectValue["full-access"] === undefined
        ? {}
        : { "full-access": projectValue["full-access"] }),
    };
  }
  if (projectValue === undefined) return globalValue;
  const readOnly = mergeReadOnlyMode(globalValue["read-only"], projectValue["read-only"]);
  const defaultMode = mergeReviewMode(globalValue.default, projectValue.default);
  const autoReview = mergeReviewMode(globalValue["auto-review"], projectValue["auto-review"]);
  const fullAccess = mergeFullAccessMode(globalValue["full-access"], projectValue["full-access"]);
  return {
    ...(readOnly === undefined ? {} : { "read-only": readOnly }),
    ...(defaultMode === undefined ? {} : { default: defaultMode }),
    ...(autoReview === undefined ? {} : { "auto-review": autoReview }),
    ...(fullAccess === undefined ? {} : { "full-access": fullAccess }),
  };
}

function policyModeHasProjectException(modes: ShellModePolicies | undefined): boolean {
  return (modes?.["read-only"]?.exceptions?.length ?? 0) > 0;
}

export function mergeShellPolicies(
  globalPolicy: ShellPolicy | undefined,
  projectPolicy: ShellPolicy | undefined,
): ShellPolicyMergeResult {
  if (globalPolicy === undefined && projectPolicy === undefined) return { issues: [] };

  const globalRules = globalPolicy?.rules ?? [];
  const ruleIds = new Set(globalRules.map((rule) => rule.id));
  const issues: ShellPolicyMergeIssue[] = [];
  if (policyModeHasProjectException(projectPolicy?.modes)) {
    issues.push({
      code: "project-readonly-exception",
      detail: "Project shell policy cannot declare read-only mode exceptions.",
    });
  }
  const projectRules = (projectPolicy?.rules ?? []).filter((rule) => {
    if (!ruleIds.has(rule.id)) {
      ruleIds.add(rule.id);
      return true;
    }
    issues.push({
      code: "duplicate-project-rule",
      detail: `Project shell policy rule id "${rule.id}" conflicts with a global rule and was ignored.`,
    });
    return false;
  });

  const modes = mergeModes(globalPolicy?.modes, projectPolicy?.modes);
  const anyMode = Object.values(modes ?? {}).some((mode) => mode !== undefined);
  const analysis = mergeAnalysis(globalPolicy?.analysis, projectPolicy?.analysis);
  const policy: ShellPolicy = {
    version: 1,
    ...(analysis === undefined ? {} : { analysis }),
    ...(anyMode && modes !== undefined ? { modes } : {}),
    rules: [...globalRules, ...projectRules],
  };
  return { policy, issues };
}
