/**
 * Scope composition for the policy evaluator.
 *
 * Scopes are folded from low to high priority: global, project, agent and
 * project-agent. Each scope is expanded on its own first, so a bare path family
 * becomes read and write surfaces before the merge. A scope whose config file
 * exists but failed to load is reported as invalid so the synthesis can clamp
 * inherited allows.
 */
import { expandScopePermission } from "./normalize";
import {
  emptyMergeState,
  mergeScopeGroups,
  type PermissionMergeState,
} from "./permission-merge";
import type { RuleOrigin } from "./rule";

export interface ScopePermissionInput {
  readonly permission?: unknown;
  /** The scope's config file existed but failed to load or validate. */
  readonly invalid?: boolean;
}

export const SCOPE_PRIORITY = Object.freeze([
  "global",
  "project",
  "agent",
  "project-agent",
] as const satisfies readonly RuleOrigin[]);

export type ConfigScopeOrigin = (typeof SCOPE_PRIORITY)[number];

export interface MergedScopePermissions extends PermissionMergeState {
  /** Invalid scopes in priority order, including global when reported. */
  readonly invalidScopes: readonly RuleOrigin[];
  /** Some scope exceeded the rule bound and was truncated. */
  readonly truncated: boolean;
}

export function mergeScopePermissions(
  scopes: Partial<Record<RuleOrigin, ScopePermissionInput>>,
): MergedScopePermissions {
  let state = emptyMergeState();
  const invalidScopes: RuleOrigin[] = [];
  let truncated = false;
  for (const origin of SCOPE_PRIORITY) {
    const scope = scopes[origin];
    if (scope === undefined) continue;
    if (scope.invalid === true) invalidScopes.push(origin);
    const expanded = expandScopePermission(scope.permission);
    if (expanded.truncated) truncated = true;
    state = mergeScopeGroups(state, expanded.groups, expanded.universal, origin);
  }
  return { ...state, invalidScopes, truncated };
}
