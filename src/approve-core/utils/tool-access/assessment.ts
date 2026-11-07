/**
 * Controlled-execution assessment over file access facts
 * (specs/tool-access.md §8).
 *
 * The assessment adds only what the host did not already resolve: one ask per
 * fact access that no scope represents, and one tool-level unknown-effects ask
 * for incomplete facts. It never invents a target, never turns incomplete
 * facts into an allow and never executes anything. `run` is reserved for
 * verified facts with no ask/deny whose executor capability proves the grant.
 */
import type { ToolAccessAccess, ToolAccessFactsResult } from "./access-facts";

export type ToolAccessScopeAccess = ToolAccessAccess | "network" | "other";
export type ToolAccessScopeState = "allow" | "ask" | "deny";

/** One host-resolved scope, or one ask this module had to add. */
export interface ToolAccessScope {
  readonly id: string;
  readonly surface: string;
  readonly target: string;
  readonly access: ToolAccessScopeAccess;
  readonly state: ToolAccessScopeState;
  readonly source?: string;
}

/** The host's proof that a controlled executor may run the granted scopes. */
export interface ToolExecutorCapability {
  readonly available: boolean;
  /** True only when the executor can enforce every granted scope. */
  readonly enforcesAllScopes: boolean;
  /** True only when every target is checked before the tool starts. */
  readonly checksAllTargetsBeforeStart: boolean;
  /** Host-owned name of the boundary actually enforced; may not be empty. */
  readonly boundary: string;
  readonly actionDigest?: string;
  readonly reason?: string;
}

export type ToolAccessExecution = "controlled" | "unavailable";

export interface ToolAccessAssessmentInput {
  readonly facts: ToolAccessFactsResult;
  readonly scopes: readonly ToolAccessScope[];
  readonly executor?: ToolExecutorCapability;
}

export interface ToolAccessAssessment {
  readonly route: "run" | "review" | "block" | "defer";
  readonly reason: string;
  /** Every scope after the missing-scope/unknown-effects asks were added. */
  readonly scopes: readonly ToolAccessScope[];
  readonly missingScopes?: readonly ToolAccessScope[];
  readonly execution: ToolAccessExecution;
  /** This module never builds reviewer context or sends model requests. */
  readonly modelRequests: 0;
}

const FACTS_STATUSES = new Set(["verified", "incomplete", "unbound"]);
const EXECUTOR_KEYS = ["available", "enforcesAllScopes", "checksAllTargetsBeforeStart", "boundary", "actionDigest", "reason"] as const;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(record: Record<string, unknown>, allowed: readonly string[]): boolean {
  return Object.keys(record).every((key) => allowed.includes(key));
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function hasFactsShape(value: unknown): value is ToolAccessFactsResult {
  if (!isObject(value)) return false;
  if (typeof value.status !== "string" || !FACTS_STATUSES.has(value.status)) return false;
  if (typeof value.complete !== "boolean") return false;
  if (!Array.isArray(value.accesses) || !Array.isArray(value.unknownEffects)) return false;
  return true;
}

function result(
  route: ToolAccessAssessment["route"],
  reason: string,
  execution: ToolAccessExecution,
  scopes: readonly ToolAccessScope[],
  missingScopes: readonly ToolAccessScope[] = [],
): ToolAccessAssessment {
  return {
    route,
    reason,
    execution,
    scopes,
    ...(missingScopes.length === 0 ? {} : { missingScopes }),
    modelRequests: 0,
  };
}

function scopeCoversAccess(scope: ToolAccessScope, access: { path: string; access: ToolAccessAccess }): boolean {
  return scope.target === access.path && scope.access === access.access;
}

/** Missing-scope asks: only targets the facts already prove, never new ones. */
function addMissingScopes(
  facts: ToolAccessFactsResult,
  scopes: ToolAccessScope[],
): ToolAccessScope[] {
  const added: ToolAccessScope[] = [];
  for (const [index, access] of facts.accesses.entries()) {
    if (scopes.some((scope) => scopeCoversAccess(scope, access))) continue;
    const scope: ToolAccessScope = {
      id: `missing-scope:${index}`,
      surface: `path_${access.access}`,
      target: access.path,
      access: access.access,
      state: "ask",
      source: "missing-scope",
    };
    scopes.push(scope);
    added.push(scope);
  }
  return added;
}

function executorGap(executor: ToolExecutorCapability | undefined): string | undefined {
  if (!isObject(executor) || !hasOnlyKeys(executor, EXECUTOR_KEYS)) return "executor-unavailable";
  if (executor.available !== true) return nonEmptyString(executor.reason) ? executor.reason : "executor-unavailable";
  if (executor.enforcesAllScopes !== true) {
    return nonEmptyString(executor.reason) ? executor.reason : "executor-scope-unavailable";
  }
  if (executor.checksAllTargetsBeforeStart !== true) {
    return nonEmptyString(executor.reason) ? executor.reason : "executor-target-unchecked";
  }
  if (typeof executor.boundary !== "string" || executor.boundary.trim().length === 0) {
    return nonEmptyString(executor.reason) ? executor.reason : "executor-boundary-unavailable";
  }
  return undefined;
}

/**
 * Assess one call. Route order follows the spec: deny, unbound, review (any
 * unverified fact or remaining ask), then the executor gate that alone may
 * produce `run`/`controlled`.
 */
export function assessToolAccessFacts(input: ToolAccessAssessmentInput): ToolAccessAssessment {
  const hostScopes: readonly ToolAccessScope[] = Array.isArray(input?.scopes) ? input.scopes : [];
  const scopes: ToolAccessScope[] = [...hostScopes];
  const facts = input?.facts;
  if (!hasFactsShape(facts)) {
    return result("defer", "incomplete-facts", "unavailable", scopes);
  }

  const missingScopes = addMissingScopes(facts, scopes);
  // Verified facts must also carry a complete, effect-free report; anything
  // else is treated as incomplete instead of trusting the status label.
  const unverified = facts.status !== "verified" || facts.complete !== true || facts.unknownEffects.length > 0;
  const unbound = facts.status === "unbound";

  if (unverified && !unbound) {
    if (!isObject(facts.tool) || !nonEmptyString(facts.tool.name)) {
      return result("defer", "tool-identity-unavailable", "unavailable", scopes, missingScopes);
    }
    scopes.push({
      id: "unknown-effects",
      surface: "tool",
      target: facts.tool.name,
      access: "other",
      state: "ask",
      source: "unknown-effects",
    });
  }

  if (scopes.some((scope) => scope.state === "deny")) {
    return result("block", "explicit-deny", "unavailable", scopes, missingScopes);
  }
  if (unbound) {
    return result("defer", "tool-unbound", "unavailable", scopes, missingScopes);
  }

  const hasAsk = scopes.some((scope) => scope.state === "ask");
  if (unverified || hasAsk) {
    const reason = missingScopes.length > 0 ? "missing-scopes" : unverified ? "unknown-effects" : "scope-review";
    return result("review", reason, "unavailable", scopes, missingScopes);
  }

  // Verified, no ask and no deny: only now may the executor decide run/defer.
  const gap = executorGap(input.executor);
  if (gap !== undefined) return result("defer", gap, "unavailable", scopes);
  return result("run", "controlled-execution", "controlled", scopes);
}
