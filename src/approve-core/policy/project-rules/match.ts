/**
 * Exact action matches.
 *
 * The host builds the match from the current action; the model never supplies
 * tool, path or wildcard values. Matching compares only semantics: transport
 * fields such as request IDs and timestamps never participate.
 */
import {
  EXACT_ACTION_CONTRACT_VERSION,
  canonicalJson,
  sha256Hex,
  sortRuleScopes,
  type ExactAction,
  type ExactActionMatch,
  type RuleMatchResult,
  type RuleScope,
  type StoredProjectRule,
} from "./types";
import { scanStructuredArguments } from "./sensitive";

export interface BuildExactMatchOptions {
  /** Best-effort canonicalization of the working directory. */
  readonly canonicalizeCwd?: (cwd: string) => string;
}

function isJsonValue(value: unknown, seen: Set<object>): boolean {
  if (value === null) return true;
  switch (typeof value) {
    case "string":
    case "boolean":
      return true;
    case "number":
      return Number.isFinite(value);
    case "object": {
      if (seen.has(value)) return false;
      seen.add(value);
      const items = Array.isArray(value) ? value : Object.values(value as Record<string, unknown>);
      for (const item of items) if (!isJsonValue(item, seen)) return false;
      seen.delete(value);
      return true;
    }
    default:
      return false;
  }
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) && isJsonValue(value, new Set());
}

/**
 * Build the persisted match for the current action. Returns `undefined` when
 * the action cannot be learned: a hard deny, no ask scope, sensitive or
 * non-JSON arguments.
 */
export function buildExactMatch(
  action: ExactAction,
  options: BuildExactMatchOptions = {},
): ExactActionMatch | undefined {
  if (action.hardDeny === true) return undefined;
  if (action.scopes.length === 0) return undefined;
  if (!isJsonObject(action.arguments)) return undefined;
  if (!scanStructuredArguments(action.arguments).ok) return undefined;
  const requiredScopes: RuleScope[] = sortRuleScopes(action.scopes.map((scope) => ({
    surface: scope.surface,
    target: scope.target,
    access: scope.access,
  })));
  return {
    contractVersion: EXACT_ACTION_CONTRACT_VERSION,
    type: "exact_action",
    tool: action.tool,
    definitionDigest: action.definitionDigest,
    arguments: action.arguments,
    argumentsDigest: action.argumentsDigest,
    cwd: options.canonicalizeCwd === undefined ? action.cwd : options.canonicalizeCwd(action.cwd),
    environmentDigest: action.environmentDigest,
    requiredScopes,
  };
}

/** Digest over the persisted match semantics; the raw arguments are excluded. */
export function exactMatchDigest(match: ExactActionMatch): string {
  return sha256Hex(canonicalJson({
    contractVersion: match.contractVersion,
    type: match.type,
    tool: {
      name: match.tool.name,
      origin: match.tool.origin,
      definitionRevision: match.tool.definitionRevision,
    },
    definitionDigest: match.definitionDigest,
    argumentsDigest: match.argumentsDigest,
    cwd: match.cwd,
    environmentDigest: match.environmentDigest,
    requiredScopes: match.requiredScopes.map((scope) => [scope.surface, scope.target, scope.access]),
  }));
}

function scopeTriple(scope: { readonly surface: string; readonly target: string; readonly access: string }): string {
  return `${scope.surface}\0${scope.target}\0${scope.access}`;
}

/**
 * Compare one rule with the current action. Only active rules without a
 * revocation participate. A definition or environment change is reported
 * separately so the caller can mark the rule for review instead of reusing an
 * old allow.
 */
export function matchExactAction(rule: StoredProjectRule, action: ExactAction): RuleMatchResult {
  if (rule.status !== "active" || rule.revocation !== undefined) return { kind: "no-match" };
  const match = rule.match;
  if (match.contractVersion !== EXACT_ACTION_CONTRACT_VERSION || match.type !== "exact_action") return { kind: "no-match" };

  if (action.tool.name !== match.tool.name || action.tool.origin !== match.tool.origin ||
    action.tool.definitionRevision !== match.tool.definitionRevision) {
    return { kind: "no-match" };
  }
  if (action.definitionDigest !== match.definitionDigest) return { kind: "definition-changed" };
  if (action.environmentDigest !== match.environmentDigest) return { kind: "environment-changed" };
  if (action.cwd !== match.cwd) return { kind: "no-match" };
  if (action.argumentsDigest !== match.argumentsDigest) return { kind: "no-match" };
  // A rule whose saved arguments no longer hash to their stored digest is not
  // trustworthy even when the current action carries the same digest.
  if (sha256Hex(canonicalJson(match.arguments)) !== match.argumentsDigest) return { kind: "no-match" };
  if (action.hardDeny === true) return { kind: "no-match" };

  const required = match.requiredScopes.map(scopeTriple);
  for (const triple of required) {
    if (!action.scopes.some((scope) => scopeTriple(scope) === triple)) return { kind: "no-match" };
  }
  const coveredScopeIds: string[] = [];
  for (const scope of action.scopes) {
    if (required.includes(scopeTriple(scope)) && !coveredScopeIds.includes(scope.id)) coveredScopeIds.push(scope.id);
  }
  return { kind: "match", match, coveredScopeIds: Object.freeze(coveredScopeIds) };
}
