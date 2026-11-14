/**
 * Rule synthesis for one policy view.
 *
 * Rules compose in the order default → MCP baseline → config; session rules
 * are appended by the caller at check time. An invalid non-global scope lowers
 * every inherited allow to ask, because a broken higher-scope file may have
 * been meant to restrict permissions. Yolo is a separate rewrite of one
 * combined view and never changes a deny.
 */
import { mergeScopePermissions, type ScopePermissionInput } from "./scope-merge";
import type { Rule, RuleAction, RuleOrigin } from "./rule";

/** Metadata surfaces unlocked by an explicit MCP allow. */
export const MCP_BASELINE_SURFACES = Object.freeze([
  "mcp_status",
  "mcp_list",
  "mcp_search",
  "mcp_describe",
  "mcp_connect",
] as const);

const MCP_BASELINE_RULES: readonly Rule[] = Object.freeze(
  MCP_BASELINE_SURFACES.map((surface) => Object.freeze({
    surface,
    pattern: "*",
    action: "allow" as const,
    origin: "baseline" as const,
    layer: "baseline" as const,
  })),
);

export interface PolicySynthesisInput {
  readonly scopes: Partial<Record<RuleOrigin, ScopePermissionInput>>;
  /** Used when no scope provides a universal default; defaults to ask. */
  readonly defaultAction?: RuleAction;
}

export interface SynthesizedPolicy {
  readonly rules: readonly Rule[];
  /** The no-match rule for every surface. */
  readonly defaultRule: Rule;
  readonly invalidScopes: readonly RuleOrigin[];
  readonly truncated: boolean;
}

/** The MCP metadata defaults, present only when an explicit `mcp` allow exists. */
export function mcpBaselineRules(): readonly Rule[] {
  return MCP_BASELINE_RULES;
}

export function synthesizePolicy(input: PolicySynthesisInput): SynthesizedPolicy {
  const merged = mergeScopePermissions(input.scopes);

  const hasMcpAllow = (merged.surfaces.get("mcp")?.entries ?? []).some(
    (entry) => entry.action === "allow" && entry.synthetic !== true,
  );

  const rules: Rule[] = [...(hasMcpAllow ? MCP_BASELINE_RULES : [])];
  for (const [surface, state] of merged.surfaces) {
    for (const entry of state.entries) {
      rules.push({
        surface,
        pattern: entry.pattern,
        action: entry.action,
        origin: state.origins.get(entry.pattern) ?? "global",
        layer: "config",
        ...(entry.reason === undefined ? {} : { reason: entry.reason }),
      });
    }
  }

  const universal = merged.universal;
  const defaultRule: Rule = universal === undefined
    ? Object.freeze({
        surface: "*",
        pattern: "*",
        action: input.defaultAction ?? "ask",
        origin: "builtin",
        layer: "default",
      })
    : Object.freeze({
        surface: "*",
        pattern: "*",
        action: universal.action,
        origin: universal.origin,
        layer: "default",
        ...(universal.reason === undefined ? {} : { reason: universal.reason }),
      });

  const clamped = clampInheritedAllows(rules, defaultRule, merged.invalidScopes);
  return {
    rules: Object.freeze(clamped.rules),
    defaultRule: clamped.defaultRule,
    invalidScopes: merged.invalidScopes,
    truncated: merged.truncated,
  };
}

export interface RewrittenView {
  readonly rules: readonly Rule[];
  readonly defaultRule: Rule;
}

/**
 * Lower every allow to ask when a non-global scope failed to load. A global
 * failure does not clamp anything: there is no lower scope for it to relax.
 */
export function clampInheritedAllows(
  rules: readonly Rule[],
  defaultRule: Rule,
  invalidScopes: readonly RuleOrigin[],
): RewrittenView {
  const failing = invalidScopes.filter((origin) => origin !== "global");
  if (failing.length === 0) return { rules, defaultRule };
  const rewrite = (rule: Rule): Rule => rule.action === "allow"
    ? { surface: rule.surface, pattern: rule.pattern, action: "ask", origin: "fail-closed", layer: rule.layer }
    : rule;
  return {
    rules: rules.map(rewrite),
    defaultRule: rewrite(defaultRule),
  };
}

/** Rewrite every ask to allow for one combined check view; deny is untouched. */
export function applyYoloRewrite(
  rules: readonly Rule[],
  defaultRule: Rule,
): RewrittenView {
  const rewrite = (rule: Rule): Rule => rule.action === "ask"
    ? {
        surface: rule.surface,
        pattern: rule.pattern,
        action: "allow",
        origin: "yolo",
        layer: rule.layer,
      }
    : rule;
  return {
    rules: rules.map(rewrite),
    defaultRule: rewrite(defaultRule),
  };
}
