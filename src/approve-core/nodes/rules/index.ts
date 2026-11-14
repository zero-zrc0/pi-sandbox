import {
  pathMatchOptions,
  type Rule,
  type RuleAction,
  type RuleEvaluator,
  type RuleMatch,
  type RuleOrigin,
} from "#approve-core/policy/rule";
import { wildcardMatch } from "#approve-core/policy/wildcard-matcher";
import { classifyToolKind } from "#approve-core/utils/access-intent/tool-kind";
import { normalizeToolTargets } from "#approve-core/utils/access-intent/input-normalizer";
import { pathFlavorForPlatform, type PathFlavor } from "#approve-core/utils/path/path-flavor";
import { MAX_REASON_LENGTH, type CallState } from "#approve-core/contracts";
import type { StepContext } from "#approve-core/runtime";
import {
  fragmentsForCall,
  type StructureAnalysisOptions,
} from "#approve-core/nodes/analysis";

/**
 * Explicit-rule node.
 *
 * Rules keep the engine's existing last-match-wins merge semantics: the host
 * hands this node the already-effective global/project/session ruleset, and
 * this node only turns matching explicit rules into unit decisions. Builtin
 * default asks are not a rule decision and are ignored; no rule means no
 * opinion.
 *
 * File allowlists are judged here, not by the chain: every path fact of a unit
 * must be covered before the allowlist can allow that unit. A deny still
 * absorbs, and a later explicit ask still beats the allowlist.
 */

export const RULE_ACTION_RANK = { allow: 0, ask: 1, deny: 2 } as const;

export interface RuleFact {
  readonly surface: string;
  readonly value: string;
  readonly values?: readonly string[];
}

export interface RuleUnitFacts {
  /** A concrete unit id, or "*" for a whole-call fact set. */
  readonly unitId: string;
  readonly facts: readonly RuleFact[];
  /** A shell whole-call fallback whose parse was incomplete. */
  readonly incomplete?: boolean;
}

export type RulesFactsResolver = (
  call: CallState,
  context: StepContext,
) => readonly RuleUnitFacts[] | Promise<readonly RuleUnitFacts[]>;

export interface RulesNodeOptions extends StructureAnalysisOptions {
  readonly rules: readonly Rule[];
  readonly mcpTargets?: (call: CallState) => readonly string[];
  /**
   * A pre-built evaluator over {@link rules} — the internal dep the host uses
   * to hand this node the same evaluation object another rules consumer
   * already holds. When omitted the node builds one over
   * {@link rules} at construction, so every fact and unit it judges within
   * the node's lifetime reuses the same compiled matchers.
   */
  readonly evaluator?: RuleEvaluator;
  /** Platform used for path-pattern folds; defaults to process.platform. */
  readonly flavor?: PathFlavor;
  /** Simple file whitelist evaluated inside this node. */
  readonly fileAllowlist?: readonly string[];
  /** Host/test seam replacing the default fact extraction. */
  readonly resolveFacts?: RulesFactsResolver;
}

/**
 * The winning explicit-rule opinion of one fact set. Exported for the chain's
 * facts projection (`chain/facts/rules.ts`), which reuses this node's decision
 * and only keeps the rule identity beside it.
 */
export interface RuleHit {
  readonly decision: "allow" | "ask" | "deny";
  readonly reason: string;
}

function clip(text: string): string {
  return text.length <= MAX_REASON_LENGTH
    ? text
    : `${text.slice(0, MAX_REASON_LENGTH - 3)}...`;
}

function isShell(toolName: string): boolean {
  return toolName === "bash" || toolName === "shell";
}

function pathFacts(call: CallState): readonly RuleFact[] {
  const value = call.arguments.path;
  if (typeof value !== "string" || value.trim().length === 0) return [];
  if (call.toolName === "read" || call.toolName === "grep" ||
      call.toolName === "find" || call.toolName === "ls") {
    return [{ surface: "path_read", value }];
  }
  if (call.toolName === "write") {
    return [{ surface: "path_write", value }];
  }
  if (call.toolName === "edit") {
    return [
      { surface: "path_read", value },
      { surface: "path_write", value },
    ];
  }
  return [];
}

/**
 * The default fact extraction of this node (shell fragments or the call-level
 * `*` entry). Exported so the chain's facts projection derives facts exactly the
 * way the node does instead of running a second extraction.
 */
export async function defaultFacts(
  call: CallState,
  options: RulesNodeOptions,
): Promise<readonly RuleUnitFacts[]> {
  if (isShell(call.toolName)) {
    const fragments = await fragmentsForCall(call, options);
    return fragments.map((fragment) => Object.freeze({
      unitId: fragment.unitId,
      ...(fragment.whole ? { incomplete: true } : {}),
      facts: Object.freeze([
        { surface: "tool", value: call.toolName },
        { surface: "bash", value: fragment.text },
      ]),
    }));
  }

  const kind = classifyToolKind(call.toolName);
  return [Object.freeze({
    unitId: "*",
    facts: Object.freeze([
      { surface: "tool", value: call.toolName },
      ...(kind === "mcp" || kind === "mcp-tool"
        ? [{ surface: "mcp", value: call.toolName, values: options.mcpTargets?.(call) ?? normalizeToolTargets(call.toolName, call.arguments).targets }]
        : []),
      ...pathFacts(call),
    ]),
  })];
}

export function explicitRuleHit(
  surface: string,
  value: string,
  evaluator: RuleEvaluator,
  values?: readonly string[],
): RuleHit | undefined {
  // The evaluator reads the ordered ruleset it was built from and reuses its
  // compiled matchers; results keep the engine's last-match-wins semantics.
  const hit = evaluator.evaluateAnyValue(surface, values ?? [value]);
  const rule = hit.rule;
  if (rule.origin === "builtin" || rule.origin === "baseline") return undefined;
  const pattern = clip(rule.pattern);
  return {
    decision: rule.action,
    reason: clip(
      `rules:${rule.origin}:${rule.action}:${surface}:${pattern}:${clip(hit.value)}`,
    ),
  };
}

/**
 * The effective explicit rule of one fact with its identity, or `undefined`
 * when the builtin/baseline default won. A thin seam for the chain's facts
 * projection (`chain/facts/rules.ts`): the decision is exactly
 * {@link explicitRuleHit}'s, this only keeps the origin and pattern the node
 * folds into its reason string.
 */
export function explicitRuleMatch(
  surface: string,
  value: string,
  evaluator: RuleEvaluator,
  values?: readonly string[],
): RuleMatch | undefined {
  const match = evaluator.evaluateAnyValue(surface, values ?? [value]);
  const origin = match.rule.origin;
  if (origin === "builtin" || origin === "baseline") return undefined;
  return match;
}

export function allowlistHit(
  facts: readonly RuleFact[],
  options: RulesNodeOptions,
): RuleHit | undefined {
  const patterns = options.fileAllowlist;
  if (!patterns || patterns.length === 0) return undefined;
  const flavor = options.flavor ?? pathFlavorForPlatform(process.platform);
  const paths = facts
    .filter((fact) => fact.surface === "path_read" || fact.surface === "path_write")
    .map((fact) => fact.value);
  if (paths.length === 0) return undefined;
  const covered = paths.every((path) => patterns.some((pattern) =>
    wildcardMatch(
      pattern,
      path,
      pathMatchOptions("path_read", flavor),
    )));
  if (!covered) return undefined;
  return {
    decision: "allow",
    reason: clip(`rules:file-allowlist:allow:${paths.join(",")}`),
  };
}

/**
 * The winning opinion of one fact set: the highest-ranked explicit-rule hit,
 * lifted by the file allowlist only when it outranks it. Exported for the
 * chain's facts projection so "which rule wins" is never computed twice.
 */
export function decideFacts(
  facts: readonly RuleFact[],
  evaluator: RuleEvaluator,
  options: RulesNodeOptions,
): RuleHit | undefined {
  let winner: RuleHit | undefined;
  for (const fact of facts) {
    const hit = explicitRuleHit(fact.surface, fact.value, evaluator, fact.values);
    if (
      hit &&
      (winner === undefined || RULE_ACTION_RANK[hit.decision] > RULE_ACTION_RANK[winner.decision])
    ) {
      winner = hit;
    }
  }
  const allowlist = allowlistHit(facts, options);
  if (
    allowlist &&
    (winner === undefined || RULE_ACTION_RANK[allowlist.decision] > RULE_ACTION_RANK[winner.decision])
  ) {
    winner = allowlist;
  }
  return winner;
}

/** Synthetic pattern of a file-allowlist allow: a list has no single pattern. */
const FILE_ALLOWLIST_PATTERN = "file-allowlist";

/**
 * The winning explicit rule of one fact set together with its identity.
 *
 * A projection seam for the chain's facts projection (`chain/facts/rules.ts`):
 * the decision is exactly {@link decideFacts}'s, and the replay below only names
 * which rule produced it, because {@link decideFacts} folds that identity into a
 * clipped reason string. Both paths share {@link explicitRuleMatch},
 * {@link allowlistHit} and {@link RULE_ACTION_RANK}, so they cannot disagree
 * about the rank or the rule; the returned `decision` stays `decideFacts`'s.
 */
export interface RuleDecisionFact {
  readonly decision: RuleAction;
  readonly origin: RuleOrigin;
  readonly pattern: string;
}

export function decideRuleFact(
  facts: readonly RuleFact[],
  evaluator: RuleEvaluator,
  options: RulesNodeOptions,
): RuleDecisionFact | undefined {
  const hit = decideFacts(facts, evaluator, options);
  if (hit === undefined) return undefined;

  let identity: RuleDecisionFact | undefined;
  let rank = -1;
  for (const fact of facts) {
    const match = explicitRuleMatch(fact.surface, fact.value, evaluator, fact.values);
    if (match === undefined) continue;
    const candidate = RULE_ACTION_RANK[match.rule.action];
    if (candidate <= rank) continue;
    rank = candidate;
    identity = {
      decision: match.rule.action,
      origin: match.rule.origin,
      pattern: match.rule.pattern,
    };
  }
  const allowlist = allowlistHit(facts, options);
  if (allowlist !== undefined && RULE_ACTION_RANK[allowlist.decision] > rank) {
    identity = { decision: allowlist.decision, origin: "global", pattern: FILE_ALLOWLIST_PATTERN };
  }
  return {
    decision: hit.decision,
    origin: identity?.origin ?? "global",
    pattern: identity?.pattern ?? "",
  };
}
