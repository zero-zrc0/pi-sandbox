import {
  createRuleEvaluator,
  pathMatchOptions,
  type Rule,
  type RuleEvaluator,
} from "#approve-core/policy/rule";
import { wildcardMatch } from "#approve-core/policy/wildcard-matcher";
import { classifyToolKind } from "#approve-core/utils/access-intent/tool-kind";
import { normalizeToolTargets } from "#approve-core/utils/access-intent/input-normalizer";
import { pathFlavorForPlatform, type PathFlavor } from "#approve-core/utils/path/path-flavor";
import { MAX_REASON_LENGTH, type CallState, type UnitDecision } from "#approve-core/contracts";
import type { ChainNode, StepContext } from "#approve-core/runtime";
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

const RULE_ACTION_RANK = { allow: 0, ask: 1, deny: 2 } as const;

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

interface RuleHit {
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

async function defaultFacts(
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

function explicitRuleHit(
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

function allowlistHit(
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

function decideFacts(
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

function isDenied(call: CallState): boolean {
  return call.units.some((unit) => unit.decision === "deny");
}

function decisionsForCall(
  call: CallState,
  entries: readonly RuleUnitFacts[],
  evaluator: RuleEvaluator,
  options: RulesNodeOptions,
): readonly UnitDecision[] {
  if (isDenied(call)) return [];
  const units = new Map(call.units.map((unit) => [unit.unitId, unit]));
  const byUnit = new Map<string, RuleHit>();

  for (const entry of entries) {
    const hit = decideFacts(entry.facts, evaluator, options);
    if (!hit || (entry.incomplete && hit.decision === "allow")) continue;
    const ids = entry.unitId === "*"
      ? call.units.map((unit) => unit.unitId)
      : [entry.unitId];
    for (const unitId of ids) {
      if (!units.has(unitId)) continue;
      const previous = byUnit.get(unitId);
      if (
        previous === undefined ||
        RULE_ACTION_RANK[hit.decision] > RULE_ACTION_RANK[previous.decision]
      ) {
        byUnit.set(unitId, hit);
      }
    }
  }

  return [...byUnit.entries()].map(([unitId, hit]) => Object.freeze({
    toolCallId: call.toolCallId,
    unitId,
    decision: hit.decision,
    reason: clip(hit.reason),
  }));
}

/**
 * The fixed front explicit-rule node. It can turn a fragment allow/ask/deny,
 * but never invents a fragment and never returns a result for a denied call.
 */
export function createRulesNode(options: RulesNodeOptions): ChainNode {
  const flavor = options.flavor ?? pathFlavorForPlatform(process.platform);
  // One evaluator per node instance: the readonly declaration keeps callers
  // from mutating the rules after the node was constructed, so the evaluator
  // can snapshot the view and reuse its compiled matchers across every fact
  // and unit this node judges.
  const evaluator = options.evaluator ??
    createRuleEvaluator(options.rules, flavor);
  return Object.freeze({
    apiVersion: "1" as const,
    id: "builtin/rules",
    evaluate: async (context: StepContext) => {
      const decisions: UnitDecision[] = [];
      for (const call of context.state.calls) {
        const entries = options.resolveFacts
          ? await options.resolveFacts(call, context)
          : await defaultFacts(call, options);
        decisions.push(...decisionsForCall(call, entries, evaluator, options));
      }
      return { decisions };
    },
  });
}
