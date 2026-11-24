/**
 * Explicit-rule opinions of one call, projected per unit for the responsibility
 * chain (v4 §2 priorities 20/21).
 *
 * What it does: turns the existing `builtin/rules` judgement
 * (`nodes/rules/index.ts`: default facts → per-fact rule match → rank) into
 * {@link UnitRuleFact} values keyed by `unitId`, so the chain's
 * `explicit-rules-restrict` / `explicit-rules-grant` handlers only have to read
 * `context.unit.rule`.
 *
 * The judgement is reused, not re-decided here:
 *
 * - last-match-wins comes from the rule evaluator, so the last rule of the
 *   array wins;
 * - inside one fact set the highest rank wins (`deny > ask > allow`, ties keep
 *   the first fact);
 * - an incomplete fact set (the whole-call fallback of a failed or uncertain
 *   parse) may only tighten, so its `allow` is dropped;
 * - the file allowlist can only allow when it covers every path fact and
 *   outranks the explicit hits;
 * - the builtin/baseline default is "no opinion", not a rule;
 * - an entry keyed `*` is the call-level fact set and expands to every unit of
 *   the call, exactly as the node applies it.
 *
 * What it does not do: no mode, danger, sensitive or assessment judgement, no
 * file access, no unit state read or write. Unit state is deliberately ignored:
 * facts are derived before the chain runs, so an already recorded deny does not
 * suppress them. `locked` is never set — this version has no `ask:locked`.
 */
import { MAX_REASON_LENGTH, type CallState } from "#approve-core/contracts";
import type { StepContext } from "#approve-core/runtime";
import {
  decideRuleFact,
  defaultFacts,
  RULE_ACTION_RANK,
  type RuleUnitFacts,
  type RulesFactsResolver,
  type RulesNodeOptions,
} from "#approve-core/nodes/rules";
import type { StructureAnalysisOptions } from "#approve-core/nodes/analysis";
import {
  createRuleEvaluator,
  type Rule,
  type RuleEvaluator,
  type RuleOrigin,
} from "#approve-core/policy/rule";
import { pathFlavorForPlatform, type PathFlavor } from "#approve-core/utils/path/path-flavor";
import type { UnitRuleFact } from "../facts";

/**
 * The bits of the rules node's construction the projection needs. Everything
 * except {@link rules} is optional and matches `RulesNodeOptions`, so a host
 * that already holds an evaluator, a step-local parser/provider or a file
 * allowlist can hand the projection the same inputs the node got.
 */
export interface RuleFactsOptions extends StructureAnalysisOptions {
  readonly rules: readonly Rule[];
  readonly evaluator?: RuleEvaluator;
  readonly flavor?: PathFlavor;
  readonly mcpTargets?: (call: CallState) => readonly string[];
  readonly fileAllowlist?: readonly string[];
  readonly resolveFacts?: RulesFactsResolver;
}

export interface ProjectRuleFactsInput {
  readonly call: CallState;
  readonly context: StepContext;
  readonly options: RuleFactsOptions;
}

/**
 * The engine's origin vocabulary collapsed onto the three scopes
 * `UnitRuleFact` can name. Rewritten views (`yolo`, `fail-closed`,
 * `unavailable`) lost their original scope, and `agent` is the global agents
 * directory, so those stay truthful without inventing a scope: `fail-closed`
 * comes from a non-global scope, everything else falls back to `global`. The
 * opinion itself is never changed by this mapping. `builtin`/`baseline` are
 * filtered out before the mapping is reached.
 */
const RULE_ORIGIN_SCOPE: Readonly<Record<RuleOrigin, UnitRuleFact["origin"]>> = Object.freeze({
  global: "global",
  project: "project",
  agent: "global",
  "project-agent": "project",
  session: "session",
  builtin: "global",
  baseline: "global",
  yolo: "global",
  "fail-closed": "project",
  unavailable: "global",
});

interface ProjectedOpinion {
  readonly decision: UnitRuleFact["decision"];
  readonly pattern: string;
  readonly origin: UnitRuleFact["origin"];
  /** `RULE_ACTION_RANK` of `decision`; kept so merging is one comparison. */
  readonly rank: number;
}

/** The node clips patterns before they reach a reason; facts do the same. */
function clipPattern(pattern: string): string {
  return pattern.length <= MAX_REASON_LENGTH
    ? pattern
    : `${pattern.slice(0, MAX_REASON_LENGTH - 3)}...`;
}

/**
 * The winning opinion of one fact set, using the node's own decision function
 * (`decideRuleFact` delegates to `decideFacts`) and only adding the identity
 * shape this projection needs.
 */
function entryOpinion(
  entry: RuleUnitFacts,
  evaluator: RuleEvaluator,
  options: RulesNodeOptions,
): ProjectedOpinion | undefined {
  const winner = decideRuleFact(entry.facts, evaluator, options);
  if (winner === undefined) return undefined;
  return {
    decision: winner.decision,
    pattern: clipPattern(winner.pattern),
    origin: RULE_ORIGIN_SCOPE[winner.origin],
    rank: RULE_ACTION_RANK[winner.decision],
  };
}

/** The fact sets of one call: the host's resolver when given, the node's default otherwise. */
async function factsForCall(
  call: CallState,
  context: StepContext,
  options: RuleFactsOptions,
  nodeOptions: RulesNodeOptions,
): Promise<readonly RuleUnitFacts[]> {
  const selectedPath = context.selectedFilePaths?.[call.toolCallId];
  const ruleCall = selectedPath === undefined ? call : { ...call, arguments: { ...call.arguments, path: selectedPath } };
  return options.resolveFacts !== undefined
    ? options.resolveFacts(call, context)
    : defaultFacts(ruleCall, nodeOptions);
}

/**
 * Project one call's explicit-rule opinions onto its units.
 *
 * Keys are `unitId`s of `call.units`; a unit with no effective rule (no match,
 * builtin default, or a dropped incomplete allow) has no entry at all. The
 * returned map is new per call and its values are frozen.
 */
export async function projectRuleFacts(
  input: ProjectRuleFactsInput,
): Promise<ReadonlyMap<string, UnitRuleFact>> {
  const { call, context, options } = input;
  const flavor = options.flavor ?? pathFlavorForPlatform(process.platform);
  const evaluator = options.evaluator ?? createRuleEvaluator(options.rules, flavor);
  // One option object for the shared helpers: `defaultFacts` and the allowlist
  // read the same parsing and path-language inputs the node would receive.
  const nodeOptions: RulesNodeOptions = { ...options, flavor };
  const entries = await factsForCall(call, context, options, nodeOptions);

  const unitIds = call.units.map((unit) => unit.unitId);
  const knownUnits = new Set(unitIds);
  const byUnit = new Map<string, ProjectedOpinion>();

  for (const entry of entries) {
    const opinion = entryOpinion(entry, evaluator, nodeOptions);
    if (opinion === undefined) continue;
    // An incomplete fact set cannot prove an allow; the node drops exactly this.
    if (entry.incomplete === true && opinion.decision === "allow") continue;
    const targets = entry.unitId === "*" ? unitIds : [entry.unitId];
    for (const unitId of targets) {
      if (!knownUnits.has(unitId)) continue;
      const previous = byUnit.get(unitId);
      if (previous !== undefined && opinion.rank <= previous.rank) continue;
      byUnit.set(unitId, opinion);
    }
  }

  const facts = new Map<string, UnitRuleFact>();
  for (const [unitId, opinion] of byUnit) {
    facts.set(unitId, Object.freeze({
      decision: opinion.decision,
      pattern: opinion.pattern,
      origin: opinion.origin,
    }));
  }
  return facts;
}
