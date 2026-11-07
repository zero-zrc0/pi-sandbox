/**
 * Ordered policy rules and their evaluator.
 *
 * A rule keeps its surface, pattern, action, source scope and the synthesis
 * layer it came from. Evaluation scans a surface's rules from the tail to the
 * head, so the last matching rule wins; among the candidate values of one
 * invocation the first value the winning rule matches is reported.
 *
 * Compiled matchers are cached per surface for the lifetime of one evaluator.
 * Replacing config, session rules or the path language builds a new evaluator;
 * callers that already hold an older one keep its whole view, never a mix.
 */
import type { PathFlavor } from "../utils/path/path-flavor";
import { splitPathSurface } from "../utils/access-intent/path-surfaces";
import {
  compileWildcard,
  type CompiledWildcard,
  type WildcardMatchOptions,
} from "./wildcard-matcher";

export type RuleAction = "allow" | "ask" | "deny";

/**
 * Where a rule came from. Scope origins feed the evaluator as config layers;
 * `builtin` is the no-match default, `baseline` a metadata default, `session`
 * an in-memory grant, and the rewrite origins mark a transformed view.
 */
export type RuleOrigin =
  | "global"
  | "project"
  | "agent"
  | "project-agent"
  | "builtin"
  | "baseline"
  | "session"
  | "yolo"
  | "fail-closed"
  | "unavailable";

export type RuleLayer = "default" | "baseline" | "config" | "session";

export interface Rule {
  readonly surface: string;
  readonly pattern: string;
  readonly action: RuleAction;
  readonly origin: RuleOrigin;
  readonly layer: RuleLayer;
  /** Custom denial text carried by a deny rule. */
  readonly reason?: string;
}

export interface RuleMatch {
  readonly rule: Rule;
  readonly value: string;
}

export interface RuleEvaluator {
  /** The ordered view this evaluator was built from. */
  readonly rules: readonly Rule[];
  /** The rule used when no stored rule matches. */
  readonly defaultRule: Rule;
  /** Winning rule for one value. */
  evaluate(surface: string, value: string): Rule;
  /**
   * Winning rule for one invocation's aliases: rules are scanned tail to head,
   * the first rule matching any candidate wins and the reported value is the
   * winning rule's first matching candidate. Empty candidates fall back to `*`.
   */
  evaluateAnyValue(surface: string, values: readonly string[]): RuleMatch;
  /**
   * Conservative reachability probe: `*` plus one representative value per
   * pattern of this surface must all evaluate to deny.
   */
  isSurfaceFullyDenied(surface: string): boolean;
}

export type PatternCompiler = (
  pattern: string,
  options: WildcardMatchOptions,
) => CompiledWildcard;

export interface RuleEvaluatorOptions {
  /** Overrides the builtin ask default used when nothing matches. */
  readonly defaultRule?: Rule;
  /** Test seam that counts or fakes pattern compilation. */
  readonly compilePattern?: PatternCompiler;
  readonly compileSurfacePattern?: PatternCompiler;
}

export const DEFAULT_RULE: Rule = Object.freeze({
  surface: "*",
  pattern: "*",
  action: "ask",
  origin: "builtin",
  layer: "default",
});

/** Match options for a surface: only the path families fold the path language. */
export function pathMatchOptions(surface: string, flavor: PathFlavor): WildcardMatchOptions {
  if (splitPathSurface(surface) === undefined) return {};
  return {
    caseInsensitive: flavor.wildcard.caseInsensitive,
    separatorEquivalence: flavor.wildcard.separatorEquivalence,
  };
}

/** One value that a pattern accepts, used for the deny-reachability probe. */
export function representativeValueOf(pattern: string): string {
  return pattern.replace(/\*/g, "x").replace(/\?/g, "x");
}

interface CompiledRule {
  readonly rule: Rule;
  readonly matcher: CompiledWildcard;
}

export function createRuleEvaluator(
  rules: readonly Rule[],
  flavor: PathFlavor,
  options: RuleEvaluatorOptions = {},
): RuleEvaluator {
  const ruleView = Object.freeze([...rules]);
  const defaultRule = options.defaultRule ?? DEFAULT_RULE;
  const compile = options.compilePattern ?? compileWildcard;
  const surfaces = new Map<string, readonly CompiledRule[]>();
  const surfaceMatchers = new Map<string, CompiledWildcard>();
  const valueMatchers = new Map<string, CompiledWildcard>();
  const compileSurface = options.compileSurfacePattern ?? compileWildcard;

  const surfaceRules = (surface: string): readonly CompiledRule[] => {
    const cached = surfaces.get(surface);
    if (cached !== undefined) return cached;
    const matchOptions = pathMatchOptions(surface, flavor);
    const compiled: CompiledRule[] = [];
    for (const [index, rule] of ruleView.entries()) {
      let matcher = surfaceMatchers.get(rule.surface);
      if (matcher === undefined) {
        matcher = compileSurface(rule.surface, {});
        surfaceMatchers.set(rule.surface, matcher);
      }
      if (!matcher.test(surface)) continue;
      const key = JSON.stringify([index, matchOptions]);
      let valueMatcher = valueMatchers.get(key);
      if (valueMatcher === undefined) {
        valueMatcher = compile(rule.pattern, matchOptions);
        valueMatchers.set(key, valueMatcher);
      }
      compiled.push({ rule, matcher: valueMatcher });
    }
    const frozen = Object.freeze(compiled);
    surfaces.set(surface, frozen);
    return frozen;
  };

  const fallbackRule = (surface: string): Rule =>
    defaultRule.surface === surface ? defaultRule : { ...defaultRule, surface };

  const evaluateAnyValue = (surface: string, values: readonly string[]): RuleMatch => {
    const candidates = values.length === 0 ? ["*"] : values;
    const compiled = surfaceRules(surface);
    for (let index = compiled.length - 1; index >= 0; index -= 1) {
      const entry = compiled[index];
      for (const candidate of candidates) {
        if (entry.matcher.test(candidate)) return { rule: entry.rule, value: candidate };
      }
    }
    return { rule: fallbackRule(surface), value: candidates[0] };
  };

  return Object.freeze({
    rules: ruleView,
    defaultRule,
    evaluate: (surface: string, value: string): Rule =>
      evaluateAnyValue(surface, [value]).rule,
    evaluateAnyValue,
    isSurfaceFullyDenied: (surface: string): boolean => {
      const probes = new Set<string>(["*"]);
      for (const entry of surfaceRules(surface)) {
        probes.add(representativeValueOf(entry.rule.pattern));
      }
      let denied = true;
      for (const probe of probes) {
        if (evaluateAnyValue(surface, [probe]).rule.action !== "deny") {
          denied = false;
          break;
        }
      }
      return denied;
    },
  });
}
