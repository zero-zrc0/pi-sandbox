/**
 * Tool admission rule table (docs/tool-rules-and-sandbox-tools-design.md §5).
 *
 * The evaluator is pure: it merges nothing itself and reads no configuration.
 * Callers hand it rules that are already ordered by precedence
 * (project-scoped declarations first, then global-scoped ones, each in
 * declaration order) and receive one of three outcomes:
 *
 * 1. argument-level `deny`
 * 2. argument-level `allow`
 * 3. tool-level `deny`
 * 4. tool-level `allow`
 * 5. no match → `ask`
 *
 * Within one priority the first rule of the supplied order wins. A rule without
 * `match.args` is tool-level; a rule with `match.args` matches only when every
 * declared pointer holds a string that matches its wildcard.
 */
import { globMatches } from "./glob";
import { decodePointer, readPointerValue } from "./pointers";

export type ToolRuleDecision = "allow" | "deny";

export type ToolRuleProfile = "file-reader" | "file-search" | "file-writer" | "file-editor";

export type ToolRuleAccess = "read" | "write";

export type ToolRuleWhenAbsent = "error" | "cwd";

export interface ToolRuleLocation {
  /** JSON Pointer into the tool input. */
  readonly pointer: string;
  readonly access: ToolRuleAccess;
  readonly whenAbsent?: ToolRuleWhenAbsent;
}

/** Where a sandbox-hosted tool module comes from (§6). */
export interface ToolRuleSandbox {
  /** npm package name; resolved from the declaring scope. */
  readonly package?: string;
  /** Package entry inside `package`, resolved through its exported subpaths. */
  readonly entry?: string;
  /** Local module path, resolved from the project root (the snapshot cwd). */
  readonly path?: string;
  /** Tool description registered with the host. */
  readonly description?: string;
  /** JSON Schema object describing the tool parameters. */
  readonly parameters?: Readonly<Record<string, unknown>>;
  /** Opaque configuration handed to the module through the worker. */
  readonly config?: unknown;
}

/** One admission rule (`toolRules` entry). */
export interface ToolRule {
  /** Stable audit identity; 1-200 characters. */
  readonly id: string;
  readonly match: {
    readonly tool: string;
    /** JSON Pointer → wildcard. Only string argument values participate. */
    readonly args?: Readonly<Record<string, string>>;
  };
  readonly decision: ToolRuleDecision;
  /** Only used by `allow` rules to build approval facts and validate input. */
  readonly profile?: ToolRuleProfile;
  readonly locations?: readonly ToolRuleLocation[];
  /** Only used by `allow` rules that execute in the sandbox. */
  readonly sandbox?: ToolRuleSandbox;
}

/** Where a declaration came from; audit names it as `global` / `project`. */
export type ToolRuleScope = "global" | "project";

export interface ScopedToolRule {
  readonly scope: ToolRuleScope;
  readonly rule: ToolRule;
}

/** One admission lookup. */
export interface ToolRuleQuery {
  readonly tool: string;
  readonly args: unknown;
}

interface MatchedRule {
  readonly rule: ToolRule;
  readonly scope: ToolRuleScope;
  readonly argumentLevel: boolean;
  readonly priority: number;
}

export type ToolRuleMatch =
  | {
      readonly kind: "allow";
      readonly ruleId: string;
      readonly scope: ToolRuleScope;
      readonly argumentLevel: boolean;
      readonly rule: ToolRule;
    }
  | {
      readonly kind: "deny";
      readonly ruleId: string;
      readonly scope: ToolRuleScope;
      readonly argumentLevel: boolean;
      readonly rule: ToolRule;
    }
  | { readonly kind: "ask" };

/** Every declared argument pointer must hold a matching string. */
function argumentsMatch(args: unknown, pattern: Readonly<Record<string, string>>): boolean {
  for (const [pointer, wildcard] of Object.entries(pattern)) {
    const tokens = decodePointer(pointer);
    if (tokens === undefined) return false;
    const value = readPointerValue(args, tokens);
    if (typeof value !== "string" || !globMatches(wildcard, value)) return false;
  }
  return true;
}

/** Argument-level rules outrank tool-level ones; `deny` outranks `allow`. */
function priorityOf(decision: ToolRuleDecision, argumentLevel: boolean): number {
  return (argumentLevel ? 2 : 0) + (decision === "deny" ? 1 : 0);
}

/**
 * Evaluate the ordered rule table for one tool call. `ask` means no rule
 * matched, so the caller must run its normal approval path.
 */
export function evaluateToolRules(
  rules: readonly ScopedToolRule[],
  query: ToolRuleQuery,
): ToolRuleMatch {
  if (!Array.isArray(rules) || rules.length === 0) return { kind: "ask" };
  if (typeof query?.tool !== "string") return { kind: "ask" };

  let best: MatchedRule | undefined;
  for (const entry of rules) {
    const rule = entry?.rule;
    if (rule === undefined || typeof rule !== "object") continue;
    if (typeof rule.id !== "string" || rule.id.length === 0) continue;
    if (rule.decision !== "allow" && rule.decision !== "deny") continue;
    if (!globMatches(rule.match.tool, query.tool)) continue;

    const cardinals = rule.match.args;
    const argumentLevel = cardinals !== undefined;
    if (cardinals !== undefined && !argumentsMatch(query.args, cardinals)) continue;

    const priority = priorityOf(rule.decision, argumentLevel);
    // Strictly greater: the first rule of one priority keeps its precedence.
    if (best === undefined || priority > best.priority) {
      best = { rule, scope: entry.scope === "project" ? "project" : "global", argumentLevel, priority };
    }
  }
  if (best === undefined) return { kind: "ask" };
  return Object.freeze({
    kind: best.rule.decision,
    ruleId: best.rule.id,
    scope: best.scope,
    argumentLevel: best.argumentLevel,
    rule: best.rule,
  });
}

/** True when an `allow` rule declares a sandbox-hosted tool module. */
export function isSandboxToolRule(rule: ToolRule | undefined): boolean {
  return rule?.decision === "allow" && rule.sandbox !== undefined;
}
