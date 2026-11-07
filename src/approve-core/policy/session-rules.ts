/**
 * In-memory session approvals.
 *
 * Only allows are stored and nothing is persisted. Approving a bare path
 * family grants both directions; approving a directional or ordinary surface
 * grants one. Every change replaces the stable rule view and its evaluator, so
 * a check that already holds an older view keeps using it unchanged. Callers
 * that read the rules receive a copy; the compile path keeps the stable array.
 */
import { splitPathSurface } from "../utils/access-intent/path-surfaces";
import type { PathFlavor } from "../utils/path/path-flavor";
import {
  createRuleEvaluator,
  type PatternCompiler,
  type Rule,
  type RuleEvaluator,
} from "./rule";

/** Upper bound on stored session rules; the oldest are dropped first. */
export const DEFAULT_MAX_SESSION_RULES = 512;

export interface SessionRuleView {
  readonly version: number;
  /** Stable internal view; never mutate. */
  readonly rules: readonly Rule[];
  readonly evaluator: RuleEvaluator;
}

export interface SessionRuleStoreOptions {
  readonly flavor: PathFlavor;
  readonly compilePattern?: PatternCompiler;
  readonly maxRules?: number;
}

function sessionTargets(surface: string): readonly string[] {
  const parts = splitPathSurface(surface);
  if (parts !== undefined && parts.direction === undefined) {
    return [`${parts.family}_read`, `${parts.family}_write`];
  }
  return [surface];
}

export class SessionRuleStore {
  private readonly flavor: PathFlavor;
  private readonly compilePattern: PatternCompiler | undefined;
  private readonly maxRules: number;
  private current: SessionRuleView;
  private droppedCount = 0;

  constructor(options: SessionRuleStoreOptions) {
    this.flavor = options.flavor;
    this.compilePattern = options.compilePattern;
    this.maxRules = Math.max(0, options.maxRules ?? DEFAULT_MAX_SESSION_RULES);
    this.current = this.build(0, []);
  }

  get version(): number {
    return this.current.version;
  }

  /** Number of rules evicted by the bound since the last clear. */
  get dropped(): number {
    return this.droppedCount;
  }

  /** The stable view the manager combines with the config rules. */
  snapshot(): SessionRuleView {
    return this.current;
  }

  /** A defensive copy of the current rules. */
  rules(): readonly Rule[] {
    return [...this.current.rules];
  }

  /** Approve one surface/pattern. A bare path family approves both directions. */
  approve(surface: string, pattern: string): SessionRuleView {
    const added: Rule[] = sessionTargets(surface).map((target) => Object.freeze({
      surface: target,
      pattern,
      action: "allow" as const,
      origin: "session" as const,
      layer: "session" as const,
    }));
    const rules = [...this.current.rules];
    let changed = false;
    for (const rule of added) {
      const known = rules.some((candidate) =>
        candidate.surface === rule.surface &&
        candidate.pattern === rule.pattern &&
        candidate.action === rule.action);
      if (known) continue;
      rules.push(rule);
      changed = true;
    }
    if (!changed) return this.current;

    let bounded = rules;
    if (bounded.length > this.maxRules) {
      const overflow = bounded.length - this.maxRules;
      this.droppedCount += overflow;
      bounded = bounded.slice(overflow);
    }
    this.current = this.build(this.current.version + 1, bounded);
    return this.current;
  }

  /** Drop every session approval. */
  clear(): SessionRuleView {
    this.droppedCount = 0;
    if (this.current.rules.length === 0) return this.current;
    this.current = this.build(this.current.version + 1, []);
    return this.current;
  }

  /** Session shutdown clears the in-memory grants. */
  shutdown(): void {
    this.clear();
  }

  private build(version: number, rules: readonly Rule[]): SessionRuleView {
    const frozen = Object.freeze([...rules]);
    return Object.freeze({
      version,
      rules: frozen,
      evaluator: createRuleEvaluator(frozen, this.flavor, this.compilePattern === undefined
        ? {}
        : { compilePattern: this.compilePattern }),
    });
  }
}
