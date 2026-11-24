/**
 * Policy manager.
 *
 * The manager turns the four resolved intent kinds into one check result. It
 * caches only compiled config views, keyed by agent and loader stamp; a view
 * combines default, MCP baseline and config with the current session rules and,
 * when enabled, the yolo rewrite. Replacing the stamp builds a new evaluator,
 * and a caller that already obtained a result is unaffected.
 *
 * Tool-level queries never include session rules or the yolo rewrite.
 */
import { classifyToolKind } from "../utils/access-intent/tool-kind";
import {
  splitPathSurface,
  directionalSurface,
} from "../utils/access-intent/path-surfaces";
import {
  normalizeToolTargets,
  type ShellToolsConfig,
} from "../utils/access-intent/input-normalizer";
import type {
  AccessIntent,
  BashCommandIntent,
  FixedValuesIntent,
  PathValuesIntent,
  RawToolIntent,
} from "../utils/access-intent/access-intent";
import type { PathFlavor } from "../utils/path/path-flavor";
import type { ResolvedPathValue } from "../utils/path/path-normalizer";
import type { PermissionCheckResult } from "../contracts";
import {
  createRuleEvaluator,
  type PatternCompiler,
  type Rule,
  type RuleAction,
  type RuleEvaluator,
  type RuleOrigin,
} from "./rule";
import { pickMostRestrictive } from "./restrictiveness";
import { synthesizePolicy, applyYoloRewrite, type SynthesizedPolicy } from "./synthesize";
import type { SessionRuleStore } from "./session-rules";

/** Upper bound on cached compiled config/check views. */
export const MAX_CACHED_POLICY_VIEWS = 8;

export interface PolicyScopeView {
  readonly permission?: unknown;
  readonly invalid?: boolean;
}

export interface PolicyLoaderView {
  readonly scopes: Partial<Record<RuleOrigin, PolicyScopeView>>;
  readonly mcpServerNames?: readonly string[];
  /** Changes whenever any loaded scope file changed. */
  readonly stamp: string;
}

export type PolicyLoader = (agent?: string) => PolicyLoaderView;

export interface PermissionManagerOptions {
  readonly flavor: PathFlavor;
  readonly session: SessionRuleStore;
  readonly loadPolicy: PolicyLoader;
  /** Yolo reader; a fresh reader result is used for every check. */
  readonly readYolo?: () => boolean;
  readonly defaultAction?: RuleAction;
  readonly shellTools?: ShellToolsConfig;
  readonly compilePattern?: PatternCompiler;
}

export interface CheckContext {
  /** The original tool name, kept on the result instead of the surface name. */
  readonly toolName?: string;
}

interface ConfigView {
  readonly key: string;
  readonly policy: SynthesizedPolicy;
  readonly evaluator: RuleEvaluator;
}

interface ActiveView {
  readonly loader: PolicyLoaderView;
  readonly config: ConfigView;
  readonly evaluator: RuleEvaluator;
}

interface ResultInput {
  readonly surface: string;
  readonly toolName: string;
  readonly rule: Rule;
  readonly matchedValue: string;
  readonly target?: string;
  readonly command?: string;
  readonly matchedSpelling?: string;
}

function sourceFor(surface: string, rule: Rule): PermissionCheckResult["source"] {
  if (rule.layer === "session") return "session";
  if (splitPathSurface(surface) !== undefined) return "special";
  if (surface === "bash") return "bash";
  if (surface === "mcp") return rule.layer === "default" ? "default" : "mcp";
  if (surface === "skill") return "skill";
  return rule.layer === "default" ? "default" : "tool";
}

function remember<T>(cache: Map<string, T>, key: string, value: T): T {
  if (cache.size >= MAX_CACHED_POLICY_VIEWS && !cache.has(key)) {
    const oldest = cache.keys().next();
    if (!oldest.done) cache.delete(oldest.value);
  }
  cache.set(key, value);
  return value;
}

export class PermissionManager {
  private readonly flavor: PathFlavor;
  private readonly session: SessionRuleStore;
  private readonly loadPolicy: PolicyLoader;
  private readonly readYolo: (() => boolean) | undefined;
  private readonly defaultAction: RuleAction | undefined;
  private readonly shellTools: ShellToolsConfig | undefined;
  private readonly compilePattern: PatternCompiler | undefined;
  private readonly configViews = new Map<string, ConfigView>();
  private readonly activeViews = new Map<string, ConfigView>();

  constructor(options: PermissionManagerOptions) {
    this.flavor = options.flavor;
    this.session = options.session;
    this.loadPolicy = options.loadPolicy;
    this.readYolo = options.readYolo;
    this.defaultAction = options.defaultAction;
    this.shellTools = options.shellTools;
    this.compilePattern = options.compilePattern;
  }

  /** Check one resolved intent against the active combined view. */
  check(
    intent: AccessIntent,
    context: CheckContext = {},
    loader: PolicyLoaderView = this.loadPolicy(intent.agent),
  ): PermissionCheckResult {
    const active = this.activeView(intent.agent, loader);
    switch (intent.kind) {
      case "raw-tool":
        return this.evaluateRaw(intent, active, context);
      case "fixed-values":
        return this.evaluateFixed(intent, active, context);
      case "path-values":
        return this.evaluatePathValues(intent, active, context);
      case "bash-command":
        return this.evaluateBash(intent, active, context);
    }
  }

  /** Check a raw tool call without building an access intent first. */
  checkRawTool(
    toolName: string,
    input: unknown,
    agent?: string,
    context: CheckContext = {},
    loader: PolicyLoaderView = this.loadPolicy(agent),
  ): PermissionCheckResult {
    const active = this.activeView(agent, loader);
    return this.evaluateRaw(
      { kind: "raw-tool", toolName, input, ...(agent === undefined ? {} : { agent }) },
      active,
      context,
    );
  }

  /** Check a Bash command with every equivalent spelling as one invocation. */
  checkBashCommand(
    original: string,
    spellings: readonly string[],
    agent?: string,
    context: CheckContext = {},
  ): PermissionCheckResult {
    const active = this.activeView(agent);
    return this.evaluateBash(
      {
        kind: "bash-command",
        surface: "bash",
        original,
        spellings,
        ...(agent === undefined ? {} : { agent }),
      },
      active,
      context,
    );
  }

  /** Pin the policy and session view used for one complete command query. */
  bashChecker(agent?: string): (original: string, spellings: readonly string[]) => PermissionCheckResult {
    const active = this.activeView(agent);
    return (original, spellings) => this.evaluateBash({
      kind: "bash-command", surface: "bash", original, spellings,
      ...(agent === undefined ? {} : { agent }),
    }, active, { toolName: "bash" });
  }

  /** Tool-level state: no session rules, no yolo rewrite. */
  toolState(toolName: string, agent?: string): RuleAction {
    const loader = this.loadPolicy(agent);
    const view = this.configViewFor(loader, agent);
    const active = this.configSurface(toolName, view, loader);
    return active.evaluator.evaluateAnyValue(active.surface, active.values).rule.action;
  }

  /** Conservative reachability probe for one tool; no session or yolo. */
  isToolFullyDenied(toolName: string, agent?: string): boolean {
    const loader = this.loadPolicy(agent);
    const view = this.configViewFor(loader, agent);
    const active = this.configSurface(toolName, view, loader);
    return active.evaluator.isSurfaceFullyDenied(active.surface);
  }

  /** Resolve one already-loaded policy into a consistent published rule view. */
  configSnapshot(loader: PolicyLoaderView, agent?: string): { readonly rules: readonly Rule[]; readonly defaultRule: Rule } {
    const view = this.configViewFor(loader, agent);
    return { rules: view.policy.rules, defaultRule: view.policy.defaultRule };
  }

  /** The synthesized config rules without session or yolo, for display. */
  configRules(agent?: string): readonly Rule[] {
    return this.configView(agent).policy.rules;
  }

  /** The synthesized default rule without session or yolo. */
  configDefaultRule(agent?: string): Rule {
    return this.configView(agent).policy.defaultRule;
  }

  private configSurface(
    toolName: string,
    view: ConfigView,
    loader: PolicyLoaderView,
  ): { readonly evaluator: RuleEvaluator; readonly surface: string; readonly values: readonly string[] } {
    const name = toolName.trim();
    const kind = classifyToolKind(name);
    if (kind === "mcp" || kind === "mcp-tool") {
      const normalized = normalizeToolTargets(name, {}, {
        ...(this.shellTools === undefined ? {} : { shellTools: this.shellTools }),
        ...(loader.mcpServerNames === undefined
          ? {}
          : { mcpConfigServers: loader.mcpServerNames }),
      });
      return {
        evaluator: view.evaluator,
        surface: "mcp",
        values: normalized.surface === "mcp" ? normalized.targets : ["*"],
      };
    }
    return { evaluator: view.evaluator, surface: name, values: ["*"] };
  }

  private configViewFor(loader: PolicyLoaderView, agent: string | undefined): ConfigView {
    const key = `${agent ?? ""}\u0000${loader.stamp}`;
    const cached = this.configViews.get(key);
    if (cached !== undefined) return cached;
    const policy = synthesizePolicy({
      scopes: loader.scopes,
      ...(this.defaultAction === undefined ? {} : { defaultAction: this.defaultAction }),
    });
    const evaluator = createRuleEvaluator(policy.rules, this.flavor, {
      defaultRule: policy.defaultRule,
      ...(this.compilePattern === undefined ? {} : { compilePattern: this.compilePattern }),
    });
    return remember(this.configViews, key, { key, policy, evaluator });
  }

  private configView(agent: string | undefined): ConfigView {
    return this.configViewFor(this.loadPolicy(agent), agent);
  }

  loadPolicyView(agent?: string): PolicyLoaderView {
    return this.loadPolicy(agent);
  }

  private activeView(agent: string | undefined, loader = this.loadPolicy(agent)): ActiveView {
    const config = this.configViewFor(loader, agent);
    const session = this.session.snapshot();
    const yolo = this.readYolo?.() === true;
    if (session.rules.length === 0 && !yolo) {
      return { loader, config, evaluator: config.evaluator };
    }
    const key = `${config.key}\u0000${session.version}\u0000${yolo ? "y" : "n"}`;
    const cached = this.activeViews.get(key);
    if (cached !== undefined) {
      return { loader, config, evaluator: cached.evaluator };
    }
    const combined = [...config.policy.rules, ...session.rules];
    const rewritten = yolo
      ? applyYoloRewrite(combined, config.policy.defaultRule)
      : { rules: combined, defaultRule: config.policy.defaultRule };
    const evaluator = createRuleEvaluator(rewritten.rules, this.flavor, {
      defaultRule: rewritten.defaultRule,
      ...(this.compilePattern === undefined ? {} : { compilePattern: this.compilePattern }),
    });
    remember(this.activeViews, key, { key, policy: config.policy, evaluator });
    return { loader, config, evaluator };
  }

  private toResult(input: ResultInput): PermissionCheckResult {
    const showsPattern = input.rule.layer === "config" || input.rule.layer === "session";
    return {
      toolName: input.toolName,
      state: input.rule.action,
      source: sourceFor(input.surface, input.rule),
      origin: input.rule.origin,
      ...(showsPattern ? { matchedPattern: input.rule.pattern } : {}),
      ...(input.rule.reason === undefined ? {} : { reason: input.rule.reason }),
      ...(input.surface === "bash"
        ? {
            command: input.command ?? input.matchedValue,
            ...(input.matchedSpelling === undefined ? {} : { matchedSpelling: input.matchedSpelling }),
          }
        : { target: input.target ?? input.matchedValue }),
    };
  }

  private checkAliases(
    surface: string,
    values: readonly string[],
    toolName: string,
    active: ActiveView,
  ): PermissionCheckResult {
    const match = active.evaluator.evaluateAnyValue(surface, values);
    return this.toResult({
      surface,
      toolName,
      rule: match.rule,
      matchedValue: match.value,
    });
  }

  private evaluateRaw(
    intent: RawToolIntent,
    active: ActiveView,
    context: CheckContext,
  ): PermissionCheckResult {
    const toolName = intent.toolName.trim();
    const normalized = normalizeToolTargets(intent.toolName, intent.input, {
      ...(this.shellTools === undefined ? {} : { shellTools: this.shellTools }),
      ...(active.loader.mcpServerNames === undefined
        ? {}
        : { mcpConfigServers: active.loader.mcpServerNames }),
    });
    if (normalized.command !== undefined) {
      return this.evaluateBash(
        {
          kind: "bash-command",
          surface: "bash",
          original: normalized.command.original,
          spellings: normalized.targets,
          ...(intent.agent === undefined ? {} : { agent: intent.agent }),
        },
        active,
        context.toolName === undefined ? { toolName } : context,
      );
    }
    return this.checkAliases(
      normalized.surface,
      normalized.targets,
      context.toolName ?? toolName,
      active,
    );
  }

  private evaluateFixed(
    intent: FixedValuesIntent,
    active: ActiveView,
    context: CheckContext,
  ): PermissionCheckResult {
    return this.checkAliases(
      intent.surface,
      intent.values,
      context.toolName ?? intent.surface,
      active,
    );
  }

  private evaluateBash(
    intent: BashCommandIntent,
    active: ActiveView,
    context: CheckContext,
  ): PermissionCheckResult {
    const values = intent.spellings.length === 0 ? [intent.original] : intent.spellings;
    const match = active.evaluator.evaluateAnyValue("bash", values);
    return this.toResult({
      surface: "bash",
      toolName: context.toolName ?? "bash",
      rule: match.rule,
      matchedValue: match.value,
      command: intent.original,
      ...(match.value === values[0] ? {} : { matchedSpelling: match.value }),
    });
  }

  private evaluatePathValues(
    intent: PathValuesIntent,
    active: ActiveView,
    context: CheckContext,
  ): PermissionCheckResult {
    const toolName = context.toolName ?? intent.surface;
    const parts = splitPathSurface(intent.surface);
    const surfaces = parts !== undefined && parts.direction === undefined
      ? [
          directionalSurface(parts.family, "read"),
          directionalSurface(parts.family, "write"),
        ]
      : [intent.surface];
    if (intent.paths.length === 0) {
      const checks = surfaces.map((surface) =>
        this.checkAliases(surface, [], toolName, active));
      return pickMostRestrictive(checks)!;
    }
    const checks: PermissionCheckResult[] = [];
    for (const path of intent.paths) {
      for (const surface of surfaces) {
        checks.push(this.checkPath(surface, path, toolName, active));
      }
    }
    return pickMostRestrictive(checks)!;
  }

  private checkPath(
    surface: string,
    path: ResolvedPathValue,
    toolName: string,
    active: ActiveView,
  ): PermissionCheckResult {
    const match = active.evaluator.evaluateAnyValue(surface, path.matchValues);
    return this.toResult({
      surface,
      toolName,
      rule: match.rule,
      matchedValue: match.value,
      target: path.display,
    });
  }
}
