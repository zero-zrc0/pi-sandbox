/**
 * Cross-extension permission service.
 *
 * The service shares one resolver, session store, path normalizer and set of
 * registered helpers with the gate. Bash queries decompose a complete command
 * when the parser is warm and fall back to the whole string when it is cold;
 * path queries reuse the gate's lexical and canonical match values; MCP
 * queries use already fixed name candidates. Tool facts stay outside: their
 * binding and assessment are delegated to the tool-access modules.
 */
import { classifyToolKind } from "../utils/access-intent/tool-kind";
import { fixedValuesIntent } from "../utils/access-intent/access-intent";
import type {
  PathExtractorLookup,
  RegisteredPathExtractor,
} from "../utils/access-intent/tool-input-path";
import type { PathNormalizer } from "../utils/path/path-normalizer";
import type { PermissionCheckResult } from "../contracts";
import { checkBashAdvisory } from "../utils/bash-advisory-check";
import { bashPathFacts } from "../utils/access-intent/bash/bash-path-resolver";
import { checkBashCommand } from "../utils/bash-command-check";
import type { BashCommand } from "../utils/access-intent/bash/command-enumeration";
import type { PermissionManager } from "./permission-manager";
import type { PermissionResolver } from "./permission-resolver";
import type { RuleAction } from "./rule";
import type { SessionRuleStore, SessionRuleView } from "./session-rules";

/** Bound on registered formatters or access extractors per registry. */
export const MAX_NAMED_REGISTRATIONS = 256;

export interface BashUnitSource {
  /** Command units when the parser is warm, `undefined` when it is cold. */
  units(command: string): readonly (BashCommand | string)[] | undefined;
}

export interface NamedRegistration {
  dispose(): void;
}

export interface PermissionServiceOptions {
  readonly manager: PermissionManager;
  readonly resolver: PermissionResolver;
  readonly normalizer: PathNormalizer;
  readonly session: SessionRuleStore;
  readonly bash?: BashUnitSource;
  readonly commandEffects?: () => unknown;
  readonly maxRegistrations?: number;
}

/** A small name-keyed registry with duplicate and stale-disposer semantics. */
class NamedRegistry<T> {
  private readonly entries = new Map<string, T>();
  private readonly order: string[] = [];
  private readonly max: number;

  constructor(max: number) {
    this.max = max;
  }

  register(name: string, value: T): NamedRegistration | undefined {
    const key = name.trim();
    if (key.length === 0 || this.entries.has(key) || this.entries.size >= this.max) {
      return undefined;
    }
    this.entries.set(key, value);
    this.order.push(key);
    let active = true;
    const registry = this;
    return Object.freeze({
      dispose(): void {
        if (!active) return;
        active = false;
        if (registry.entries.get(key) !== value) return;
        registry.entries.delete(key);
        const index = registry.order.indexOf(key);
        if (index >= 0) registry.order.splice(index, 1);
      },
    });
  }

  resolve(name: string): T | undefined {
    return this.entries.get(name.trim());
  }

  names(): readonly string[] {
    return [...this.order];
  }
}

export class PermissionService {
  private readonly manager: PermissionManager;
  private readonly resolver: PermissionResolver;
  private readonly normalizer: PathNormalizer;
  private readonly session: SessionRuleStore;
  private readonly bash: BashUnitSource | undefined;
  private readonly commandEffects: (() => unknown) | undefined;
  private readonly formatterRegistry: NamedRegistry<unknown>;
  private readonly extractorRegistry: NamedRegistry<unknown>;

  constructor(options: PermissionServiceOptions) {
    this.manager = options.manager;
    this.resolver = options.resolver;
    this.normalizer = options.normalizer;
    this.session = options.session;
    this.bash = options.bash;
    this.commandEffects = options.commandEffects;
    const max = options.maxRegistrations ?? MAX_NAMED_REGISTRATIONS;
    this.formatterRegistry = new NamedRegistry(max);
    this.extractorRegistry = new NamedRegistry(max);
  }

  /** The shared session approval store. */
  get sessionRules(): SessionRuleStore {
    return this.session;
  }

  /** The shared path normalizer, so path answers stay identical to the gate. */
  get pathNormalizer(): PathNormalizer {
    return this.normalizer;
  }

  checkTool(
    toolName: string,
    input: unknown,
    agent?: string,
  ): PermissionCheckResult {
    return this.resolver.check({
      toolName,
      input,
      ...(agent === undefined ? {} : { agent }),
    });
  }

  checkPath(
    surface: string,
    literal: string,
    agent?: string,
    baseDir?: string,
  ): PermissionCheckResult {
    return this.resolver.checkPath(surface, literal, {
      ...(agent === undefined ? {} : { agent }),
      ...(baseDir === undefined ? {} : { baseDir }),
    });
  }

  /** Fixed MCP targets: names come from the tool name, never from proxy input. */
  checkMcp(toolName: string, agent?: string): PermissionCheckResult {
    const name = toolName.trim();
    if (classifyToolKind(name) !== "mcp" && classifyToolKind(name) !== "mcp-tool") {
      return this.manager.checkRawTool(name, {}, agent, { toolName: name });
    }
    if (classifyToolKind(name) === "mcp") {
      return this.manager.check(fixedValuesIntent("mcp", [name], agent), { toolName: name });
    }
    return this.resolver.check({ toolName: name, input: {}, ...(agent === undefined ? {} : { agent }) });
  }

  /** Check a complete shell command, decomposed when the parser is warm. */
  checkBash(command: string, agent?: string): PermissionCheckResult {
    const check = this.manager.bashChecker(agent);
    const resolve = (text: string, unit?: BashCommand) =>
      check(text, [text, ...(unit?.equivalents ?? [])]);
    const units = this.bash?.units(command);
    if (units !== undefined && units.some((unit) => typeof unit !== "string")) {
      const incomplete = units.some((unit) => typeof unit === "string");
      const normalized = units.map((unit) =>
        typeof unit === "string" ? { text: unit, parseUnresolved: true } : unit);
      return {
        ...checkBashCommand({ command, units: normalized, resolve }).check,
        bashAnalysis: incomplete ? "incomplete" : "decomposed",
      };
    }
    let advisory: ReturnType<typeof checkBashAdvisory>;
    try {
      advisory = checkBashAdvisory({ command, normalizer: this.normalizer, resolve, pathFacts: bashPathFacts, commandEffects: this.commandEffects?.() });
    } catch {
      const whole = resolve(command);
      return whole.state === "deny"
        ? { ...whole, bashAnalysis: "incomplete" }
        : { ...whole, state: "ask", floor: "<bash-analysis-unavailable>", bashAnalysis: "incomplete" };
    }
    if (advisory.mode === "decomposed" || units === undefined || units.length === 0) {
      return { ...advisory.check, bashAnalysis: advisory.mode };
    }
    return { ...checkBashCommand({
      command,
      units: units.map((unit) => typeof unit === "string" ? { text: unit, parseUnresolved: true } : unit),
      resolve,
    }).check, bashAnalysis: "incomplete" };
  }

  toolState(toolName: string, agent?: string): RuleAction {
    return this.manager.toolState(toolName, agent);
  }

  isToolFullyDenied(toolName: string, agent?: string): boolean {
    return this.manager.isToolFullyDenied(toolName, agent);
  }

  approve(surface: string, pattern: string): SessionRuleView {
    return this.session.approve(surface, pattern);
  }

  clearSession(): void {
    this.session.clear();
  }

  registerFormatter(name: string, formatter: unknown): NamedRegistration | undefined {
    return this.formatterRegistry.register(name, formatter);
  }

  resolveFormatter<T = unknown>(name: string): T | undefined {
    return this.formatterRegistry.resolve(name) as T | undefined;
  }

  formatterNames(): readonly string[] {
    return this.formatterRegistry.names();
  }

  registerAccessExtractor(
    name: string,
    extractor: unknown,
  ): NamedRegistration | undefined {
    return this.extractorRegistry.register(name, extractor);
  }

  resolveAccessExtractor<T = unknown>(name: string): T | undefined {
    return this.extractorRegistry.resolve(name) as T | undefined;
  }

  accessExtractorNames(): readonly string[] {
    return this.extractorRegistry.names();
  }

  /**
   * The same registry as the access-intent lookup seam, so the gate and the
   * service resolve extension extractors through one table.
   */
  extractorLookup(): PathExtractorLookup {
    return {
      lookup: (toolName: string) => {
        const value = this.extractorRegistry.resolve(toolName);
        if (typeof value !== "object" || value === null) return undefined;
        const candidate = value as { origin?: unknown; extract?: unknown };
        if (candidate.origin !== "local" && candidate.origin !== "inherited") return undefined;
        if (typeof candidate.extract !== "function") return undefined;
        return candidate as RegisteredPathExtractor;
      },
    };
  }
}
