/**
 * Gate-facing permission resolver.
 *
 * The resolver is the one gate entry point: it turns a raw tool call or a path
 * literal into an access intent with the session path normalizer, then hands
 * the intent to the manager. Path value objects are expanded to match values
 * exactly once — in the manager — and already fixed path values are never
 * rebuilt. Session rules are part of every check the manager answers.
 */
import {
  buildAccessIntent,
  pathValuesIntent,
  type AccessIntent,
} from "../utils/access-intent/access-intent";
import type { PathExtractorLookup } from "../utils/access-intent/tool-input-path";
import type { ShellToolsConfig } from "../utils/access-intent/input-normalizer";
import type { PathNormalizer, ResolvedPathValue } from "../utils/path/path-normalizer";
import type { PermissionCheckResult } from "../contracts";
import type { PermissionManager, PolicyLoaderView } from "./permission-manager";

export interface GateCheckRequest {
  readonly toolName: string;
  readonly input: unknown;
  readonly agent?: string;
}

export interface PathCheckOptions {
  readonly agent?: string;
  /** Base directory for relative literals; defaults to the session cwd. */
  readonly baseDir?: string;
  /** Tool name reported on the result; defaults to the surface. */
  readonly toolName?: string;
}

export interface PermissionResolverOptions {
  readonly manager: PermissionManager;
  readonly normalizer: PathNormalizer;
  readonly shellTools?: ShellToolsConfig;
  readonly mcpConfigServers?: readonly string[] | (() => readonly string[]);
  readonly extractorLookup?: PathExtractorLookup;
}

export class PermissionResolver {
  private readonly manager: PermissionManager;
  private readonly normalizer: PathNormalizer;
  private readonly shellTools: ShellToolsConfig | undefined;
  private readonly mcpConfigServers: (() => readonly string[]) | undefined;
  private readonly extractorLookup: PathExtractorLookup | undefined;

  constructor(options: PermissionResolverOptions) {
    this.manager = options.manager;
    this.normalizer = options.normalizer;
    this.shellTools = options.shellTools;
    const mcpConfigServers = options.mcpConfigServers;
    this.mcpConfigServers = mcpConfigServers === undefined
      ? undefined
      : typeof mcpConfigServers === "function"
        ? mcpConfigServers
        : () => mcpConfigServers;
    this.extractorLookup = options.extractorLookup;
  }

  /** Resolve a raw tool call into the intent kind the policy manager consumes. */
  buildIntent(toolName: string, input: unknown, agent?: string, policy?: PolicyLoaderView): AccessIntent {
    const mcpConfigServers = policy?.mcpServerNames ?? this.mcpConfigServers?.();
    return buildAccessIntent(toolName, input, {
      normalizer: this.normalizer,
      ...(this.shellTools === undefined ? {} : { shellTools: this.shellTools }),
      ...(mcpConfigServers === undefined ? {} : { mcpConfigServers }),
      ...(this.extractorLookup === undefined ? {} : { extractorLookup: this.extractorLookup }),
      ...(agent === undefined ? {} : { agent }),
    });
  }

  check(request: GateCheckRequest): PermissionCheckResult {
    const policy = this.manager.loadPolicyView(request.agent);
    const intent = this.buildIntent(request.toolName, request.input, request.agent, policy);
    return this.manager.check(intent, { toolName: request.toolName }, policy);
  }

  /** Check one path literal on a surface, resolving it with the session cwd. */
  checkPath(
    surface: string,
    literal: string,
    options: PathCheckOptions = {},
  ): PermissionCheckResult {
    const path = this.normalizer.normalPath(
      literal,
      options.baseDir ?? this.normalizer.cwd,
    );
    return this.checkPathValues(surface, [path], options);
  }

  /** Check already resolved path values without rebuilding them. */
  checkPathValues(
    surface: string,
    paths: readonly ResolvedPathValue[],
    options: PathCheckOptions = {},
  ): PermissionCheckResult {
    return this.manager.check(
      pathValuesIntent(surface, paths, options.agent),
      options.toolName === undefined ? {} : { toolName: options.toolName },
    );
  }
}
