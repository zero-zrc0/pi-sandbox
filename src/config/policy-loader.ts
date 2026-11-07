/**
 * Policy loader (specs/config-loading.md section 4).
 *
 * Resolves the four permission scopes, the effective MCP server names and a
 * combined cache stamp for the policy manager. The manager only asks for a
 * view; this module owns which files back each scope and how they are read.
 *
 * Only combination problems are reported here — a fail-closed project scope
 * and the legacy MCP key — because the configuration issue reporter owns the
 * schema details. A global configuration problem never invalidates policy: the
 * global scope is the floor the manager evaluates against, so an unreadable
 * global file simply contributes no permission rules.
 *
 * File contents are cached by path and mtime. A load re-stats every candidate
 * file (the stamp must observe changes) but re-reads only files whose mtime is
 * new, so the policy manager can poll as often as it likes.
 */
import {
  createConfigFileReader,
  createConfigFileStat,
  normalizeFlatPermissionValue,
  stripJsonComments,
  type ConfigFileContent,
  type ConfigFileReader,
  type ConfigFileStat,
  type ConfigMessage,
} from "#config/config-loader";
import { joinPath, type ConfigPaths } from "#config/config-paths";
import type { FlatPermissionConfig } from "#config/config-schema";
import { parseApprovalChainConfig } from "#config/schema";
import { readFrontmatterMap } from "#config/yaml-frontmatter";

export type PolicyScopeName = "global" | "project" | "agent" | "project-agent";

/** One scope as the policy manager sees it. */
export interface PolicyScopeView {
  readonly permission?: FlatPermissionConfig;
  readonly invalid?: boolean;
}

/** Resolved file behind each scope; absent when the scope is unavailable. */
export interface PolicyScopeFiles {
  readonly globalConfigFile: string;
  readonly projectConfigFile?: string;
  readonly agentFile?: string;
  readonly projectAgentFile?: string;
  readonly mcpGlobalFile?: string;
  readonly mcpProjectFile?: string;
}

/** Complete loader result consumed by the policy manager. */
export interface PolicyLoaderView {
  readonly scopes: Partial<Record<PolicyScopeName, PolicyScopeView>>;
  readonly mcpServerNames: readonly string[];
  readonly stamp: string;
  readonly paths: PolicyScopeFiles;
  readonly messages: readonly ConfigMessage[];
}

export interface PolicyLoaderOptions {
  readonly paths: ConfigPaths;
  /** Empty means no project scope. */
  readonly cwd: string;
  /** An untrusted project never contributes a scope. */
  readonly projectTrusted: boolean;
  /** Global agent markdown directory; empty disables agent scopes. */
  readonly globalAgentsDir: string;
  /** Global MCP configuration; absent or empty means it is not read. */
  readonly mcpConfigFile?: string;
  /** Project MCP configuration; only read while the project scope is available. */
  readonly projectMcpConfigFile?: string;
  /** Explicit MCP server names that replace reading MCP files. */
  readonly mcpServerNames?: readonly string[];
  readonly readFile?: ConfigFileReader;
  readonly readMtime?: ConfigFileStat;
}

export interface PolicyLoader {
  load(agentName?: string): PolicyLoaderView;
}

/* ------------------------------------------------------------------ */
/* Fixed display messages                                              */
/* ------------------------------------------------------------------ */

const PROJECT_INVALID_MESSAGE =
  "The project permission configuration could not be loaded; allow rules inherited from the global scope require confirmation instead.";
const AGENT_INVALID_MESSAGE =
  "The agent permission file could not be loaded; allow rules inherited from the global scope require confirmation instead.";
const PROJECT_AGENT_INVALID_MESSAGE =
  "The project agent permission file could not be loaded; allow rules inherited from the global scope require confirmation instead.";
const MCP_KEY_MIGRATION_MESSAGE =
  'The legacy "mcp-servers" key is deprecated; rename it to "mcpServers".';

/* ------------------------------------------------------------------ */
/* Internal shapes                                                     */
/* ------------------------------------------------------------------ */

type ParsePurpose = "config" | "agent" | "mcp";

interface FileCacheEntry {
  readonly mtime: number;
  readonly content: ConfigFileContent;
  /** Parsed views derived from the cached text, one per consumer kind. */
  readonly derived: Map<ParsePurpose, unknown>;
}

type ParsedConfigScope =
  | { readonly state: "missing" }
  | { readonly state: "invalid" }
  | { readonly state: "valid"; readonly permission?: FlatPermissionConfig };

interface McpFileResult {
  readonly names: readonly string[];
  readonly legacyKey: boolean;
}

interface JsonParseOutcome {
  readonly ok: boolean;
  readonly value?: unknown;
}

const EMPTY_SCOPE: PolicyScopeView = Object.freeze({});
const INVALID_SCOPE: PolicyScopeView = Object.freeze({ invalid: true });
const EMPTY_MCP_RESULT: McpFileResult = Object.freeze({
  names: Object.freeze([]) as readonly string[],
  legacyKey: false,
});

/* ------------------------------------------------------------------ */
/* Loader                                                              */
/* ------------------------------------------------------------------ */

export function createPolicyLoader(options: PolicyLoaderOptions): PolicyLoader {
  const readFile = options.readFile ?? createConfigFileReader();
  const readMtime = options.readMtime ?? createConfigFileStat();
  const cache = new Map<string, FileCacheEntry>();
  const overrideServerNames =
    options.mcpServerNames === undefined
      ? undefined
      : (Object.freeze(normalizeServerNames(options.mcpServerNames)) as readonly string[]);

  function readContent(path: string): ConfigFileContent {
    try {
      return readFile(path);
    } catch (error) {
      // A throwing reader is a failed read, never a reason to allow more.
      return { state: "unreadable", reason: error instanceof Error ? error.message : String(error) };
    }
  }

  function mtimeOf(path: string): number | undefined {
    try {
      return readMtime(path);
    } catch {
      return undefined;
    }
  }

  function entryFor(path: string, mtime: number): FileCacheEntry {
    const cached = cache.get(path);
    if (cached !== undefined && cached.mtime === mtime) return cached;
    const entry: FileCacheEntry = { mtime, content: readContent(path), derived: new Map() };
    cache.set(path, entry);
    return entry;
  }

  function memo<T>(entry: FileCacheEntry, purpose: ParsePurpose, compute: () => T): T {
    if (entry.derived.has(purpose)) return entry.derived.get(purpose) as T;
    const value = compute();
    entry.derived.set(purpose, value);
    return value;
  }

  function configScopeFor(path: string, mtime: number | undefined): ParsedConfigScope {
    if (mtime === undefined) return { state: "missing" };
    const entry = entryFor(path, mtime);
    const content = entry.content;
    if (content.state === "missing") return { state: "missing" };
    if (content.state === "unreadable") return { state: "invalid" };
    const text = content.text;
    return memo(entry, "config", (): ParsedConfigScope => {
      const parsedJson = parseJsonc(text);
      if (!parsedJson.ok) return { state: "invalid" };
      const parsedConfig = parseApprovalChainConfig(parsedJson.value);
      if (!parsedConfig.ok) return { state: "invalid" };
      const permission = parsedConfig.config.permission;
      return permission === undefined
        ? { state: "valid" }
        : { state: "valid", permission: freezePermission(permission) };
    });
  }

  function agentScopeFor(path: string, mtime: number | undefined): ParsedConfigScope {
    if (mtime === undefined) return { state: "missing" };
    const entry = entryFor(path, mtime);
    const content = entry.content;
    if (content.state === "missing") return { state: "missing" };
    if (content.state === "unreadable") return { state: "invalid" };
    const text = content.text;
    return memo(entry, "agent", (): ParsedConfigScope => {
      const frontmatter = readFrontmatterMap(text);
      if (!Object.prototype.hasOwnProperty.call(frontmatter, "permission")) return { state: "valid" };
      const permission = normalizeFlatPermissionValue(frontmatter.permission);
      return permission === undefined
        ? { state: "valid" }
        : { state: "valid", permission: freezePermission(permission) };
    });
  }

  function mcpFileFor(path: string | undefined, mtime: number | undefined): McpFileResult | undefined {
    if (path === undefined || mtime === undefined) return undefined;
    const entry = entryFor(path, mtime);
    if (entry.content.state !== "text") return undefined;
    const text = entry.content.text;
    return memo(entry, "mcp", () => parseMcpDocument(text));
  }

  function loadView(requestedAgentName: string | undefined): PolicyLoaderView {
    const projectAvailable = options.cwd.trim() !== "" && options.projectTrusted === true;
    const agentName = normalizeAgentName(requestedAgentName);
    const agentAvailable = agentName !== undefined && options.globalAgentsDir.trim() !== "";
    const projectAgentAvailable =
      projectAvailable && agentAvailable && options.paths.projectAgentsDir.trim() !== "";

    const agentFile =
      agentName !== undefined && agentAvailable
        ? joinPath(options.globalAgentsDir, `${agentName}.md`)
        : undefined;
    const projectAgentFile =
      agentName !== undefined && projectAgentAvailable
        ? joinPath(options.paths.projectAgentsDir, `${agentName}.md`)
        : undefined;

    const configuredMcpGlobal = nonEmptyPath(options.mcpConfigFile);
    const configuredMcpProject = projectAvailable ? nonEmptyPath(options.projectMcpConfigFile) : undefined;
    const bypassMcpFiles = overrideServerNames !== undefined;
    const readMcpGlobal = bypassMcpFiles ? undefined : configuredMcpGlobal;
    const readMcpProject = bypassMcpFiles ? undefined : configuredMcpProject;

    // Stat every candidate once per load: the stamp has to observe changes.
    const globalMtime = mtimeOf(options.paths.globalConfigFile);
    const projectMtime = projectAvailable ? mtimeOf(options.paths.projectConfigFile) : undefined;
    const agentMtime = agentFile === undefined ? undefined : mtimeOf(agentFile);
    const projectAgentMtime =
      projectAgentFile === undefined ? undefined : mtimeOf(projectAgentFile);
    const mcpGlobalMtime = readMcpGlobal === undefined ? undefined : mtimeOf(readMcpGlobal);
    const mcpProjectMtime = readMcpProject === undefined ? undefined : mtimeOf(readMcpProject);

    const stamp = [
      `g=${stampValue(globalMtime)}`,
      `p=${projectAvailable ? stampValue(projectMtime) : "-"}`,
      `a=${agentFile === undefined ? "-" : stampValue(agentMtime)}`,
      `pa=${projectAgentFile === undefined ? "-" : stampValue(projectAgentMtime)}`,
      `m=${readMcpGlobal === undefined ? "-" : stampValue(mcpGlobalMtime)}`,
      `pm=${readMcpProject === undefined ? "-" : stampValue(mcpProjectMtime)}`,
    ].join("|");

    const scopes: Partial<Record<PolicyScopeName, PolicyScopeView>> = {};
    const messages: ConfigMessage[] = [];

    // Global scope: never invalid, never produces a message.
    const globalScope = configScopeFor(options.paths.globalConfigFile, globalMtime);
    scopes.global = globalScope.state === "valid" ? permissionScope(globalScope.permission) : EMPTY_SCOPE;

    if (projectAvailable) {
      const projectScope = configScopeFor(options.paths.projectConfigFile, projectMtime);
      if (projectScope.state === "invalid") {
        scopes.project = INVALID_SCOPE;
        messages.push(invalidScopeMessage(options.paths.projectConfigFile, PROJECT_INVALID_MESSAGE));
      } else if (projectScope.state === "valid") {
        scopes.project = permissionScope(projectScope.permission);
      } else {
        scopes.project = EMPTY_SCOPE;
      }
    }

    if (agentFile !== undefined) {
      const agentScope = agentScopeFor(agentFile, agentMtime);
      if (agentScope.state === "invalid") {
        scopes.agent = INVALID_SCOPE;
        messages.push(invalidScopeMessage(agentFile, AGENT_INVALID_MESSAGE));
      } else if (agentScope.state === "valid") {
        scopes.agent = permissionScope(agentScope.permission);
      } else {
        scopes.agent = EMPTY_SCOPE;
      }
    }

    if (projectAgentFile !== undefined) {
      const projectAgentScope = agentScopeFor(projectAgentFile, projectAgentMtime);
      if (projectAgentScope.state === "invalid") {
        scopes["project-agent"] = INVALID_SCOPE;
        messages.push(invalidScopeMessage(projectAgentFile, PROJECT_AGENT_INVALID_MESSAGE));
      } else if (projectAgentScope.state === "valid") {
        scopes["project-agent"] = permissionScope(projectAgentScope.permission);
      } else {
        scopes["project-agent"] = EMPTY_SCOPE;
      }
    }

    let mcpServerNames: readonly string[];
    if (overrideServerNames !== undefined) {
      mcpServerNames = overrideServerNames;
    } else {
      const collected: string[] = [];
      const globalMcp = mcpFileFor(readMcpGlobal, mcpGlobalMtime);
      if (globalMcp !== undefined) {
        collected.push(...globalMcp.names);
        if (globalMcp.legacyKey && readMcpGlobal !== undefined) {
          messages.push(mcpMigrationMessage(readMcpGlobal));
        }
      }
      const projectMcp = mcpFileFor(readMcpProject, mcpProjectMtime);
      if (projectMcp !== undefined) {
        collected.push(...projectMcp.names);
        if (projectMcp.legacyKey && readMcpProject !== undefined) {
          messages.push(mcpMigrationMessage(readMcpProject));
        }
      }
      mcpServerNames = sortServerNames(collected);
    }

    const paths: PolicyScopeFiles = Object.freeze({
      globalConfigFile: options.paths.globalConfigFile,
      ...(projectAvailable ? { projectConfigFile: options.paths.projectConfigFile } : {}),
      ...(agentFile === undefined ? {} : { agentFile }),
      ...(projectAgentFile === undefined ? {} : { projectAgentFile }),
      ...(configuredMcpGlobal === undefined ? {} : { mcpGlobalFile: configuredMcpGlobal }),
      ...(configuredMcpProject === undefined ? {} : { mcpProjectFile: configuredMcpProject }),
    });

    return Object.freeze({
      scopes: Object.freeze(scopes),
      mcpServerNames,
      stamp,
      paths,
      messages: Object.freeze(messages),
    });
  }

  return { load: (agentName?: string): PolicyLoaderView => loadView(agentName) };
}

/* ------------------------------------------------------------------ */
/* Pure helpers                                                        */
/* ------------------------------------------------------------------ */

function normalizeAgentName(name: string | undefined): string | undefined {
  if (name === undefined || name.length === 0) return undefined;
  if (/\s/u.test(name)) return undefined;
  if (name === "..") return undefined;
  if (name.includes("/") || name.includes("\\")) return undefined;
  return name;
}

function nonEmptyPath(value: string | undefined): string | undefined {
  return value === undefined || value.trim() === "" ? undefined : value;
}

function stampValue(mtime: number | undefined): string {
  return mtime === undefined ? "missing" : String(mtime);
}

function permissionScope(permission: FlatPermissionConfig | undefined): PolicyScopeView {
  return permission === undefined ? EMPTY_SCOPE : Object.freeze({ permission });
}

function invalidScopeMessage(file: string, message: string): ConfigMessage {
  return Object.freeze({ code: "invalid-scope", file, path: "", message });
}

function mcpMigrationMessage(file: string): ConfigMessage {
  return Object.freeze({
    code: "mcp-key-migration",
    file,
    path: "mcp-servers",
    message: MCP_KEY_MIGRATION_MESSAGE,
  });
}

/** Trim, drop empty and dedupe names in first-occurrence order. */
function normalizeServerNames(names: readonly string[]): readonly string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const name of names) {
    const trimmed = name.trim();
    if (trimmed.length === 0 || seen.has(trimmed)) continue;
    seen.add(trimmed);
    result.push(trimmed);
  }
  return result;
}

/**
 * Sort names by length (descending) and then by code point (ascending), so a
 * tool name is matched against longer servers before its prefixes. Locale
 * collation is deliberately avoided: matching must be deterministic.
 */
function sortServerNames(names: readonly string[]): readonly string[] {
  const sorted = [...normalizeServerNames(names)];
  sorted.sort(
    (left, right) => right.length - left.length || (left < right ? -1 : left > right ? 1 : 0),
  );
  return Object.freeze(sorted) as readonly string[];
}

function parseJsonc(text: string): JsonParseOutcome {
  try {
    return { ok: true, value: JSON.parse(stripJsonComments(text)) as unknown };
  } catch {
    return { ok: false };
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function parseMcpDocument(text: string): McpFileResult {
  const parsed = parseJsonc(text);
  if (!parsed.ok || !isPlainObject(parsed.value)) return EMPTY_MCP_RESULT;
  const record = parsed.value;
  const modern = record.mcpServers;
  if (isPlainObject(modern)) return { names: Object.keys(modern), legacyKey: false };
  const legacy = record["mcp-servers"];
  if (isPlainObject(legacy)) return { names: Object.keys(legacy), legacyKey: true };
  return EMPTY_MCP_RESULT;
}

function freezePermission(permission: FlatPermissionConfig): FlatPermissionConfig {
  for (const surfaceValue of Object.values(permission)) {
    if (typeof surfaceValue !== "object" || surfaceValue === null) continue;
    for (const patternValue of Object.values(surfaceValue)) {
      if (typeof patternValue === "object" && patternValue !== null) Object.freeze(patternValue);
    }
    Object.freeze(surfaceValue);
  }
  return Object.freeze(permission) as FlatPermissionConfig;
}
