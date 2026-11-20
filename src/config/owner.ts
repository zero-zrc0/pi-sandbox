/**
 * Formal approval-chain configuration owner (specs/config-loading.md sections
 * 5-9).
 *
 * The owner is the single authority over the formal `config.json` of the
 * extension. It reads the global and project scopes, enforces the trust and
 * user-scope boundaries and normalizes execution network hosts against the
 * injected platform. It composes the effective approval nodes, publishes one
 * immutable snapshot with a stable revision, and writes configuration files
 * atomically.
 *
 * Effective node composition is shared with the approval contracts through a
 * small pure module, while this owner retains configuration loading and fallback.
 *
 * Everything host specific is injected: paths, working directory, trust, file
 * reader, platform and temporary file names. No function in this module reads
 * this module reads the ambient working directory, environment or platform.
 */
import { createHash, randomBytes } from "node:crypto";
import { closeSync, fsyncSync, mkdirSync, openSync, renameSync, unlinkSync, writeSync } from "node:fs";
import { dirname, join } from "node:path";
import { domainToASCII } from "node:url";
import {
  describeEffectiveNodes as composeEffectiveNodes,
  type EffectiveNodeConfiguration,
} from "#approve-core/effective-nodes";
import { wildcardMatch } from "#approve-core/policy/wildcard-matcher";
import type { ScopedToolRule, ToolRule } from "#approve-core/policy/tool-rules";
import {
  createConfigFileReader,
  extractRuntimeFields,
  mergeRuntimeConfigs,
  messagesFromIssues,
  stripJsonComments,
  type ConfigFileReader,
  type ConfigMessage,
} from "#config/config-loader";
import type { ConfigPaths } from "#config/config-paths";
import { DEFAULT_NETWORK_PORTS } from "#config/execution-source-schema";
import type {
  NetworkScope,
  ShellExecutionPermissions,
} from "#config/execution-source-schema";
import { mergeShellPolicies } from "#approve-core/policy/shell-policy/merge";
import {
  PERMISSION_MODES,
  parseApprovalChainConfig,
  stripLegacyMcpSandbox,
  toNodeEntries,
  type ApprovalChainConfig,
  type ApprovalNodeDeclaration,
  type PermissionModeName,
} from "#config/schema";
import { migrateToolBindings, type ToolRuleDeclaration } from "#config/tool-rule-schema";

/* ------------------------------------------------------------------------- */
/* Public contracts                                                           */
/* ------------------------------------------------------------------------- */

/** Which scope produced the effective configuration. */
export type ConfigSourceName = "default" | "global" | "project" | "invalid";

/** Which scope contributed the effective permission mode. */
export type ModeSourceName = "default" | "global" | "project" | "session";

/** One immutable view of the effective approval-chain configuration. */
export interface ApprovalChainConfigSnapshot {
  /** Effective configuration: mode, runtime fields, execution and approval nodes. */
  readonly config: ApprovalChainConfig;
  /** Normalized global configuration. */
  readonly globalConfig: ApprovalChainConfig;
  /** Normalized project configuration when it exists and is valid. */
  readonly projectConfig?: ApprovalChainConfig;
  readonly paths: ConfigPaths;
  readonly cwd: string;
  readonly projectTrusted: boolean;
  readonly projectConfigInvalid: boolean;
  readonly source: ConfigSourceName;
  readonly modeSource: ModeSourceName;
  readonly canWrite: boolean;
  readonly revision: number;
  readonly issues: readonly ConfigMessage[];
  /** Effective node order, warnings and digest. */
  readonly nodeConfig: EffectiveNodeConfiguration;
  /**
   * Admission rules in evaluation order: project declarations first, then
   * global declarations, each in declaration order (§5.2).
   */
  readonly toolRules: readonly ScopedToolRule[];
  readonly sessionId?: string;
}

export interface ApprovalChainConfigOwnerOptions {
  readonly paths: ConfigPaths;
  /** Empty means the project scope is unavailable. */
  readonly cwd: string;
  readonly projectTrusted: boolean;
  readonly readFile?: ConfigFileReader;
  /** Host path/host normalization platform; defaults to "posix". */
  readonly platform?: NodeJS.Platform | "posix" | "win32" | string;
  /** Host-resolved variables available in shell filesystem grants. */
  readonly shellPathVariables?: ShellPathVariables;
  /** Atomic-write temporary file name; defaults to a random hidden name. */
  readonly tempName?: () => string;
  /** Clock port reserved for callers that need time-dependent decisions. */
  readonly now?: () => number;
}

export interface ShellPathVariables {
  readonly workspace: string;
  readonly tempDir: string;
}

export type ConfigSaveFailureCode = "not-writable" | "invalid-config" | "write-failed";

export type ConfigSaveResult =
  | { readonly ok: true; readonly snapshot: ApprovalChainConfigSnapshot }
  | {
      readonly ok: false;
      readonly code: ConfigSaveFailureCode;
      readonly messages: readonly ConfigMessage[];
    };

export type ProjectRuleFailureCode =
  | "not-trusted"
  | "no-project"
  | "corrupt-file"
  | "legacy-execution"
  | "denied-by-policy"
  | "invalid-config"
  | "write-failed";

export type ProjectRuleSaveResult =
  | { readonly ok: true; readonly snapshot: ApprovalChainConfigSnapshot }
  | {
      readonly ok: false;
      readonly code: ProjectRuleFailureCode;
      readonly messages: readonly ConfigMessage[];
    };

export interface ProjectRuleInput {
  /** Any non-empty surface name, including `path_*` directions. */
  readonly surface: string;
  /** Non-empty rule pattern. */
  readonly pattern: string;
}

export interface ProjectRuleSaveOptions {
  readonly sessionId?: string;
}

export interface ApprovalChainConfigReloadCandidate {
  readonly snapshot: ApprovalChainConfigSnapshot;
  commit(): boolean;
}

export interface ApprovalChainConfigOwner {
  snapshot(options?: { readonly sessionId?: string }): ApprovalChainConfigSnapshot;
  reload(options?: { readonly sessionId?: string }): ApprovalChainConfigSnapshot;
  prepareReload(options?: { readonly sessionId?: string }): ApprovalChainConfigReloadCandidate;
  /** Overwrite the global file with a complete formal configuration. */
  save(next: unknown, options?: { readonly sessionId?: string }): ConfigSaveResult;
  update(
    mutate: (current: ApprovalChainConfig) => unknown,
    options?: { readonly sessionId?: string },
  ): ConfigSaveResult;
  setMode(mode: PermissionModeName, options?: { readonly sessionId?: string }): ConfigSaveResult;
  setSessionMode(sessionId: string | undefined, mode: PermissionModeName | null): void;
  saveProjectRule(input: ProjectRuleInput, options?: ProjectRuleSaveOptions): ProjectRuleSaveResult;
}

/* ------------------------------------------------------------------------- */
/* Shared value helpers                                                       */
/* ------------------------------------------------------------------------- */

type JsonRecord = Record<string, unknown>;

function isPlainObject(value: unknown): value is JsonRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasOwn(value: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

/** Deep-freeze a value tree; returns the same reference for convenience. */
function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

/**
 * Serialize a JSON value with object keys sorted, so a digest depends on the
 * content and not on declaration order. `undefined` members are skipped exactly
 * like `JSON.stringify` skips them.
 */
function stableSerialize(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableSerialize(entry === undefined ? null : entry)).join(",")}]`;
  }
  if (typeof value === "object") {
    const object = value as Record<string, unknown>;
    const entries = Object.keys(object)
      .filter((key) => object[key] !== undefined)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableSerialize(object[key])}`);
    return `{${entries.join(",")}}`;
  }
  return "null";
}

/** sha256 of the stable JSON form. */
function stableDigest(value: unknown): string {
  return createHash("sha256").update(stableSerialize(value)).digest("hex");
}

function asciiLower(value: string): string {
  return value.replace(/[A-Z]/g, (character) => character.toLowerCase());
}

function errorDetail(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function displayMessage(
  code: string,
  file: string | undefined,
  path: string,
  message: string,
): ConfigMessage {
  return file === undefined ? { code, path, message } : { code, file, path, message };
}

/** The configuration produced by parsing an empty document: the schema defaults. */
function defaultApprovalChainConfig(): ApprovalChainConfig {
  const parsed = parseApprovalChainConfig({});
  if (!parsed.ok) throw new Error("The approval-chain schema defaults are not parseable");
  return parsed.config;
}

/* ------------------------------------------------------------------------- */
/* Platform path normalization (exported pure functions)                      */
/* ------------------------------------------------------------------------- */

function isWindowsPlatform(platform: string): boolean {
  return platform === "win32";
}

interface SplitAbsolutePath {
  readonly kind: "posix" | "drive" | "unc";
  /** Fixed root segments: `[]` for POSIX, `["C:"]` for a drive, `[server, share]` for UNC. */
  readonly root: readonly string[];
  readonly segments: readonly string[];
}

function splitSeparators(value: string): string[] {
  return value.split(/[\\/]/u);
}

function splitAbsolutePath(value: string, windows: boolean): SplitAbsolutePath | undefined {
  if (!windows) {
    if (!value.startsWith("/")) return undefined;
    return { kind: "posix", root: [], segments: splitSeparators(value.slice(1)) };
  }
  const drive = /^([A-Za-z]):[\\/]/u.exec(value);
  if (drive !== null) {
    return {
      kind: "drive",
      root: [`${drive[1]!.toUpperCase()}:`],
      segments: splitSeparators(value.slice(drive[0].length)),
    };
  }
  const unc = /^[\\/]{2}/u.exec(value);
  if (unc !== null) {
    const parts = splitSeparators(value.slice(2)).filter((part) => part.length > 0);
    if (parts.length < 2) return { kind: "unc", root: [], segments: [] };
    return { kind: "unc", root: [parts[0]!, parts[1]!], segments: parts.slice(2) };
  }
  return undefined;
}

/**
 * Resolve one declared execution grant to a host path.
 *
 * A relative grant is resolved against `baseDir`; a POSIX absolute path, a
 * Windows drive path or a Windows UNC path is taken as-is. Dot segments are
 * folded and `..` stops at the root instead of escaping it. The separator style
 * follows the injected platform, never the host `process.platform`.
 *
 * Returns `undefined` for an empty, whitespace-only or NUL-containing grant.
 */
export function resolveExecutionGrantPath(
  baseDir: string,
  grantPath: string,
  platform: NodeJS.Platform | "posix" | "win32" | string = "posix",
): string | undefined {
  if (grantPath.length === 0 || grantPath.trim().length === 0) return undefined;
  if (grantPath.includes("\u0000")) return undefined;
  const windows = isWindowsPlatform(platform);
  const grantAbsolute = splitAbsolutePath(grantPath, windows);

  let rootKind: "posix" | "drive" | "unc";
  let root: readonly string[];
  let segments: readonly string[];
  if (grantAbsolute !== undefined) {
    rootKind = grantAbsolute.kind;
    root = grantAbsolute.root;
    segments = grantAbsolute.segments;
  } else {
    const baseAbsolute = splitAbsolutePath(baseDir, windows);
    if (baseAbsolute === undefined) {
      rootKind = windows ? "drive" : "posix";
      root = [];
      segments = [...splitSeparators(baseDir).filter((part) => part.length > 0), ...splitSeparators(grantPath)];
    } else {
      rootKind = baseAbsolute.kind;
      root = baseAbsolute.root;
      segments = [...baseAbsolute.segments, ...splitSeparators(grantPath)];
    }
  }

  // `rootSegments` is the floor a `..` cannot pop past.
  const rootSegments = root.length;
  const folded: string[] = [...root];
  for (const segment of segments) {
    if (segment.length === 0 || segment === ".") continue;
    if (segment === "..") {
      if (folded.length > rootSegments) folded.pop();
      continue;
    }
    folded.push(segment);
  }
  const rest = folded.slice(rootSegments);
  if (rootKind === "posix") {
    return `/${rest.join("/")}`;
  }
  if (rootKind === "drive") {
    const drive = folded[0] ?? "C:";
    return rest.length === 0 ? `${drive}\\` : `${drive}\\${rest.join("\\")}`;
  }
  // UNC: the server and share are the root and can never be popped.
  const server = folded[0];
  const share = folded[1];
  if (server === undefined || share === undefined) return undefined;
  return rest.length === 0 ? `\\\\${server}\\${share}` : `\\\\${server}\\${share}\\${rest.join("\\")}`;
}

const FORBIDDEN_HOST_CHARACTERS = /[*/:@]/u;
const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u;

function stripTrailingDots(value: string): string {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 0x2e) end -= 1;
  return value.slice(0, end);
}

/**
 * Normalize one network host to its ASCII lower-case form.
 *
 * Whitespace and the characters `*`, `/`, `:`, `@` are rejected before the
 * IDNA conversion, trailing dots are dropped, and every resulting label must be
 * 1-63 characters of `[a-z0-9-]` starting and ending alphanumeric. IPv4
 * literals pass, IPv6 literals are rejected by the `:` rule.
 */
export function normalizeExecutionHost(host: string): string | undefined {
  if (typeof host !== "string") return undefined;
  if (/\s/u.test(host) || FORBIDDEN_HOST_CHARACTERS.test(host)) return undefined;
  const trimmed = stripTrailingDots(host);
  if (trimmed.length === 0) return undefined;
  const ascii = stripTrailingDots(domainToASCII(trimmed)).toLowerCase();
  if (ascii.length === 0 || ascii.length > 253) return undefined;
  for (const label of ascii.split(".")) {
    if (label.length === 0 || label.length > 63) return undefined;
    if (!HOST_LABEL.test(label)) return undefined;
  }
  return ascii;
}

/* ------------------------------------------------------------------------- */
/* Execution normalization                                                    */
/* ------------------------------------------------------------------------- */

function normalizeNetworkScope(scope: NetworkScope): NetworkScope | undefined {
  if (scope.mode !== "allowlist") return deepFreeze({ mode: scope.mode });
  const allow: { host: string; port?: number | "any" }[] = [];
  for (const destination of scope.allow) {
    const host = normalizeExecutionHost(destination.host);
    if (host === undefined) return undefined;
    if (destination.port === undefined) {
      for (const port of DEFAULT_NETWORK_PORTS) allow.push({ host, port });
    } else {
      allow.push({ host, port: destination.port });
    }
  }
  return deepFreeze({ mode: "allowlist" as const, allow: deepFreeze(allow) });
}

function normalizeFilesystemGrants(
  grants: readonly { readonly path: string; readonly granularity: "file" | "directory" }[],
  baseDir: string,
  platform: string,
): { path: string; granularity: "file" | "directory" }[] | undefined {
  const normalized: { path: string; granularity: "file" | "directory" }[] = [];
  for (const grant of grants) {
    const path = resolveExecutionGrantPath(baseDir, grant.path, platform);
    if (path === undefined) return undefined;
    normalized.push({ path, granularity: grant.granularity });
  }
  return normalized;
}

function normalizeDenyPaths(paths: readonly string[] | undefined, baseDir: string, platform: string): string[] | undefined {
  return paths?.map(path => path.startsWith("~") ? path : resolveExecutionGrantPath(baseDir, path, platform) ?? path);
}

function normalizeShellPermissions(
  permissions: ShellExecutionPermissions,
  baseDir: string,
  platform: string,
  variables: ShellPathVariables | undefined,
): ShellExecutionPermissions | undefined {
  const expand = (grant: ShellExecutionPermissions["filesystem"]["read"][number]) => {
    let unresolved = false;
    const path = grant.path.replace(/\$\{([^}]+)\}/gu, (placeholder, name: string) => {
      const value = name === "workspace" ? variables?.workspace
        : name === "tempDir" ? variables?.tempDir
          : undefined;
      if (value === undefined || value.trim().length === 0) {
        unresolved = true;
        return placeholder;
      }
      return value;
    });
    if (unresolved || path.includes("${")) return undefined;
    return { path, granularity: grant.granularity };
  };
  const expandGrants = (grants: ShellExecutionPermissions["filesystem"]["read"]) => {
    const expanded = grants.map(expand);
    return expanded.some((grant) => grant === undefined)
      ? undefined
      : expanded.filter((grant): grant is NonNullable<typeof grant> => grant !== undefined);
  };
  const readGrants = expandGrants(permissions.filesystem.read);
  const writeGrants = expandGrants(permissions.filesystem.write);
  if (readGrants === undefined || writeGrants === undefined) return undefined;
  const read = normalizeFilesystemGrants(readGrants, baseDir, platform);
  const write = normalizeFilesystemGrants(writeGrants, baseDir, platform);
  const network = normalizeNetworkScope(permissions.network);
  if (read === undefined || write === undefined || network === undefined) return undefined;
  return deepFreeze({ filesystem: { read, write }, network });
}

/* ------------------------------------------------------------------------- */
/* Execution ceiling checks                                                   */
/* ------------------------------------------------------------------------- */

function pathsEqual(left: string, right: string, windows: boolean): boolean {
  return windows ? asciiLower(left) === asciiLower(right) : left === right;
}

function isPathAtOrInside(child: string, parent: string, windows: boolean): boolean {
  if (pathsEqual(child, parent, windows)) return true;
  const separator = windows ? "\\" : "/";
  const prefix = parent.endsWith(separator) ? parent : `${parent}${separator}`;
  return windows
    ? asciiLower(child).startsWith(asciiLower(prefix))
    : child.startsWith(prefix);
}

function isFilesystemSubset(
  project: ShellExecutionPermissions["filesystem"],
  ceiling: ShellExecutionPermissions["filesystem"],
  windows: boolean,
): boolean {
  for (const direction of ["read", "write"] as const) {
    for (const grant of project[direction]) {
      const covered = ceiling[direction].some((limit) =>
        limit.granularity === "directory"
          ? isPathAtOrInside(grant.path, limit.path, windows)
          : grant.granularity === "file" && pathsEqual(grant.path, limit.path, windows));
      if (!covered) return false;
    }
  }
  return true;
}

function isNetworkSubset(project: NetworkScope, ceiling: NetworkScope): boolean {
  if (project.mode === "none") return true;
  if (ceiling.mode === "all") return true;
  if (ceiling.mode === "none") return false;
  if (project.mode !== "allowlist") return false;
  return project.allow.every((destination) =>
    ceiling.allow.some((limit) =>
      limit.host === destination.host
      && (limit.port === "any" || limit.port === destination.port)));
}

/* ------------------------------------------------------------------------- */
/* File reading                                                               */
/* ------------------------------------------------------------------------- */

type JsonFileRead =
  | { readonly state: "missing" }
  | { readonly state: "invalid"; readonly message: ConfigMessage }
  | { readonly state: "value"; readonly value: JsonRecord };

function readJsonObject(readFile: ConfigFileReader, path: string): JsonFileRead {
  const content = readFile(path);
  if (content.state === "missing") return { state: "missing" };
  if (content.state === "unreadable") {
    return {
      state: "invalid",
      message: displayMessage(
        "read-failed",
        path,
        "",
        `The configuration file could not be read (${content.reason}).`,
      ),
    };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(stripJsonComments(content.text));
  } catch (error) {
    return {
      state: "invalid",
      message: displayMessage(
        "parse-failed",
        path,
        "",
        `The configuration file is not valid JSON (${errorDetail(error)}).`,
      ),
    };
  }
  if (!isPlainObject(parsed)) {
    return {
      state: "invalid",
      message: displayMessage("invalid-config", path, "", "The configuration file must contain a JSON object."),
    };
  }
  return { state: "value", value: parsed };
}

/* ------------------------------------------------------------------------- */
/* Legacy declaration detection                                               */
/* ------------------------------------------------------------------------- */

interface LegacyDeclaration {
  readonly path: string;
  readonly detail: string;
}

function findLegacyDeclaration(raw: JsonRecord): LegacyDeclaration | undefined {
  const approver = raw.approver;
  if (isPlainObject(approver)) {
    const judge = approver.judge;
    if (isPlainObject(judge) && (judge.type === "endpoint" || judge.type === "profile")) {
      return { path: "approver.judge", detail: `a legacy judge type "${String(judge.type)}"` };
    }
  }
  return undefined;
}

/* ------------------------------------------------------------------------- */
/* Owner factory                                                              */
/* ------------------------------------------------------------------------- */

const MODE_RANK: Readonly<Record<PermissionModeName, number>> = Object.freeze({
  "read-only": 0,
  default: 1,
  "auto-review": 2,
  "full-access": 3,
});

/** Project declarations that only the user scope may own. */
const USER_SCOPE_FIELDS = ["approver", "learning", "toolBindings", "experimental"] as const;

/** Runtime fields a project scope may merge. */
const PROJECT_RUNTIME_FIELDS = [
  "debugLog",
  "permissionReviewLog",
  "doublePressToConfirm",
  "forwardingTimeoutMs",
  "promptTimeoutMs",
  "promptMaxRows",
  "promptFieldMaxWidth",
  "reviewLogFieldMaxWidth",
  "toolInputPreviewMaxLength",
  "toolTextSummaryMaxLength",
  "promptNotifications",
  "piInfrastructureReadPaths",
  "permission",
  "shellTools",
  "permissionDialogKeys",
] as const;

const NONE_NETWORK: NetworkScope = deepFreeze({ mode: "none" });
const NONE_SHELL: ShellExecutionPermissions = deepFreeze({
  filesystem: { read: [], write: [] },
  network: NONE_NETWORK,
});

interface GlobalLoad {
  readonly exists: boolean;
  readonly invalid: boolean;
  readonly config: ApprovalChainConfig;
  readonly messages: readonly ConfigMessage[];
}

interface ProjectLoad {
  readonly kind: "absent" | "invalid" | "valid";
  readonly messages: readonly ConfigMessage[];
  readonly config?: ApprovalChainConfig;
  readonly raw?: JsonRecord;
  readonly networkDeclared: boolean;
  readonly networkInvalid: boolean;
  readonly network?: NetworkScope;
  readonly shellDeclared: boolean;
  readonly shellUsable: boolean;
}

interface SnapshotInputs {
  readonly config: ApprovalChainConfig;
  readonly globalConfig: ApprovalChainConfig;
  readonly projectConfig?: ApprovalChainConfig;
  readonly projectConfigInvalid: boolean;
  readonly source: ConfigSourceName;
  readonly modeSource: ModeSourceName;
  readonly canWrite: boolean;
  readonly issues: readonly ConfigMessage[];
  readonly nodeConfig: EffectiveNodeConfiguration;
  readonly toolRules: readonly ScopedToolRule[];
  readonly sessionId?: string;
}

function isValidSessionId(sessionId: string | undefined): sessionId is string {
  return sessionId !== undefined && sessionId.trim().length > 0;
}

function normalizeSandboxPlatform(platform: string | undefined): string {
  return platform ?? "posix";
}

export function createApprovalChainConfigOwner(
  options: ApprovalChainConfigOwnerOptions,
): ApprovalChainConfigOwner {
  const readFile = options.readFile ?? createConfigFileReader();
  const platform = normalizeSandboxPlatform(options.platform);
  const windows = isWindowsPlatform(platform);
  const tempName = options.tempName ?? (() => `.config.${randomBytes(8).toString("hex")}.tmp`);
  const paths = options.paths;
  const cwd = options.cwd;
  const projectTrusted = options.projectTrusted;
  const shellPathVariables = options.shellPathVariables;

  /** Per-key `{ digest, revision }` counters (session or cwd+trust). */
  const revisions = new Map<string, { readonly digest: string; readonly revision: number }>();
  /** In-memory session mode overrides; never persisted and never published. */
  const sessionModes = new Map<string, PermissionModeName>();
  const sessionSnapshots = new Map<string, ApprovalChainConfigSnapshot>();
  let activeBaseSnapshot: ApprovalChainConfigSnapshot | undefined;
  let activeVersion = 0;

  const defaultConfig = defaultApprovalChainConfig();

  /* ---- messages ---- */

  const nodeConfigMessage = (reason: string): ConfigMessage => displayMessage(
    "node-config",
    paths.globalConfigFile,
    "approval.nodes",
    `The effective approval node configuration was rejected (${reason}).`,
  );

  /* ---- global scope ---- */

  function loadGlobal(messages: ConfigMessage[]): GlobalLoad {
    const read = readJsonObject(readFile, paths.globalConfigFile);
    if (read.state === "missing") {
      return { exists: false, invalid: false, config: defaultConfig, messages };
    }
    if (read.state === "invalid") {
      messages.push(read.message);
      return { exists: true, invalid: true, config: defaultConfig, messages };
    }
    const raw = stripLegacyMcpSandbox(read.value) as JsonRecord;
    const legacy = findLegacyDeclaration(raw);
    if (legacy !== undefined) {
      messages.push(displayMessage(
        "legacy-declaration",
        paths.globalConfigFile,
        legacy.path,
        `The configuration contains ${legacy.detail}; legacy declarations are not supported and the file is kept unchanged.`,
      ));
      return { exists: true, invalid: true, config: defaultConfig, messages };
    }

    let candidate: JsonRecord = raw;
    if (hasOwn(raw, "classifier") || hasOwn(raw, "classifierModel")) {
      const { classifier: _ignoredClassifier, classifierModel: _ignoredClassifierModel, ...rest } = raw;
      candidate = rest;
      messages.push(displayMessage(
        "migration",
        paths.globalConfigFile,
        "",
        "The legacy classifier configuration was ignored; its contents are not read.",
      ));
    }

    const parsed = parseApprovalChainConfig(candidate);
    if (!parsed.ok) {
      messages.push(...messagesFromIssues(paths.globalConfigFile, parsed.issues));
      return { exists: true, invalid: true, config: defaultConfig, messages };
    }

    const shellDeclared = isPlainObject(candidate.execution) && hasOwn(candidate.execution, "shell");
    const normalizedShell = parsed.config.execution.shell === undefined
      ? undefined
      : normalizeShellPermissions(parsed.config.execution.shell, paths.globalConfigDir, platform, shellPathVariables);
    const shell = shellDeclared ? normalizedShell ?? NONE_SHELL : undefined;
    if (shellDeclared && normalizedShell === undefined) {
      messages.push(displayMessage(
        "execution",
        paths.globalConfigFile,
        "execution.shell",
        "The global shell permissions contain an invalid host path or network destination; shell access is disabled.",
      ));
    }

    const declaredNetwork = parsed.config.execution.network;
    let network: NetworkScope | undefined;
    if (declaredNetwork !== undefined) {
      const normalized = normalizeNetworkScope(declaredNetwork);
      if (normalized === undefined) {
        network = NONE_NETWORK;
        messages.push(displayMessage(
          "network",
          paths.globalConfigFile,
          "execution.network",
          "The global execution network declares a host that is not valid; network access is disabled.",
        ));
      } else {
        network = normalized;
      }
    }
    const config = deepFreeze({
      ...parsed.config,
      execution: {
        ...(network === undefined ? {} : { network }),
        ...(shell === undefined ? {} : { shell }),
        ...(parsed.config.execution.denyPaths === undefined ? {} : {
          denyPaths: normalizeDenyPaths(parsed.config.execution.denyPaths, paths.globalConfigDir, platform),
        }),
      },
    });
    return { exists: true, invalid: false, config, messages };
  }

  /* ---- project scope ---- */

  function loadProject(messages: ConfigMessage[]): ProjectLoad {
    if (cwd.trim().length === 0) {
      return {
        kind: "absent",
        messages,
        networkDeclared: false,
        networkInvalid: false,
        shellDeclared: false,
        shellUsable: true,
      };
    }
    if (!projectTrusted) {
      const exists = readFile(paths.projectConfigFile).state !== "missing";
      if (exists) {
        messages.push(displayMessage(
          "untrusted-project",
          paths.projectConfigFile,
          "",
          "The project configuration was ignored because the project is not trusted.",
        ));
      }
      return {
        kind: "absent",
        messages,
        networkDeclared: false,
        networkInvalid: false,
        shellDeclared: false,
        shellUsable: true,
      };
    }

    const read = readJsonObject(readFile, paths.projectConfigFile);
    if (read.state === "missing") {
      return {
        kind: "absent",
        messages,
        networkDeclared: false,
        networkInvalid: false,
        shellDeclared: false,
        shellUsable: true,
      };
    }
    if (read.state === "invalid") {
      messages.push(read.message);
      return {
        kind: "invalid",
        messages,
        networkDeclared: false,
        networkInvalid: false,
        shellDeclared: false,
        shellUsable: false,
      };
    }
    const raw = stripLegacyMcpSandbox(read.value) as JsonRecord;
    const parsed = parseApprovalChainConfig(raw);
    if (!parsed.ok) {
      messages.push(...messagesFromIssues(paths.projectConfigFile, parsed.issues));
      return {
        kind: "invalid",
        messages,
        networkDeclared: false,
        networkInvalid: false,
        shellDeclared: false,
        shellUsable: false,
      };
    }

    const rawExecution = isPlainObject(raw.execution) ? raw.execution : undefined;
    const networkDeclared = rawExecution !== undefined && hasOwn(rawExecution, "network");
    const shellDeclared = rawExecution !== undefined && hasOwn(rawExecution, "shell");

    let network: NetworkScope | undefined;
    let networkInvalid = false;
    if (networkDeclared) {
      const declaredNetwork = parsed.config.execution.network;
      const normalized = declaredNetwork === undefined ? undefined : normalizeNetworkScope(declaredNetwork);
      if (normalized === undefined) {
        network = NONE_NETWORK;
        networkInvalid = true;
        messages.push(displayMessage(
          "network",
          paths.projectConfigFile,
          "execution.network",
          "The project execution network declares a host that is not valid; network access is disabled.",
        ));
      } else {
        network = normalized;
      }
    }

    const normalizedShell = parsed.config.execution.shell === undefined
      ? undefined
      : normalizeShellPermissions(parsed.config.execution.shell, paths.projectConfigDir, platform, shellPathVariables);
    const shellUsable = !shellDeclared || normalizedShell !== undefined;
    if (shellDeclared && normalizedShell === undefined) {
      messages.push(displayMessage(
        "execution",
        paths.projectConfigFile,
        "execution.shell",
        "The project shell permissions contain an invalid host path or network destination; shell access is disabled.",
      ));
    }

    const config = deepFreeze({
      ...parsed.config,
      execution: {
        ...(networkDeclared ? { network: network ?? NONE_NETWORK } : {}),
        ...(shellDeclared ? { shell: normalizedShell ?? NONE_SHELL } : {}),
        ...(parsed.config.execution.denyPaths === undefined ? {} : {
          denyPaths: normalizeDenyPaths(parsed.config.execution.denyPaths, paths.projectConfigDir, platform),
        }),
      },
    });
    return {
      kind: "valid",
      messages,
      config,
      raw,
      networkDeclared,
      networkInvalid,
      shellDeclared,
      shellUsable,
      ...(networkDeclared ? { network: network ?? NONE_NETWORK } : {}),
    };
  }

  /* ---- effective configuration ---- */

  function projectRuntimeOverride(project: ApprovalChainConfig, raw: JsonRecord): Record<string, unknown> {
    const override: Record<string, unknown> = {};
    for (const field of PROJECT_RUNTIME_FIELDS) {
      if (!hasOwn(raw, field)) continue;
      const value = (project as unknown as Record<string, unknown>)[field];
      if (value !== undefined) override[field] = value;
    }
    return override;
  }

  function foldCommandEffects(
    globalEffects: ApprovalChainConfig["commandEffects"],
    projectEffects: ApprovalChainConfig["commandEffects"],
  ): ApprovalChainConfig["commandEffects"] {
    if (globalEffects === undefined && projectEffects === undefined) return undefined;
    const folded: Record<string, unknown> = { ...(globalEffects ?? {}) };
    for (const [command, declaration] of Object.entries(projectEffects ?? {})) {
      folded[command] = declaration;
    }
    return deepFreeze(folded) as ApprovalChainConfig["commandEffects"];
  }

  function buildSnapshot(inputs: SnapshotInputs, commitRevision = true): ApprovalChainConfigSnapshot {
    const digest = stableDigest({
      config: inputs.config,
      globalConfig: inputs.globalConfig,
      projectConfig: inputs.projectConfig ?? null,
      source: inputs.source,
      modeSource: inputs.modeSource,
      canWrite: inputs.canWrite,
      nodeConfigDigest: inputs.nodeConfig.digest,
      toolRules: inputs.toolRules.map((entry) => [entry.scope, entry.rule.id]),
      projectTrusted,
      projectConfigInvalid: inputs.projectConfigInvalid,
    });
    const key = isValidSessionId(inputs.sessionId)
      ? `session:${inputs.sessionId}`
      : `${cwd}\u0000${projectTrusted}`;
    const previous = revisions.get(key);
    let revision: number;
    if (previous === undefined) revision = 1;
    else if (previous.digest === digest) revision = previous.revision;
    else revision = previous.revision + 1;
    if (commitRevision) revisions.set(key, { digest, revision });

    const snapshot: ApprovalChainConfigSnapshot = {
      config: deepFreeze(inputs.config),
      globalConfig: deepFreeze(inputs.globalConfig),
      ...(inputs.projectConfig === undefined ? {} : { projectConfig: inputs.projectConfig }),
      paths: deepFreeze({ ...paths }),
      cwd,
      projectTrusted,
      projectConfigInvalid: inputs.projectConfigInvalid,
      source: inputs.source,
      modeSource: inputs.modeSource,
      canWrite: inputs.canWrite,
      revision,
      issues: deepFreeze([...inputs.issues]),
      nodeConfig: inputs.nodeConfig,
      toolRules: deepFreeze([...inputs.toolRules]),
      ...(isValidSessionId(inputs.sessionId) ? { sessionId: inputs.sessionId } : {}),
    };
    return deepFreeze(snapshot);
  }

  /* ---- load pipeline ---- */

  function load(commitRevision = true): ApprovalChainConfigSnapshot {
    const messages: ConfigMessage[] = [];
    const globalLoad = loadGlobal(messages);
    if (globalLoad.invalid) {
      const nodeConfig = composeEffectiveNodes([], []);
      const config = defaultConfig;
      return buildSnapshot({
        config,
        globalConfig: config,
        projectConfigInvalid: false,
        source: "invalid",
        modeSource: "default",
        canWrite: false,
        issues: messages,
        nodeConfig: nodeConfig.ok ? nodeConfig.configuration : { nodes: [], warnings: [], digest: stableDigest({}) },
        toolRules: [],
      }, commitRevision);
    }

    const globalConfig = globalLoad.config;
    const projectLoad = loadProject(messages);
    const shellPolicyMerge = mergeShellPolicies(
      globalConfig.shellPolicy,
      projectLoad.kind === "valid" ? projectLoad.config?.shellPolicy : undefined,
    );
    for (const issue of shellPolicyMerge.issues) {
      messages.push(displayMessage(
        "shell-policy",
        paths.projectConfigFile,
        "shellPolicy",
        issue.detail,
      ));
    }

    /* -- effective nodes -- */
    const globalEntries = toNodeEntries(globalConfig.approval.nodes);
    const projectEntries = projectLoad.kind === "valid" && projectLoad.config !== undefined
      ? toNodeEntries(projectLoad.config.approval.nodes)
      : [];
    let composition = composeEffectiveNodes(globalEntries, projectEntries);
    let nodesMode: "combined" | "global" | "empty" = "combined";
    if (!composition.ok) {
      messages.push(nodeConfigMessage(composition.reason));
      composition = composeEffectiveNodes(globalEntries, []);
      nodesMode = "global";
    }
    if (!composition.ok) {
      messages.push(nodeConfigMessage(composition.reason));
      composition = composeEffectiveNodes([], []);
      nodesMode = "empty";
    }
    if (!composition.ok) {
      // Unreachable: an empty composition always succeeds.
      throw new Error(`Effective node composition failed: ${composition.reason}`);
    }
    const nodeConfig = composition.configuration;

    const projectDeclarations = projectLoad.kind === "valid" && projectLoad.config !== undefined
      ? projectLoad.config.approval.nodes
      : {};
    let nodesDeclaration: Readonly<Record<string, ApprovalNodeDeclaration>>;
    if (nodesMode === "empty") {
      nodesDeclaration = {};
    } else if (nodesMode === "global") {
      nodesDeclaration = globalConfig.approval.nodes;
    } else {
      const shadowed = new Set(nodeConfig.warnings.map((warning) => warning.id));
      const combined: Record<string, ApprovalNodeDeclaration> = { ...globalConfig.approval.nodes };
      for (const [id, declaration] of Object.entries(projectDeclarations)) {
        if (shadowed.has(id)) continue;
        combined[id] = declaration;
      }
      nodesDeclaration = combined;
    }

    /* -- effective mode -- */
    let mode = globalConfig.mode;
    let modeSource: ModeSourceName = globalLoad.exists ? "global" : "default";
    let projectContributed = false;
    let projectModeAdopted = false;
    if (projectLoad.kind === "valid" && projectLoad.raw !== undefined && projectLoad.config !== undefined) {
      const raw = projectLoad.raw;
      const project = projectLoad.config;
      if (hasOwn(raw, "mode") && MODE_RANK[project.mode] <= MODE_RANK[globalConfig.mode]) {
        mode = project.mode;
        modeSource = "project";
        projectModeAdopted = true;
      } else if (hasOwn(raw, "mode")) {
        messages.push(displayMessage(
          "mode-escalation",
          paths.projectConfigFile,
          "mode",
          `The project permission mode "${project.mode}" may not be less restrictive than the global mode "${globalConfig.mode}"; the global mode is kept.`,
        ));
      }
      for (const field of USER_SCOPE_FIELDS) {
        if (!hasOwn(raw, field)) continue;
        messages.push(displayMessage(
          "user-scope-only",
          paths.projectConfigFile,
          field,
          `"${field}" belongs to the user scope and cannot be set by the project configuration.`,
        ));
      }
    }
    if (projectModeAdopted) projectContributed = true;
    if (projectLoad.kind === "valid" && (projectLoad.config?.execution.denyPaths?.length ?? 0) > 0) {
      projectContributed = true;
    }

    /* -- engine runtime merge -- */
    const projectRuntime = projectLoad.kind === "valid" && projectLoad.config !== undefined && projectLoad.raw !== undefined
      ? projectRuntimeOverride(projectLoad.config, projectLoad.raw)
      : {};
    const mergedRuntime = projectLoad.kind === "valid"
      ? mergeRuntimeConfigs(extractRuntimeFields(globalConfig), projectRuntime)
      : extractRuntimeFields(globalConfig);
    if (Object.keys(projectRuntime).length > 0) projectContributed = true;

    /* -- effective top-level network -- */
    const globalNetwork = globalConfig.execution.network ?? NONE_NETWORK;
    let effectiveNetwork: NetworkScope = globalNetwork;
    if (projectLoad.kind === "invalid") {
      effectiveNetwork = NONE_NETWORK;
    } else if (projectLoad.kind === "valid" && projectLoad.networkDeclared) {
      const projectNetwork = projectLoad.network;
      if (projectLoad.networkInvalid || projectNetwork === undefined) {
        // The invalid host was already reported while normalizing the project.
        effectiveNetwork = NONE_NETWORK;
      } else if (isNetworkSubset(projectNetwork, globalNetwork)) {
        effectiveNetwork = projectNetwork;
        projectContributed = true;
      } else {
        effectiveNetwork = NONE_NETWORK;
        messages.push(displayMessage(
          "network",
          paths.projectConfigFile,
          "execution.network",
          "The project execution network exceeds the global network ceiling; network access is disabled.",
        ));
      }
    }

    let effectiveShell = globalConfig.execution.shell;
    if (projectLoad.kind === "invalid") {
      effectiveShell = NONE_SHELL;
    } else if (projectLoad.kind === "valid" && projectLoad.shellDeclared) {
      const projectShell = projectLoad.config?.execution.shell ?? NONE_SHELL;
      const globalShell = globalConfig.execution.shell;
      if (!projectLoad.shellUsable) {
        effectiveShell = NONE_SHELL;
      } else if (globalShell === undefined) {
        effectiveShell = NONE_SHELL;
        messages.push(displayMessage(
          "execution",
          paths.projectConfigFile,
          "execution.shell",
          "The project shell permissions have no global shell ceiling; shell access is disabled.",
        ));
      } else if (!isFilesystemSubset(projectShell.filesystem, globalShell.filesystem, windows) ||
          !isNetworkSubset(projectShell.network, globalShell.network)) {
        effectiveShell = NONE_SHELL;
        messages.push(displayMessage(
          "execution",
          paths.projectConfigFile,
          "execution.shell",
          "The project shell permissions exceed the global shell ceiling; shell access is disabled.",
        ));
      } else {
        effectiveShell = projectShell;
        projectContributed = true;
      }
    }

    /* -- nodes contribution and command effects -- */
    if (nodesMode === "combined" && projectLoad.kind === "valid") {
      const shadowed = new Set(nodeConfig.warnings.map((warning) => warning.id));
      const contributesNode = Object.keys(projectDeclarations).some((id) => !shadowed.has(id));
      if (contributesNode) projectContributed = true;
    }
    const projectEffects = projectLoad.kind === "valid" && projectLoad.raw !== undefined && hasOwn(projectLoad.raw, "commandEffects")
      ? projectLoad.config?.commandEffects
      : undefined;
    if (projectEffects !== undefined) projectContributed = true;
    const commandEffects = foldCommandEffects(globalConfig.commandEffects, projectEffects);
    if (projectLoad.kind === "valid" && projectLoad.config?.shellPolicy !== undefined &&
        stableDigest(shellPolicyMerge.policy ?? null) !== stableDigest(globalConfig.shellPolicy ?? null)) {
      projectContributed = true;
    }

    /* -- effective admission rules (design §5.4) -- */
    const projectRules = projectLoad.kind === "valid" && projectLoad.config !== undefined
      ? projectLoad.config.toolRules
      : [];
    const globalRules = globalConfig.toolRules;
    const migratedBindings = globalRules.length === 0 && projectRules.length === 0 &&
        globalConfig.toolBindings.length > 0
      ? migrateToolBindings(globalConfig.toolBindings)
      : undefined;
    if (migratedBindings !== undefined) {
      messages.push(displayMessage(
        "deprecated",
        paths.globalConfigFile,
        "toolBindings",
        "\"toolBindings\" is deprecated; its declarations were migrated into equivalent allow rules under \"toolRules\".",
      ));
    }
    const effectiveRules: readonly ToolRuleDeclaration[] =
      migratedBindings ?? [...projectRules, ...globalRules];
    const toolRules: readonly ScopedToolRule[] = migratedBindings === undefined
      ? [
          ...projectRules.map((rule) => Object.freeze({ scope: "project" as const, rule: rule as ToolRule })),
          ...globalRules.map((rule) => Object.freeze({ scope: "global" as const, rule: rule as ToolRule })),
        ]
      : migratedBindings.map((rule) => Object.freeze({ scope: "global" as const, rule: rule as ToolRule }));
    if (projectRules.length > 0) projectContributed = true;

    /* -- effective config -- */
    const config: ApprovalChainConfig = {
      ...mergedRuntime,
      mode,
      approver: globalConfig.approver,
      toolBindings: globalConfig.toolBindings,
      toolRules: effectiveRules,
      learning: globalConfig.learning,
      experimental: globalConfig.experimental,
      execution: {
        network: effectiveNetwork,
        ...(effectiveShell === undefined ? {} : { shell: effectiveShell }),
        ...((globalConfig.execution.denyPaths !== undefined || projectLoad.config?.execution.denyPaths !== undefined) ? {
          denyPaths: [...(globalConfig.execution.denyPaths ?? []), ...(projectLoad.config?.execution.denyPaths ?? [])],
        } : {}),
      },
      approval: { nodes: nodesDeclaration },
      ...(shellPolicyMerge.policy === undefined ? {} : { shellPolicy: shellPolicyMerge.policy }),
      ...(commandEffects === undefined ? {} : { commandEffects }),
      ...(globalConfig.$schema === undefined ? {} : { $schema: globalConfig.$schema }),
      ...(globalConfig.migration === undefined ? {} : { migration: globalConfig.migration }),
    } as ApprovalChainConfig;

    const source: ConfigSourceName = projectContributed
      ? "project"
      : globalLoad.exists
        ? "global"
        : "default";

    return buildSnapshot({
      config,
      globalConfig,
      ...(projectLoad.kind === "valid" && projectLoad.config !== undefined ? { projectConfig: projectLoad.config } : {}),
      projectConfigInvalid: projectLoad.kind === "invalid",
      source,
      modeSource,
      canWrite: true,
      issues: messages,
      nodeConfig,
      toolRules,
    }, commitRevision);
  }

  function snapshotInputs(base: ApprovalChainConfigSnapshot, sessionId: string): SnapshotInputs {
    const override = base.source === "invalid" ? undefined : sessionModes.get(sessionId);
    const config = override === undefined ? base.config : deepFreeze({ ...base.config, mode: override });
    return {
      config,
      globalConfig: base.globalConfig,
      ...(base.projectConfig === undefined ? {} : { projectConfig: base.projectConfig }),
      projectConfigInvalid: base.projectConfigInvalid,
      source: base.source,
      modeSource: override === undefined ? base.modeSource : "session",
      canWrite: base.canWrite,
      issues: base.issues,
      nodeConfig: base.nodeConfig,
      toolRules: base.toolRules,
      sessionId,
    };
  }

  function snapshotDigest(snapshot: ApprovalChainConfigSnapshot): string {
    return stableDigest({
      config: snapshot.config,
      globalConfig: snapshot.globalConfig,
      projectConfig: snapshot.projectConfig ?? null,
      source: snapshot.source,
      modeSource: snapshot.modeSource,
      canWrite: snapshot.canWrite,
      nodeConfigDigest: snapshot.nodeConfig.digest,
      toolRules: snapshot.toolRules.map((entry) => [entry.scope, entry.rule.id]),
      projectTrusted,
      projectConfigInvalid: snapshot.projectConfigInvalid,
    });
  }

  function rememberSnapshot(snapshot: ApprovalChainConfigSnapshot): void {
    const key = isValidSessionId(snapshot.sessionId)
      ? `session:${snapshot.sessionId}`
      : `${cwd}\u0000${projectTrusted}`;
    revisions.set(key, { digest: snapshotDigest(snapshot), revision: snapshot.revision });
  }

  function ensureActiveBase(): ApprovalChainConfigSnapshot {
    if (activeBaseSnapshot === undefined) {
      activeBaseSnapshot = load();
      activeVersion += 1;
    }
    return activeBaseSnapshot;
  }

  function getSnapshot(sessionId?: string): ApprovalChainConfigSnapshot {
    const base = ensureActiveBase();
    if (!isValidSessionId(sessionId)) return base;
    const cached = sessionSnapshots.get(sessionId);
    if (cached !== undefined) return cached;
    const view = buildSnapshot(snapshotInputs(base, sessionId));
    sessionSnapshots.set(sessionId, view);
    return view;
  }

  function snapshot(snapshotOptions?: { readonly sessionId?: string }): ApprovalChainConfigSnapshot {
    return getSnapshot(snapshotOptions?.sessionId);
  }

  function prepareReload(reloadOptions?: { readonly sessionId?: string }): ApprovalChainConfigReloadCandidate {
    const base = load(false);
    const sessionId = reloadOptions?.sessionId;
    const candidateSnapshot = isValidSessionId(sessionId)
      ? buildSnapshot(snapshotInputs(base, sessionId), false)
      : base;
    const preparedAtVersion = activeVersion;
    const preparedSessionMode = isValidSessionId(sessionId) ? sessionModes.get(sessionId) : undefined;
    let committed = false;
    return {
      snapshot: candidateSnapshot,
      commit() {
        if (committed || activeVersion !== preparedAtVersion) return false;
        if (isValidSessionId(sessionId) && sessionModes.get(sessionId) !== preparedSessionMode) return false;
        committed = true;
        activeBaseSnapshot = base;
        activeVersion += 1;
        sessionSnapshots.clear();
        rememberSnapshot(base);
        if (isValidSessionId(sessionId)) {
          rememberSnapshot(candidateSnapshot);
          sessionSnapshots.set(sessionId, candidateSnapshot);
        }
        return true;
      },
    };
  }

  function reload(reloadOptions?: { readonly sessionId?: string }): ApprovalChainConfigSnapshot {
    const candidate = prepareReload(reloadOptions);
    candidate.commit();
    return snapshot(reloadOptions);
  }

  /* ---- atomic write ---- */

  function atomicWrite(filePath: string, value: unknown): void {
    const directory = dirname(filePath);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const temporaryPath = join(directory, tempName());
    let handle: number | undefined;
    try {
      handle = openSync(temporaryPath, "wx", 0o600);
      writeSync(handle, `${JSON.stringify(value, null, 2)}\n`);
      fsyncSync(handle);
      closeSync(handle);
      handle = undefined;
      renameSync(temporaryPath, filePath);
    } catch (error) {
      if (handle !== undefined) {
        try {
          closeSync(handle);
        } catch {
          // Best effort: the write already failed.
        }
      }
      try {
        unlinkSync(temporaryPath);
      } catch {
        // Best effort: the temporary file may never have been created.
      }
      throw error;
    }
  }

  /* ---- save operations ---- */

  function saveFailure(
    code: ConfigSaveFailureCode,
    path: string,
    message: string,
  ): ConfigSaveResult {
    return { ok: false, code, messages: [displayMessage(code, paths.globalConfigFile, path, message)] };
  }

  function persistGlobalConfig(next: unknown, current: ApprovalChainConfigSnapshot): ConfigSaveResult {
    const persisted = stripLegacyMcpSandbox(next);
    const parsed = parseApprovalChainConfig(persisted);
    if (!parsed.ok) {
      return {
        ok: false,
        code: "invalid-config",
        messages: messagesFromIssues(paths.globalConfigFile, parsed.issues),
      };
    }
    try {
      atomicWrite(paths.globalConfigFile, persisted);
    } catch (error) {
      return saveFailure(
        "write-failed",
        "",
        `The configuration file could not be written (${errorDetail(error)}).`,
      );
    }
    return { ok: true, snapshot: current };
  }

  function save(next: unknown, saveOptions?: { readonly sessionId?: string }): ConfigSaveResult {
    const current = snapshot({ sessionId: saveOptions?.sessionId });
    if (!current.canWrite) {
      return saveFailure(
        "not-writable",
        "",
        "The global configuration cannot be written while the current file is invalid.",
      );
    }
    return persistGlobalConfig(next, current);
  }

  function update(
    mutate: (current: ApprovalChainConfig) => unknown,
    updateOptions?: { readonly sessionId?: string },
  ): ConfigSaveResult {
    const current = snapshot({ sessionId: updateOptions?.sessionId });
    const disk = load(false);
    if (!disk.canWrite) {
      return saveFailure(
        "not-writable",
        "",
        "The global configuration cannot be updated while the current file is invalid.",
      );
    }
    let next: unknown;
    try {
      next = mutate(disk.globalConfig);
    } catch (error) {
      return saveFailure(
        "invalid-config",
        "",
        `The configuration update failed (${errorDetail(error)}).`,
      );
    }
    return persistGlobalConfig(next, current);
  }

  function setMode(mode: PermissionModeName, saveOptions?: { readonly sessionId?: string }): ConfigSaveResult {
    if (!(PERMISSION_MODES as readonly string[]).includes(mode)) {
      return saveFailure("invalid-config", "mode", `Unknown permission mode "${String(mode)}".`);
    }
    return update((current) => ({ ...current, mode }), saveOptions);
  }

  function setSessionMode(sessionId: string | undefined, mode: PermissionModeName | null): void {
    if (!isValidSessionId(sessionId)) {
      if (mode === null) return;
      throw new Error("A session mode override requires a session id");
    }
    if (mode === null) sessionModes.delete(sessionId);
    else sessionModes.set(sessionId, mode);
    sessionSnapshots.delete(sessionId);
  }

  /* ---- project rule persistence ---- */

  function projectRuleFailure(
    code: ProjectRuleFailureCode,
    path: string,
    message: string,
  ): ProjectRuleSaveResult {
    return { ok: false, code, messages: [displayMessage(code, paths.projectConfigFile, path, message)] };
  }

  function collectDenyPatterns(surfaceValue: unknown): string[] {
    if (surfaceValue === undefined) return [];
    if (typeof surfaceValue === "string") return surfaceValue === "deny" ? ["*"] : [];
    if (!isPlainObject(surfaceValue)) return [];
    const patterns: string[] = [];
    for (const [pattern, value] of Object.entries(surfaceValue)) {
      if (value === "deny" || (isPlainObject(value) && value.action === "deny")) patterns.push(pattern);
    }
    return patterns;
  }

  function appendAllow(
    permission: Readonly<Record<string, unknown>> | undefined,
    surface: string,
    pattern: string,
  ): Record<string, unknown> {
    const next: Record<string, unknown> = permission === undefined ? {} : { ...permission };
    const current = next[surface];
    if (current === undefined) {
      next[surface] = { [pattern]: "allow" };
      return next;
    }
    if (typeof current === "string") {
      next[surface] = { "*": current, [pattern]: "allow" };
      return next;
    }
    if (!isPlainObject(current)) {
      // Strict validation of the result reports the real problem.
      next[surface] = { [pattern]: "allow" };
      return next;
    }
    const patterns: Record<string, unknown> = { ...current };
    patterns[pattern] = "allow";
    next[surface] = patterns;
    return next;
  }

  function saveProjectRule(
    input: ProjectRuleInput,
    ruleOptions?: ProjectRuleSaveOptions,
  ): ProjectRuleSaveResult {
    if (!projectTrusted) {
      return projectRuleFailure(
        "not-trusted",
        "",
        "The project configuration cannot be written because the project is not trusted.",
      );
    }
    if (cwd.trim().length === 0) {
      return projectRuleFailure("no-project", "", "The project configuration cannot be written without a working directory.");
    }
    const read = readJsonObject(readFile, paths.projectConfigFile);
    if (read.state === "missing") {
      return projectRuleFailure("no-project", "", "The project configuration file does not exist.");
    }
    if (read.state === "invalid") {
      return projectRuleFailure(
        "corrupt-file",
        "",
        `The project configuration file cannot be loaded (${read.message.message}).`,
      );
    }
    const raw = read.value;
    const legacy = findLegacyDeclaration(raw);
    if (legacy !== undefined) {
      return projectRuleFailure(
        "legacy-execution",
        legacy.path,
        `The project configuration contains legacy declarations (${legacy.detail}) and is not migrated or changed.`,
      );
    }
    if (typeof input.surface !== "string" || input.surface.trim().length === 0) {
      return projectRuleFailure("invalid-config", "permission", "The rule surface must be a non-empty string.");
    }
    if (typeof input.pattern !== "string" || input.pattern.trim().length === 0) {
      return projectRuleFailure("invalid-config", "permission", "The rule pattern must be a non-empty string.");
    }
    const surface = input.surface;
    const pattern = input.pattern;

    const rawPermission = raw.permission;
    if (rawPermission !== undefined && !isPlainObject(rawPermission)) {
      return projectRuleFailure("invalid-config", "permission", "The project permission value must be an object.");
    }
    const projectSurface = isPlainObject(rawPermission) ? rawPermission[surface] : undefined;
    const globalSnapshot = snapshot({ sessionId: ruleOptions?.sessionId });
    const globalSurface = globalSnapshot.globalConfig.permission?.[surface];
    const denyPatterns = [...collectDenyPatterns(projectSurface), ...collectDenyPatterns(globalSurface)];
    const covered = denyPatterns.find((denyPattern) => wildcardMatch(denyPattern, pattern));
    if (covered !== undefined) {
      return projectRuleFailure(
        "denied-by-policy",
        `permission.${surface}`,
        `The rule cannot be added because the deny rule "${covered}" covers it.`,
      );
    }

    const updatedRaw: JsonRecord = {
      ...raw,
      permission: appendAllow(rawPermission as Readonly<Record<string, unknown>> | undefined, surface, pattern),
    };
    const parsed = parseApprovalChainConfig(updatedRaw);
    if (!parsed.ok) {
      return {
        ok: false,
        code: "invalid-config",
        messages: messagesFromIssues(paths.projectConfigFile, parsed.issues),
      };
    }
    try {
      atomicWrite(paths.projectConfigFile, updatedRaw);
    } catch (error) {
      return projectRuleFailure(
        "write-failed",
        "",
        `The project configuration file could not be written (${errorDetail(error)}).`,
      );
    }
    return { ok: true, snapshot: snapshot({ sessionId: ruleOptions?.sessionId }) };
  }

  return Object.freeze({
    snapshot,
    reload,
    prepareReload,
    save,
    update,
    setMode,
    setSessionMode,
    saveProjectRule,
  });
}
