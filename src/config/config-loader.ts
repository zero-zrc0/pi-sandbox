/**
 * Unified configuration loading (specs/config-loading.md sections 1-3).
 *
 * Configuration files are JSON with comments. This module owns the comment
 * scanner, the strict single-file loader, the loose permission normalization
 * used for agent frontmatter, the unified merge rules, and the multi-source
 * loader that reads legacy policy files, the legacy extension runtime
 * configuration and the formal global/project configuration in rising
 * priority order.
 *
 * Everything here is a pure function over an injected file reader: no module in
 * this file reads the ambient working directory, environment or platform.
 */
import { readFileSync, statSync } from "node:fs";
import {
  patternValueSchema,
  permissionStateSchema,
  type ConfigIssue,
  type ConfigParseResult,
  type FlatPermissionConfig,
  type PatternValue,
  type SurfaceValue,
} from "#config/config-schema";
import type { CommandEffectDeclaration, CommandEffects } from "#config/command-effects-config";
import { resolveConfigPaths, samePath, type ConfigPaths } from "#config/config-paths";
import { resolveDialogKeys } from "#config/dialog-keys";
import {
  parseApprovalChainConfig,
  parseRuntimeConfig,
  type ApprovalChainConfig,
  type LegacyConfigSource,
  type RuntimeConfig,
} from "#config/schema";

/* ------------------------------------------------------------------ */
/* JSON with comments                                                  */
/* ------------------------------------------------------------------ */

const DOUBLE_QUOTE = 0x22;
const SINGLE_QUOTE = 0x27;
const BACKSLASH = 0x5c;
const SLASH = 0x2f;
const ASTERISK = 0x2a;
const LINE_FEED = 0x0a;
const CARRIAGE_RETURN = 0x0d;

/**
 * Remove JSONC comments while respecting string state.
 *
 * A comment marker inside a string is data. Both quote styles are tracked
 * because hand-edited files sometimes quote loosely; a backslash escapes the
 * following character inside a string. `//` removes to the end of the line but
 * keeps the newline; an unterminated `/*` removes to the end of the input. An
 * unterminated string keeps its scanned text, so the later JSON parse reports
 * the real problem instead of a rewritten document.
 */
export function stripJsonComments(text: string): string {
  let result = "";
  let index = 0;
  let quote = 0;
  while (index < text.length) {
    const code = text.charCodeAt(index);
    if (quote !== 0) {
      result += text[index];
      if (code === BACKSLASH && index + 1 < text.length) {
        result += text[index + 1];
        index += 2;
        continue;
      }
      if (code === quote) quote = 0;
      index += 1;
      continue;
    }
    if (code === DOUBLE_QUOTE || code === SINGLE_QUOTE) {
      quote = code;
      result += text[index];
      index += 1;
      continue;
    }
    if (code === SLASH && index + 1 < text.length) {
      const next = text.charCodeAt(index + 1);
      if (next === SLASH) {
        index += 2;
        while (index < text.length) {
          const line = text.charCodeAt(index);
          if (line === LINE_FEED || line === CARRIAGE_RETURN) break;
          index += 1;
        }
        continue;
      }
      if (next === ASTERISK) {
        index += 2;
        while (index < text.length) {
          if (text.charCodeAt(index) === ASTERISK && text.charCodeAt(index + 1) === SLASH) {
            index += 2;
            break;
          }
          index += 1;
        }
        continue;
      }
    }
    result += text[index];
    index += 1;
  }
  return result;
}

/* ------------------------------------------------------------------ */
/* File access ports                                                   */
/* ------------------------------------------------------------------ */

/** What a configuration file lookup produced. Missing and unreadable are distinct. */
export type ConfigFileContent =
  | { readonly state: "missing" }
  | { readonly state: "text"; readonly text: string }
  | { readonly state: "unreadable"; readonly reason: string };

/** Reads one configuration file without throwing. */
export type ConfigFileReader = (path: string) => ConfigFileContent;

/** Returns a file's modification time, or `undefined` when it cannot be stated. */
export type ConfigFileStat = (path: string) => number | undefined;

/** Default reader backed by the host file system. */
export function createConfigFileReader(): ConfigFileReader {
  return (path) => {
    try {
      return { state: "text", text: readFileSync(path, "utf8") };
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT") return { state: "missing" };
      return { state: "unreadable", reason: code ?? "unknown read error" };
    }
  };
}

/** Default stat backed by the host file system. */
export function createConfigFileStat(): ConfigFileStat {
  return (path) => {
    try {
      return statSync(path).mtimeMs;
    } catch {
      return undefined;
    }
  };
}

/* ------------------------------------------------------------------ */
/* Display messages                                                    */
/* ------------------------------------------------------------------ */

/**
 * One displayable configuration or policy problem.
 *
 * `code` is the stable machine category; `file`, `path` and `message` are for
 * humans. Loaders, the formal owner and the policy view all produce this shape
 * so one reporter latch can de-duplicate across sources.
 */
export interface ConfigMessage {
  readonly code: string;
  readonly file?: string;
  readonly path: string;
  readonly message: string;
}

/** Stable identity of a message for report de-duplication. */
export function configMessageKey(message: ConfigMessage): string {
  return `${message.code}\u0000${message.file ?? ""}\u0000${message.path}\u0000${message.message}`;
}

/** Render one message as a single line, naming its file and field when known. */
export function formatConfigMessage(message: ConfigMessage): string {
  const location = message.file === undefined
    ? message.path
    : message.path.length === 0
      ? message.file
      : `${message.file}: ${message.path}`;
  return location.length === 0 ? message.message : `${location}: ${message.message}`;
}

/** Convert schema issues into display messages attributed to their file. */
export function messagesFromIssues(file: string, issues: readonly ConfigIssue[]): ConfigMessage[] {
  return issues.map((issue) => ({
    code: issue.code,
    file,
    path: issue.path,
    message: issue.message,
  }));
}

/* ------------------------------------------------------------------ */
/* Strict single-file loading                                          */
/* ------------------------------------------------------------------ */

/** Outcome of loading one configuration scope from one file. */
export interface LoadedConfigScope<T> {
  readonly config: T;
  readonly exists: boolean;
  readonly invalid: boolean;
  readonly raw?: unknown;
  readonly messages: readonly ConfigMessage[];
}

export interface LoadConfigScopeOptions<T> {
  readonly path: string;
  readonly parse: (value: unknown) => ConfigParseResult<T>;
  readonly empty: () => T;
  readonly readFile?: ConfigFileReader;
}

/**
 * Load and strictly validate one scope.
 *
 * A missing file is a legal empty scope. Any read, parse or schema failure makes
 * the whole scope empty: a partially valid document is never accepted, because
 * a rejected field might have been the restriction the user meant to apply.
 */
export function loadConfigScope<T>(options: LoadConfigScopeOptions<T>): LoadedConfigScope<T> {
  const readFile = options.readFile ?? createConfigFileReader();
  const content = readFile(options.path);
  if (content.state === "missing") {
    return { config: options.empty(), exists: false, invalid: false, messages: [] };
  }
  if (content.state === "unreadable") {
    return {
      config: options.empty(),
      exists: true,
      invalid: true,
      messages: [{
        code: "read-failed",
        file: options.path,
        path: "",
        message: `The configuration file could not be read (${content.reason}).`,
      }],
    };
  }
  let raw: unknown;
  try {
    raw = JSON.parse(stripJsonComments(content.text));
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return {
      config: options.empty(),
      exists: true,
      invalid: true,
      messages: [{
        code: "parse-failed",
        file: options.path,
        path: "",
        message: `The configuration file is not valid JSON (${detail}).`,
      }],
    };
  }
  const parsed = options.parse(raw);
  if (!parsed.ok) {
    return {
      config: options.empty(),
      exists: true,
      invalid: true,
      raw,
      messages: messagesFromIssues(options.path, parsed.issues),
    };
  }
  return { config: parsed.config, exists: true, invalid: false, raw, messages: [] };
}

/* ------------------------------------------------------------------ */
/* Shared value helpers                                                */
/* ------------------------------------------------------------------ */

function isPlainObject(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/* ------------------------------------------------------------------ */
/* Loose permission normalization (agent frontmatter)                  */
/* ------------------------------------------------------------------ */

function toPatternValue(value: unknown): PatternValue | undefined {
  const parsed = patternValueSchema.safeParse(value);
  return parsed.success ? parsed.data : undefined;
}

/**
 * Normalize a permission value read from agent frontmatter.
 *
 * Frontmatter is free-form user text, so a broken value must never invalidate
 * the agent: a non-object top level, an invalid action, an array surface and an
 * invalid pattern value are dropped, and a surface or map with nothing valid
 * left disappears. Direction surface spellings are not policed here; that is
 * the strict schema's job.
 */
export function normalizeFlatPermissionValue(value: unknown): FlatPermissionConfig | undefined {
  if (!isPlainObject(value)) return undefined;
  const surfaces: Record<string, SurfaceValue> = {};
  for (const [surface, surfaceValue] of Object.entries(value)) {
    if (surface.length === 0) continue;
    const catchAll = typeof surfaceValue === "string"
      ? permissionStateSchema.safeParse(surfaceValue)
      : undefined;
    if (catchAll?.success === true) {
      surfaces[surface] = catchAll.data;
      continue;
    }
    if (!isPlainObject(surfaceValue)) continue;
    const patterns: Record<string, PatternValue> = {};
    for (const [pattern, patternValue] of Object.entries(surfaceValue)) {
      if (pattern.length === 0) continue;
      const parsed = toPatternValue(patternValue);
      if (parsed !== undefined) patterns[pattern] = parsed;
    }
    if (Object.keys(patterns).length > 0) surfaces[surface] = patterns;
  }
  return Object.keys(surfaces).length > 0 ? surfaces : undefined;
}

/* ------------------------------------------------------------------ */
/* Unified merge rules                                                 */
/* ------------------------------------------------------------------ */

/** Runtime fields replaced wholesale by a higher scope. Declaration order is the schema order. */
const REPLACED_RUNTIME_FIELDS = [
  "debugLog",
  "permissionReviewLog",
  "yoloMode",
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
  "authorizerChain",
] as const;

/** Runtime fields carried by the merged configuration, in schema declaration order. */
const MERGED_RUNTIME_FIELDS = [
  ...REPLACED_RUNTIME_FIELDS,
  "permission",
  "shellTools",
  "permissionDialogKeys",
] as const;

/** Runtime fields a legacy layer may contribute, including the folded command effects. */
const LEGACY_RUNTIME_FIELDS = [...MERGED_RUNTIME_FIELDS, "commandEffects"] as const;

function mergePermissionMaps(
  base: FlatPermissionConfig | undefined,
  override: FlatPermissionConfig | undefined,
): FlatPermissionConfig | undefined {
  if (override === undefined) return base;
  if (base === undefined) return override;
  const merged: Record<string, SurfaceValue> = { ...base };
  for (const [surface, value] of Object.entries(override)) {
    const current = merged[surface];
    merged[surface] = isPlainObject(current) && isPlainObject(value)
      ? { ...current, ...value }
      : value;
  }
  return merged;
}

function mergeShellTools(
  base: RuntimeConfig["shellTools"],
  override: RuntimeConfig["shellTools"],
): RuntimeConfig["shellTools"] {
  if (override === undefined) return base;
  if (base === undefined) return override;
  return { ...base, ...override };
}

/**
 * Merge two runtime configuration layers, higher scope overriding lower.
 *
 * Scalars, arrays and prompt notifications replace when the override defines
 * them (a defined `false`, `0` or empty array is a real value). Dialog keys
 * replace as one map so two individually valid maps cannot merge into a
 * conflict. Shell tools merge by tool name. Permission maps merge pattern by
 * pattern only when both sides are maps; otherwise the higher surface value
 * replaces the whole surface. Command effects are folded by the loader, not
 * merged here, and the `$schema` marker is declaration metadata.
 */
export function mergeRuntimeConfigs(base: RuntimeConfig, override: RuntimeConfig): RuntimeConfig {
  const result: Record<string, unknown> = {};
  for (const field of REPLACED_RUNTIME_FIELDS) {
    const value = override[field] ?? base[field];
    if (value !== undefined) result[field] = value;
  }
  const permission = mergePermissionMaps(base.permission, override.permission);
  if (permission !== undefined) result.permission = permission;
  const shellTools = mergeShellTools(base.shellTools, override.shellTools);
  if (shellTools !== undefined) result.shellTools = shellTools;
  const dialogKeys = override.permissionDialogKeys ?? base.permissionDialogKeys;
  if (dialogKeys !== undefined) result.permissionDialogKeys = dialogKeys;
  return result as RuntimeConfig;
}

/**
 * Take the runtime fields of a formal configuration.
 *
 * The formal file is the single source of truth for the whole extension, but
 * the unified runtime configuration carries only the fields the runtime
 * readers consume: engine limits, permission maps, shell tools and display
 * preferences. Mode, approver, tool bindings, learning, execution, approval
 * nodes, migration metadata and command effects stay with their owners.
 */
export function extractRuntimeFields(config: ApprovalChainConfig): RuntimeConfig {
  const result: Record<string, unknown> = {};
  for (const field of MERGED_RUNTIME_FIELDS) {
    const value = (config as unknown as Record<string, unknown>)[field];
    if (value !== undefined) result[field] = value;
  }
  return result as RuntimeConfig;
}

/* ------------------------------------------------------------------ */
/* Command effect folding                                              */
/* ------------------------------------------------------------------ */

/** Which configuration scope declared a folded command effect. */
export type CommandEffectScope = "global" | "project";

export interface FoldedCommandEffect {
  readonly declaration: CommandEffectDeclaration;
  readonly scope: CommandEffectScope;
}

/**
 * Fold command effect declarations from low to high priority.
 *
 * Command effects do not take part in the normal merged configuration: each
 * command keeps the scope that declared it, and a project declaration of the
 * same command replaces the global entry as a whole. A replaced entry keeps its
 * original position so declaration order stays stable.
 */
export function foldCommandEffects(
  layers: readonly { readonly scope: CommandEffectScope; readonly declarations: CommandEffects }[],
): Readonly<Record<string, FoldedCommandEffect>> {
  const folded: Record<string, FoldedCommandEffect> = {};
  for (const layer of layers) {
    for (const [command, declaration] of Object.entries(layer.declarations)) {
      folded[command] = { declaration, scope: layer.scope };
    }
  }
  return Object.freeze(folded);
}

/* ------------------------------------------------------------------ */
/* Multi-source unified loading                                        */
/* ------------------------------------------------------------------ */

/** Where one unified configuration layer came from. */
export type UnifiedConfigLayerSource = LegacyConfigSource | "global" | "project";

/** One examined layer: even a missing layer is listed with `exists: false`. */
export interface UnifiedConfigLayer {
  readonly source: UnifiedConfigLayerSource;
  readonly path: string;
  readonly exists: boolean;
  readonly config: RuntimeConfig;
}

export interface UnifiedConfigLoadOptions {
  readonly paths: ConfigPaths;
  readonly cwd: string;
  readonly projectTrusted: boolean;
  readonly ignoreExtensionConfigFiles?: boolean;
  readonly readFile?: ConfigFileReader;
  readonly coreCommands?: readonly string[];
  readonly wrapperCommands?: readonly string[];
}

export interface UnifiedConfigLoadResult {
  readonly config: RuntimeConfig;
  readonly commandEffects: Readonly<Record<string, FoldedCommandEffect>>;
  readonly messages: readonly ConfigMessage[];
  readonly layers: readonly UnifiedConfigLayer[];
}

interface LayerLoad {
  readonly layer: UnifiedConfigLayer;
  readonly messages: readonly ConfigMessage[];
  readonly effects?: CommandEffects;
}

const MIGRATION_DEPRECATED =
  "The legacy configuration file is deprecated; move its settings to the unified configuration file.";
const MIGRATION_FAILED =
  "The legacy configuration file could not be loaded and its settings were ignored.";
const CLASSIFIER_IGNORED =
  "The legacy classifier declaration was ignored; its contents are not read.";

function migrationMessage(
  code: "migration" | "legacy-classifier" | "ignored-project-config",
  file: string,
  message: string,
): ConfigMessage {
  return { code, file, path: "", message };
}

/** Pick the runtime-shaped keys a legacy document may carry. */
function pickLegacyRuntimeFields(raw: Readonly<Record<string, unknown>>): Record<string, unknown> {
  const picked: Record<string, unknown> = {};
  for (const field of LEGACY_RUNTIME_FIELDS) {
    if (Object.hasOwn(raw, field)) picked[field] = raw[field];
  }
  return picked;
}

function loadLegacyPolicyLayer(
  source: "legacy-global-policy" | "legacy-project-policy",
  path: string,
  readFile: ConfigFileReader,
): LayerLoad {
  const scope = loadConfigScope<RuntimeConfig>({
    path,
    readFile,
    parse: (raw) => {
      if (!isPlainObject(raw)) {
        return { ok: false, issues: [{ path: "", code: "invalid", message: "expected a JSON object" }] };
      }
      const candidate = Object.hasOwn(raw, "permission") ? { permission: raw.permission } : { permission: raw };
      return parseRuntimeConfig(candidate);
    },
    empty: () => ({}),
  });
  const messages: ConfigMessage[] = [];
  if (scope.exists) {
    messages.push(scope.invalid
      ? migrationMessage("migration", path, MIGRATION_FAILED)
      : migrationMessage("migration", path, MIGRATION_DEPRECATED));
  }
  return {
    layer: { source, path, exists: scope.exists, config: scope.invalid ? {} : scope.config },
    messages,
  };
}

function loadLegacyRuntimeLayer(path: string, readFile: ConfigFileReader): LayerLoad {
  let document: Readonly<Record<string, unknown>> | undefined;
  const scope = loadConfigScope<RuntimeConfig>({
    path,
    readFile,
    parse: (raw) => {
      if (!isPlainObject(raw)) {
        return { ok: false, issues: [{ path: "", code: "invalid", message: "expected a JSON object" }] };
      }
      document = raw;
      return parseRuntimeConfig(pickLegacyRuntimeFields(raw));
    },
    empty: () => ({}),
  });
  const messages: ConfigMessage[] = [];
  if (scope.exists) {
    messages.push(scope.invalid
      ? migrationMessage("migration", path, MIGRATION_FAILED)
      : migrationMessage("migration", path, MIGRATION_DEPRECATED));
  }
  if (document !== undefined &&
      (Object.hasOwn(document, "classifier") || Object.hasOwn(document, "classifierModel"))) {
    messages.push(migrationMessage("legacy-classifier", path, CLASSIFIER_IGNORED));
  }
  return {
    layer: {
      source: "legacy-extension-config",
      path,
      exists: scope.exists,
      config: scope.invalid ? {} : scope.config,
    },
    messages,
    ...(scope.invalid || scope.config.commandEffects === undefined
      ? {}
      : { effects: scope.config.commandEffects }),
  };
}

function loadFormalLayer(
  source: "global" | "project",
  path: string,
  readFile: ConfigFileReader,
): LayerLoad {
  let formal: ApprovalChainConfig | undefined;
  const scope = loadConfigScope<RuntimeConfig>({
    path,
    readFile,
    parse: (raw) => {
      const parsed = parseApprovalChainConfig(raw);
      if (!parsed.ok) return parsed;
      formal = parsed.config;
      return { ok: true, config: extractRuntimeFields(parsed.config) };
    },
    empty: () => ({}),
  });
  return {
    layer: { source, path, exists: scope.exists, config: scope.invalid ? {} : scope.config },
    messages: scope.invalid ? scope.messages : [],
    ...(formal?.commandEffects === undefined ? {} : { effects: formal.commandEffects }),
  };
}

function dialogKeyMessages(config: RuntimeConfig): ConfigMessage[] {
  const resolution = resolveDialogKeys(config.permissionDialogKeys);
  return resolution.issues.map((issue) => ({
    code: "dialog-key",
    path: `permissionDialogKeys.${issue.action}`,
    message: `The dialog key for ${issue.action} cannot be used (${issue.code}); the default key stays.`,
  }));
}

/** True when a pattern value resolves to an allow action. */
function isAllowValue(value: unknown): boolean {
  if (value === "allow") return true;
  return isPlainObject(value) && value.action === "allow";
}

/**
 * A universal allow makes every unnamed tool inherit allow. Bash keeps its own
 * guard rails only when the user narrowed it explicitly, so report the gap.
 */
function broadDefaultMessages(config: RuntimeConfig): ConfigMessage[] {
  const permission = config.permission;
  if (permission === undefined) return [];
  const universal = permission["*"];
  const allow = typeof universal === "string" ? universal === "allow" : isPlainObject(universal) && isAllowValue(universal["*"]);
  if (!allow) return [];
  const bash = permission.bash;
  const bashConstrained = typeof bash === "string" ||
    (isPlainObject(bash) && Object.hasOwn(bash, "*"));
  if (bashConstrained) return [];
  return [{
    code: "broad-default",
    path: "permission",
    message: "permission[*] allows everything while Bash has no catch-all, so Bash inherits the broad default.",
  }];
}

function deprecatedPreviewMessages(config: RuntimeConfig): ConfigMessage[] {
  const messages: ConfigMessage[] = [];
  for (const field of ["toolInputPreviewMaxLength", "toolTextSummaryMaxLength"] as const) {
    if (config[field] === undefined) continue;
    messages.push({
      code: "deprecated",
      path: field,
      message: `${field} is deprecated and has no runtime effect.`,
    });
  }
  return messages;
}

function commandEffectMessages(
  commandEffects: Readonly<Record<string, FoldedCommandEffect>>,
  coreCommands: readonly string[],
  wrapperCommands: readonly string[],
): ConfigMessage[] {
  const core = new Set(coreCommands);
  const wrappers = new Set(wrapperCommands);
  const messages: ConfigMessage[] = [];
  for (const command of Object.keys(commandEffects)) {
    if (wrappers.has(command)) {
      messages.push({
        code: "command-effect",
        path: `commandEffects.${command}`,
        message: `The command effect declaration for ${command} is ignored because it is a wrapper command.`,
      });
      continue;
    }
    if (core.has(command)) {
      messages.push({
        code: "command-effect",
        path: `commandEffects.${command}`,
        message: `The command effect declaration for ${command} is ignored because it is a pure reader.`,
      });
    }
  }
  return messages;
}

/**
 * Load the unified runtime configuration from every source, low to high:
 * legacy global policy, legacy extension runtime configuration, the new global
 * configuration, legacy project policy and the new project configuration.
 *
 * Legacy files are compatibility data: their schema problems become one
 * migration notice instead of field-level noise, while their supported fields
 * still merge. The project scope is skipped entirely when the project is not
 * trusted or no working directory is known.
 */
export function loadUnifiedConfig(options: UnifiedConfigLoadOptions): UnifiedConfigLoadResult {
  const readFile = options.readFile ?? createConfigFileReader();
  const ignoreExtensionConfigFiles = options.ignoreExtensionConfigFiles === true;
  const projectEnabled = options.cwd.trim().length > 0 && options.projectTrusted;
  const messages: ConfigMessage[] = [];
  const layers: UnifiedConfigLayer[] = [];
  const effectLayers: { readonly scope: CommandEffectScope; readonly declarations: CommandEffects }[] = [];

  const append = (load: LayerLoad): void => {
    layers.push(load.layer);
    messages.push(...load.messages);
    if (load.effects !== undefined && load.layer.exists) {
      effectLayers.push({ scope: load.layer.source === "project" ? "project" : "global", declarations: load.effects });
    }
  };

  append(loadLegacyPolicyLayer("legacy-global-policy", options.paths.legacyGlobalPolicyFile, readFile));
  const legacyExtensionDiffers = !samePath(
    options.paths.legacyExtensionConfigFile,
    options.paths.globalConfigFile,
  );
  if (!ignoreExtensionConfigFiles && legacyExtensionDiffers) {
    append(loadLegacyRuntimeLayer(options.paths.legacyExtensionConfigFile, readFile));
  }
  if (!ignoreExtensionConfigFiles) {
    append(loadFormalLayer("global", options.paths.globalConfigFile, readFile));
  }
  if (projectEnabled) {
    append(loadLegacyPolicyLayer("legacy-project-policy", options.paths.legacyProjectPolicyFile, readFile));
  }
  if (projectEnabled && !ignoreExtensionConfigFiles) {
    append(loadFormalLayer("project", options.paths.projectConfigFile, readFile));
  }
  if (projectEnabled && ignoreExtensionConfigFiles) {
    const projectConfigExists = readFile(options.paths.projectConfigFile).state !== "missing";
    const sharesManagedPath = samePath(
      options.paths.projectConfigFile,
      options.paths.legacyProjectPolicyFile,
    );
    if (projectConfigExists && !sharesManagedPath) {
      messages.push(migrationMessage(
        "ignored-project-config",
        options.paths.projectConfigFile,
        "The project extension configuration was ignored because the owning extension already loaded runtime configuration.",
      ));
    }
  }

  let config: RuntimeConfig = {};
  for (const layer of layers) config = mergeRuntimeConfigs(config, layer.config);
  const commandEffects = foldCommandEffects(effectLayers);

  messages.push(...dialogKeyMessages(config));
  messages.push(...broadDefaultMessages(config));
  messages.push(...deprecatedPreviewMessages(config));
  messages.push(...commandEffectMessages(
    commandEffects,
    options.coreCommands ?? [],
    options.wrapperCommands ?? [],
  ));

  return { config, commandEffects, messages, layers };
}

/** Re-exported so callers that only need paths do not import the resolver twice. */
export { resolveConfigPaths };
