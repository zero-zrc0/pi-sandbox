/**
 * Declarative tool bindings (specs/tool-access.md §4, specs/config-schema.md §7).
 *
 * A declaration may bind one captured tool by exact origin identity or by npm
 * package identity (package provenance itself is proven elsewhere). Compilation
 * validates the closed schema, JSON Pointer locations, the profile safe-parameter
 * table and the file-search cwd fallback before any binding exists; extraction
 * then trusts only the compiled binding.
 */
import {
  normalizeToolAccessFacts,
  type ToolAccess,
  type ToolAccessFactsResult,
} from "./access-facts";
import type { ToolDefinition, ToolIdentity } from "./tool-definition";

const DECLARED_SOURCE = "declared";
const CWD_DEFAULT = "$cwd";

export type DeclaredToolProfile = "file-reader" | "file-search" | "file-writer" | "file-editor";
export type DeclaredToolAccess = "read" | "write";
export type DeclaredToolWhenAbsent = "error" | "cwd";

export interface DeclaredToolLocation {
  /** JSON Pointer into the tool input; `~0`/`~1` escapes are decoded. */
  readonly pointer: string;
  readonly access: DeclaredToolAccess;
  readonly whenAbsent: DeclaredToolWhenAbsent;
}

export interface DeclaredToolSafeParam {
  readonly pointer: string;
  readonly type: "string" | "number" | "boolean";
}

export type DeclaredToolIdentity =
  | { readonly kind: "origin"; readonly name: string; readonly origin: string }
  | { readonly kind: "package"; readonly name: string; readonly package: string; readonly entry?: string };

/** A compiled declaration; only these fields drive later extraction. */
export interface DeclaredToolBinding {
  readonly profile: DeclaredToolProfile;
  readonly identity: DeclaredToolIdentity;
  /** Captured identity of the tool the declaration was compiled against. */
  readonly tool: ToolIdentity;
  readonly locations: readonly DeclaredToolLocation[];
  readonly safeParams: readonly DeclaredToolSafeParam[];
}

export type DeclarativeBindingProblem =
  | "invalid-declaration"
  | "unknown-profile"
  | "invalid-identity"
  | "identity-mismatch"
  | "schema-not-closed"
  | "required-not-array"
  | "no-locations"
  | "invalid-location"
  | "invalid-location-pointer"
  | "invalid-location-schema"
  | "nested-location-prefix-not-object"
  | "invalid-access"
  | "profile-access-mismatch"
  | "invalid-when-absent"
  | "unsafe-parameter"
  | "parameter-type-mismatch"
  | "duplicate-location"
  | "invalid-input"
  | "unmodeled-input-key"
  | "missing-location"
  | "invalid-location-value"
  | "empty-path"
  | "url-path";

export type DeclarativeCompileResult =
  | { readonly status: "bound"; readonly binding: DeclaredToolBinding }
  | { readonly status: "incomplete"; readonly reason: DeclarativeBindingProblem }
  | { readonly status: "unbound"; readonly reason: DeclarativeBindingProblem };

const DECLARATION_KEYS = ["tool", "profile", "locations", "origin", "package", "entry"] as const;
const LOCATION_KEYS = ["pointer", "access", "whenAbsent"] as const;

const PROFILE_ACCESS: Readonly<Record<DeclaredToolProfile, readonly DeclaredToolAccess[]>> = {
  "file-reader": ["read"],
  "file-search": ["read"],
  "file-writer": ["write"],
  "file-editor": ["read", "write"],
};

type SafeParamType = DeclaredToolSafeParam["type"];

const PROFILE_SAFE_PARAMS: Readonly<Record<DeclaredToolProfile, Readonly<Record<string, SafeParamType>>>> = {
  "file-reader": { offset: "number", limit: "number", maxBytes: "number", encoding: "string" },
  "file-search": {
    query: "string",
    pattern: "string",
    glob: "string",
    caseSensitive: "boolean",
    wholeWord: "boolean",
    literal: "boolean",
    hidden: "boolean",
    contextLines: "number",
    maxCount: "number",
  },
  "file-writer": { content: "string", encoding: "string", overwrite: "boolean", create: "boolean" },
  "file-editor": { content: "string", oldText: "string", newText: "string", replaceAll: "boolean" },
};

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasOnlyKeys(record: Record<string, unknown>, allowed: readonly string[]): boolean {
  return Object.keys(record).every((key) => allowed.includes(key));
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isDeclaredToolProfile(value: string): value is DeclaredToolProfile {
  return value === "file-reader" || value === "file-search" || value === "file-writer" || value === "file-editor";
}

/** Decode a JSON Pointer; empty pointers and invalid `~` escapes are rejected. */
function decodePointer(pointer: string): string[] | undefined {
  if (pointer.length === 0 || !pointer.startsWith("/")) return undefined;
  const tokens: string[] = [];
  for (const raw of pointer.slice(1).split("/")) {
    if (raw.length === 0 || /~(?![01])/u.test(raw)) return undefined;
    tokens.push(raw.replace(/~1/gu, "/").replace(/~0/gu, "~"));
  }
  return tokens;
}

function encodePointer(tokens: readonly string[]): string {
  return `/${tokens.map((token) => token.replace(/~/gu, "~0").replace(/\//gu, "~1")).join("/")}`;
}

/** URL schemes are two or more scheme characters; a Windows drive is not one. */
function looksLikeUrl(path: string): boolean {
  const match = /^([A-Za-z][A-Za-z0-9+.-]*):/.exec(path);
  return match !== null && (match[1] as string).length > 1;
}

function isAbsolutePath(path: string): boolean {
  return /^[A-Za-z]:[\\/]/u.test(path) || path.startsWith("/") || path.startsWith("\\");
}

/** Simple join: cwd fallback and relative locations only need a stable fact path. */
function resolveFactPath(cwd: string, path: string): string {
  if (isAbsolutePath(path)) return path;
  const base = cwd.trim();
  if (base.length === 0) return path;
  const separator = base.includes("\\") ? "\\" : "/";
  const relative = separator === "\\" ? path.replace(/\//gu, "\\") : path;
  return base.endsWith("/") || base.endsWith("\\") ? `${base}${relative}` : `${base}${separator}${relative}`;
}

function unbound(reason: DeclarativeBindingProblem): DeclarativeCompileResult {
  return { status: "unbound", reason };
}

function incomplete(reason: DeclarativeBindingProblem): DeclarativeCompileResult {
  return { status: "incomplete", reason };
}

/** Resolve a location pointer to its schema; intermediate steps must be objects. */
function resolveLocationSchema(
  parameters: Record<string, unknown>,
  tokens: readonly string[],
): { readonly schema: Record<string, unknown> } | { readonly problem: DeclarativeBindingProblem } {
  let current: Record<string, unknown> = parameters;
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index] as string;
    const properties = current.properties;
    if (!isPlainRecord(properties) || !Object.prototype.hasOwnProperty.call(properties, token)) {
      return { problem: "invalid-location-pointer" };
    }
    const next = properties[token];
    if (!isPlainRecord(next)) return { problem: "invalid-location-schema" };
    if (index === tokens.length - 1) return { schema: next };
    if (next.type !== "object") return { problem: "nested-location-prefix-not-object" };
    current = next;
  }
  return { problem: "invalid-location-pointer" };
}

interface LeafSchema {
  readonly tokens: readonly string[];
  readonly schema: Record<string, unknown>;
}

/** Every schema leaf; object containers recurse so nested locations work. */
function collectLeaves(schema: Record<string, unknown>, tokens: readonly string[], leaves: LeafSchema[]): void {
  const properties = schema.properties;
  if (schema.type === "object" && isPlainRecord(properties)) {
    for (const [key, value] of Object.entries(properties)) {
      if (!isPlainRecord(value)) continue;
      collectLeaves(value, [...tokens, key], leaves);
    }
    return;
  }
  leaves.push({ tokens, schema });
}

/**
 * Compile one declaration against the captured tool definition. Wrong identity
 * or shape is unbound; schema/pointer/property problems are incomplete.
 */
export function compileDeclarativeBinding(declaration: unknown, tool: ToolDefinition): DeclarativeCompileResult {
  if (!isPlainRecord(declaration) || !hasOnlyKeys(declaration, DECLARATION_KEYS)) return unbound("invalid-declaration");

  const toolName = declaration.tool;
  const profileRaw = declaration.profile;
  const locationsRaw = declaration.locations;
  if (!nonEmptyString(toolName)) return unbound("invalid-declaration");
  if (typeof profileRaw !== "string") return unbound("invalid-declaration");
  if (!Array.isArray(locationsRaw)) return unbound("invalid-declaration");
  if (!isDeclaredToolProfile(profileRaw)) return unbound("unknown-profile");
  const profile = profileRaw;

  const hasOrigin = declaration.origin !== undefined;
  const hasPackage = declaration.package !== undefined;
  if (hasOrigin === hasPackage) return unbound("invalid-declaration");
  // `entry` belongs to the package form only and may never accompany origin.
  if (hasOrigin && declaration.entry !== undefined) return unbound("invalid-declaration");
  let identity: DeclaredToolIdentity;
  if (hasOrigin) {
    if (!nonEmptyString(declaration.origin)) return unbound("invalid-identity");
    identity = { kind: "origin", name: toolName, origin: declaration.origin };
  } else {
    if (!nonEmptyString(declaration.package)) return unbound("invalid-identity");
    if (declaration.entry !== undefined && !nonEmptyString(declaration.entry)) return unbound("invalid-identity");
    identity = declaration.entry === undefined
      ? { kind: "package", name: toolName, package: declaration.package }
      : { kind: "package", name: toolName, package: declaration.package, entry: declaration.entry };
  }

  const captured = tool.identity;
  if (captured.name !== toolName) return unbound("identity-mismatch");
  if (identity.kind === "origin" && captured.origin !== identity.origin) return unbound("identity-mismatch");

  const parameters = tool.parameters;
  if (!isPlainRecord(parameters) || parameters.type !== "object" || parameters.additionalProperties !== false) {
    return incomplete("schema-not-closed");
  }
  const requiredRaw = parameters.required;
  if (!Array.isArray(requiredRaw)) return incomplete("required-not-array");
  // Compatibility boundary: a required array containing non-strings is treated
  // as an empty required set instead of rejecting the declaration.
  const requiredNames = requiredRaw.every((item) => typeof item === "string")
    ? new Set(requiredRaw as string[])
    : new Set<string>();

  if (locationsRaw.length === 0) return incomplete("no-locations");
  const locations: DeclaredToolLocation[] = [];
  const seen = new Set<string>();
  for (const item of locationsRaw) {
    if (!isPlainRecord(item) || !hasOnlyKeys(item, LOCATION_KEYS)) return incomplete("invalid-location");
    const pointer = item.pointer;
    if (typeof pointer !== "string") return incomplete("invalid-location");
    const accessRaw = item.access;
    if (accessRaw !== "read" && accessRaw !== "write") return incomplete("invalid-location");
    const access: DeclaredToolAccess = accessRaw;
    const whenAbsentRaw = item.whenAbsent;
    if (whenAbsentRaw !== undefined && whenAbsentRaw !== "error" && whenAbsentRaw !== "cwd") {
      return incomplete("invalid-location");
    }
    const whenAbsent: DeclaredToolWhenAbsent = whenAbsentRaw === undefined ? "error" : whenAbsentRaw;

    const tokens = decodePointer(pointer);
    if (tokens === undefined) return incomplete("invalid-location-pointer");
    if (!PROFILE_ACCESS[profile].includes(access)) return incomplete("profile-access-mismatch");

    const resolved = resolveLocationSchema(parameters, tokens);
    if ("problem" in resolved) return incomplete(resolved.problem);
    const leaf = resolved.schema;
    const leafIsString = leaf.type === "string";
    const leafIsStringArray = leaf.type === "array" && isPlainRecord(leaf.items) && leaf.items.type === "string";
    if (!leafIsString && !leafIsStringArray) return incomplete("invalid-location-schema");

    if (whenAbsent === "cwd") {
      // Only the file-search top-level optional location pins the input to cwd.
      if (profile !== "file-search") return incomplete("invalid-when-absent");
      if (tokens.length !== 1) return incomplete("invalid-when-absent");
      const topLevel = tokens[0] as string;
      if (requiredNames.has(topLevel) || leaf.default !== CWD_DEFAULT) return incomplete("invalid-when-absent");
    }

    const encoded = encodePointer(tokens);
    const dedupeKey = `${encoded}\u0000${access}`;
    if (seen.has(dedupeKey)) return incomplete("duplicate-location");
    seen.add(dedupeKey);
    locations.push(Object.freeze({ pointer: encoded, access, whenAbsent }));
  }

  const locationKeys = new Set(locations.map((location) => (decodePointer(location.pointer) as string[]).join("\u0000")));
  const leaves: LeafSchema[] = [];
  collectLeaves(parameters, [], leaves);
  const safeParams: DeclaredToolSafeParam[] = [];
  for (const leaf of leaves) {
    if (locationKeys.has(leaf.tokens.join("\u0000"))) continue;
    const name = leaf.tokens[leaf.tokens.length - 1] as string;
    const expectedType = PROFILE_SAFE_PARAMS[profile][name];
    if (expectedType === undefined) return incomplete("unsafe-parameter");
    if (leaf.schema.type !== expectedType) return incomplete("parameter-type-mismatch");
    safeParams.push(Object.freeze({ pointer: encodePointer(leaf.tokens), type: expectedType }));
  }

  return {
    status: "bound",
    binding: Object.freeze({
      profile,
      identity: Object.freeze(identity),
      tool: captured,
      locations: Object.freeze(locations),
      safeParams: Object.freeze(safeParams),
    }),
  };
}

function declaredFacts(binding: DeclaredToolBinding, accesses: readonly ToolAccess[], complete: boolean, unknownEffects: readonly string[]): ToolAccessFactsResult {
  return normalizeToolAccessFacts({ accesses, complete, unknownEffects }, binding.tool, DECLARED_SOURCE);
}

function invalidDeclaredValue(binding: DeclaredToolBinding, reason: DeclarativeBindingProblem): ToolAccessFactsResult {
  return declaredFacts(binding, [], false, [reason]);
}

const MISSING = Symbol("missing-pointer-value");

function readPointerValue(input: Record<string, unknown>, tokens: readonly string[]): unknown {
  let current: unknown = input;
  for (const token of tokens) {
    if (!isPlainRecord(current) || !Object.prototype.hasOwnProperty.call(current, token)) return MISSING;
    current = current[token];
  }
  return current;
}

function modeledTokensOf(binding: DeclaredToolBinding): string[][] {
  const pointers = [
    ...binding.locations.map((location) => location.pointer),
    ...binding.safeParams.map((param) => param.pointer),
  ];
  return pointers.map((pointer) => decodePointer(pointer) ?? []);
}

/** The input may not contain keys the compiled schema never modeled. */
function hasUnmodeledKey(
  value: Record<string, unknown>,
  modeled: readonly (readonly string[])[],
  prefix: readonly string[] = [],
): boolean {
  const allowed = new Set<string>();
  for (const tokens of modeled) {
    if (tokens.length <= prefix.length) continue;
    if (prefix.every((token, index) => tokens[index] === token)) allowed.add(tokens[prefix.length] as string);
  }
  for (const [key, child] of Object.entries(value)) {
    if (!allowed.has(key)) return true;
    if (isPlainRecord(child) && hasUnmodeledKey(child, modeled, [...prefix, key])) return true;
  }
  return false;
}

interface PathCheck {
  readonly ok: true;
  readonly path: string;
}

function checkLocationPath(value: string): PathCheck | { readonly ok: false; readonly reason: DeclarativeBindingProblem } {
  const path = value.trim();
  if (path.length === 0) return { ok: false, reason: "empty-path" };
  if (looksLikeUrl(path)) return { ok: false, reason: "url-path" };
  return { ok: true, path };
}

function locationPaths(
  value: unknown,
): { readonly ok: true; readonly paths: readonly string[] } | { readonly ok: false; readonly reason: DeclarativeBindingProblem } {
  if (typeof value === "string") {
    const checked = checkLocationPath(value);
    return checked.ok ? { ok: true, paths: [checked.path] } : checked;
  }
  // A string-array location must be non-empty and contain only strings.
  if (!Array.isArray(value) || value.length === 0) return { ok: false, reason: "invalid-location-value" };
  const paths: string[] = [];
  for (const item of value) {
    if (typeof item !== "string") return { ok: false, reason: "invalid-location-value" };
    const checked = checkLocationPath(item);
    if (!checked.ok) return checked;
    paths.push(checked.path);
  }
  return { ok: true, paths };
}

/** Extract access facts for one already-compiled declaration binding. */
export function extractDeclaredToolAccess(
  binding: DeclaredToolBinding,
  input: unknown,
  cwd: string,
): ToolAccessFactsResult {
  if (!isPlainRecord(input)) return invalidDeclaredValue(binding, "invalid-input");
  const modeled = modeledTokensOf(binding);
  if (hasUnmodeledKey(input, modeled)) return invalidDeclaredValue(binding, "unmodeled-input-key");

  const base = typeof cwd === "string" ? cwd.trim() : "";
  const accesses: ToolAccess[] = [];
  for (const location of binding.locations) {
    const tokens = decodePointer(location.pointer);
    if (tokens === undefined) return invalidDeclaredValue(binding, "invalid-location-pointer");
    const value = readPointerValue(input, tokens);
    if (value === MISSING) {
      if (location.whenAbsent !== "cwd") return invalidDeclaredValue(binding, "missing-location");
      if (base.length === 0) return invalidDeclaredValue(binding, "empty-path");
      accesses.push({ path: base, access: location.access, operation: location.access });
      continue;
    }
    const paths = locationPaths(value);
    if (!paths.ok) return invalidDeclaredValue(binding, paths.reason);
    for (const path of paths.paths) {
      accesses.push({
        path: resolveFactPath(base, path),
        access: location.access,
        operation: location.access,
      });
    }
  }
  return declaredFacts(binding, accesses, true, []);
}
