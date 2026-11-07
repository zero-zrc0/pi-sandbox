/**
 * npm source proof for registered tools (specs/tool-access.md §5).
 *
 * A package declaration may only select a tool whose live source proves the
 * npm package it came from. The proof reads the raw tool's own data
 * properties only: getters, prototypes and inherited fields never contribute.
 *
 * The proof's `originKey` is the captured identity origin for a package tool:
 * a NUL-joined `source/scope/origin/package-relative entry` tuple. The captured
 * `ToolIdentity.origin` must equal it character for character, so future
 * invocation capture builds that origin with {@link npmOriginKey}.
 */
import posixPath from "node:path/posix";
import win32Path from "node:path/win32";

export type NpmSourceProof =
  | {
      readonly kind: "proven";
      readonly packageName: string;
      readonly version?: string;
      readonly originKey: string;
    }
  | { readonly kind: "not-npm" }
  | { readonly kind: "unproven"; readonly reason: string };

/** Separator between origin-key components; NUL cannot appear in a host path. */
export const NPM_ORIGIN_SEPARATOR = "\u0000";

/**
 * The one canonical origin key for a package tool. Phase 12/13 origin capture
 * must call this helper instead of re-assembling the string.
 */
export function npmOriginKey(
  source: string,
  scope: string,
  origin: string,
  entry: string,
): string {
  return [source, scope, origin, entry].join(NPM_ORIGIN_SEPARATOR);
}

const SOURCE_INFO_KEY = "sourceInfo";
const NPM_SOURCE_PREFIX = "npm:";

interface SourceInfoFields {
  readonly path: string;
  readonly source: string;
  readonly scope: string;
  readonly origin: string;
}

function unproven(reason: string): NpmSourceProof {
  return Object.freeze({ kind: "unproven", reason });
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/** Read an own data property; accessors and inherited fields yield undefined. */
function readOwnData(target: unknown, key: string): unknown {
  if (typeof target !== "object" || target === null) return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(target, key);
  if (descriptor === undefined || !("value" in descriptor)) return undefined;
  return descriptor.value;
}

function nonEmptyString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function readsAsWin32(path: string): boolean {
  return /^[A-Za-z]:[\\/]/u.test(path) || path.startsWith("\\\\");
}

function pathFlavorFor(...paths: readonly string[]): typeof posixPath {
  return paths.some(readsAsWin32) ? win32Path : posixPath;
}

const UNSCOPED_PACKAGE_NAME = /^[a-z0-9][a-z0-9._~-]*$/u;
const SCOPED_PACKAGE_NAME = /^@[a-z0-9][a-z0-9._~-]*\/[a-z0-9][a-z0-9._~-]*$/u;

/** Parse `name`, `name@range`, `@scope/name` or `@scope/name@range`. */
function parseNpmSpec(spec: string): { readonly packageName: string; readonly version?: string } | undefined {
  const trimmed = spec.trim();
  if (trimmed.length === 0) return undefined;
  const versionAt = trimmed.lastIndexOf("@");
  const namePart = versionAt > 0 ? trimmed.slice(0, versionAt) : trimmed;
  const version = versionAt > 0 ? trimmed.slice(versionAt + 1) : undefined;
  const packageName = SCOPED_PACKAGE_NAME.test(namePart) || UNSCOPED_PACKAGE_NAME.test(namePart)
    ? namePart
    : undefined;
  if (packageName === undefined) return undefined;
  if (version !== undefined && (version.length === 0 || /[\s/]/u.test(version))) return undefined;
  return version === undefined ? { packageName } : { packageName, version };
}

/** Normalize a package-relative entry: `/` separators, no `./`, no escapes. */
function normalizeEntry(entry: string): string | undefined {
  let normalized = entry.trim().replace(/\\/gu, "/");
  while (normalized.startsWith("./")) normalized = normalized.slice(2);
  normalized = normalized.replace(/\/+/gu, "/");
  while (normalized.endsWith("/")) normalized = normalized.slice(0, -1);
  if (normalized.length === 0 || normalized.startsWith("/")) return undefined;
  if (normalized.split("/").some((segment) => segment.length === 0 || segment === "." || segment === "..")) {
    return undefined;
  }
  return normalized;
}

/** Read the identity origin already captured for the raw tool, if present. */
function readCapturedOrigin(tool: unknown): string | undefined {
  const flat = nonEmptyString(readOwnData(tool, "origin"));
  if (flat !== undefined) return flat;
  const definition = readOwnData(tool, "definition");
  const identity = readOwnData(definition, "identity");
  return nonEmptyString(readOwnData(identity, "origin"));
}

function readSourceInfo(tool: unknown): SourceInfoFields | NpmSourceProof {
  const raw = readOwnData(tool, SOURCE_INFO_KEY);
  if (!isPlainRecord(raw)) return unproven("missing-source-info");
  const path = nonEmptyString(readOwnData(raw, "path"));
  const source = nonEmptyString(readOwnData(raw, "source"));
  const scope = nonEmptyString(readOwnData(raw, "scope"));
  const origin = nonEmptyString(readOwnData(raw, "origin"));
  if (path === undefined || source === undefined || scope === undefined || origin === undefined) {
    return unproven("invalid-source-info");
  }
  return { path, source, scope, origin };
}

/** Prove the npm package a raw tool came from; never guess from path or name. */
export function proveNpmSource(tool: unknown): NpmSourceProof {
  const info = readSourceInfo(tool);
  if ("kind" in info) return info;

  if (info.origin !== "package" || !info.source.startsWith(NPM_SOURCE_PREFIX)) {
    return Object.freeze({ kind: "not-npm" });
  }
  const packageSpec = parseNpmSpec(info.source.slice(NPM_SOURCE_PREFIX.length));
  if (packageSpec === undefined) return unproven("unparseable-npm-spec");

  const rawBaseDir = readOwnData(readOwnData(tool, SOURCE_INFO_KEY), "baseDir");
  const baseDir = nonEmptyString(rawBaseDir);
  if (baseDir === undefined) return unproven("missing-base-dir");

  const flavor = pathFlavorFor(info.path, baseDir);
  const pathIsWin32 = readsAsWin32(info.path);
  const baseIsWin32 = readsAsWin32(baseDir);
  if (pathIsWin32 !== baseIsWin32) return unproven("invalid-source-path");
  if (!flavor.isAbsolute(info.path) || !flavor.isAbsolute(baseDir)) {
    return unproven("invalid-source-path");
  }

  const relative = flavor.relative(baseDir, info.path);
  if (relative.length === 0 || flavor.isAbsolute(relative) ||
      relative === ".." || relative.startsWith("../") || relative.startsWith("..\\")) {
    return unproven("entry-outside-package");
  }
  const entry = normalizeEntry(relative);
  if (entry === undefined) return unproven("invalid-entry-path");

  const originKey = npmOriginKey(info.source, info.scope, info.origin, entry);
  const capturedOrigin = readCapturedOrigin(tool);
  if (capturedOrigin !== undefined && capturedOrigin !== originKey) {
    return unproven("origin-mismatch");
  }

  return Object.freeze({
    kind: "proven" as const,
    packageName: packageSpec.packageName,
    ...(packageSpec.version === undefined ? {} : { version: packageSpec.version }),
    originKey,
  });
}

function proofEntry(originKey: string): string | undefined {
  const parts = originKey.split(NPM_ORIGIN_SEPARATOR);
  return parts.length === 4 ? parts[3] : undefined;
}

/**
 * Whether an origin entry (`package`, optional package-relative entry) matches
 * a proven npm source. A not-npm or unproven proof never matches.
 */
export function matchesNpmDeclaration(
  declaration: { readonly package: string; readonly entry?: string },
  proof: NpmSourceProof,
): boolean {
  if (proof.kind !== "proven") return false;
  if (declaration.package.trim() !== proof.packageName) return false;
  if (declaration.entry === undefined) return true;
  const entry = normalizeEntry(declaration.entry);
  return entry !== undefined && entry === proofEntry(proof.originKey);
}
