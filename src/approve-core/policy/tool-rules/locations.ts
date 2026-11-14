/**
 * Declared file locations of an `allow` rule (design §5.1, §6.5).
 *
 * A rule may name JSON Pointers into the tool input that carry file paths. The
 * profile fixes which access directions are legal, every declared pointer must
 * resolve to a non-empty path (or fall back to `cwd`), and URLs are rejected:
 * the result feeds argument validation and the sandbox execution plan, and it
 * never grants permission by itself.
 */
import { decodePointer, isPlainObject, readPointerValue } from "./pointers";
import type { ToolRule, ToolRuleLocation, ToolRuleProfile } from "./rules";

export interface ToolRuleAccessFact {
  readonly path: string;
  readonly access: "read" | "write";
  readonly operation: "read" | "write";
}

export type ToolRuleLocationFacts =
  | { readonly ok: true; readonly facts: readonly ToolRuleAccessFact[] }
  | { readonly ok: false; readonly reason: string };

const PROFILE_ACCESS: Readonly<Record<ToolRuleProfile, readonly ("read" | "write")[]>> = {
  "file-reader": ["read"],
  "file-search": ["read"],
  "file-writer": ["write"],
  "file-editor": ["read", "write"],
};

/** URL schemes are two or more scheme characters; a Windows drive is not one. */
function looksLikeUrl(path: string): boolean {
  const match = /^([A-Za-z][A-Za-z0-9+.-]*):/u.exec(path);
  return match !== null && (match[1] as string).length > 1;
}

function isAbsolutePath(path: string): boolean {
  return /^[A-Za-z]:[\\/]/u.test(path) || path.startsWith("/") || path.startsWith("\\");
}

/** Join a relative fact path to the working directory with the host separator. */
function resolveFactPath(cwd: string, path: string): string {
  if (isAbsolutePath(path)) return path;
  const base = cwd.trim();
  if (base.length === 0) return path;
  const separator = base.includes("\\") ? "\\" : "/";
  const relative = separator === "\\" ? path.replace(/\//gu, "\\") : path;
  return base.endsWith("/") || base.endsWith("\\") ? `${base}${relative}` : `${base}${separator}${relative}`;
}

function readPaths(value: unknown): readonly string[] | undefined {
  const strings = typeof value === "string"
    ? [value]
    : Array.isArray(value) && value.length > 0 && value.every((item) => typeof item === "string")
      ? (value as string[])
      : undefined;
  if (strings === undefined) return undefined;
  const paths: string[] = [];
  for (const item of strings) {
    const path = item.trim();
    if (path.length === 0 || looksLikeUrl(path)) return undefined;
    paths.push(path);
  }
  return paths;
}

function readLocation(
  location: ToolRuleLocation,
  args: unknown,
  cwd: string,
): { readonly ok: true; readonly facts: readonly ToolRuleAccessFact[] } | { readonly ok: false; readonly reason: string } {
  const tokens = decodePointer(location.pointer);
  if (tokens === undefined) return { ok: false, reason: "invalid-location-pointer" };
  const value = readPointerValue(args, tokens);
  if (value === undefined) {
    if (location.whenAbsent !== "cwd") return { ok: false, reason: "missing-location" };
    const base = cwd.trim();
    if (base.length === 0) return { ok: false, reason: "empty-path" };
    return { ok: true, facts: [{ path: base, access: location.access, operation: location.access }] };
  }
  const paths = readPaths(value);
  if (paths === undefined) return { ok: false, reason: "invalid-location-value" };
  return {
    ok: true,
    facts: paths.map((path) => ({
      path: resolveFactPath(cwd, path),
      access: location.access,
      operation: location.access,
    })),
  };
}

/**
 * Read every declared location of one `allow` rule. A rule without locations
 * yields no facts and never fails; a rule with locations fails when any
 * declared argument is absent, malformed or outside the profile's access set.
 */
export function collectToolRuleLocations(
  rule: ToolRule,
  args: unknown,
  cwd: string,
): ToolRuleLocationFacts {
  const locations = rule.locations ?? [];
  if (locations.length === 0) return { ok: true, facts: [] };
  if (rule.profile === undefined) return { ok: false, reason: "missing-profile" };
  if (!isPlainObject(args)) return { ok: false, reason: "invalid-input" };
  const allowed = PROFILE_ACCESS[rule.profile];
  const facts: ToolRuleAccessFact[] = [];
  for (const location of locations) {
    if (!allowed.includes(location.access)) return { ok: false, reason: "profile-access-mismatch" };
    const read = readLocation(location, args, typeof cwd === "string" ? cwd : "");
    if (!read.ok) return read;
    facts.push(...read.facts);
  }
  return { ok: true, facts };
}
