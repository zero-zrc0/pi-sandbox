import { basename, dirname, isAbsolute, join, parse, relative, resolve, sep } from "node:path";
import { realpathSync } from "node:fs";

/** Control directories that a writable parent never grants implicitly. */
export const PROTECTED_CONTROL_DIRECTORY_NAMES = Object.freeze([
  ".git",
  ".agents",
  ".codex",
  ".aws",
] as const);

/** Control directories that stay writable-restricted but readable (agent state and skills live here). */
export const READABLE_CONTROL_DIRECTORY_NAMES = Object.freeze([".agents", ".codex"] as const);

function stripTrailingSeparators(value: string): string {
  if (value.length <= 1) return value;
  let end = value.length;
  while (end > 1 && (value[end - 1] === sep || value[end - 1] === "/")) {
    end -= 1;
  }
  const stripped = value.slice(0, end);
  // Keep a drive root such as `C:` intact after resolving `C:\`.
  return /^[A-Za-z]:$/.test(stripped) ? `${stripped}${sep}` : stripped;
}

/** Resolve a host-provided path and reject values that are not absolute. */
export function normalizeHostPath(value: unknown): string | null {
  if (typeof value !== "string") return null;
  if (!value.trim() || value.includes("\0")) return null;
  if (!isAbsolute(value)) return null;
  return stripTrailingSeparators(resolve(value));
}

/**
 * Resolve the real identity of an absolute host path. Existing components are
 * canonicalized with `realpath`; missing trailing components are appended to
 * the canonical existing parent so a write target can still be planned. Any
 * failure other than "not found" is treated as unprovable and yields null.
 */
export function resolveHostPathIdentity(value: string): string | null {
  const normalized = normalizeHostPath(value);
  if (!normalized) return null;
  let current = normalized;
  const missing: string[] = [];
  while (true) {
    try {
      const canonical = normalizeHostPath(realpathSync.native(current));
      if (!canonical) return null;
      return missing.length === 0
        ? canonical
        : normalizeHostPath(join(canonical, ...missing.reverse()));
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== "ENOENT") return null;
      const parent = dirname(current);
      if (parent === current) return null;
      missing.push(basename(current));
      current = parent;
    }
  }
}

export function pathKey(value: string): string {
  return process.platform === "win32" ? value.toLowerCase() : value;
}

/** True when `child` is strictly inside `parent` (or equal). */
export function isPathWithin(parent: string, child: string): boolean {
  const normalizedParent = normalizeHostPath(parent);
  const normalizedChild = normalizeHostPath(child);
  if (!normalizedParent || !normalizedChild) return false;
  if (pathKey(normalizedParent) === pathKey(normalizedChild)) return true;
  const rel = relative(normalizedParent, normalizedChild);
  return (
    rel.length > 0 &&
    !rel.startsWith(`..${sep}`) &&
    rel !== ".." &&
    !isAbsolute(rel)
  );
}

export function isSamePath(left: string, right: string): boolean {
  return pathKey(left) === pathKey(right);
}

/**
 * Return the protected control root enclosing `target`, if any. A segment match
 * is intentionally conservative: a backend should deny nested control
 * directories such as `repo/packages/x/.git` as well.
 */
export function findProtectedControlRoot(
  target: string,
  names: readonly string[] = PROTECTED_CONTROL_DIRECTORY_NAMES,
): string | null {
  const normalized = normalizeHostPath(target);
  if (!normalized) return null;
  const parsed = parse(normalized);
  const wanted = new Set(names.map((name) => pathKey(name)));
  let current = parsed.root;
  for (const part of normalized
    .slice(parsed.root.length)
    .split(/[\\/]+/)
    .filter(Boolean)) {
    current = join(current, part);
    if (wanted.has(pathKey(part))) return current;
  }
  return null;
}

/**
 * Return the protected control root that blocks a read. Directories listed as
 * readable (`READABLE_CONTROL_DIRECTORY_NAMES`) only enforce write restrictions.
 */
export function findProtectedControlReadRoot(
  target: string,
  names: readonly string[] = PROTECTED_CONTROL_DIRECTORY_NAMES,
): string | null {
  const readable = new Set(READABLE_CONTROL_DIRECTORY_NAMES.map((name) => pathKey(name)));
  return findProtectedControlRoot(target, names.filter((name) => !readable.has(pathKey(name))));
}

export function protectedPathsForGrant(
  directory: string,
  names: readonly string[] = PROTECTED_CONTROL_DIRECTORY_NAMES,
): readonly string[] {
  const root = normalizeHostPath(directory);
  if (!root) return [];
  return names.map((name) => join(root, name)).filter(isAbsolute);
}
