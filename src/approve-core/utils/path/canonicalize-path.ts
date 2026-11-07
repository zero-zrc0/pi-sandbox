/**
 * Canonical path resolution.
 *
 * Canonical values resolve symbolic links as far as possible and are used
 * for containment decisions. Lexical spellings are used for display and rule
 * aliases; the two must never be mixed.
 */

import posixPath from "node:path/posix";
import win32Path from "node:path/win32";

export interface CanonicalDeps {
  /** Resolve an existing path to its real path (async variant). */
  readonly realpath: (path: string) => Promise<string>;
}

function pathLanguage(path: string): typeof posixPath {
  return /^[A-Za-z]:[\\/]/.test(path) || path.startsWith("\\\\") ? win32Path : posixPath;
}

export interface CanonicalSyncDeps {
  readonly realpath: (path: string) => string;
}

interface RetryableFsError {
  readonly code?: string;
}

function isRetriable(error: unknown): boolean {
  const code = (error as RetryableFsError | null)?.code;
  return code === "ENOENT" || code === "ENOTDIR";
}

/**
 * Resolve the longest existing ancestor through `realpath`, then append the
 * non-existent tail. Permission errors and symlink loops return the original
 * input; an empty input is returned as-is.
 */
export async function canonicalizePath(path: string, deps: CanonicalDeps): Promise<string> {
  if (path.length === 0) return path;
  const flavor = pathLanguage(path);
  const tail: string[] = [];
  let current = path;
  for (;;) {
    try {
      const resolved = await deps.realpath(current);
      if (tail.length === 0) return resolved;
      return flavor.join(resolved, ...tail);
    } catch (error) {
      if (!isRetriable(error)) return path;
      const parent = flavor.dirname(current);
      if (parent === current) return path;
      tail.unshift(flavor.basename(current));
      current = parent;
    }
  }
}

/** Synchronous variant of {@link canonicalizePath}. */
export function canonicalizePathSync(path: string, deps: CanonicalSyncDeps): string {
  return canonicalizePathSyncWithStatus(path, deps).path;
}

export function canonicalizePathSyncWithStatus(path: string, deps: CanonicalSyncDeps): { readonly path: string; readonly proven: boolean; readonly fromAncestor?: boolean; readonly missingPaths?: readonly string[] } {
  if (path.length === 0) return { path, proven: false };
  const flavor = pathLanguage(path);
  const tail: string[] = [];
  const missingPaths: string[] = [];
  let current = path;
  for (;;) {
    try {
      const resolved = deps.realpath(current);
      if (tail.length === 0) return { path: resolved, proven: true };
      return { path: flavor.join(resolved, ...tail), proven: true, fromAncestor: true, missingPaths };
    } catch (error) {
      if (!isRetriable(error)) return { path, proven: false };
      missingPaths.push(current);
      const parent = flavor.dirname(current);
      if (parent === current) return { path, proven: false };
      tail.unshift(flavor.basename(current));
      current = parent;
    }
  }
}
