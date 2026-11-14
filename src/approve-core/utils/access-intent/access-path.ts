/**
 * Access paths.
 *
 * Policy-facing constructors over the session path normalizer. The value
 * object shape (display / match / boundary / redirect note) is defined by
 * the path normalizer; this module is the access-intent domain's door to it.
 */
import type { PathNormalizer, ResolvedPathValue } from "../path/path-normalizer";

export type AccessPath = ResolvedPathValue;

/** Build an access path from a policy path literal, defaulting to the session cwd. */
export function accessPathFromLiteral(
  normalizer: PathNormalizer,
  literal: string,
  baseDir?: string,
): AccessPath {
  return normalizer.normalPath(literal, baseDir ?? normalizer.cwd);
}

/** Build an access path for a native file tool input. */
export function accessPathForNativeTool(
  normalizer: PathNormalizer,
  toolName: string,
  literal: string,
): AccessPath {
  return normalizer.nativeToolPath(toolName, literal);
}
