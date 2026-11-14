/**
 * Out-of-tree geometry.
 *
 * These predicates operate on canonical operands only. Callers that cannot
 * canonicalize must take their own conservative branch; an empty operand is
 * never judged external here.
 */
import type { PathFlavor } from "./path-flavor";
import { isSafeDevice } from "./safe-system-paths";

/**
 * True when `canonicalPath` lies outside `canonicalCwd`. The four safe
 * devices never count as external. Empty operands are not external; the
 * caller decides how to handle an unknown location.
 */
export function isOutsideCanonicalCwd(
  canonicalPath: string,
  canonicalCwd: string,
  flavor: PathFlavor,
): boolean {
  if (canonicalPath.length === 0 || canonicalCwd.length === 0) return false;
  if (isSafeDevice(canonicalPath)) return false;
  return !flavor.contains(canonicalCwd, canonicalPath);
}
