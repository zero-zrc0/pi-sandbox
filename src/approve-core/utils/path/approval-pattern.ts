/**
 * Session path authorization patterns.
 *
 * Confirmed directories produce two rules (the directory itself and a
 * directory wildcard) so sibling directories sharing a name prefix are not
 * covered. Anything else falls back to a parent-scope wildcard; a
 * separator-less relative value scopes the current directory.
 */
import type { PathFlavor } from "./path-flavor";

export interface SessionPatternOptions {
  readonly flavor: PathFlavor;
  readonly isConfirmedDir: (path: string) => boolean;
}

function trailingSeparatorOf(value: string, lastSeparator: number): boolean {
  return lastSeparator >= 0 && lastSeparator === value.length - 1;
}

export function sessionApprovalPatterns(value: string, options: SessionPatternOptions): readonly string[] {
  const { flavor } = options;
  const lastSeparator = flavor.lastSeparatorIndex(value);
  const trailingSeparator = trailingSeparatorOf(value, lastSeparator);
  const directory = trailingSeparator ? value.slice(0, -1) : value;

  if (options.isConfirmedDir(directory)) {
    if (trailingSeparator) return [directory, `${value}*`];
    if (lastSeparator === -1) {
      const separator = flavor.kind === "win32" ? "\\" : "/";
      return [directory, `${directory}${separator}*`];
    }
    const separator = value[lastSeparator];
    return [directory, `${directory}${separator}*`];
  }

  // File, missing entry or unconfirmable directory: parent-scope wildcard.
  const parent = flavor.dirname(directory);
  if (parent.length === 0 || parent === ".") return ["*"];
  if (parent.endsWith("/") || parent.endsWith("\\")) return [`${parent}*`];
  return [`${parent}/*`];
}
