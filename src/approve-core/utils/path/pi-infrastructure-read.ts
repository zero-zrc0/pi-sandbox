/**
 * Pi infrastructure read exemption.
 *
 * Only read-family tools qualify, and only when the target is inside a
 * configured infrastructure path or the project's `.pi/npm` / `.pi/git`,
 * and inside no excluded directory. Exclusions win over every allowance.
 */
import type { PathFlavor } from "./path-flavor";
import { expandHome } from "./expand-home";

export interface InfrastructureReadOptions {
  readonly flavor: PathFlavor;
  readonly cwd: string;
  readonly home: string;
  readonly configuredPaths: readonly string[];
  readonly exclusions: readonly string[];
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Compile a configured entry with optional home prefix and `*`/`?` globs. */
function entryToMatcher(entry: string, options: InfrastructureReadOptions): ((path: string) => boolean) | undefined {
  const expanded = expandHome(entry.trim(), options.home);
  if (expanded.length === 0) return undefined;
  const folded = options.flavor.fold(expanded);
  const hasGlob = folded.includes("*") || folded.includes("?");
  if (!hasGlob) {
    return (path) => options.flavor.contains(folded, options.flavor.fold(path));
  }
  const pattern = folded
    .split("")
    .map((ch) => (ch === "*" ? ".*" : ch === "?" ? "." : escapeRegExp(ch)))
    .join("");
  const regex = new RegExp(`^${pattern}$`);
  return (path) => regex.test(options.flavor.fold(path));
}

export function isInfrastructureRead(path: string, options: InfrastructureReadOptions): boolean {
  if (path.length === 0) return false;
  const folded = options.flavor.fold(path);

  for (const exclusion of options.exclusions) {
    const expanded = options.flavor.fold(expandHome(exclusion.trim(), options.home));
    if (expanded.length === 0) continue;
    if (options.flavor.contains(expanded, folded)) return false;
  }

  if (options.cwd.length > 0) {
    const cwdFolded = options.flavor.fold(options.flavor.normalize(options.cwd));
    for (const local of ["/.pi/npm", "/.pi/git"]) {
      if (options.flavor.contains(`${cwdFolded}${local}`, folded)) return true;
    }
  }

  for (const entry of options.configuredPaths) {
    const matcher = entryToMatcher(entry, options);
    if (matcher !== undefined && matcher(path)) return true;
  }
  return false;
}
