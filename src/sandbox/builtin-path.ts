import { existsSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { resolveNativeToolTarget } from "../approve-core/utils/path/native-tool-target";
import { pathFlavorForPlatform } from "../approve-core/utils/path/path-flavor";
import type { BuiltinToolName } from "./types";

export function builtinToolPath(name: BuiltinToolName, path: string, cwd: string): string {
  return resolveNativeToolTarget(path, {
    cwd, flavor: pathFlavorForPlatform(process.platform), readFallbacks: name === "read", exists: existsSync,
  }).target;
}

/** The variables a sandboxed file tool may spell to reach its temporary area. */
const TEMPORARY_PATH_VARIABLES = ["TMPDIR", "TMP", "TEMP"] as const;
const BRACED_VARIABLE = /^\$\{([A-Za-z_][A-Za-z0-9_]*)\}/u;
const BARE_VARIABLE = /^\$([A-Za-z_][A-Za-z0-9_]*)(?=[\\/]|$)/u;

function isTemporaryVariable(
  name: string,
  environment: Readonly<Record<string, string>>,
): boolean {
  return (TEMPORARY_PATH_VARIABLES as readonly string[]).includes(name) &&
    typeof environment[name] === "string" &&
    isAbsolute(environment[name]);
}

function joinTail(root: string, tail: string): string {
  const trimmed = tail.replace(/^[\\/]+/u, "");
  return trimmed.length === 0 ? root : join(root, trimmed);
}

/**
 * Resolve a file-tool path that spells a temporary variable (`$TMPDIR`,
 * `${TMPDIR}`, `$TMP`, `$TEMP`) onto the temporary directory that applies for
 * this call. File-tool arguments are not shell-expanded, so without this a
 * model that writes `$TMPDIR/notes.txt` would target a literal `$TMPDIR` entry
 * in the project while the shell resolves the same spelling to its own temp
 * directory. Absolute temporary paths are NOT rewritten: they remain ordinary
 * paths for the approval chain.
 *
 * The caller chooses the root: the session workspace tmp while the sandbox is
 * on, the host temp directory otherwise.
 *
 * Returns undefined when the input does not begin with a temporary variable.
 */
export function resolveTemporaryToolPath(
  input: string,
  hostEnvironment: Readonly<Record<string, string>>,
  temporaryRoot: string | undefined,
): string | undefined {
  if (typeof input !== "string" || input.length === 0) return undefined;
  if (typeof temporaryRoot !== "string" || !isAbsolute(temporaryRoot)) return undefined;
  const variable = BRACED_VARIABLE.exec(input) ?? BARE_VARIABLE.exec(input);
  if (variable === null) return undefined;
  const name = variable[1]!;
  if (!isTemporaryVariable(name, hostEnvironment)) return undefined;
  return joinTail(temporaryRoot, input.slice(variable[0].length));
}
