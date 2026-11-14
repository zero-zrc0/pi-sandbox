/**
 * Home prefix expansion.
 *
 * Supported prefixes are exactly `~`, `$HOME` and `${HOME}`. A prefix must
 * stand alone or be followed by `/` (or `\\`). `~user`, `$HOMEDIR` and
 * operator forms such as `${HOME:-...}` never expand.
 */

/** Split a supported home prefix off `literal` without joining or normalizing the rest. */
export function splitHomePrefix(
  literal: string,
  home: string,
): { readonly prefix: string; readonly rest: string } | undefined {
  let rest: string | undefined;
  if (literal === "~" || literal === "$HOME" || literal === "${HOME}") {
    rest = "";
  } else if (literal.startsWith("~/") || literal.startsWith("~\\")) {
    rest = literal.slice(1);
  } else if (literal.startsWith("$HOME/") || literal.startsWith("$HOME\\")) {
    rest = literal.slice("$HOME".length);
  } else if (literal.startsWith("${HOME}/") || literal.startsWith("${HOME}\\")) {
    rest = literal.slice("${HOME}".length);
  }
  if (rest === undefined) return undefined;
  return { prefix: home, rest };
}

/**
 * Expand a supported home prefix using the OS home directory. The remaining
 * text keeps its own semantics; only the prefix is replaced.
 */
export function expandHome(literal: string, home: string): string {
  const split = splitHomePrefix(literal, home);
  if (split === undefined) return literal;
  if (split.rest.length === 0) return split.prefix;
  const homeEndsWithSeparator = split.prefix.endsWith("/") || split.prefix.endsWith("\\");
  // `rest` already begins with the separator; drop it when home ends with one.
  return homeEndsWithSeparator ? split.prefix + split.rest.slice(1) : split.prefix + split.rest;
}
