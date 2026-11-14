/**
 * Tool-rule glob matching (docs/tool-rules-and-sandbox-tools-design.md §5.3).
 *
 * The syntax is deliberately tiny and anchored:
 * - `*` matches zero or more characters but never `/`;
 * - `**` matches zero or more characters including `/`;
 * - `?` matches exactly one character but never `/`.
 *
 * Matching is always anchored to the whole value (`^...$`), so `foo` does not
 * match `foobar` and `*foo*` is the explicit substring form. There is no escape
 * syntax (`\*` is a literal backslash followed by a wildcard) and no regular
 * expression input, so a malformed pattern cannot cause backtracking work.
 */

const REGEX_SPECIALS = /[.*+?^${}()|[\]\\]/gu;

function escapeLiteral(character: string): string {
  return character.replace(REGEX_SPECIALS, "\\$&");
}

/**
 * Compile one wildcard pattern into an anchored regular expression source.
 * Invalid input (anything that is not a string) throws: a rule table is
 * configuration, and a broken pattern must not silently match everything.
 */
export function globToRegExpSource(pattern: string): string {
  if (typeof pattern !== "string") throw new TypeError("glob pattern must be a string");
  let source = "";
  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern[index] as string;
    if (character === "*") {
      if (pattern[index + 1] === "*") {
        source += ".*";
        index += 1;
      } else {
        source += "[^/]*";
      }
      continue;
    }
    if (character === "?") {
      source += "[^/]";
      continue;
    }
    source += escapeLiteral(character);
  }
  return `^${source}$`;
}

/** Test one anchored wildcard match; a non-string value never matches. */
export function globMatches(pattern: string, value: unknown): boolean {
  if (typeof value !== "string") return false;
  let expression: RegExp;
  try {
    expression = new RegExp(globToRegExpSource(pattern), "u");
  } catch {
    return false;
  }
  return expression.test(value);
}
