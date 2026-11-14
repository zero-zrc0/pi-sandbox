/**
 * Wildcard matching for rule patterns.
 *
 * `*` spans any run of characters (including newlines and the empty run),
 * `?` is exactly one character (including a newline), every other character
 * is literal, and the whole value must match. A pattern that ends in a space
 * followed by `*` makes that space and the rest optional, so `git *` accepts
 * both `git` and `git status`.
 *
 * Windows path surfaces compile and match with folded case and equivalent
 * separators. The surface name itself is never folded.
 */

export interface WildcardMatchOptions {
  /** Compare case-insensitively (win32 path surfaces). */
  readonly caseInsensitive?: boolean;
  /** Treat `/` and `\` as the same separator (win32 path surfaces). */
  readonly separatorEquivalence?: boolean;
}

export interface CompiledWildcard {
  /** The original pattern text, kept for reporting. */
  readonly pattern: string;
  test(value: string): boolean;
}

const REGEX_SPECIAL = /[\\^$.*+?()[\]{}|]/;

function literalSource(char: string, separatorEquivalence: boolean): string {
  if (separatorEquivalence && (char === "/" || char === "\\")) return "/";
  return REGEX_SPECIAL.test(char) ? `\\${char}` : char;
}

function wildcardSource(pattern: string, separatorEquivalence: boolean): string {
  let source = "";
  for (const char of pattern) {
    if (char === "*") source += "[\\s\\S]*";
    else if (char === "?") source += "[\\s\\S]";
    else source += literalSource(char, separatorEquivalence);
  }
  return source;
}

/** Compile one pattern. Compilation is pure; callers that need reuse cache the result. */
export function compileWildcard(
  pattern: string,
  options: WildcardMatchOptions = {},
): CompiledWildcard {
  const separatorEquivalence = options.separatorEquivalence === true;
  const optionalTail =
    pattern.length > 1 && pattern.endsWith("*") && pattern[pattern.length - 2] === " ";
  const head = optionalTail ? pattern.slice(0, -2) : pattern;
  const source = `^(?:${wildcardSource(head, separatorEquivalence)})` +
    (optionalTail ? "(?: [\\s\\S]*)?" : "") +
    "(?![\\s\\S])";
  const expression = new RegExp(source, options.caseInsensitive === true ? "i" : "");
  const value = separatorEquivalence
    ? (input: string): string => input.replace(/[\\/]/g, "/")
    : (input: string): string => input;
  return Object.freeze({
    pattern,
    test: (input: string) => expression.test(value(input)),
  });
}

/** Match one value against one pattern without retaining the compiled form. */
export function wildcardMatch(
  pattern: string,
  value: string,
  options: WildcardMatchOptions = {},
): boolean {
  return compileWildcard(pattern, options).test(value);
}
