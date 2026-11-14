/**
 * Session approval suggestions for Bash commands.
 *
 * A suggestion is the longest semantically meaningful prefix of a command.
 * Whole-line comments are dropped first. Wrapper text is kept only when every
 * layer is safely generalizable and the inner command is a plain literal;
 * otherwise the whole command is the suggestion, so a grant never widens.
 */
import { commandPrefixArity } from "../utils/access-intent/bash/bash-arity";

export type SessionCommandShape =
  | { readonly kind: "literal"; readonly text: string }
  | {
      readonly kind: "wrapped";
      /** Exact full command text, used when the wrapper cannot generalize. */
      readonly text: string;
      /** Text of the wrapper layers that precede the inner command. */
      readonly prefix: string;
      readonly inner: SessionCommandShape;
      /** Whether every wrapper layer is safe to generalize. */
      readonly generalizable: boolean;
    }
  | { readonly kind: "opaque"; readonly text: string };

interface CommandToken {
  /** Token as written, quotes and escapes included. */
  readonly raw: string;
  /** Token value with simple quotes and backslash escapes removed. */
  readonly value: string;
  /** Offset of the token's first character in the command text. */
  readonly start: number;
}

const RESERVED_WORDS = new Set([
  "if",
  "then",
  "else",
  "elif",
  "fi",
  "for",
  "while",
  "until",
  "do",
  "done",
  "case",
  "esac",
  "select",
  "function",
  "time",
  "in",
  "!",
  "{",
  "}",
  "[[",
  "]]",
]);

function stripWholeLineComments(text: string): string {
  return text
    .split("\n")
    .filter((line) => !/^\s*#/.test(line))
    .join("\n")
    .trim();
}

function tokenize(text: string): CommandToken[] {
  const tokens: CommandToken[] = [];
  let raw = "";
  let value = "";
  let start = -1;
  let quote: "'" | '"' | null = null;

  const flush = (): void => {
    if (start >= 0) tokens.push({ raw, value, start });
    raw = "";
    value = "";
    start = -1;
  };

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quote === "'") {
      raw += char;
      if (char === "'") quote = null;
      else value += char;
      continue;
    }
    if (quote === '"') {
      if (char === "\\" && index + 1 < text.length) {
        raw += char + text[index + 1];
        value += text[index + 1];
        index += 1;
        continue;
      }
      raw += char;
      if (char === '"') quote = null;
      else value += char;
      continue;
    }
    if (/\s/.test(char)) {
      flush();
      continue;
    }
    if (start < 0) start = index;
    if (char === "'" || char === '"') {
      raw += char;
      quote = char;
      continue;
    }
    if (char === "\\" && index + 1 < text.length) {
      raw += char + text[index + 1];
      value += text[index + 1];
      index += 1;
      continue;
    }
    raw += char;
    value += char;
  }
  flush();
  return tokens;
}

/** True when the text contains shell syntax that a plain prefix cannot cover. */
function hasShellSyntax(text: string): boolean {
  let quote: "'" | '"' | null = null;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quote === "'") {
      if (char === "'") quote = null;
      continue;
    }
    if (quote === '"') {
      if (char === "\\") {
        index += 1;
        continue;
      }
      if (char === '"') quote = null;
      continue;
    }
    if (char === "\\") {
      index += 1;
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
      continue;
    }
    if ("|&;<>()`\n".includes(char)) return true;
    if (char === "$" && text[index + 1] === "(") return true;
  }
  return false;
}

function literalSuggestion(text: string): string {
  if (text.length === 0) return "";
  const tokens = tokenize(text);
  if (tokens.length === 0) return "";
  if (hasShellSyntax(text)) return text;
  if (RESERVED_WORDS.has(tokens[0].value)) return text;
  if (tokens.length === 1) return text;
  const arity = commandPrefixArity(tokens.map((token) => token.value));
  if (arity >= tokens.length) return `${text}*`;
  return `${text.slice(0, tokens[arity].start).trimEnd()} *`;
}

function suggestionFor(shape: SessionCommandShape): string {
  if (shape.kind === "opaque") return shape.text.trim();
  if (shape.kind === "literal") return literalSuggestion(stripWholeLineComments(shape.text));
  if (!shape.generalizable) return shape.text.trim();
  if (shape.inner.kind !== "literal") return shape.text.trim();
  const inner = literalSuggestion(stripWholeLineComments(shape.inner.text));
  if (inner.length === 0) return shape.text.trim();
  const prefix = shape.prefix.trim();
  return prefix.length === 0 ? inner : `${prefix} ${inner}`;
}

/**
 * Build the session approval pattern for a command text or an analyzed shape.
 * An empty result means there is nothing to authorize (blank or all comments).
 */
export function suggestSessionPattern(shape: string | SessionCommandShape): string {
  if (typeof shape === "string") {
    return literalSuggestion(stripWholeLineComments(shape));
  }
  return suggestionFor(shape);
}
