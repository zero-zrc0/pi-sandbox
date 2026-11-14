/**
 * JSON Pointer helpers shared by the tool-rule evaluator and the declared
 * location reader (design §5.1, §5.3).
 */

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const POSIX_INDEX = /^(?:0|[1-9][0-9]*)$/u;

/** Decode a JSON Pointer; `undefined` means the pointer itself is invalid. */
export function decodePointer(pointer: string): readonly string[] | undefined {
  if (pointer.length === 0 || !pointer.startsWith("/")) return undefined;
  const tokens: string[] = [];
  for (const raw of pointer.slice(1).split("/")) {
    if (raw.length === 0 || /~(?![01])/u.test(raw)) return undefined;
    tokens.push(raw.replace(/~1/gu, "/").replace(/~0/gu, "~"));
  }
  return tokens;
}

/** Follow a pointer through objects and arrays; a missing path yields `undefined`. */
export function readPointerValue(value: unknown, tokens: readonly string[]): unknown {
  let current = value;
  for (const token of tokens) {
    if (Array.isArray(current)) {
      if (!POSIX_INDEX.test(token)) return undefined;
      current = current[Number(token)];
      continue;
    }
    if (!isPlainObject(current) || !Object.hasOwn(current, token)) return undefined;
    current = current[token];
  }
  return current;
}
