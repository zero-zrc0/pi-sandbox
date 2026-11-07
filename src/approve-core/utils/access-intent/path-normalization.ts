/**
 * Policy path literal cleaning.
 *
 * Pure, host-free transformations: trim, remove at most one leading quote
 * and at most one trailing quote (no pairing required), remove one leading
 * `@`, then expand a supported home prefix.
 */
import { expandHome } from "../path/expand-home";

const QUOTE_PAIRS: readonly (readonly [string, string])[] = [
  ['"', '"'],
  ["'", "'"],
];

/** Clean a policy path literal. An empty result produces no match values. */
export function cleanPolicyLiteral(literal: string, home: string): string {
  let cleaned = literal.trim();
  for (const [open] of QUOTE_PAIRS) {
    if (cleaned.startsWith(open)) {
      cleaned = cleaned.slice(1);
      break;
    }
  }
  for (const [, close] of QUOTE_PAIRS) {
    if (cleaned.endsWith(close)) {
      cleaned = cleaned.slice(0, -1);
      break;
    }
  }
  if (cleaned.startsWith("@")) cleaned = cleaned.slice(1);
  return expandHome(cleaned, home);
}
