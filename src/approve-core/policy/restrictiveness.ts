/**
 * Restrictiveness ordering shared by rule results.
 *
 * Independent accesses are folded with deny > ask > allow. Ties keep the
 * first complete result so its tool name, pattern, origin, source and reason
 * survive; that is different from rule order, where the last match wins.
 */
import type { RuleAction } from "./rule";

export const ACTION_RANK: Readonly<Record<RuleAction, number>> = Object.freeze({
  allow: 0,
  ask: 1,
  deny: 2,
});

/** The more restrictive of two actions. */
export function moreRestrictive(left: RuleAction, right: RuleAction): RuleAction {
  return ACTION_RANK[left] >= ACTION_RANK[right] ? left : right;
}

/**
 * Fold independent checks into the most restrictive one. The first check of
 * the winning rank is returned unchanged; an empty list has no restriction.
 */
export function pickMostRestrictive<T extends { readonly state: RuleAction }>(
  checks: readonly T[],
): T | undefined {
  let winner: T | undefined;
  for (const check of checks) {
    if (winner === undefined || ACTION_RANK[check.state] > ACTION_RANK[winner.state]) {
      winner = check;
      if (check.state === "deny") break;
    }
  }
  return winner;
}
