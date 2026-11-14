/**
 * `explicit-rules` — the user's own rules (v4 §2, priority 20/21).
 *
 * One matched rule is one opinion, split over the two kinds the algebra
 * distinguishes so a rule can never do two things at once:
 *
 * - {@link createExplicitRuleRestrictionHandler} turns a rule `deny` into a
 *   deny and a rule `ask` into an ask.
 * - {@link createExplicitRuleGrantHandler} turns a rule `allow` into a grant
 *   that resolves `unknown` but never erases an ask or deny.
 *
 * The split exists because "restriction may only tighten" and "grant may only
 * allow" are checked by the composition, so a single link that could do both
 * could not state a rule violation honestly.
 */
import type { ApprovalContext } from "../facts";
import type { Handler } from "../run";
import type { HandlerResult } from "../verdict";

export const EXPLICIT_RULE_RESTRICTION_PRIORITY = 20;
export const EXPLICIT_RULE_GRANT_PRIORITY = 21;

export function createExplicitRuleRestrictionHandler(): Handler {
  return Object.freeze({
    id: "builtin/explicit-rules-restrict",
    priority: EXPLICIT_RULE_RESTRICTION_PRIORITY,
    kind: "restriction" as const,
    evaluate: (context: ApprovalContext): HandlerResult => {
      const rule = context.unit.rule;
      if (rule === undefined || rule.decision === "allow") return { action: "pass" };
      const reason = `rules:${rule.origin}:${rule.decision}:${rule.pattern}`;
      if (rule.decision === "deny") return { action: "deny", reason };
      return { action: "ask", reason };
    },
  });
}

export function createExplicitRuleGrantHandler(): Handler {
  return Object.freeze({
    id: "builtin/explicit-rules-grant",
    priority: EXPLICIT_RULE_GRANT_PRIORITY,
    kind: "grant" as const,
    evaluate: (context: ApprovalContext): HandlerResult => {
      const rule = context.unit.rule;
      if (rule === undefined || rule.decision !== "allow") return { action: "pass" };
      return { action: "allow", reason: `rules:${rule.origin}:allow:${rule.pattern}` };
    },
  });
}
