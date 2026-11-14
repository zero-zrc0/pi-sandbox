/**
 * `danger-intent` — the built-in danger families (v4 §3, priority 30).
 *
 * Detection is `risk/danger.ts`; this link only translates a hit into the
 * channel's verdict:
 *
 * A risk deny short-circuits both normal and elevation calls. Permission
 * elevation cannot authorize an action that the risk policy forbids.
 *
 * A danger that the rule table reports as `ask` (a bulk delete under an `ask`
 * policy) is raised as an escalation ask as well: a destructive shape is not
 * something a model should approve on its own.
 */
import type { ApprovalContext } from "../facts";
import type { DangerHit } from "../../risk/danger";
import type { Handler } from "../run";
import type { HandlerResult } from "../verdict";

export const DANGER_INTENT_PRIORITY = 30;

/**
 * Hits arrive in the v3 §5 table order (`risk/danger.ts`), so the first hit is
 * the most severe family the facts prove; the reason stays reproducible instead
 * of depending on the order the units were written.
 */
export function createDangerIntentHandler(): Handler {
  return Object.freeze({
    id: "builtin/danger-intent",
    priority: DANGER_INTENT_PRIORITY,
    kind: "restriction" as const,
    evaluate: (context: ApprovalContext): HandlerResult => {
      const hits = context.unit.dangers ?? [];
      if (hits.length === 0) return { action: "pass" };
      return dangerOpinion(hits[0], context.channel === "elevation");
    },
  });
}

function dangerOpinion(hit: DangerHit, elevation: boolean): HandlerResult {
  const detail = detailOf(hit);
  if (hit.action === "deny") {
    return { action: "deny", reason: `risk:${hit.kind}:blocked:${detail}` };
  }
  if (elevation) {
    return {
      action: "ask",
      askFor: "escalate",
      reason: `risk:${hit.kind}:elevation-confirmation:${detail}`,
    };
  }
  return {
    action: "ask",
    askFor: "escalate",
    reason: `risk:${hit.kind}:needs-confirmation:${detail}`,
  };
}

/** `risk:<kind>:<detail>` → `<detail>`; keeps the reason machine-readable. */
function detailOf(hit: DangerHit): string {
  const prefix = `risk:${hit.kind}:`;
  return hit.reason.startsWith(prefix) ? hit.reason.slice(prefix.length) : hit.reason;
}
