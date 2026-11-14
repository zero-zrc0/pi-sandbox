/**
 * `fallback` — the end of the chain (v4 §2, priority 1000).
 *
 * It turns unresolved `unknown` and `none` states into asks after explicit
 * authorization and any sandbox receipt have had a chance to resolve them.
 */
import type { ApprovalContext } from "../facts";
import type { Handler } from "../run";
import type { HandlerResult } from "../verdict";

export const FALLBACK_PRIORITY = 1000;

export function createFallbackHandler(): Handler {
  return Object.freeze({
    id: "builtin/fallback",
    priority: FALLBACK_PRIORITY,
    kind: "restriction" as const,
    evaluate: (context: ApprovalContext): HandlerResult => {
      if (context.accumulated.state === "unknown") {
        return { action: "ask", reason: context.accumulated.reason || "fallback:unknown-effect" };
      }
      if (context.accumulated.state === "none") return { action: "ask", reason: "fallback:no-handler" };
      return { action: "pass" };
    },
  });
}
