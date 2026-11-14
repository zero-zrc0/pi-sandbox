/**
 * Adapters from an already-computed per-call opinion to a chain link.
 *
 * Three sources keep their existing evaluators but must stop writing final
 * decisions: the configured shell policy (`builtin/powershell` /
 * `builtin/external-command`), the tool assessment, and the mode's
 * `uncertain`/`unmatched` overrides. The decision node computes their opinions
 * once per call (that is where the facts live) and hands them to these thin
 * links, so the composition still happens in one place.
 *
 * A key of `"*"` means "every unit of the call"; anything else is a unitId.
 */
import type { ApprovalContext } from "../facts";
import type { Handler } from "../run";
import type { AskTarget, Decision, HandlerResult } from "../verdict";

export const SHELL_POLICY_RESTRICTION_PRIORITY = 25;
export const SHELL_POLICY_GRANT_PRIORITY = 26;
export const ASSESSMENT_RESTRICTION_PRIORITY = 27;
export const ASSESSMENT_GRANT_PRIORITY = 28;
export const MODE_OVERRIDE_PRIORITY = 5;

export interface UnitOpinion {
  readonly decision: Decision;
  readonly reason: string;
  readonly askFor?: AskTarget;
}

const EVERY_UNIT = "*";

function opinionFor(
  opinions: ReadonlyMap<string, UnitOpinion>,
  context: ApprovalContext,
): UnitOpinion | undefined {
  return opinions.get(context.unit.unitId) ?? opinions.get(EVERY_UNIT);
}

function resultOf(opinion: UnitOpinion, action: Decision): HandlerResult {
  return {
    action,
    reason: opinion.reason,
    ...(action === "ask" && opinion.askFor !== undefined ? { askFor: opinion.askFor } : {}),
  };
}

interface OpinionHandlerOptions {
  readonly id: string;
  readonly priority: number;
  readonly opinions: ReadonlyMap<string, UnitOpinion>;
}

/**
 * Only the tightening half: `deny` stays a deny, `ask` stays an ask, `allow`
 * is somebody else's business.
 */
export function createOpinionRestrictionHandler(options: OpinionHandlerOptions): Handler {
  return Object.freeze({
    id: options.id,
    priority: options.priority,
    kind: "restriction" as const,
    evaluate: (context: ApprovalContext): HandlerResult => {
      const opinion = opinionFor(options.opinions, context);
      if (opinion === undefined || opinion.decision === "allow") return { action: "pass" };
      return resultOf(opinion, opinion.decision);
    },
  });
}

/** Only the widening half: an `allow` opinion, nothing else. */
export function createOpinionGrantHandler(options: OpinionHandlerOptions): Handler {
  return Object.freeze({
    id: options.id,
    priority: options.priority,
    kind: "grant" as const,
    evaluate: (context: ApprovalContext): HandlerResult => {
      const opinion = opinionFor(options.opinions, context);
      if (opinion === undefined || opinion.decision !== "allow") return { action: "pass" };
      return resultOf(opinion, "allow");
    },
  });
}

/**
 * The mode's configured `uncertain`/`unmatched` override is a base attitude: it
 * replaces what `mode-base` said for that unit, which is what the mode node used
 * to do with its own `decide` result. Composition still decides the outcome: a
 * deny and ask are never softened; allow only resolves no-opinion or unknown.
 */
export function createModeOverrideHandler(options: {
  readonly priority?: number;
  readonly overrides: ReadonlyMap<string, UnitOpinion>;
}): Handler {
  return Object.freeze({
    id: "builtin/mode-override",
    priority: options.priority ?? MODE_OVERRIDE_PRIORITY,
    kind: "base" as const,
    evaluate: (context: ApprovalContext): HandlerResult => {
      const override = opinionFor(options.overrides, context);
      if (override === undefined) return { action: "pass" };
      return {
        action: override.decision,
        reason: override.reason,
        ...(override.decision === "ask" && override.askFor !== undefined
          ? { askFor: override.askFor }
          : {}),
      };
    },
  });
}
