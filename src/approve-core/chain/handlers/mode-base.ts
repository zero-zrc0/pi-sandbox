/**
 * `mode-base` — the mode's baseline attitude (v4 §2, priority 0).
 *
 * This link answers one question only: "given this mode, what does the mode
 * itself think about this unit?" It never looks at danger rules, sensitive
 * paths or explicit rules — those are later restrictions that tighten this
 * baseline, and that is why `full-access` can no longer disable them:
 * `full-access` stops at "no prompt for ordinary work", it does not make the
 * chain skip its restrictions.
 *
 * The access facts are the ones the analysis already proved. An empty list is
 * `unknown`, never `allow`: a unit whose effect nobody can state is exactly what
 * the fallback, the model resolver and C2 exist for.
 *
 * An explicit one-time elevation is an `escalate` ask, so later grants cannot
 * replace approval of its selected tier.
 */
import type { PermissionMode } from "../../../contracts";
import type { ApprovalContext, UnitAccessFact } from "../facts";
import type { Handler } from "../run";
import type { HandlerResult } from "../verdict";

export const MODE_BASE_PRIORITY = 0;

export interface ModeBaseOptions {
  readonly strictApproval?: boolean;
}

export function createModeBaseHandler(options: ModeBaseOptions = {}): Handler {
  return Object.freeze({
    id: "builtin/mode-base",
    priority: MODE_BASE_PRIORITY,
    kind: "base" as const,
    evaluate: (context: ApprovalContext): HandlerResult => baseOpinion(context, options.strictApproval === true),
  });
}

function baseOpinion(context: ApprovalContext, strictApproval: boolean): HandlerResult {
  const { call, unit, mode } = context;
  if (call.hostExecutionRequest !== undefined) {
    const elevation = call.hostExecutionRequest.elevation;
    const facts = provenAccess(unit.access);
    if (facts.some(fact => fact.kind === "unknown" || fact.kind === "network" || fact.kind === "review")) {
      return { action: "deny", reason: "mode:elevation:effects-unproven-or-unsafe" };
    }
    if (elevation.tier === "default" && facts.some(fact => fact.external === true || fact.externalDelete === true)) {
      return { action: "deny", reason: "mode:elevation:scope-exceeds-default" };
    }
    return { action: "ask", askFor: "escalate", reason: `mode:${mode}:one-time-${elevation.tier}-execution` };
  }
  if (mode === "full-access") {
    return { action: "allow", reason: "mode:full-access:bypass-remaining-ask" };
  }
  const facts = provenAccess(unit.access);
  if (mode === "read-only") return readOnlyOpinion(facts);
  if (
    call.toolName === "write" &&
    unit.rule?.origin === "session" &&
    unit.rule.decision === "allow" &&
    unit.access.length === 1 &&
    unit.access[0]?.kind === "write" &&
    unit.access[0].external === true &&
    unit.access[0].externalDelete !== true
  ) {
    return { action: "allow", reason: "mode:session-path-write-allow" };
  }
  return defaultOpinion(mode, facts, strictApproval);
}

/** No proven access is `unknown`, not "nothing to see". */
function provenAccess(facts: readonly UnitAccessFact[]): readonly UnitAccessFact[] {
  return facts.length === 0 ? [{ kind: "unknown" }] : facts;
}

function readOnlyOpinion(facts: readonly UnitAccessFact[]): HandlerResult {
  if (facts.some((fact) => fact.kind === "write")) {
    return { action: "deny", reason: "mode:read-only:write-forbidden" };
  }
  if (facts.some((fact) => fact.kind === "network")) {
    return { action: "deny", reason: "mode:read-only:network-forbidden" };
  }
  if (facts.some((fact) => fact.kind === "review")) {
    return { action: "ask", reason: "mode:read-only:destructive-needs-approval" };
  }
  if (facts.some((fact) => fact.kind === "unknown")) {
    return { action: "ask", reason: "mode:read-only:effect-unproven" };
  }
  if (isProvenLocal(facts)) {
    return { action: "allow", reason: "mode:read-only:workspace-read-allow" };
  }
  return { action: "ask", reason: "mode:read-only:effect-unproven" };
}

function defaultOpinion(
  mode: PermissionMode,
  facts: readonly UnitAccessFact[],
  strictApproval: boolean,
): HandlerResult {
  if (facts.some((fact) => fact.externalDelete === true)) {
    return {
      action: "ask",
      askFor: "escalate",
      reason: `mode:${mode}:external-delete-needs-approval`,
    };
  }
  if (facts.some((fact) => fact.kind === "network")) {
    return { action: "ask", reason: `mode:${mode}:network-needs-approval` };
  }
  if (facts.some((fact) => fact.kind === "write" && fact.external === true)) {
    return {
      action: "ask",
      askFor: "escalate",
      reason: `mode:${mode}:external-write-needs-approval`,
    };
  }
  if (facts.some((fact) => fact.kind === "review")) {
    return { action: "ask", reason: `mode:${mode}:destructive-needs-approval` };
  }
  if (facts.some((fact) => fact.kind === "unknown")) {
    return { action: "unknown", reason: `mode:${mode}:effect-unproven` };
  }
  if (isProvenLocal(facts)) {
    if (strictApproval) return { action: "unknown", reason: `mode:${mode}:strict-approval-required` };
    const readsOnly = facts.every((fact) => fact.kind === "read");
    return {
      action: "allow",
      reason: `mode:${mode}:${readsOnly ? "workspace-read-allow" : "workspace-write-allow"}`,
    };
  }
  return { action: "unknown", reason: `mode:${mode}:effect-unproven` };
}

/**
 * Every direction proven and local: a mixed read+write command (`echo hi >
 * out.txt`) is as local as a pure read, so both allow.
 */
function isProvenLocal(facts: readonly UnitAccessFact[]): boolean {
  return facts.length > 0 && facts.every((fact) =>
    (fact.kind === "read" || fact.kind === "write") &&
    fact.external !== true &&
    fact.externalDelete !== true);
}
