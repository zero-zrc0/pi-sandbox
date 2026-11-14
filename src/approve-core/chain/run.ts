/**
 * The chain runner (v4 §1): ordered links, incremental composition, deny
 * short-circuit.
 *
 * The runner owns ordering and fault reporting; the links own their opinions.
 * Rules that make the outcome independent of who ran first:
 *
 * 1. `deny` ends the chain immediately — later links never execute, so they can
 *    never revive the call.
 * 2. An ask remains the rule verdict; reviewers record an exact-call outcome separately.
 * 3. A link that throws or returns a malformed result is a **fault**, not an
 *    opinion: the runner stops and reports it, so the caller fails the step
 *    closed instead of guessing what the link meant.
 *
 * Links are ordered by `priority` (lower first), then by declaration order, so
 * an equal-priority pair keeps the order the caller declared.
 */
import type { ApprovalContext } from "./facts";
import {
  composeVerdict,
  isHandlerResult,
  strongestVerdict,
  type HandlerKind,
  type HandlerResult,
  type Verdict,
} from "./verdict";

export interface Handler {
  readonly id: string;
  /** Lower runs first. Built-ins use 0/10/20/30/40/50/60, users 70-990. */
  readonly priority: number;
  readonly kind: HandlerKind;
  evaluate(context: ApprovalContext): HandlerResult | Promise<HandlerResult>;
}

export type OrderHandlersFailure =
  | "invalid-handlers"
  | "invalid-handler"
  | "duplicate-handler-id"
  | "invalid-priority"
  | "invalid-kind";

export type OrderHandlersResult =
  | { readonly ok: true; readonly handlers: readonly Handler[] }
  | { readonly ok: false; readonly reason: OrderHandlersFailure };

/** One link's contribution, kept for the audit trail. */
export interface ChainStep {
  readonly handlerId: string;
  readonly kind: HandlerKind;
  readonly priority: number;
  readonly result: HandlerResult;
  /** Set when the link violated its kind or returned nothing usable. */
  readonly violation?: string;
  /** Set when `evaluate` threw; the runner then stops. */
  readonly fault?: string;
}

export interface ChainOutcome {
  readonly verdict: Verdict;
  readonly steps: readonly ChainStep[];
  /** Set when the chain stopped early; the caller must fail the step closed. */
  readonly fault?: ChainFault;
}

export interface ChainFault {
  readonly handlerId: string;
  readonly reason: string;
}

/**
 * A handler list is data, not code: it must never silently drop a link. Ids are
 * unique (they appear in the audit trail), priorities are safe integers so the
 * order is total, and only the three documented kinds exist.
 */
export function orderHandlers(handlers: readonly Handler[]): OrderHandlersResult {
  if (!Array.isArray(handlers)) return { ok: false, reason: "invalid-handlers" };
  const seen = new Set<string>();
  for (const handler of handlers) {
    if (handler === null || typeof handler !== "object") {
      return { ok: false, reason: "invalid-handler" };
    }
    if (typeof handler.id !== "string" || handler.id.trim().length === 0) {
      return { ok: false, reason: "invalid-handler" };
    }
    if (typeof handler.evaluate !== "function") {
      return { ok: false, reason: "invalid-handler" };
    }
    if (seen.has(handler.id)) return { ok: false, reason: "duplicate-handler-id" };
    seen.add(handler.id);
    if (!Number.isSafeInteger(handler.priority)) {
      return { ok: false, reason: "invalid-priority" };
    }
    if (
      handler.kind !== "base" &&
      handler.kind !== "restriction" &&
      handler.kind !== "grant"
    ) {
      return { ok: false, reason: "invalid-kind" };
    }
  }
  const ordered = handlers
    .map((handler, index) => ({ handler, index }))
    .sort((left, right) => left.handler.priority === right.handler.priority
      ? left.index - right.index
      : left.handler.priority - right.handler.priority)
    .map((entry) => entry.handler);
  return { ok: true, handlers: Object.freeze(ordered) };
}

/** Run the chain for one unit and return the composed verdict. */
export async function runChain(
  handlers: readonly Handler[],
  context: ApprovalContext,
): Promise<ChainOutcome> {
  const steps: ChainStep[] = [];
  let verdict: Verdict = context.accumulated;

  for (const handler of handlers) {
    let raw: unknown;
    try {
      raw = await handler.evaluate({ ...context, accumulated: verdict });
    } catch (error) {
      const reason = error instanceof Error ? error.message : "threw";
      steps.push({
        handlerId: handler.id,
        kind: handler.kind,
        priority: handler.priority,
        result: { action: "pass" },
        fault: reason,
      });
      return {
        verdict,
        steps,
        fault: { handlerId: handler.id, reason },
      };
    }

    if (!isHandlerResult(raw)) {
      steps.push({
        handlerId: handler.id,
        kind: handler.kind,
        priority: handler.priority,
        result: { action: "pass" },
        violation: "invalid-handler-result",
      });
      return {
        verdict,
        steps,
        fault: { handlerId: handler.id, reason: "invalid-handler-result" },
      };
    }

    const composed = composeVerdict(verdict, raw, handler.kind, handler.id);
    verdict = composed.verdict;
    steps.push({
      handlerId: handler.id,
      kind: handler.kind,
      priority: handler.priority,
      result: raw,
      ...(composed.violation === undefined ? {} : { violation: composed.violation }),
    });
    if (composed.violation !== undefined) {
      return {
        verdict,
        steps,
        fault: { handlerId: handler.id, reason: composed.violation },
      };
    }
    // Deny short-circuits: the remaining links must not run at all.
    if (verdict.state === "deny") return { verdict, steps };
  }

  return { verdict, steps };
}

export interface UnitVerdict {
  readonly unitId: string;
  readonly verdict: Verdict;
  readonly steps: readonly ChainStep[];
}

export interface CallVerdict {
  /** The call-level verdict: any deny wins, then any ask, else allow. */
  readonly verdict: Verdict;
  readonly units: readonly UnitVerdict[];
}

/**
 * Fold unit verdicts into one call verdict (v4 §3 combine): `deny > ask >
 * allow`. A call whose asking units include an escalation ask stays escalated as
 * a whole, so no resolver may auto-approve the rest of it.
 */
export function combineCall(units: readonly UnitVerdict[]): Verdict {
  if (units.length === 0) {
    return strongestVerdict([]);
  }
  return strongestVerdict(units.map((unit) => unit.verdict));
}
