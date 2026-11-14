/**
 * Per-unit chain execution and call-level aggregation (v4 §1, §3 combine).
 *
 * `decideCall` is the single entry point the host uses: hand it the frozen facts
 * of one call, get back one verdict per unit plus the call verdict. It runs the
 * same ordered chain for every unit, so two units of one call can never see
 * different rule sets, different modes or a partially updated state.
 *
 * A handler fault (throw, malformed result, kind violation) is not converted
 * into a verdict here: it is returned as `fault` so the caller fails the step
 * closed, which keeps the existing runtime semantics (one node fault = the step's
 * fault fallback) without inventing a second fail-closed policy.
 */
import type { PermissionMode } from "../../contracts";
import type { ApprovalContext, ChainCallFacts, ChainChannel, ChainUnitFacts } from "./facts";
import {
  combineCall,
  orderHandlers,
  runChain,
  type ChainFault,
  type Handler,
  type OrderHandlersFailure,
  type UnitVerdict,
} from "./run";
import { askVerdict, NO_VERDICT, type Verdict } from "./verdict";

export interface DecideOptions {
  readonly mode: PermissionMode;
  readonly channel?: ChainChannel;
  readonly handlers: readonly Handler[];
  readonly signal?: AbortSignal;
}

export interface DecideResult {
  readonly verdict: Verdict;
  readonly units: readonly UnitVerdict[];
  /** Set when a handler failed; the caller must fail the step closed. */
  readonly fault?: ChainFault;
  /** Set when the handler list itself is unusable. */
  readonly ordering?: OrderHandlersFailure;
}

export async function decideCall(
  call: ChainCallFacts,
  options: DecideOptions,
): Promise<DecideResult> {
  const ordered = orderHandlers(options.handlers);
  if (!ordered.ok) {
    return {
      verdict: askVerdict(`chain:invalid-handlers:${ordered.reason}`, "chain", {
        askFor: "escalate",
      }),
      units: [],
      ordering: ordered.reason,
    };
  }

  const channel: ChainChannel = options.channel ?? "normal";
  const units: UnitVerdict[] = [];
  for (const unit of call.units) {
    const outcome = await runChain(ordered.handlers, contextFor(call, unit, options.mode, channel, options.signal));
    units.push({ unitId: unit.unitId, verdict: outcome.verdict, steps: outcome.steps });
    if (outcome.fault !== undefined) {
      return {
        verdict: askVerdict(
          `chain:fault:${outcome.fault.handlerId}:${outcome.fault.reason}`,
          outcome.fault.handlerId,
          { askFor: "escalate" },
        ),
        units,
        fault: outcome.fault,
      };
    }
  }

  return { verdict: combineCall(units), units };
}

function contextFor(
  call: ChainCallFacts,
  unit: ChainUnitFacts,
  mode: PermissionMode,
  channel: ChainChannel,
  signal: AbortSignal | undefined,
): ApprovalContext {
  return {
    call,
    unit,
    mode,
    channel,
    accumulated: NO_VERDICT,
    ...(signal === undefined ? {} : { signal }),
  };
}
