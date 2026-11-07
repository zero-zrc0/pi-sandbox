import type { CallState, StepState } from "#approve-core/contracts";

export function pendingCalls(state: StepState): readonly CallState[] {
  return state.calls.filter((call) =>
    !call.units.some((unit) => unit.decision === "deny") &&
    call.units.some((unit) => unit.decision === "ask"));
}
