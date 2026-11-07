import type { CancellationCode } from "#sandbox/types";

/**
 * A refusal to continue an approval. The controller turns it into a cancelled
 * outcome, so the code stays inside the cancellation vocabulary.
 */
export interface ValidityRefusal {
  readonly code: CancellationCode;
  readonly reason: string;
}

/**
 * Host-owned statement that an approval is still current.
 *
 * A plan crosses a process boundary and is digest-checked, so it cannot carry
 * this: validity depends on live host facts (policy, config, session, adapter
 * generation) that only the host can read. The controller therefore re-checks
 * the lease after every wait it owns — dequeue, and again before the business
 * start — instead of trusting a check the caller made before queueing.
 */
export interface ExecutionValidityGuard {
  /** `null` means still valid; a refusal means the approval expired. */
  readonly check: () => ValidityRefusal | null;
}

const issuedGuards = new WeakSet<ExecutionValidityGuard>();

const REFUSAL_CODES: readonly CancellationCode[] = [
  "execution-cancelled",
  "execution-timeout",
  "plan-invalidated",
  "session-disposed",
];

/**
 * Only this factory issues accepted guards. A plan, helper message or model
 * argument cannot produce an object the controller will honour.
 */
export function createExecutionValidityGuard(
  check: () => ValidityRefusal | null,
): ExecutionValidityGuard {
  const guard: ExecutionValidityGuard = Object.freeze({ check });
  issuedGuards.add(guard);
  return guard;
}

export function isExecutionValidityGuard(
  value: unknown,
): value is ExecutionValidityGuard {
  return (
    typeof value === "object" &&
    value !== null &&
    issuedGuards.has(value as ExecutionValidityGuard)
  );
}

/**
 * Runs a lease and fails closed. A guard that throws or returns something
 * unusable means the host can no longer prove the approval is current, which
 * is a refusal rather than a pass.
 */
export function validityRefusal(
  guard: ExecutionValidityGuard | undefined,
): ValidityRefusal | null {
  if (guard === undefined) return null;
  let verdict: ValidityRefusal | null;
  try {
    verdict = guard.check();
  } catch {
    return {
      code: "plan-invalidated",
      reason: "the host validity lease threw while checking the approval",
    };
  }
  if (verdict === null) return null;
  if (
    typeof verdict !== "object" ||
    typeof verdict.reason !== "string" ||
    !REFUSAL_CODES.includes(verdict.code)
  ) {
    return {
      code: "plan-invalidated",
      reason: "the host validity lease returned an unusable refusal",
    };
  }
  return verdict;
}
