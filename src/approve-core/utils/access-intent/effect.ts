/**
 * Access effects and their proofs.
 *
 * `unproven` means there is not enough proof — it is not a third file
 * operation. Proof sources are tracked so audit can explain why an effect
 * was attributed.
 */

export type AccessEffect = "read" | "write" | "unproven";

export type EffectProofSource =
  | "syntax"
  | "builtin-core"
  | "global-declared"
  | "project-declared"
  | "declaration-retracted"
  | "unknown";

export interface EffectProof {
  readonly effect: AccessEffect;
  readonly source: EffectProofSource;
  /** Optional machine-readable explanation, e.g. the retracting option. */
  readonly detail?: string;
}

export function proof(effect: AccessEffect, source: EffectProofSource, detail?: string): EffectProof {
  return detail === undefined ? { effect, source } : { effect, source, detail };
}

/** Higher rank means more diagnostic value when effects agree. */
const SOURCE_RANK: Record<EffectProofSource, number> = {
  syntax: 5,
  "declaration-retracted": 4,
  "builtin-core": 3,
  "project-declared": 2,
  "global-declared": 1,
  unknown: 0,
};

/**
 * Merge two proofs for the same path. Equal effects keep the proof whose
 * source carries more diagnostic value; disagreeing effects become unknown.
 * The merge is symmetric in argument order.
 */
export function mergeEffectProofs(a: EffectProof, b: EffectProof): EffectProof {
  if (a.effect !== b.effect) return { effect: "unproven", source: "unknown" };
  if (a.source === b.source) {
    return a.detail !== undefined ? a : b;
  }
  return SOURCE_RANK[a.source] >= SOURCE_RANK[b.source] ? a : b;
}
