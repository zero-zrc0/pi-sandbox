/**
 * Verdict algebra of the approval responsibility chain (v4 §1).
 *
 * Every link of the chain states one opinion about one unit: `pass` (no
 * opinion), `unknown`, `allow`, `ask` or `deny`. The runner composes those opinions once,
 * incrementally, into a single {@link Verdict}; no link writes final state and
 * no link overrides another link's decision.
 *
 * Within one unit, `deny > ask > allow > unknown`:
 *
 * - `deny` terminates the chain — an already denied verdict is never revived.
 * - `ask` is sticky against allow; review outcomes are stored separately.
 * - `allow` can resolve `none` or `unknown`, but it cannot erase `ask`.
 *
 * `askFor: "escalate"` determines which reviewer may authorize the exact call.
 * It does not change the rule verdict.
 *
 * Two kinds of ask exist (v4 §0.1) and only one of them is a decision: "no
 * opinion yet" is `none`; `unknown` means the mode cannot prove the effect.
 * The fallback turns unresolved unknown into an ask after all configured
 * authorization and sandbox-receipt checks have run.
 *
 * A link that violates its own kind (`restriction` returning allow, `grant`
 * returning deny/ask) is a fault, not an opinion: the outcome fails closed with
 * an escalation ask, so a broken plugin can never widen access.
 */
import type { PermissionMode } from "../../contracts";

export type Decision = "allow" | "ask" | "deny";

export type AskTarget = "allow" | "escalate";

/**
 * What a link is allowed to say. `base` states the mode's baseline attitude;
 * `base` may state `unknown`; `restriction` may only tighten (`ask`/`deny`);
 * `grant` may resolve `unknown` (`allow`).
 */
export type HandlerKind = "base" | "restriction" | "grant";

export interface HandlerResult {
  readonly action: "pass" | "unknown" | Decision;
  readonly reason?: string;
  /**
   * Only meaningful with `action: "ask"`. `escalate` marks an elevation ask.
   */
  readonly askFor?: AskTarget;
}

/** `none` is "no link has stated an opinion yet", not an ask. */
export type VerdictState = "none" | "unknown" | Decision;

export interface Verdict {
  readonly state: VerdictState;
  /** Set only for `ask`; `escalate` wins over `allow`. */
  readonly askFor?: AskTarget;
  /** Legacy marker for `askFor: "escalate"`; reviewers may authorize the exact call. */
  readonly locked: boolean;
  /** Machine-readable reason; empty for `none`. */
  readonly reason: string;
  /** The id of the link that produced the current state. */
  readonly source: string;
}

/** The chain's starting point: no link has spoken. */
export const NO_VERDICT: Verdict = Object.freeze({
  state: "none",
  locked: false,
  reason: "",
  source: "",
});

export function allowVerdict(reason: string, source: string): Verdict {
  return Object.freeze({ state: "allow", locked: false, reason, source });
}

export function unknownVerdict(reason: string, source: string): Verdict {
  return Object.freeze({ state: "unknown", locked: false, reason, source });
}

export function askVerdict(
  reason: string,
  source: string,
  options: { readonly askFor?: AskTarget } = {},
): Verdict {
  return Object.freeze({
    state: "ask",
    locked: options.askFor === "escalate",
    reason,
    source,
    ...(options.askFor === undefined ? {} : { askFor: options.askFor }),
  });
}

export function denyVerdict(reason: string, source: string): Verdict {
  return Object.freeze({ state: "deny", locked: false, reason, source });
}

/**
 * The stricter of two ask targets: an ask that needs a host execution stays an
 * escalation ask even when another link only wanted an approval.
 */
export function strongerAskTarget(
  left: AskTarget | undefined,
  right: AskTarget | undefined,
): AskTarget | undefined {
  if (left === "escalate" || right === "escalate") return "escalate";
  if (left === "allow" || right === "allow") return "allow";
  return undefined;
}

/**
 * Whether a configured reviewer may handle this verdict. Reviewers may assess
 * any ask; `askFor` controls the execution authorization that follows.
 */
export function isResolverEligible(verdict: Verdict): boolean {
  return verdict.state === "ask";
}

export interface ComposeOutcome {
  readonly verdict: Verdict;
  /** Set when the link violated its kind; the verdict then fails closed. */
  readonly violation?: string;
}

/**
 * Compose one link's result into the running verdict. The caller short-circuits
 * `deny` before this, so `current` never holds a deny here.
 */
export function composeVerdict(
  current: Verdict,
  result: HandlerResult,
  kind: HandlerKind,
  source: string,
): ComposeOutcome {
  const failClosed = (reason: string): ComposeOutcome => ({
    verdict: askVerdict(`chain:invalid-handler-result:${reason}`, source, {
      askFor: "escalate",
    }),
    violation: reason,
  });

  if (current.state === "deny") return { verdict: current };
  if (result.action === "pass") return { verdict: current };

  if (result.action === "unknown") {
    if (kind !== "base") return failClosed(`${kind}-cannot-mark-unknown`);
    if (current.state === "none") {
      return { verdict: unknownVerdict(result.reason ?? current.reason, source) };
    }
    return { verdict: current };
  }

  if (result.action === "deny") {
    // A grant exists to widen, never to narrow.
    if (kind === "grant") return failClosed("grant-cannot-deny");
    return { verdict: denyVerdict(result.reason ?? current.reason, source) };
  }

  if (result.action === "allow") {
    // A restriction may only tighten, so an allow from one is a broken link.
    if (kind === "restriction") return failClosed("restriction-cannot-allow");
    const reason = result.reason ?? current.reason;
    if (current.state === "none" || current.state === "unknown") {
      return { verdict: allowVerdict(reason, source) };
    }
    if (current.state === "allow") return { verdict: current };
    return { verdict: current };
  }

  // `ask` is allowed from every kind, and it always raises the bar.
  if (kind === "grant") return failClosed("grant-cannot-ask");
  const askFor = strongerAskTarget(current.askFor, result.askFor);
  return {
    verdict: askVerdict(result.reason ?? current.reason, source, {
      ...(askFor === undefined ? {} : { askFor }),
    }),
  };
}

/**
 * Fold unit verdicts into one call verdict. An unresolved unit cannot be hidden
 * by an allow from another unit.
 *
 * Among asks the escalation ask outranks a plain ask, so the call-level reason
 * names the decision that actually blocks.
 */
export function strongestVerdict(verdicts: readonly Verdict[]): Verdict {
  if (verdicts.length === 0) return NO_VERDICT;
  const denied = verdicts.find((verdict) => verdict.state === "deny");
  if (denied !== undefined) return denied;

  const asks = verdicts.filter((verdict) => verdict.state === "ask");
  if (asks.length > 0) {
    const ranked = [...asks].sort((left, right) => askRank(right) - askRank(left));
    const winner = ranked[0];
    const askFor = asks.reduce<AskTarget | undefined>(
      (target, verdict) => strongerAskTarget(target, verdict.askFor),
      undefined,
    );
    return askVerdict(winner.reason, winner.source, {
      ...(askFor === undefined ? {} : { askFor }),
    });
  }

  const unknown = verdicts.find((verdict) => verdict.state === "unknown");
  if (unknown !== undefined) return unknown;
  return verdicts.find((verdict) => verdict.state === "allow") ?? NO_VERDICT;
}

/** Ranking inside the ask band: an escalation ask comes first. */
function askRank(verdict: Verdict): number {
  return verdict.askFor === "escalate" ? 2 : 0;
}

/** Runtime shape check for results that may come from a user handler. */
export function isHandlerResult(value: unknown): value is HandlerResult {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const candidate = value as {
    readonly action?: unknown;
    readonly reason?: unknown;
    readonly askFor?: unknown;
  };
  if (
    candidate.action !== "pass" &&
    candidate.action !== "unknown" &&
    candidate.action !== "allow" &&
    candidate.action !== "ask" &&
    candidate.action !== "deny"
  ) {
    return false;
  }
  if (candidate.action === "pass") {
    // A pass carries no opinion; extra fields would be silently dropped.
    return candidate.reason === undefined && candidate.askFor === undefined;
  }
  if (candidate.reason !== undefined && typeof candidate.reason !== "string") return false;
  if (
    candidate.askFor !== undefined &&
    candidate.askFor !== "allow" &&
    candidate.askFor !== "escalate"
  ) {
    return false;
  }
  // `askFor` describes how an ask is satisfied; on any other action it would be
  // a contradiction the runner must not silently accept.
  if (candidate.action !== "ask" && candidate.askFor !== undefined) return false;
  return true;
}

/** Re-exported for handlers that only need the mode type. */
export type { PermissionMode };
