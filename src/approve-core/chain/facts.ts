import type { ExecutionRequest } from "../../elevation";
/**
 * Facts a chain link may read (v4 §1 `ApprovalContext`, §3 `ShellFacts`).
 *
 * This file is the seam between "facts are derived once" and "links state
 * opinions". It holds plain readonly data: a link gets no file system, no
 * network, no shell and no mutable state, so the same facts always compose into
 * the same verdict.
 *
 * The shapes mirror the facts the existing analysis already produces, so the
 * projection is a mapping rather than a second derivation:
 *
 * - `UnitAccessFact` is structurally the same as `AccessFact`
 *   (`nodes/mode/index.ts`), the read/write/network direction each unit proves;
 * - `dangers` is `detectDangers()` output (`risk/danger.ts`), already reduced to
 *   the six v3 §5 families with a machine-readable reason;
 * - `rule` is the effective explicit rule that matched the unit;
 * - `sensitive` is the sensitive-path reference of each target the unit
 *   touches.
 *
 * Nothing here decides anything: the handlers do, and they only read fields.
 */
import type { PermissionMode } from "../../contracts";
import type { DangerHit } from "../risk/danger";
import type { Decision, Verdict } from "./verdict";

/** `normal` is an ordinary tool call; `elevation` is `request_tool_elevation`. */
export type ChainChannel = "normal" | "elevation";

/**
 * The direction one unit proves for one target. `review` marks a shape whose
 * paths are local but which still needs a human look (a recursive, forced
 * delete).
 */
export type UnitAccessKind = "read" | "write" | "network" | "unknown" | "review";

export interface UnitAccessFact {
  readonly kind: UnitAccessKind;
  readonly path?: string;
  /** Set when the path resolves outside the workspace. */
  readonly external?: boolean;
  /** Set when a PowerShell delete removes a path outside the workspace. */
  readonly externalDelete?: boolean;
}

/**
 * The explicit rule that decided this unit. Kept separate from built-in
 * opinions: a user rule is evidence of intent, not a mode baseline.
 */
export interface UnitRuleFact {
  readonly decision: Decision;
  readonly pattern: string;
  readonly origin: "global" | "project" | "session";
  /**
   * For `decision: "ask"`: true when the user asked for a human decision.
   * Unset means a grant or the model resolver may still approve it.
   */
  readonly locked?: boolean;
}

/** What a unit does to one sensitive target. */
export type SensitiveSurface = "read" | "write" | "delete" | "upload";

export interface SensitiveRef {
  readonly path: string;
  /** The protected family the path belongs to (`.git`, `.ssh`, `.env`, ...). */
  readonly category: string;
  readonly surface: SensitiveSurface;
}

/** One unit's frozen facts; `unitId` binds to the prepared unit and its digest. */
export interface ChainUnitFacts {
  readonly unitId: string;
  readonly toolName: string;
  /** Every access direction this unit proves; empty means "nothing proven". */
  readonly access: readonly UnitAccessFact[];
  readonly dangers?: readonly DangerHit[];
  readonly rule?: UnitRuleFact;
  readonly sensitive?: readonly SensitiveRef[];
}

/** One frozen call: the unit set plus the host's execution request, if any. */
export interface ChainCallFacts {
  readonly toolCallId: string;
  readonly toolName: string;
  readonly units: readonly ChainUnitFacts[];
  /** Set when the call came through the one-time host-execution channel. */
  readonly hostExecutionRequest?: ExecutionRequest;
}

/** What a link receives for one unit. */
export interface ApprovalContext {
  readonly call: ChainCallFacts;
  readonly unit: ChainUnitFacts;
  readonly mode: PermissionMode;
  readonly channel: ChainChannel;
  /** The verdict so far for this unit, so a link can name what it changes. */
  readonly accumulated: Verdict;
  readonly signal?: AbortSignal;
}

/** Every fact hits are reported per unit; a call-level danger repeats per unit. */
export interface UnitFactsProjection {
  readonly access: readonly UnitAccessFact[];
  readonly dangers: readonly DangerHit[];
  readonly rule?: UnitRuleFact;
  readonly sensitive: readonly SensitiveRef[];
}
