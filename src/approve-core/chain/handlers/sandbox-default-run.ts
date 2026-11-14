/**
 * `sandbox-default-run` — C2, the sandbox unknown resolver (v4 §2, priority 60).
 *
 * This base link resolves an `unknown` verdict only when the execution layer
 * issued a valid receipt for this frozen call. It cannot change an existing
 * allow, ask or deny, and it does not authorize execution outside the sandbox.
 * A proven risk, sensitive target, external write or review-marked shape keeps
 * its own verdict and is never resolved by this receipt.
 *
 * Gates, in order — the first one that does not hold returns `pass`:
 *
 * 1. the mode is `default` or `auto-review` (C2 is not a `read-only` or
 *    `full-access` concept; both modes already decided elsewhere);
 * 2. the channel is `normal` (the elevation channel is a one-time host
 *    execution, never a sandbox run);
 * 3. the accumulated verdict is `unknown`; allow, ask and deny are left intact;
 * 4. the call carries no one-time host execution request;
 * 5. the receipt verifies against this call, session, workspace and clock;
 * 6. the unit is clean: no danger hits, no sensitive references, and every
 *    access fact is either local read/write, all-unknown (opaque but clean), or
 *    network behind a proxied policy with no external write.
 *
 * "Opaque but clean" is the core of C2: `unknown` is resolved because the
 * sandbox confines it and a failed command only fails. It does not make the
 * command safe — {@link SandboxReceipt} only proves what the sandbox stops.
 */
import type { ApprovalContext, ChainUnitFacts, UnitAccessFact } from "../facts";
import { chainCallDigest, receiptAllows, type SandboxReceipt } from "../receipt";
import type { Handler } from "../run";
import type { HandlerResult } from "../verdict";

export const SANDBOX_DEFAULT_RUN_ID = "builtin/sandbox-default-run";
export const SANDBOX_DEFAULT_RUN_PRIORITY = 60;

const REASON_PREFIX = "sandbox:default-run";

/** The host-supplied facts this link reads. Everything else is in the context. */
export interface SandboxDefaultRunOptions {
  /** The receipt issued for the current frozen call, if the host issued one. */
  readonly receipt?: SandboxReceipt;
  /** Clock; defaults to `Date.now`. A throwing clock fails closed. */
  readonly nowMs?: () => number;
  /** The session the receipt must belong to. Omitted means "cannot verify". */
  readonly sessionId?: string;
  /** The workspace root the receipt must belong to. Omitted means "cannot verify". */
  readonly workspaceRoot?: string;
}

const PASS: HandlerResult = Object.freeze({ action: "pass" });

/** A sandbox baseline: it resolves only an otherwise undecided unit. */
export function createSandboxDefaultRunHandler(options: SandboxDefaultRunOptions): Handler {
  const handler: Handler = {
    id: SANDBOX_DEFAULT_RUN_ID,
    priority: SANDBOX_DEFAULT_RUN_PRIORITY,
    kind: "base",
    evaluate: (context: ApprovalContext): HandlerResult => sandboxDefaultRun(context, options),
  };
  return Object.freeze(handler);
}

function sandboxDefaultRun(
  context: ApprovalContext,
  options: SandboxDefaultRunOptions,
): HandlerResult {
  if (context.mode !== "default" && context.mode !== "auto-review") return PASS;
  if (context.channel === "elevation") return PASS;

  const { accumulated } = context;
  if (accumulated.state !== "unknown") return PASS;
  if (context.unit.rule?.decision === "ask") return PASS;

  // A host execution request is the elevation channel's subject; a sandbox
  // receipt must never authorize one, whichever channel carries it.
  if (context.call.hostExecutionRequest !== undefined) return PASS;

  const receipt = options.receipt;
  const sessionId = options.sessionId;
  const workspaceRoot = options.workspaceRoot;
  // An unbound receipt proves nothing: when the host did not say whose session
  // and workspace are current, this link must abstain instead of guessing.
  if (receipt === undefined || sessionId === undefined || workspaceRoot === undefined) {
    return PASS;
  }
  if (sessionId.length === 0 || workspaceRoot.length === 0) return PASS;

  const unit = context.unit;
  const shell = shellOf(unit.toolName);
  if (shell === undefined) return PASS;
  const check = receiptAllows(receipt, {
    callDigest: chainCallDigest(context.call),
    nowMs: nowOf(options.nowMs),
    sessionId,
    workspaceRoot,
    ...(shell === undefined ? {} : { shell }),
    ...(usesNetwork(unit.access) ? { needsNetwork: true } : {}),
  });
  if (!check.ok) return PASS;

  if (!unitIsClean(unit)) return PASS;
  return { action: "allow", reason: `${REASON_PREFIX}:${receipt.backend}` };
}

/** The unit's shell, when its tool name names one. */
function shellOf(toolName: string): "bash" | "powershell" | undefined {
  if (toolName === "bash") return "bash";
  if (toolName === "powershell") return "powershell";
  return undefined;
}

/**
 * Read the clock once per evaluation. A throwing or non-finite clock must not
 * throw out of the link (that would be a chain fault): `NaN` reaches the
 * receipt check, which fails closed as `expired`.
 */
function nowOf(nowMs: (() => number) | undefined): number {
  if (nowMs === undefined) return Date.now();
  try {
    return nowMs();
  } catch {
    return Number.NaN;
  }
}

function usesNetwork(access: readonly UnitAccessFact[]): boolean {
  return access.some((fact) => fact.kind === "network");
}

/** C2 only accepts a unit with no risk evidence and no surface outside the sandbox. */
function unitIsClean(unit: ChainUnitFacts): boolean {
  if (unit.dangers !== undefined && unit.dangers.length > 0) return false;
  if (unit.sensitive !== undefined && unit.sensitive.length > 0) return false;
  return accessIsClean(unit.access);
}

/**
 * One unit's access is clean when it is:
 *
 * - empty — nothing proven, the same "opaque" meaning as an all-unknown unit;
 * - all `unknown` — opaque but contained, the shape C2 exists for;
 * - `read` / `write` / `network` facts, none external and no external delete.
 *   A network fact additionally needs a `proxied` receipt, which
 *   {@link receiptAllows} checks with `needsNetwork`.
 *
 * `review` and external targets abstain. Unknown facts do not grant additional
 * access; the same sandbox plan confines the complete call.
 */
function accessIsClean(access: readonly UnitAccessFact[]): boolean {
  if (access.length === 0) return true;
  if (access.some((fact) => fact.kind === "review")) return false;
  if (access.some((fact) => fact.external === true || fact.externalDelete === true)) return false;
  return true;
}
