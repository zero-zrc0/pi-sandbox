/**
 * Sandbox receipts for the C2 `sandbox-default-run` link (v4 §2, priority 60).
 *
 * A receipt is the execution layer's *proof about the boundary*, not about the
 * command. It states that one frozen call will run inside a sandbox whose
 * backend, workspace and network policy are the ones named here; it says
 * nothing about whether the command itself is safe. The receipt only proves
 * what the sandbox can stop, so it may only be used to let a clean, opaque
 * command fail inside that boundary — never to widen access to a surface the
 * boundary does not cover (v3 §1 rule 6).
 *
 * Everything here is a pure function over plain data. Nothing probes the host,
 * reads the file system, or asks a backend for its state: an unavailable
 * backend, a stale window, another session or a mutated field all fail closed.
 * The fail-closed direction is deliberate — refusing a receipt only keeps the
 * call's ordinary ask, while accepting a bad one would run unsandboxed work.
 *
 * Shape and digest:
 *
 * - {@link createSandboxReceipt} projects the documented fields and appends
 *   `digest = jsonDigest(fields)` (`src/json.ts`, canonical key order).
 * - {@link readSandboxReceipt} is the validation boundary: unknown values are
 *   rejected with `undefined`, never repaired. It requires the exact key set,
 *   non-empty strings, a usable time window, a known network policy and a
 *   matching digest, so extra or mutated fields cannot ride along.
 * - {@link receiptAllows} applies a receipt to one call. Its checks run in a
 *   fixed order — integrity, freshness, call binding, session/workspace binding,
 *   backend, shell, network — and the first failure names the reason. A caller
 *   must treat every non-`ok` result as "no receipt".
 *
 * Time uses the half-open interval `[issuedAtMs, expiresAtMs)`: a receipt is
 * valid at its issue instant and before, but not at, its expiry instant. Any
 * instant outside that window (including a clock before issuance) is reported
 * as `expired`; the failure list has no separate "not yet valid" state.
 */
import { jsonDigest } from "../../json";
import type { ChainCallFacts } from "./facts";

/** Why a receipt could not authorize a call. Never an allow. */
export type ReceiptFailure =
  | "missing"
  | "digest-mismatch"
  | "expired"
  | "backend-unavailable"
  | "network-policy-missing"
  | "cross-session"
  | "tampered"
  | "unsupported-shell";

/**
 * What the sandbox does to network access.
 *
 * - `"none"` — the sandbox denies all network access;
 * - `"proxied"` — traffic may only leave through the sandbox's proxy;
 * - `"host"` — the command would use the host network, i.e. the boundary does
 *   not cover it.
 *
 * Only `"proxied"` satisfies a call that proves network access; a `"none"` or
 * `"host"` receipt still authorizes calls that prove no network access.
 */
export type SandboxNetworkPolicy = "none" | "proxied" | "host";

/** The immutable fields a receipt binds; `digest` seals exactly these fields. */
export interface SandboxReceipt {
  readonly sessionId: string;
  /** The host-owned backend capability identifier (for example `windows-mxc`). */
  readonly backend: string;
  /** The revision of the compiled execution plan the receipt belongs to. */
  readonly planRevision: string;
  /** Digest of the frozen call this receipt is bound to. */
  readonly callDigest: string;
  readonly issuedAtMs: number;
  /** Exclusive end of the validity window. */
  readonly expiresAtMs: number;
  readonly workspaceRoot: string;
  readonly networkPolicy: SandboxNetworkPolicy;
  /** Self-digest over every other field; any mutation breaks it. */
  readonly digest: string;
}

/** The receipt fields before sealing. */
export type SandboxReceiptFields = Omit<SandboxReceipt, "digest">;

/** Input of one receipt check. Everything is supplied by the chain, not read. */
export interface ReceiptCheckInput {
  /** Digest of the frozen call, computed by {@link chainCallDigest}. */
  readonly callDigest: string;
  readonly nowMs: number;
  readonly sessionId: string;
  readonly workspaceRoot: string;
  /** Shell the unit would run; when set, the backend must support it. */
  readonly shell?: "bash" | "powershell";
  /**
   * Set when the frozen call proves network access. This is the one input the
   * minimal v4 §2 shape cannot derive from the receipt: a receipt cannot know
   * what the command does. Absent or `false` means "no network requirement".
   */
  readonly needsNetwork?: boolean;
}

/** The result of applying a receipt to one call. */
export type ReceiptCheck =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: ReceiptFailure };

/**
 * Backends that may host a C2 direct run, mapped to the one shell they can run.
 *
 * This is intentionally an allowlist: an unknown backend id (including
 * `unsupported-platform`) reports `backend-unavailable`, because the chain has
 * no proof that the boundary exists. Adding a real backend requires updating
 * this table together with `src/sandbox/production.ts`'s `backendId`.
 */
function supportedShell(backend: string): "bash" | "powershell" | undefined {
  if (backend === "windows-mxc") return "powershell";
  if (backend === "linux-bwrap-landlock-seccomp") return "bash";
  return undefined;
}

const RECEIPT_KEYS: readonly string[] = Object.freeze([
  "backend",
  "callDigest",
  "digest",
  "expiresAtMs",
  "issuedAtMs",
  "networkPolicy",
  "planRevision",
  "sessionId",
  "workspaceRoot",
]);

const DIGEST_PATTERN = /^[0-9a-f]{64}$/u;

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value);
}

function isNetworkPolicy(value: unknown): value is SandboxNetworkPolicy {
  return value === "none" || value === "proxied" || value === "host";
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const own = Object.keys(value);
  return own.length === keys.length &&
    keys.every((key) => Object.prototype.hasOwnProperty.call(value, key));
}

/** Stable digest over exactly the sealed fields; key order is canonicalized. */
function receiptDigest(fields: SandboxReceiptFields): string {
  return jsonDigest({
    sessionId: fields.sessionId,
    backend: fields.backend,
    planRevision: fields.planRevision,
    callDigest: fields.callDigest,
    issuedAtMs: fields.issuedAtMs,
    expiresAtMs: fields.expiresAtMs,
    workspaceRoot: fields.workspaceRoot,
    networkPolicy: fields.networkPolicy,
  });
}

interface ParsedReceipt {
  readonly fields: SandboxReceiptFields;
  readonly digest: string;
}

/**
 * Validate one unknown value into sealed fields. This is the only place that
 * reads the value: fields are copied while validated, so a getter cannot return
 * one thing during validation and another afterwards.
 */
function parseReceipt(value: unknown): ParsedReceipt | undefined {
  try {
    if (!isRecord(value) || !hasExactKeys(value, RECEIPT_KEYS)) return undefined;
    const {
      sessionId,
      backend,
      planRevision,
      callDigest,
      issuedAtMs,
      expiresAtMs,
      workspaceRoot,
      networkPolicy,
      digest,
    } = value;
    if (
      !nonEmptyString(sessionId) ||
      !nonEmptyString(backend) ||
      !nonEmptyString(planRevision) ||
      !nonEmptyString(callDigest) ||
      !nonEmptyString(workspaceRoot)
    ) {
      return undefined;
    }
    if (!isSafeInteger(issuedAtMs) || !isSafeInteger(expiresAtMs)) return undefined;
    if (issuedAtMs < 0 || expiresAtMs <= issuedAtMs) return undefined;
    if (!isNetworkPolicy(networkPolicy)) return undefined;
    if (typeof digest !== "string" || !DIGEST_PATTERN.test(digest)) return undefined;
    const fields: SandboxReceiptFields = {
      sessionId,
      backend,
      planRevision,
      callDigest,
      issuedAtMs,
      expiresAtMs,
      workspaceRoot,
      networkPolicy,
    };
    if (receiptDigest(fields) !== digest) return undefined;
    return { fields, digest };
  } catch {
    return undefined;
  }
}

/**
 * Seal the documented fields into a receipt. The input is projected, so extra
 * properties a caller happens to hold never become part of the sealed object;
 * {@link readSandboxReceipt} is still the authority on whether the result is
 * usable (an empty backend, an inverted window, or a NaN instant is rejected
 * there rather than silently repaired here).
 */
export function createSandboxReceipt(fields: SandboxReceiptFields): SandboxReceipt {
  const binding: SandboxReceiptFields = {
    sessionId: fields.sessionId,
    backend: fields.backend,
    planRevision: fields.planRevision,
    callDigest: fields.callDigest,
    issuedAtMs: fields.issuedAtMs,
    expiresAtMs: fields.expiresAtMs,
    workspaceRoot: fields.workspaceRoot,
    networkPolicy: fields.networkPolicy,
  };
  return Object.freeze({ ...binding, digest: receiptDigest(binding) });
}

/**
 * Read a receipt from untrusted data, or `undefined` when it is not a valid,
 * untampered one. Never repairs, fills in defaults, or throws: a malformed
 * receipt and an absent one must be indistinguishable to the chain, so neither
 * can widen access.
 */
export function readSandboxReceipt(value: unknown): SandboxReceipt | undefined {
  const parsed = parseReceipt(value);
  if (parsed === undefined) return undefined;
  return Object.freeze({ ...parsed.fields, digest: parsed.digest });
}

/**
 * Whether this receipt authorizes this frozen call. Checks run in one fixed
 * order so a diagnosis is reproducible; the first failure is returned.
 *
 * 1. `missing` — no receipt at all;
 * 2. `tampered` — the value is not a well-formed, digest-matching receipt;
 * 3. `expired` — `nowMs` is outside the half-open validity window;
 * 4. `digest-mismatch` — the receipt binds a different frozen call;
 * 5. `cross-session` — the receipt belongs to another session or workspace;
 * 6. `backend-unavailable` — the backend is not a known sandbox backend;
 * 7. `unsupported-shell` — the unit's shell is not the backend's shell;
 * 8. `network-policy-missing` — network access is proven but not proxied.
 *
 * `ok` is only returned when every binding matches; anything else must be
 * treated by the caller as "there is no receipt".
 */
export function receiptAllows(
  receipt: SandboxReceipt | undefined,
  input: ReceiptCheckInput,
): ReceiptCheck {
  if (receipt === undefined) return { ok: false, reason: "missing" };
  const parsed = parseReceipt(receipt);
  if (parsed === undefined) return { ok: false, reason: "tampered" };
  const fields = parsed.fields;

  if (
    !Number.isFinite(input.nowMs) ||
    input.nowMs < fields.issuedAtMs ||
    input.nowMs >= fields.expiresAtMs
  ) {
    return { ok: false, reason: "expired" };
  }
  if (fields.callDigest !== input.callDigest) {
    return { ok: false, reason: "digest-mismatch" };
  }
  if (fields.sessionId !== input.sessionId || fields.workspaceRoot !== input.workspaceRoot) {
    return { ok: false, reason: "cross-session" };
  }
  const shell = supportedShell(fields.backend);
  if (shell === undefined) return { ok: false, reason: "backend-unavailable" };
  if (input.shell !== undefined && input.shell !== shell) {
    return { ok: false, reason: "unsupported-shell" };
  }
  if (input.needsNetwork === true && fields.networkPolicy !== "proxied") {
    return { ok: false, reason: "network-policy-missing" };
  }
  return { ok: true };
}

/**
 * Digest a frozen call the way a receipt must bind it. The host that issues a
 * receipt and the chain link that checks it must both use this helper, so a
 * plan revision or a changed unit set invalidates the receipt instead of
 * silently matching a different call.
 */
export function chainCallDigest(call: ChainCallFacts): string {
  return jsonDigest({
    toolCallId: call.toolCallId,
    toolName: call.toolName,
    units: call.units,
    hostExecutionRequest: call.hostExecutionRequest,
  });
}
