/**
 * Multi-source fact ownership (specs/tool-access.md §7).
 *
 * Selection is pure policy over already-built candidate reports: builtin
 * participates whenever it is not unbound, configured declarations replace the
 * SDK adapter, and an unresolved package source fails the whole lookup. Merging
 * accepts only identical verified access sets; any incomplete report or set
 * conflict keeps the result incomplete while retaining verified accesses as
 * diagnostics, never as a verified result.
 */
import {
  normalizeToolAccessFacts,
  readToolIdentity,
  type ToolAccess,
  type ToolAccessFactsResult,
} from "./access-facts";
import type { ToolIdentity } from "./tool-definition";

const MERGED_SOURCE = "merged";
const CANDIDATE_SOURCES = new Set(["builtin", "declared", "sdk", "merged"]);

export interface ToolAccessCandidate {
  readonly source: "builtin" | "declared" | "sdk" | "merged";
  readonly facts: ToolAccessFactsResult;
}

export interface ToolAccessCandidateSelection {
  readonly builtin?: ToolAccessFactsResult;
  readonly declarations?: readonly ToolAccessFactsResult[];
  readonly declarativeUnresolved?: boolean;
  readonly sdk?: ToolAccessFactsResult;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isFactsResult(value: unknown): value is ToolAccessFactsResult {
  if (!isPlainRecord(value)) return false;
  if (value.status !== "verified" && value.status !== "incomplete" && value.status !== "unbound") return false;
  return typeof value.complete === "boolean" &&
    Array.isArray(value.accesses) &&
    Array.isArray(value.unknownEffects);
}

function isCandidate(value: unknown): value is ToolAccessCandidate {
  if (!isPlainRecord(value)) return false;
  if (typeof value.source !== "string" || !CANDIDATE_SOURCES.has(value.source)) return false;
  return isFactsResult(value.facts);
}

function frozenUnbound(): ToolAccessFactsResult {
  return Object.freeze({
    status: "unbound" as const,
    source: MERGED_SOURCE,
    complete: false,
    unknownEffects: Object.freeze([]) as readonly string[],
    accesses: Object.freeze([]) as readonly ToolAccess[],
  });
}

function accessKey(access: ToolAccess): string {
  return JSON.stringify([access.path, access.access, access.operation ?? null]);
}

/** Deduplicated accesses in deterministic canonical order. */
function canonicalAccesses(accesses: readonly ToolAccess[]): ToolAccess[] {
  const byKey = new Map<string, ToolAccess>();
  for (const access of accesses) byKey.set(accessKey(access), access);
  return [...byKey.entries()]
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    .map(([, access]) => access);
}

function accessSetKey(accesses: readonly ToolAccess[]): string {
  return canonicalAccesses(accesses).map(accessKey).join("\n");
}

function uniqueStrings(values: readonly string[]): string[] {
  return [...new Set(values)];
}

function toolIdentityOf(candidates: readonly ToolAccessCandidate[]): ToolIdentity | undefined {
  for (const candidate of candidates) {
    const identity = readToolIdentity(candidate.facts.tool);
    if (identity !== undefined) return identity;
  }
  return undefined;
}

/**
 * Collect participating candidates. A package source that is still unresolved
 * contributes no subset at all: SDK may not mask it.
 */
export function selectToolAccessCandidates(
  input: ToolAccessCandidateSelection,
): readonly ToolAccessCandidate[] {
  const selection = isPlainRecord(input) ? input : {};
  if (selection.declarativeUnresolved === true) return Object.freeze([]);

  const candidates: ToolAccessCandidate[] = [];
  const builtin = selection.builtin;
  if (isFactsResult(builtin) && builtin.status !== "unbound") {
    candidates.push(Object.freeze({ source: "builtin", facts: builtin }));
  }

  const declarations = Array.isArray(selection.declarations)
    ? selection.declarations.filter(isFactsResult)
    : [];
  if (declarations.length > 0) {
    for (const facts of declarations) {
      if (facts.status !== "unbound") candidates.push(Object.freeze({ source: "declared", facts }));
    }
  } else {
    const sdk = selection.sdk;
    if (isFactsResult(sdk) && sdk.status !== "unbound") {
      candidates.push(Object.freeze({ source: "sdk", facts: sdk }));
    }
  }
  return Object.freeze(candidates);
}

/**
 * Merge candidates into one normalized report. Verified sets must match exactly
 * and no candidate may be incomplete; otherwise the result is incomplete and
 * keeps the verified accesses only as diagnostics.
 */
export function mergeToolAccessCandidates(candidates: readonly ToolAccessCandidate[]): ToolAccessFactsResult {
  const valid = Array.isArray(candidates) ? candidates.filter(isCandidate) : [];
  if (valid.length === 0) return frozenUnbound();
  if (valid.length === 1) return (valid[0] as ToolAccessCandidate).facts;
  if (valid.some((candidate) => candidate.facts.status === "unbound")) return frozenUnbound();

  const tool = toolIdentityOf(valid);
  const verified = valid.filter((candidate) => candidate.facts.status === "verified");
  const incompletes = valid.filter((candidate) => candidate.facts.status === "incomplete");
  const conflicting = verified.length > 1 &&
    new Set(verified.map((candidate) => accessSetKey(candidate.facts.accesses))).size > 1;

  if (incompletes.length > 0 || conflicting || verified.length === 0) {
    const unknownEffects = uniqueStrings([
      ...incompletes.flatMap((candidate) => [...candidate.facts.unknownEffects]),
      ...(conflicting ? ["access-conflict"] : []),
      ...(verified.length === 0 && incompletes.length === 0 ? ["no-verified-source"] : []),
    ]);
    const diagnostics = canonicalAccesses(verified.flatMap((candidate) => [...candidate.facts.accesses]));
    return normalizeToolAccessFacts(
      { accesses: diagnostics, complete: false, unknownEffects },
      tool,
      MERGED_SOURCE,
    );
  }

  const accesses = canonicalAccesses((verified[0] as ToolAccessCandidate).facts.accesses);
  return normalizeToolAccessFacts({ accesses, complete: true, unknownEffects: [] }, tool, MERGED_SOURCE);
}

/** One adapter status probe; a throw or unreadable result is unverified. */
function runStatusCheck(check: () => ToolAccessFactsResult): ToolAccessFactsResult {
  try {
    const result: unknown = check();
    if (isFactsResult(result)) return result;
    return statusFailure("invalid-result");
  } catch {
    return statusFailure("adapter-error");
  }
}

function statusFailure(reason: string): ToolAccessFactsResult {
  return Object.freeze({
    status: "incomplete" as const,
    source: "probe",
    complete: false,
    unknownEffects: Object.freeze([reason]) as readonly string[],
    accesses: Object.freeze([]) as readonly ToolAccess[],
  });
}

export interface ToolAccessAdapterStatusInput {
  /** Probe input evaluation of the builtin definition. */
  readonly probe?: () => ToolAccessFactsResult;
  /** One schema-generated minimal-input validation per declaration. */
  readonly validations?: readonly (() => ToolAccessFactsResult)[];
  /** Independent sources that overlap for this tool, if known statically. */
  readonly overlappingSources?: number;
}

export interface ToolAccessAdapterStatus {
  readonly verified: boolean;
  readonly available: boolean;
  readonly inputDependent?: boolean;
}

/**
 * Minimal adapter status used by configuration UI. Only a single usable source
 * can be reported verified/available; overlapping sources are input-dependent
 * because the per-call merge still has to compare them.
 */
export function toolAccessAdapterStatus(input: ToolAccessAdapterStatusInput): ToolAccessAdapterStatus {
  const status = isPlainRecord(input) ? input : {};
  const checks: Array<() => ToolAccessFactsResult> = [];
  if (typeof status.probe === "function") checks.push(status.probe as () => ToolAccessFactsResult);
  if (Array.isArray(status.validations)) {
    for (const validation of status.validations) {
      if (typeof validation === "function") checks.push(validation as () => ToolAccessFactsResult);
    }
  }
  const results = checks.map(runStatusCheck);
  const usable = results.filter((result) => result.status !== "unbound");
  const overlapping = typeof status.overlappingSources === "number" && Number.isFinite(status.overlappingSources)
    ? status.overlappingSources
    : 0;
  const inputDependent = usable.length > 1 || overlapping > 1;
  if (usable.length === 0) return { verified: false, available: false };

  const only = usable[0] as ToolAccessFactsResult;
  const verified = !inputDependent &&
    usable.length === 1 &&
    only.status === "verified" &&
    only.complete === true &&
    only.unknownEffects.length === 0;
  return {
    verified,
    available: !inputDependent,
    ...(inputDependent ? { inputDependent: true } : {}),
  };
}
