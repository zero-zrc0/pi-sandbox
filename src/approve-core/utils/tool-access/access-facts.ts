/**
 * File access facts (specs/tool-access.md §1/§2).
 *
 * Adapters report only what the host tool can prove: accesses, whether the
 * report is complete, and effects it could not model. This module turns that
 * untrusted shape into a frozen result. Any unreadable field, unknown field,
 * URL path, unlearnable value or missing tool identity fails closed to
 * `incomplete`; a result is `verified` only when the adapter reported complete
 * facts, no unknown effects and a readable tool identity.
 */
import type { ToolIdentity } from "./tool-definition";

export type ToolAccessAccess = "read" | "write";

export type ToolAccessOperation =
  | "read"
  | "write"
  | "create"
  | "delete"
  | "move-source"
  | "move-target"
  | "copy-source"
  | "copy-target";

export interface ToolAccess {
  readonly path: string;
  readonly access: ToolAccessAccess;
  /** Optional finer-grained effect; never a substitute for path/access. */
  readonly operation?: ToolAccessOperation;
}

export type ToolAccessFactsStatus = "verified" | "incomplete" | "unbound";

/** One normalized adapter report, frozen. */
export interface ToolAccessFactsResult {
  readonly status: ToolAccessFactsStatus;
  /** Stable name of the source that produced the facts. */
  readonly source: string;
  readonly complete: boolean;
  readonly unknownEffects: readonly string[];
  readonly accesses: readonly ToolAccess[];
  readonly tool?: ToolIdentity;
  /** Stable failure category when the facts are not verified. */
  readonly diagnostic?: string;
}

const RAW_KEYS = ["accesses", "complete", "unknownEffects"] as const;
const ACCESS_KEYS = ["path", "access", "operation"] as const;
const ACCESS_VALUES = new Set<ToolAccessAccess>(["read", "write"]);
const OPERATION_VALUES = new Set<ToolAccessOperation>([
  "read",
  "write",
  "create",
  "delete",
  "move-source",
  "move-target",
  "copy-source",
  "copy-target",
]);

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasOnlyKeys(record: Record<string, unknown>, allowed: readonly string[]): boolean {
  return Object.keys(record).every((key) => allowed.includes(key));
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

/** A URL scheme is anything with two or more scheme characters before `:`; a
 * single letter is a Windows drive, not a scheme. */
function looksLikeUrl(path: string): boolean {
  const match = /^([A-Za-z][A-Za-z0-9+.-]*):/.exec(path);
  return match !== null && (match[1] as string).length > 1;
}

function sourceOf(source: unknown): string {
  return nonEmptyString(source) ? source.trim() : "unknown";
}

/** Read a tool identity from a flat `RegisteredToolFacts` or a `ToolDefinition`. */
export function readToolIdentity(tool: unknown): ToolIdentity | undefined {
  if (!isPlainRecord(tool)) return undefined;
  const candidate = isPlainRecord(tool.identity) ? tool.identity : tool;
  const name = candidate.name;
  const origin = candidate.origin;
  const revision = candidate.revision;
  if (!nonEmptyString(name) || !nonEmptyString(origin) || !nonEmptyString(revision)) return undefined;
  return Object.freeze({ name, origin, revision });
}

function failure(source: string, diagnostic: string): ToolAccessFactsResult {
  return Object.freeze({
    status: "incomplete" as const,
    source,
    complete: false,
    unknownEffects: Object.freeze([]) as readonly string[],
    accesses: Object.freeze([]) as readonly ToolAccess[],
    diagnostic,
  });
}

type AccessParse = { readonly ok: true; readonly access: ToolAccess } | { readonly ok: false; readonly diagnostic: string };

function parseAccess(value: unknown): AccessParse {
  if (!isPlainRecord(value)) return { ok: false, diagnostic: "invalid-access" };
  if (!hasOnlyKeys(value, ACCESS_KEYS)) return { ok: false, diagnostic: "unknown-field" };

  const path = value.path;
  if (typeof path !== "string") return { ok: false, diagnostic: "invalid-access" };
  const trimmedPath = path.trim();
  if (trimmedPath.length === 0) return { ok: false, diagnostic: "invalid-path" };
  if (looksLikeUrl(trimmedPath)) return { ok: false, diagnostic: "url-path" };

  const access = value.access;
  if (typeof access !== "string" || !ACCESS_VALUES.has(access as ToolAccessAccess)) {
    return { ok: false, diagnostic: "invalid-access" };
  }
  const operation = value.operation;
  if (operation !== undefined) {
    if (typeof operation !== "string" || !OPERATION_VALUES.has(operation as ToolAccessOperation)) {
      return { ok: false, diagnostic: "invalid-operation" };
    }
  }
  return {
    ok: true,
    access: Object.freeze({
      path: trimmedPath,
      access: access as ToolAccessAccess,
      ...(operation === undefined ? {} : { operation: operation as ToolAccessOperation }),
    }),
  };
}

function parseUnknownEffect(value: unknown): string | undefined {
  if (!nonEmptyString(value)) return undefined;
  return value.trim();
}

/**
 * Normalize one adapter report. `tool` is the captured tool definition/facts
 * (flat or nested); `source` names the producer. A missing or unreadable tool
 * identity always keeps the result incomplete.
 */
export function normalizeToolAccessFacts(raw: unknown, tool?: unknown, source?: unknown): ToolAccessFactsResult {
  const normalizedSource = sourceOf(source);
  try {
    return normalizeFacts(raw, tool, normalizedSource);
  } catch {
    // A throwing getter or other hostile value fails closed like an adapter error.
    return failure(normalizedSource, "invalid-object");
  }
}

function normalizeFacts(raw: unknown, tool: unknown, normalizedSource: string): ToolAccessFactsResult {
  if (!isPlainRecord(raw)) return failure(normalizedSource, "invalid-object");
  if (!hasOnlyKeys(raw, RAW_KEYS)) return failure(normalizedSource, "unknown-field");

  const accessesRaw = raw.accesses;
  if (!Array.isArray(accessesRaw)) return failure(normalizedSource, "invalid-accesses");
  const completeRaw = raw.complete;
  if (typeof completeRaw !== "boolean") return failure(normalizedSource, "invalid-complete");
  const unknownRaw = raw.unknownEffects;
  if (!Array.isArray(unknownRaw)) return failure(normalizedSource, "invalid-unknown-effects");

  // Structural access errors fail closed as a whole: a partially readable list
  // must never look verified.
  const accesses: ToolAccess[] = [];
  for (const candidate of accessesRaw) {
    const parsed = parseAccess(candidate);
    if (!parsed.ok) return failure(normalizedSource, parsed.diagnostic);
    accesses.push(parsed.access);
  }

  const unknownEffects: string[] = [];
  for (const candidate of unknownRaw) {
    const effect = parseUnknownEffect(candidate);
    if (effect === undefined) return failure(normalizedSource, "invalid-unknown-effect");
    unknownEffects.push(effect);
  }

  const identity = readToolIdentity(tool);
  const frozenAccesses = Object.freeze(accesses);
  const frozenUnknownEffects = Object.freeze(unknownEffects);
  const base = {
    source: normalizedSource,
    complete: completeRaw,
    unknownEffects: frozenUnknownEffects,
    accesses: frozenAccesses,
  };
  if (identity === undefined) {
    return Object.freeze({ ...base, status: "incomplete" as const, diagnostic: "tool-identity-unavailable" });
  }
  if (completeRaw && unknownEffects.length === 0) {
    return Object.freeze({ ...base, status: "verified" as const, tool: identity });
  }
  return Object.freeze({ status: "incomplete" as const, ...base, tool: identity });
}
