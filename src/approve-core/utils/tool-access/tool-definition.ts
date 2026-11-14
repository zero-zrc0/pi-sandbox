/**
 * Public tool definitions (specs/tool-access.md §1/§5).
 *
 * A tool definition is the frozen public projection of one registered host
 * tool: its identity (name/origin/revision), description, JSON parameter
 * schema and optional annotations/namespace. Only these fields take part in
 * the definition digest; runtime callbacks and host-private metadata are never
 * captured. The captured origin string is kept verbatim so a package-tool
 * proof can bind its origin key character for character.
 */
import { canonicalJson, sha256Hex } from "#approve-core/policy/project-rules/types";

export interface ToolIdentity {
  readonly name: string;
  readonly origin: string;
  readonly revision: string;
}

export interface ToolDefinition {
  readonly identity: ToolIdentity;
  /** May be empty: a definition without documentation is still public. */
  readonly description: string;
  /** JSON object; frozen on capture. */
  readonly parameters: Readonly<Record<string, unknown>>;
  readonly annotations?: Readonly<Record<string, unknown>>;
  readonly namespace?: string;
}

/** Result of freezing one JSON value; `ok: false` means it is not JSON data. */
export type FrozenJsonResult =
  | { readonly ok: true; readonly value: unknown }
  | { readonly ok: false };

const NESTED_KEYS = ["identity", "description", "parameters", "annotations", "namespace"] as const;
const FLAT_KEYS = ["name", "origin", "revision", "description", "parameters", "annotations", "namespace"] as const;
const IDENTITY_KEYS = ["name", "origin", "revision"] as const;

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

/**
 * Clone one JSON value and freeze every container. Definitions and facts share
 * this rule so captured data can never be mutated after the fact.
 */
export function cloneFrozenJson(value: unknown): FrozenJsonResult {
  return cloneValue(value, new Set<object>());
}

function cloneValue(value: unknown, ancestors: Set<object>): FrozenJsonResult {
  if (value === null) return { ok: true, value: null };
  switch (typeof value) {
    case "string":
    case "boolean":
      return { ok: true, value };
    case "number":
      return Number.isFinite(value) ? { ok: true, value } : { ok: false };
    case "object": {
      if (ancestors.has(value)) return { ok: false };
      ancestors.add(value);
      try {
        if (Array.isArray(value)) {
          const items: unknown[] = [];
          for (const item of value) {
            const cloned = cloneValue(item, ancestors);
            if (!cloned.ok) return { ok: false };
            items.push(cloned.value);
          }
          return { ok: true, value: Object.freeze(items) };
        }
        if (!isPlainRecord(value)) return { ok: false };
        if (Object.getOwnPropertySymbols(value).length > 0) return { ok: false };
        const entries: Record<string, unknown> = {};
        for (const [key, item] of Object.entries(value)) {
          const cloned = cloneValue(item, ancestors);
          if (!cloned.ok) return { ok: false };
          entries[key] = cloned.value;
        }
        return { ok: true, value: Object.freeze(entries) };
      } finally {
        ancestors.delete(value);
      }
    }
    default:
      return { ok: false };
  }
}

/** Read name/origin/revision from either a flat or a nested identity shape. */
function readIdentity(value: unknown): ToolIdentity | undefined {
  if (!isPlainRecord(value)) return undefined;
  const name = value.name;
  const origin = value.origin;
  const revision = value.revision;
  if (!nonEmptyString(name) || !nonEmptyString(origin) || !nonEmptyString(revision)) return undefined;
  return Object.freeze({ name, origin, revision });
}

/**
 * Normalize a raw registered tool definition. Accepts the host's flat shape
 * (`{name, origin, revision, description, parameters, ...}`) and the already
 * nested shape (`{identity, description, parameters, ...}`). Unknown fields,
 * mixed identities and values that cannot be frozen as JSON are rejected.
 */
export function normalizeToolDefinition(raw: unknown): ToolDefinition | undefined {
  try {
    return normalizeDefinition(raw);
  } catch {
    // A throwing getter or other hostile value is not a public definition.
    return undefined;
  }
}

function normalizeDefinition(raw: unknown): ToolDefinition | undefined {
  if (!isPlainRecord(raw)) return undefined;
  if (Object.getOwnPropertySymbols(raw).length > 0) return undefined;

  const nested = "identity" in raw;
  if (!hasOnlyKeys(raw, nested ? NESTED_KEYS : FLAT_KEYS)) return undefined;
  if (nested && (raw.name !== undefined || raw.origin !== undefined || raw.revision !== undefined)) return undefined;

  const identity = nested ? readNestedIdentity(raw.identity) : readIdentity(raw);
  if (identity === undefined) return undefined;

  const description = raw.description;
  if (typeof description !== "string") return undefined;

  const parameters = cloneFrozenJson(raw.parameters);
  if (!parameters.ok || !isPlainRecord(parameters.value)) return undefined;

  let annotations: Readonly<Record<string, unknown>> | undefined;
  if (raw.annotations !== undefined) {
    const cloned = cloneFrozenJson(raw.annotations);
    if (!cloned.ok || !isPlainRecord(cloned.value)) return undefined;
    annotations = cloned.value;
  }

  let namespace: string | undefined;
  if (raw.namespace !== undefined) {
    if (!nonEmptyString(raw.namespace)) return undefined;
    namespace = raw.namespace;
  }

  return Object.freeze({
    identity,
    description,
    parameters: parameters.value,
    ...(annotations === undefined ? {} : { annotations }),
    ...(namespace === undefined ? {} : { namespace }),
  });
}

function readNestedIdentity(value: unknown): ToolIdentity | undefined {
  if (!isPlainRecord(value) || !hasOnlyKeys(value, IDENTITY_KEYS)) return undefined;
  return readIdentity(value);
}

/**
 * Deterministic sha256 over every public field. Transport-only fields and
 * host-private metadata never change the digest; the environment is not part
 * of a definition at all.
 */
export function toolDefinitionDigest(definition: ToolDefinition): string {
  return sha256Hex(canonicalJson({
    name: definition.identity.name,
    origin: definition.identity.origin,
    revision: definition.identity.revision,
    description: definition.description,
    parameters: definition.parameters,
    ...(definition.annotations === undefined ? {} : { annotations: definition.annotations }),
    ...(definition.namespace === undefined ? {} : { namespace: definition.namespace }),
  }));
}
