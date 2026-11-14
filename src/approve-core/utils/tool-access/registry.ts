/**
 * Exact-identity SDK adapter registry (specs/tool-access.md §6).
 *
 * Adapters are keyed by the full `name/origin/revision` triple. A missing
 * registration is unbound and is reported as such; the caller decides what an
 * adapter exception means (`incomplete`), so this registry never catches one.
 * Disposers are identity-checked: a stale disposer can never delete a later
 * registration that replaced the original entry.
 */
import type { ToolAccessFactsResult } from "./access-facts";
import type { ToolIdentity } from "./tool-definition";

export interface ToolAccessAdapter {
  readonly identity: ToolIdentity;
  /** Whether this adapter currently has facts it can prove. */
  factsAvailable(): boolean;
  extract(input: unknown, cwd: string): ToolAccessFactsResult;
}

/** Bound/verified status of one exact identity. */
export interface ToolAccessAdapterStatus {
  /** An adapter is registered for the exact name/origin/revision triple. */
  readonly verified: boolean;
  /** The registered adapter reports facts as available. */
  readonly available: boolean;
}

const IDENTITY_SEPARATOR = "\u0000";
const NO_ADAPTER_STATUS: ToolAccessAdapterStatus = Object.freeze({
  verified: false,
  available: false,
});

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function identityKey(identity: ToolIdentity): string | undefined {
  if (!isPlainObject(identity)) return undefined;
  const { name, origin, revision } = identity;
  if (!nonEmptyString(name) || !nonEmptyString(origin) || !nonEmptyString(revision)) return undefined;
  return [name, origin, revision].join(IDENTITY_SEPARATOR);
}

export class ToolAccessAdapterRegistry {
  private readonly adapters = new Map<string, ToolAccessAdapter>();

  /**
   * Register one adapter. Duplicate identities are rejected so a registered
   * adapter keeps its exact meaning for the whole registration lifetime.
   */
  register(adapter: ToolAccessAdapter): () => void {
    if (!isPlainObject(adapter)) throw new Error("tool-access-adapter: invalid adapter");
    if (typeof adapter.factsAvailable !== "function" || typeof adapter.extract !== "function") {
      throw new Error("tool-access-adapter: invalid adapter");
    }
    const key = identityKey(adapter.identity);
    if (key === undefined) throw new Error("tool-access-adapter: invalid identity");
    if (this.adapters.has(key)) throw new Error("tool-access-adapter: duplicate identity");
    this.adapters.set(key, adapter);

    let active = true;
    return (): void => {
      if (!active) return;
      active = false;
      // A replacement registration makes this disposer stale: only remove the
      // exact entry this registration installed.
      if (this.adapters.get(key) === adapter) this.adapters.delete(key);
    };
  }

  /** The adapter registered for the exact identity, if any. */
  get(identity: ToolIdentity): ToolAccessAdapter | undefined {
    const key = identityKey(identity);
    return key === undefined ? undefined : this.adapters.get(key);
  }

  /** Adapters in registration order; the snapshot itself is immutable. */
  list(): readonly ToolAccessAdapter[] {
    return Object.freeze([...this.adapters.values()]);
  }

  /** Whether a registered adapter reports its facts as available. */
  factsAvailable(identity: ToolIdentity): boolean {
    return this.get(identity)?.factsAvailable() ?? false;
  }

  /** Report the bound/verified adapter and facts availability for one identity. */
  status(identity: ToolIdentity): ToolAccessAdapterStatus {
    const adapter = this.get(identity);
    if (adapter === undefined) return NO_ADAPTER_STATUS;
    return Object.freeze({ verified: true, available: adapter.factsAvailable() });
  }

  /** Remove every registration; the registry stays usable afterwards. */
  dispose(): void {
    this.adapters.clear();
  }
}
