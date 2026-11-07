import { describe, expect, it } from "vitest";
import type { ToolAccessFactsResult } from "#approve-core/utils/tool-access/access-facts";
import type { ToolIdentity } from "#approve-core/utils/tool-access/tool-definition";
import {
  ToolAccessAdapterRegistry,
  type ToolAccessAdapter,
} from "#approve-core/utils/tool-access/registry";

const FACTS: ToolAccessFactsResult = Object.freeze({
  status: "verified",
  source: "sdk",
  complete: true,
  unknownEffects: Object.freeze([]),
  accesses: Object.freeze([Object.freeze({ path: "/work/a.txt", access: "read", operation: "read" })]),
});

const IDENTITY: ToolIdentity = Object.freeze({ name: "sdk-tool", origin: "sdk:sdk-tool", revision: "7" });

function adapter(overrides: Partial<ToolAccessAdapter> = {}): ToolAccessAdapter {
  return {
    identity: IDENTITY,
    factsAvailable: () => true,
    extract: () => FACTS,
    ...overrides,
  };
}

describe("ToolAccessAdapterRegistry registration", () => {
  it("registers and returns the adapter for its exact identity", () => {
    const registry = new ToolAccessAdapterRegistry();
    const registered = adapter();
    const dispose = registry.register(registered);

    expect(registry.get(IDENTITY)).toBe(registered);
    expect(registry.list()).toEqual([registered]);
    expect(typeof dispose).toBe("function");
  });

  it("matches the full name/origin/revision triple only", () => {
    const registry = new ToolAccessAdapterRegistry();
    registry.register(adapter());

    for (const identity of [
      { ...IDENTITY, name: "other" },
      { ...IDENTITY, origin: "sdk:other" },
      { ...IDENTITY, revision: "8" },
    ]) {
      expect(registry.get(identity)).toBeUndefined();
    }
  });

  it("rejects a duplicate identity and keeps the first registration", () => {
    const registry = new ToolAccessAdapterRegistry();
    const first = adapter();
    const second = adapter();
    registry.register(first);

    expect(() => registry.register(second)).toThrow(/duplicate/iu);
    expect(registry.get(IDENTITY)).toBe(first);
    expect(registry.list()).toEqual([first]);
  });

  it("rejects malformed adapters", () => {
    const registry = new ToolAccessAdapterRegistry();

    expect(() => registry.register(null as unknown as ToolAccessAdapter)).toThrow();
    expect(() => registry.register({ identity: IDENTITY } as unknown as ToolAccessAdapter)).toThrow();
    expect(() => registry.register(adapter({ identity: { ...IDENTITY, name: "" } }))).toThrow();
    expect(() => registry.register(adapter({ identity: { ...IDENTITY, revision: "  " } }))).toThrow();
    expect(() => registry.register(adapter({ factsAvailable: 7 as unknown as () => boolean }))).toThrow();
    expect(() => registry.register(adapter({ extract: "x" as unknown as ToolAccessAdapter["extract"] }))).toThrow();
  });
});

describe("ToolAccessAdapterRegistry lookup and status", () => {
  it("reports unbound for an unregistered identity", () => {
    const registry = new ToolAccessAdapterRegistry();

    expect(registry.get(IDENTITY)).toBeUndefined();
    expect(registry.list()).toEqual([]);
    expect(registry.status(IDENTITY)).toEqual({ verified: false, available: false });
  });

  it("reports the verified adapter and its facts availability", () => {
    const registry = new ToolAccessAdapterRegistry();
    registry.register(adapter({ factsAvailable: () => true }));
    expect(registry.status(IDENTITY)).toEqual({ verified: true, available: true });

    const unavailable = new ToolAccessAdapterRegistry();
    unavailable.register(adapter({ factsAvailable: () => false }));
    expect(unavailable.status(IDENTITY)).toEqual({ verified: true, available: false });
    expect(unavailable.factsAvailable(IDENTITY)).toBe(false);
  });

  it("does not swallow adapter exceptions", () => {
    const registry = new ToolAccessAdapterRegistry();
    const failure = new Error("adapter failed");
    registry.register(adapter({
      factsAvailable: () => { throw failure; },
      extract: () => { throw failure; },
    }));

    const found = registry.get(IDENTITY);
    expect(found).toBeDefined();
    expect(() => found!.extract({ path: "a" }, "/work")).toThrow(failure);
    expect(() => registry.factsAvailable(IDENTITY)).toThrow(failure);
    expect(() => registry.status(IDENTITY)).toThrow(failure);
  });

  it("returns immutable list snapshots and passes deep-frozen facts through", () => {
    const registry = new ToolAccessAdapterRegistry();
    const registered = adapter();
    registry.register(registered);

    const first = registry.list();
    const second = registry.list();
    expect(Object.isFrozen(first)).toBe(true);
    expect(first).toEqual([registered]);
    expect(first).not.toBe(second);

    const facts = registry.get(IDENTITY)!.extract({}, "/work");
    expect(facts).toBe(FACTS);
    expect(Object.isFrozen(facts)).toBe(true);
    expect(Object.isFrozen(facts.accesses)).toBe(true);
    expect(Object.isFrozen(facts.accesses[0])).toBe(true);
  });
});

describe("ToolAccessAdapterRegistry disposal", () => {
  it("removes a registration through its disposer", () => {
    const registry = new ToolAccessAdapterRegistry();
    const dispose = registry.register(adapter());

    dispose();
    expect(registry.get(IDENTITY)).toBeUndefined();
    expect(registry.list()).toEqual([]);
  });

  it("does not let a stale disposer remove a replacement registration", () => {
    const registry = new ToolAccessAdapterRegistry();
    const stale = registry.register(adapter());
    stale();
    const replacement = adapter();
    registry.register(replacement);

    stale();
    expect(registry.get(IDENTITY)).toBe(replacement);
    expect(registry.list()).toEqual([replacement]);
  });

  it("clears every registration on dispose", () => {
    const registry = new ToolAccessAdapterRegistry();
    const dispose = registry.register(adapter());

    registry.dispose();
    expect(registry.get(IDENTITY)).toBeUndefined();
    expect(registry.list()).toEqual([]);
    dispose();
    expect(registry.get(IDENTITY)).toBeUndefined();
  });
});
