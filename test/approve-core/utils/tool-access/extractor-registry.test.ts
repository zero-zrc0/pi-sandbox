import { describe, expect, it } from "vitest";
import {
  ToolAccessExtractorRegistry,
  type PathExtractor,
} from "#approve-core/utils/tool-access/tool-access-extractor-registry";

function extractorReturning(value: unknown): PathExtractor {
  return () => value;
}

describe("ToolAccessExtractorRegistry registration", () => {
  it("registers an extractor and resolves it as a local capability", () => {
    const registry = new ToolAccessExtractorRegistry();
    const custom = extractorReturning("/work/a.txt");
    const dispose = registry.register("custom", custom);

    expect(registry.resolve("custom")).toEqual({ extractor: custom, source: "local" });
    expect(registry.lookup("custom")).toBe(custom);
    expect(typeof dispose).toBe("function");
  });

  it("returns only the capability through the public lookup", () => {
    const registry = new ToolAccessExtractorRegistry();
    const custom = extractorReturning("/work/a.txt");
    registry.register("custom", custom);

    const lookup = registry.lookup("custom");
    expect(lookup).toBe(custom);
    expect(lookup).not.toHaveProperty("source");
  });

  it("reports a missing extractor without throwing", () => {
    const registry = new ToolAccessExtractorRegistry();

    expect(registry.resolve("missing").extractor).toBeUndefined();
    expect(registry.lookup("missing")).toBeUndefined();
  });

  it("rejects a duplicate name and keeps the first extractor", () => {
    const registry = new ToolAccessExtractorRegistry();
    const first = extractorReturning("first");
    const second = extractorReturning("second");
    registry.register("custom", first);

    expect(() => registry.register("custom", second)).toThrow(/duplicate/iu);
    expect(registry.lookup("custom")).toBe(first);
  });

  it("trims registration names", () => {
    const registry = new ToolAccessExtractorRegistry();
    const custom = extractorReturning("x");
    registry.register(" custom ", custom);

    expect(registry.lookup("custom")).toBe(custom);
  });

  it("rejects malformed registrations", () => {
    const registry = new ToolAccessExtractorRegistry();

    expect(() => registry.register("", () => "x")).toThrow();
    expect(() => registry.register("   ", () => "x")).toThrow();
    expect(() => registry.register("custom", 7 as unknown as PathExtractor)).toThrow();
  });
});

describe("ToolAccessExtractorRegistry inheritance", () => {
  it("resolves an inherited extractor with its source", () => {
    const inherited = extractorReturning("inherited");
    const registry = new ToolAccessExtractorRegistry({
      inherited: [{ name: "host-tool", extract: inherited }],
    });

    expect(registry.resolve("host-tool")).toEqual({ extractor: inherited, source: "inherited" });
    expect(registry.lookup("host-tool")).toBe(inherited);
  });

  it("lets a local extractor shadow an inherited one and restores it on disposal", () => {
    const inherited = extractorReturning("inherited");
    const local = extractorReturning("local");
    const registry = new ToolAccessExtractorRegistry({
      inherited: [{ name: "host-tool", extract: inherited }],
    });

    const dispose = registry.register("host-tool", local);
    expect(registry.resolve("host-tool")).toEqual({ extractor: local, source: "local" });

    dispose();
    expect(registry.resolve("host-tool")).toEqual({ extractor: inherited, source: "inherited" });
  });

  it("rejects duplicate inherited names at construction", () => {
    expect(() => new ToolAccessExtractorRegistry({
      inherited: [
        { name: "host-tool", extract: extractorReturning("a") },
        { name: "host-tool", extract: extractorReturning("b") },
      ],
    })).toThrow(/duplicate/iu);
  });
});

describe("ToolAccessExtractorRegistry disposal", () => {
  it("removes a registration through its disposer", () => {
    const registry = new ToolAccessExtractorRegistry();
    const dispose = registry.register("custom", extractorReturning("x"));

    dispose();
    expect(registry.lookup("custom")).toBeUndefined();
  });

  it("does not let a stale disposer remove a replacement extractor", () => {
    const registry = new ToolAccessExtractorRegistry();
    const stale = registry.register("custom", extractorReturning("first"));
    stale();
    const replacement = extractorReturning("second");
    registry.register("custom", replacement);

    stale();
    expect(registry.lookup("custom")).toBe(replacement);
  });

  it("clears local and inherited entries on dispose", () => {
    const registry = new ToolAccessExtractorRegistry({
      inherited: [{ name: "host-tool", extract: extractorReturning("inherited") }],
    });
    const dispose = registry.register("custom", extractorReturning("local"));

    registry.dispose();
    expect(registry.lookup("custom")).toBeUndefined();
    expect(registry.lookup("host-tool")).toBeUndefined();
    dispose();
    expect(registry.lookup("custom")).toBeUndefined();
  });
});
