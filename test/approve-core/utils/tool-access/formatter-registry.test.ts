import { describe, expect, it } from "vitest";
import {
  ToolInputFormatterRegistry,
  type ToolInputFormatter,
} from "#approve-core/utils/tool-access/tool-input-formatter-registry";

function formatterReturning(value: unknown): ToolInputFormatter {
  return () => value;
}

describe("ToolInputFormatterRegistry registration", () => {
  it("registers a formatter and resolves it as a local capability", () => {
    const registry = new ToolInputFormatterRegistry();
    const custom = formatterReturning("path: /work/a.txt");
    const dispose = registry.register("custom", custom);

    expect(registry.resolve("custom")).toEqual({ formatter: custom, source: "local" });
    expect(registry.lookup("custom")).toBe(custom);
    expect(typeof dispose).toBe("function");
  });

  it("returns only the capability through the public lookup", () => {
    const registry = new ToolInputFormatterRegistry();
    const custom = formatterReturning("formatted");
    registry.register("custom", custom);

    const lookup = registry.lookup("custom");
    expect(lookup).toBe(custom);
    expect(lookup).not.toHaveProperty("source");
  });

  it("reports a missing formatter without throwing", () => {
    const registry = new ToolInputFormatterRegistry();

    expect(registry.resolve("missing").formatter).toBeUndefined();
    expect(registry.lookup("missing")).toBeUndefined();
  });

  it("rejects a duplicate name and keeps the first formatter", () => {
    const registry = new ToolInputFormatterRegistry();
    const first = formatterReturning("first");
    const second = formatterReturning("second");
    registry.register("custom", first);

    expect(() => registry.register("custom", second)).toThrow(/duplicate/iu);
    expect(registry.lookup("custom")).toBe(first);
  });

  it("trims registration names", () => {
    const registry = new ToolInputFormatterRegistry();
    const custom = formatterReturning("x");
    registry.register(" custom ", custom);

    expect(registry.lookup("custom")).toBe(custom);
  });

  it("rejects malformed registrations", () => {
    const registry = new ToolInputFormatterRegistry();

    expect(() => registry.register("", () => "x")).toThrow();
    expect(() => registry.register("   ", () => "x")).toThrow();
    expect(() => registry.register("custom", 7 as unknown as ToolInputFormatter)).toThrow();
  });
});

describe("ToolInputFormatterRegistry inheritance", () => {
  it("resolves an inherited formatter with its source", () => {
    const inherited = formatterReturning("inherited");
    const registry = new ToolInputFormatterRegistry({
      inherited: [{ name: "host-tool", format: inherited }],
    });

    expect(registry.resolve("host-tool")).toEqual({ formatter: inherited, source: "inherited" });
    expect(registry.lookup("host-tool")).toBe(inherited);
  });

  it("lets a local formatter shadow an inherited one and restores it on disposal", () => {
    const inherited = formatterReturning("inherited");
    const local = formatterReturning("local");
    const registry = new ToolInputFormatterRegistry({
      inherited: [{ name: "host-tool", format: inherited }],
    });

    const dispose = registry.register("host-tool", local);
    expect(registry.resolve("host-tool")).toEqual({ formatter: local, source: "local" });

    dispose();
    expect(registry.resolve("host-tool")).toEqual({ formatter: inherited, source: "inherited" });
  });

  it("rejects duplicate inherited names at construction", () => {
    expect(() => new ToolInputFormatterRegistry({
      inherited: [
        { name: "host-tool", format: formatterReturning("a") },
        { name: "host-tool", format: formatterReturning("b") },
      ],
    })).toThrow(/duplicate/iu);
  });
});

describe("ToolInputFormatterRegistry disposal", () => {
  it("removes a registration through its disposer", () => {
    const registry = new ToolInputFormatterRegistry();
    const dispose = registry.register("custom", formatterReturning("x"));

    dispose();
    expect(registry.lookup("custom")).toBeUndefined();
  });

  it("does not let a stale disposer remove a replacement formatter", () => {
    const registry = new ToolInputFormatterRegistry();
    const stale = registry.register("custom", formatterReturning("first"));
    stale();
    const replacement = formatterReturning("second");
    registry.register("custom", replacement);

    stale();
    expect(registry.lookup("custom")).toBe(replacement);
  });

  it("clears local and inherited entries on dispose", () => {
    const registry = new ToolInputFormatterRegistry({
      inherited: [{ name: "host-tool", format: formatterReturning("inherited") }],
    });
    const dispose = registry.register("custom", formatterReturning("local"));

    registry.dispose();
    expect(registry.lookup("custom")).toBeUndefined();
    expect(registry.lookup("host-tool")).toBeUndefined();
    dispose();
    expect(registry.lookup("custom")).toBeUndefined();
  });
});
