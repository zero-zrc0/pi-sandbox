import { describe, expect, it } from "vitest";
import {
  normalizeToolAccessFacts,
  type ToolAccessFactsResult,
} from "#approve-core/utils/tool-access/access-facts";

const flatTool = {
  name: "read",
  origin: "builtin:read",
  revision: "7",
  description: "Read a file",
  parameters: { type: "object", properties: { path: { type: "string" } }, required: ["path"] },
};

function normalize(raw: unknown, tool?: unknown, source?: unknown): ToolAccessFactsResult {
  return normalizeToolAccessFacts(raw, tool, source);
}

function validRaw(accesses: readonly unknown[] = [{ path: "C:/work/a.txt", access: "read", operation: "read" }]): Record<string, unknown> {
  return { accesses, complete: true, unknownEffects: [] };
}

describe("normalizeToolAccessFacts", () => {
  it("verifies complete facts with a tool identity and freezes the result", () => {
    const facts = normalize(validRaw([
      { path: "  C:/work/a.txt  ", access: "read", operation: "read" },
      { path: "C:/work/b.txt", access: "write" },
    ]), flatTool, "builtin");

    expect(facts.status).toBe("verified");
    expect(facts.complete).toBe(true);
    expect(facts.source).toBe("builtin");
    expect(facts.unknownEffects).toEqual([]);
    expect(facts.tool).toEqual({ name: "read", origin: "builtin:read", revision: "7" });
    expect(facts.accesses).toEqual([
      { path: "C:/work/a.txt", access: "read", operation: "read" },
      { path: "C:/work/b.txt", access: "write" },
    ]);
    expect(Object.isFrozen(facts)).toBe(true);
    expect(Object.isFrozen(facts.accesses)).toBe(true);
    expect(Object.isFrozen(facts.accesses[0])).toBe(true);
  });

  it("accepts a nested tool definition as the tool fact", () => {
    const facts = normalize(validRaw(), {
      identity: { name: "read", origin: "builtin:read", revision: "7" },
      description: "Read a file",
      parameters: { type: "object" },
    });
    expect(facts.status).toBe("verified");
    expect(facts.tool?.name).toBe("read");
  });

  it("stays incomplete without tool facts", () => {
    const facts = normalize(validRaw());
    expect(facts.status).toBe("incomplete");
    expect(facts.complete).toBe(true);
    expect(facts.diagnostic).toBe("tool-identity-unavailable");
    expect(facts.accesses).toHaveLength(1);
  });

  it("stays incomplete when the tool identity is unreadable", () => {
    expect(normalize(validRaw(), { name: "read" }).status).toBe("incomplete");
    expect(normalize(validRaw(), { name: "read", origin: "builtin:read" }).status).toBe("incomplete");
    expect(normalize(validRaw(), { name: 7, origin: "o", revision: "r" }).status).toBe("incomplete");
  });

  it("keeps the parsed accesses for an explicit incomplete result or unknown effects", () => {
    const explicit = normalize({ ...validRaw(), complete: false }, flatTool, "builtin");
    expect(explicit.status).toBe("incomplete");
    expect(explicit.complete).toBe(false);
    expect(explicit.accesses).toHaveLength(1);

    const unknown = normalize({ ...validRaw(), unknownEffects: ["invalid-file-path"] }, flatTool, "builtin");
    expect(unknown.status).toBe("incomplete");
    expect(unknown.unknownEffects).toEqual(["invalid-file-path"]);
  });

  it("rejects a raw value that is not a plain object", () => {
    for (const raw of [null, undefined, [], "facts", 7, true]) {
      const facts = normalize(raw);
      expect(facts.status).toBe("incomplete");
      expect(facts.accesses).toEqual([]);
      expect(facts.diagnostic).toBe("invalid-object");
    }
  });

  it("rejects unknown top-level and access fields", () => {
    expect(normalize({ ...validRaw(), extra: 1 }).diagnostic).toBe("unknown-field");
    expect(normalize(validRaw([{ path: "C:/a", access: "read", extra: 1 }]), flatTool).diagnostic).toBe("unknown-field");
  });

  it("requires arrays, a boolean complete flag and non-empty unknown effects", () => {
    expect(normalize({ accesses: {}, complete: true, unknownEffects: [] }).diagnostic).toBe("invalid-accesses");
    expect(normalize({ accesses: [], complete: "yes", unknownEffects: [] }).diagnostic).toBe("invalid-complete");
    expect(normalize({ accesses: [], complete: true, unknownEffects: {} }).diagnostic).toBe("invalid-unknown-effects");
    expect(normalize({ accesses: [], complete: true, unknownEffects: [""] }).diagnostic).toBe("invalid-unknown-effect");
    expect(normalize({ accesses: [], complete: true, unknownEffects: ["  "] }).diagnostic).toBe("invalid-unknown-effect");
    expect(normalize({ accesses: [], complete: true, unknownEffects: [7] }).diagnostic).toBe("invalid-unknown-effect");
  });

  it("rejects invalid access values and operations", () => {
    expect(normalize(validRaw([{ path: "C:/a", access: "execute" }]), flatTool).diagnostic).toBe("invalid-access");
    expect(normalize(validRaw([{ path: "C:/a", access: "read", operation: "rename" }]), flatTool).diagnostic)
      .toBe("invalid-operation");
    expect(normalize(validRaw([{ path: "C:/a" }]), flatTool).diagnostic).toBe("invalid-access");
    expect(normalize(validRaw([{ access: "read" }]), flatTool).diagnostic).toBe("invalid-access");
  });

  it("rejects empty paths and URLs while keeping Windows drive paths", () => {
    expect(normalize(validRaw([{ path: "   ", access: "read" }]), flatTool).diagnostic).toBe("invalid-path");
    expect(normalize(validRaw([{ path: "https://example.com/a.txt", access: "read" }]), flatTool).diagnostic).toBe("url-path");
    expect(normalize(validRaw([{ path: "file:///C:/work/a.txt", access: "read" }]), flatTool).diagnostic).toBe("url-path");
    expect(normalize(validRaw([{ path: "mailto:user@example.com", access: "read" }]), flatTool).diagnostic).toBe("url-path");

    for (const path of ["C:\\work\\a.txt", "D:/data/file.txt", "//server/share/file.txt", "C:"]) {
      expect(normalize(validRaw([{ path, access: "read" }]), flatTool).status).toBe("verified");
    }
  });

  it("fails closed on partially valid access lists", () => {
    const facts = normalize(validRaw([
      { path: "C:/good.txt", access: "read" },
      { path: "https://example.com/bad.txt", access: "read" },
    ]), flatTool);

    expect(facts.status).toBe("incomplete");
    expect(facts.accesses).toEqual([]);
    expect(facts.diagnostic).toBe("url-path");
  });

  it("rejects values that cannot be frozen as JSON", () => {
    expect(normalize({ accesses: [{ path: "C:/a", access: "read" }], complete: true, unknownEffects: [], run: () => 1 }).diagnostic)
      .toBe("unknown-field");
    expect(normalize(validRaw([{ path: "C:/a", access: "read", extra: () => 1 }]), flatTool).diagnostic)
      .toBe("unknown-field");
    expect(normalize({ accesses: [{ path: "C:/a", access: "read" }], complete: true, unknownEffects: [undefined] }).diagnostic)
      .toBe("invalid-unknown-effect");

    const cyclic: Record<string, unknown> = { path: "C:/a", access: "read" };
    cyclic.self = cyclic;
    expect(normalize(validRaw([cyclic]), flatTool).diagnostic).toBe("unknown-field");
  });

  it("normalizes the source string and falls back to unknown", () => {
    expect(normalize(validRaw(), flatTool, "  builtin  ").source).toBe("builtin");
    expect(normalize(validRaw(), flatTool, undefined).source).toBe("unknown");
    expect(normalize(validRaw(), flatTool, 42).source).toBe("unknown");
    expect(normalize(validRaw(), flatTool, "").source).toBe("unknown");
  });

  it("always expands complete=true plus empty unknown effects only when the tool fact is present", () => {
    expect(normalize(validRaw(), flatTool).status).toBe("verified");
    expect(normalize({ ...validRaw(), complete: false }, flatTool).status).toBe("incomplete");
    expect(normalize({ ...validRaw(), unknownEffects: ["x"] }, flatTool).status).toBe("incomplete");
    expect(normalize(validRaw()).status).toBe("incomplete");
  });
});
