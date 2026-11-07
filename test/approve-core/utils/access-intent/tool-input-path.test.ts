import { describe, expect, it } from "vitest";
import {
  extractToolInputPath,
  type PathExtractorLookup,
  type RegisteredPathExtractor,
} from "#approve-core/utils/access-intent/tool-input-path";

function lookup(entries: Record<string, RegisteredPathExtractor>): PathExtractorLookup {
  return { lookup: (name) => entries[name] };
}

describe("extractToolInputPath conventions", () => {
  it("returns no path for Bash (token analysis owns Bash paths)", () => {
    expect(extractToolInputPath("bash", { command: "cat x" })).toBeUndefined();
  });

  it("reads input.path for builtin path tools", () => {
    expect(extractToolInputPath("read", { path: "/a" })).toEqual({ path: "/a", source: "convention" });
    expect(extractToolInputPath("edit", { path: "  /a " })).toEqual({ path: "/a", source: "convention" });
  });

  it("reads arguments.path for the MCP proxy tool", () => {
    expect(extractToolInputPath("mcp", { arguments: { path: "/mcp/a" } })).toEqual({
      path: "/mcp/a",
      source: "convention",
    });
  });

  it("ignores non-string, blank and non-own values", () => {
    expect(extractToolInputPath("read", { path: 42 })).toBeUndefined();
    expect(extractToolInputPath("read", { path: "   " })).toBeUndefined();
    expect(extractToolInputPath("read", {})).toBeUndefined();
    expect(extractToolInputPath("read", null)).toBeUndefined();
    expect(extractToolInputPath("read", "just a string")).toBeUndefined();
  });
});

describe("extractToolInputPath with extractors", () => {
  it("prefers a registered extractor and reports its origin", () => {
    const registry = lookup({
      notes: { origin: "local", extract: (input) => (input as { file?: unknown }).file },
    });
    const extracted = extractToolInputPath("notes", { file: "/note/1" }, registry);
    expect(extracted).toEqual({ path: "/note/1", source: "local-extractor" });
  });

  it("reports inherited origins separately", () => {
    const registry = lookup({
      ext: { origin: "inherited", extract: () => "/from/parent" },
    });
    expect(extractToolInputPath("ext", {}, registry)).toEqual({
      path: "/from/parent",
      source: "inherited-extractor",
    });
  });

  it("falls back to input.path when the extractor declines or returns invalid values", () => {
    const declining = lookup({ ext: { origin: "local", extract: () => undefined } });
    expect(extractToolInputPath("ext", { path: "/fallback" }, declining)).toEqual({
      path: "/fallback",
      source: "convention",
    });
    const invalid = lookup({ ext: { origin: "local", extract: () => "  " } });
    expect(extractToolInputPath("ext", { path: "/fallback" }, invalid)).toEqual({
      path: "/fallback",
      source: "convention",
    });
  });

  it("builtin-only queries never consult extractors for non-path tools", () => {
    let consulted = 0;
    const registry: PathExtractorLookup = {
      lookup: () => {
        consulted += 1;
        return { origin: "local", extract: () => "/x" };
      },
    };
    expect(extractToolInputPath("ext", { path: "/p" }, registry, { builtinOnly: true })).toBeUndefined();
    expect(consulted).toBe(0);
    expect(extractToolInputPath("read", { path: "/p" }, registry, { builtinOnly: true })).toEqual({
      path: "/p",
      source: "convention",
    });
    expect(consulted).toBe(0);
  });
});
