/**
 * Multi-source fact merging (specs/tool-access.md §7).
 *
 * Selection is pure policy over already-built candidate reports: builtin wins
 * participation whenever it is not unbound, configured declarations replace the
 * SDK adapter, and an unresolved package source fails the whole lookup. Merge
 * trusts only identical verified access sets; any incomplete report or conflict
 * keeps the result incomplete while retaining verified accesses as diagnostics.
 */
import { describe, expect, it } from "vitest";
import {
  mergeToolAccessCandidates,
  selectToolAccessCandidates,
  toolAccessAdapterStatus,
  type ToolAccessCandidate,
} from "#approve-core/utils/tool-access/facts-owner";
import type { ToolAccess, ToolAccessFactsResult } from "#approve-core/utils/tool-access/access-facts";
import type { ToolIdentity } from "#approve-core/utils/tool-access/tool-definition";

const TOOL: ToolIdentity = { name: "reader_tool", origin: "plugin:acme", revision: "rev-1" };

function access(path: string, mode: "read" | "write", operation?: ToolAccess["operation"]): ToolAccess {
  return operation === undefined ? { path, access: mode } : { path, access: mode, operation };
}

function verifiedFacts(
  accesses: readonly ToolAccess[],
  source = "builtin",
  tool: ToolIdentity = TOOL,
): ToolAccessFactsResult {
  return { status: "verified", source, complete: true, unknownEffects: [], accesses, tool };
}

function incompleteFacts(
  unknownEffects: readonly string[],
  accesses: readonly ToolAccess[] = [],
  source = "declared",
): ToolAccessFactsResult {
  return { status: "incomplete", source, complete: false, unknownEffects, accesses, tool: TOOL };
}

function unboundFacts(source = "sdk"): ToolAccessFactsResult {
  return { status: "unbound", source, complete: false, unknownEffects: [], accesses: [] };
}

function candidate(source: ToolAccessCandidate["source"], facts: ToolAccessFactsResult): ToolAccessCandidate {
  return { source, facts };
}

const FACTS_A = verifiedFacts([access("src/a.ts", "read", "read")]);

describe("selectToolAccessCandidates", () => {
  it("returns nothing without candidates", () => {
    expect(selectToolAccessCandidates({})).toEqual([]);
  });

  it("keeps a non-unbound builtin candidate", () => {
    const candidates = selectToolAccessCandidates({ builtin: FACTS_A });
    expect(candidates).toHaveLength(1);
    expect(candidates[0]?.source).toBe("builtin");
    expect(candidates[0]?.facts).toBe(FACTS_A);
  });

  it("drops an unbound builtin candidate", () => {
    expect(selectToolAccessCandidates({ builtin: unboundFacts("builtin") })).toEqual([]);
  });

  it("keeps incomplete builtin facts as a participating candidate", () => {
    const facts = incompleteFacts(["schema-drift"]);
    const candidates = selectToolAccessCandidates({ builtin: facts });
    expect(candidates.map((entry) => entry.source)).toEqual(["builtin"]);
  });

  it("uses every configured declaration and ignores the SDK adapter", () => {
    const declaredOne = verifiedFacts([access("a", "read", "read")], "declared");
    const declaredTwo = verifiedFacts([access("b", "read", "read")], "declared");
    const sdk = verifiedFacts([access("c", "read", "read")], "sdk");
    const candidates = selectToolAccessCandidates({
      builtin: FACTS_A,
      declarations: [declaredOne, declaredTwo],
      sdk,
    });
    expect(candidates.map((entry) => entry.source)).toEqual(["builtin", "declared", "declared"]);
    expect(candidates[1]?.facts).toBe(declaredOne);
    expect(candidates[2]?.facts).toBe(declaredTwo);
  });

  it("falls back to the SDK adapter when there is no configuration declaration", () => {
    const sdk = verifiedFacts([access("c", "read", "read")], "sdk");
    expect(selectToolAccessCandidates({ declarations: [], sdk }).map((entry) => entry.source)).toEqual(["sdk"]);
    expect(selectToolAccessCandidates({ sdk }).map((entry) => entry.source)).toEqual(["sdk"]);
  });

  it("drops unbound declarations but keeps the rest", () => {
    const declared = verifiedFacts([access("a", "read", "read")], "declared");
    const candidates = selectToolAccessCandidates({
      builtin: FACTS_A,
      declarations: [unboundFacts("declared"), declared],
    });
    expect(candidates.map((entry) => entry.source)).toEqual(["builtin", "declared"]);
  });

  it("returns nothing when there is no candidate left", () => {
    expect(selectToolAccessCandidates({ builtin: unboundFacts("builtin"), declarations: [unboundFacts("declared")] })).toEqual([]);
  });

  it("fails the whole lookup on an unresolved package declaration", () => {
    const declared = verifiedFacts([access("a", "read", "read")], "declared");
    expect(selectToolAccessCandidates({
      builtin: FACTS_A,
      declarations: [declared],
      declarativeUnresolved: true,
      sdk: verifiedFacts([access("b", "read", "read")], "sdk"),
    })).toEqual([]);
  });
});

describe("mergeToolAccessCandidates", () => {
  it("returns unbound when there is no candidate", () => {
    const merged = mergeToolAccessCandidates([]);
    expect(merged.status).toBe("unbound");
    expect(merged.accesses).toEqual([]);
  });

  it("returns a single verified candidate unchanged", () => {
    const merged = mergeToolAccessCandidates([candidate("builtin", FACTS_A)]);
    expect(merged.status).toBe("verified");
    expect(merged.source).toBe("builtin");
    expect(merged.accesses).toEqual([...FACTS_A.accesses]);
  });

  it("merges identical verified sets into a merged source", () => {
    const declared = verifiedFacts([
      access("src/a.ts", "read", "read"),
    ], "declared");
    const merged = mergeToolAccessCandidates([
      candidate("builtin", FACTS_A),
      candidate("declared", declared),
    ]);
    expect(merged.status).toBe("verified");
    expect(merged.source).toBe("merged");
    expect(merged.accesses.map((entry) => `${entry.access}|${entry.operation}|${entry.path}`)).toEqual([
      "read|read|src/a.ts",
    ]);
  });

  it("compares access sets order-insensitively", () => {
    const one = verifiedFacts([
      access("b.ts", "read", "read"),
      access("a.ts", "read", "read"),
    ]);
    const two = verifiedFacts([
      access("a.ts", "read", "read"),
      access("b.ts", "read", "read"),
    ], "sdk");
    const merged = mergeToolAccessCandidates([candidate("builtin", one), candidate("sdk", two)]);
    expect(merged.status).toBe("verified");
    expect(merged.source).toBe("merged");
    expect(merged.accesses.map((entry) => entry.path).sort()).toEqual(["a.ts", "b.ts"]);
  });

  it("reports an incompleteness when verified sets conflict", () => {
    const other = verifiedFacts([access("src/b.ts", "read", "read")], "declared");
    const merged = mergeToolAccessCandidates([candidate("builtin", FACTS_A), candidate("declared", other)]);
    expect(merged.status).toBe("incomplete");
    expect(merged.unknownEffects).toContain("access-conflict");
    expect(merged.accesses.length).toBeGreaterThan(0);
  });

  it("treats a differing operation as a conflict", () => {
    const withOperation = verifiedFacts([access("src/a.ts", "read", "read")], "declared");
    const withoutOperation = verifiedFacts([access("src/a.ts", "read")], "sdk");
    const merged = mergeToolAccessCandidates([
      candidate("builtin", withOperation),
      candidate("sdk", withoutOperation),
    ]);
    expect(merged.status).toBe("incomplete");
    expect(merged.unknownEffects).toContain("access-conflict");
  });

  it("keeps verified accesses as diagnostics when any candidate is incomplete", () => {
    const incomplete = incompleteFacts(["schema-drift"]);
    const merged = mergeToolAccessCandidates([
      candidate("builtin", FACTS_A),
      candidate("declared", incomplete),
    ]);
    expect(merged.status).toBe("incomplete");
    expect(merged.unknownEffects).toContain("schema-drift");
    expect(merged.accesses).toEqual([...FACTS_A.accesses]);
  });

  it("returns unbound when any candidate is unbound", () => {
    const merged = mergeToolAccessCandidates([
      candidate("builtin", unboundFacts("builtin")),
      candidate("sdk", FACTS_A),
    ]);
    expect(merged.status).toBe("unbound");
  });

  it("returns incomplete when every candidate is incomplete", () => {
    const merged = mergeToolAccessCandidates([
      candidate("declared", incompleteFacts(["missing-location"])),
      candidate("declared", incompleteFacts(["unmodeled-input-key"])),
    ]);
    expect(merged.status).toBe("incomplete");
    expect(merged.unknownEffects).toEqual(expect.arrayContaining(["missing-location", "unmodeled-input-key"]));
    expect(merged.accesses).toEqual([]);
  });

  it("returns a single incomplete candidate unchanged", () => {
    const incomplete = incompleteFacts(["missing-location"]);
    const merged = mergeToolAccessCandidates([candidate("declared", incomplete)]);
    expect(merged.status).toBe("incomplete");
    expect(merged.unknownEffects).toEqual(["missing-location"]);
  });
});

describe("toolAccessAdapterStatus", () => {
  it("reports unavailable without any probe", () => {
    expect(toolAccessAdapterStatus({})).toEqual({ verified: false, available: false });
  });

  it("reports verified for a single verified probe", () => {
    expect(toolAccessAdapterStatus({ probe: () => FACTS_A })).toEqual({ verified: true, available: true });
  });

  it("reports unverified but available for a single incomplete probe", () => {
    expect(toolAccessAdapterStatus({ probe: () => incompleteFacts(["schema-drift"]) })).toEqual({
      verified: false,
      available: true,
    });
  });

  it("treats a throwing probe as unverified", () => {
    expect(toolAccessAdapterStatus({
      probe: () => {
        throw new Error("adapter exploded");
      },
    })).toEqual({ verified: false, available: true });
  });

  it("reports unavailable for a single unbound probe", () => {
    expect(toolAccessAdapterStatus({ probe: () => unboundFacts("builtin") })).toEqual({
      verified: false,
      available: false,
    });
  });

  it("marks overlapping probe and declaration validations as input-dependent", () => {
    const status = toolAccessAdapterStatus({
      probe: () => FACTS_A,
      validations: [() => FACTS_A],
    });
    expect(status.verified).toBe(false);
    expect(status.inputDependent).toBe(true);
  });

  it("marks multiple declaration validations as input-dependent", () => {
    const status = toolAccessAdapterStatus({
      validations: [() => FACTS_A, () => FACTS_A],
    });
    expect(status.verified).toBe(false);
    expect(status.inputDependent).toBe(true);
  });

  it("marks an explicit overlapping source count as input-dependent", () => {
    const status = toolAccessAdapterStatus({ probe: () => FACTS_A, overlappingSources: 2 });
    expect(status.verified).toBe(false);
    expect(status.inputDependent).toBe(true);
  });

  it("ignores unbound validations when counting usable sources", () => {
    const status = toolAccessAdapterStatus({
      probe: () => FACTS_A,
      validations: [() => unboundFacts("declared")],
    });
    expect(status).toEqual({ verified: true, available: true });
  });

  it("treats a non-verified result label as unverified", () => {
    const mislabeled = { ...FACTS_A, status: "incomplete" as const, complete: false, unknownEffects: ["x"] };
    expect(toolAccessAdapterStatus({ probe: () => mislabeled })).toEqual({ verified: false, available: true });
  });
});
