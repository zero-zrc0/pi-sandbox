import { describe, expect, it } from "vitest";
import { createBuiltinFrontBindings } from "#approve-core/nodes/mode/bindings";
import type { ChainNode } from "#approve-core/runtime";

function node(id: string): ChainNode {
  return { apiVersion: "1", id, evaluate: async () => ({ decisions: [] }) };
}

describe("createBuiltinFrontBindings", () => {
  it("places enabled optional shell nodes after assessment and before mode", () => {
    const bindings = createBuiltinFrontBindings({
      rules: { rules: [] },
      assessment: { resolve: () => null },
      mode: { mode: "default" },
      powershell: node("builtin/powershell"),
      externalCommand: node("builtin/external-command"),
    });

    expect(bindings.map((binding) => binding.node.id)).toEqual([
      "builtin/structure-analysis",
      "builtin/identity",
      "builtin/rules",
      "builtin/assessment",
      "builtin/powershell",
      "builtin/external-command",
      "builtin/mode",
    ]);
  });

  it("rejects an optional node that is not in the fixed optional order", () => {
    expect(() => createBuiltinFrontBindings({
      rules: { rules: [] },
      assessment: { resolve: () => null },
      mode: { mode: "default" },
      powershell: node("builtin/external-command"),
    })).toThrow("optional built-in front nodes do not match the frozen contract");
  });
});
