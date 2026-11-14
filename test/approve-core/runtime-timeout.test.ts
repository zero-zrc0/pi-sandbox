import { describe, expect, it } from "vitest";
import { orderChainNodes } from "../../src/approve-core/runtime";

describe("reviewer timeout", () => {
  it("preserves the configured timeout when ordering nodes", () => {
    const result = orderChainNodes([{
      position: "post",
      priority: null,
      timeoutMs: 5_000,
      node: { apiVersion: "1", id: "builtin/llm-approver", evaluate: () => ({ decisions: [] }) },
    }]);
    expect(result.ok && result.nodes[0]?.timeoutMs).toBe(5_000);
  });
});
