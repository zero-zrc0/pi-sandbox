import { describe, expect, it } from "vitest";
import { defineApprovalNode } from "../src/sdk/index";

describe("approval node SDK", () => {
  it("preserves the module provided by the consumer", () => {
    const module = {
      apiVersion: "1" as const,
      createNode: () => ({
        apiVersion: "1" as const,
        id: "user:example",
        evaluate: () => ({ decisions: [] }),
      }),
    };

    expect(defineApprovalNode(module)).toBe(module);
  });
});
