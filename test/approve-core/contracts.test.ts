import { describe, expect, it } from "vitest";
import { reviewDigest } from "#approve-core/context/types";
import { captureStep, describeEffectiveNodes } from "#approve-core/contracts";

describe("contracts node-composition compatibility", () => {
  it("keeps the established import path for effective node composition", () => {
    const result = describeEffectiveNodes();

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.configuration.nodes.some((node) => node.id === "builtin/mode")).toBe(true);
  });
});

describe("step capture JSON identity", () => {
  it("keeps captured facts stable when JSON object keys arrive in a different order", () => {
    const firstArguments = { nested: { z: 1, a: 2 }, name: "n" };
    const secondArguments = { name: "n", nested: { a: 2, z: 1 } };
    const argumentsDigest = reviewDigest(firstArguments);
    const capture = (args: typeof firstArguments) => captureStep({
      stepKey: "step-1",
      sessionId: "session-1",
      sourceEntryId: "entry-1",
      manifestRevision: 1,
      complete: true,
      directCalls: [{
        toolCallId: "call-1",
        toolName: "read",
        arguments: args,
        argumentsDigest,
      }],
    });

    const first = capture(firstArguments);
    const second = capture(secondArguments);
    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    if (!first.ok || !second.ok) throw new Error("valid step facts were rejected");

    expect(first.capture.digest).toBe(second.capture.digest);
    expect(Object.isFrozen(first.capture.directCalls[0]!.arguments.nested)).toBe(true);
  });
});
