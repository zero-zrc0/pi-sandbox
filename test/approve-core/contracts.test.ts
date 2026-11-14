import { describe, expect, it } from "vitest";
import { reviewDigest } from "#approve-core/context/types";
import {
  applyNodeResult,
  captureStep,
  describeEffectiveNodes,
  mapCallReview,
  prepareStep,
  readyCallResults,
} from "#approve-core/contracts";

describe("contracts node-composition compatibility", () => {
  it("keeps the established import path for effective node composition", () => {
    const result = describeEffectiveNodes();

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.configuration.nodes.some((node) => node.id === "builtin/decision")).toBe(true);
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

describe("review decisions", () => {
  it("keeps the rule ask and records approval as a separate exact-call resolution", () => {
    const args = { path: "./report.txt" };
    const captured = captureStep({
      stepKey: "step-review",
      sessionId: "session-review",
      sourceEntryId: "entry-review",
      manifestRevision: 1,
      complete: true,
      directCalls: [{
        toolCallId: "call-review",
        toolName: "write",
        arguments: args,
        argumentsDigest: reviewDigest(args),
      }],
    });
    expect(captured.ok).toBe(true);
    if (!captured.ok) throw new Error("valid review call was rejected");

    const prepared = prepareStep(captured.capture, [{
      toolCallId: "call-review",
      unitId: "unit-review",
      actionDigest: captured.capture.directCalls[0]!.digest,
      reason: "write target requires review",
    }]);
    expect(prepared.ok).toBe(true);
    if (!prepared.ok) throw new Error("valid review unit was rejected");

    const ruled = applyNodeResult(prepared.state, {
      node: { id: "builtin/decision", priority: 0 },
      evaluatedRevision: prepared.state.revision,
      result: {
        decisions: [{
          toolCallId: "call-review",
          unitId: "unit-review",
          decision: "ask",
          reason: "rules:global:ask:write:*",
        }],
      },
    });
    expect(ruled.ok).toBe(true);
    if (!ruled.ok) throw new Error("rule ask was rejected");

    const overwritten = applyNodeResult(ruled.state, {
      node: { id: "plugin/ordinary-allow", priority: 80 },
      evaluatedRevision: ruled.state.revision,
      result: {
        decisions: [{
          toolCallId: "call-review",
          unitId: "unit-review",
          decision: "allow",
          reason: "plugin-allow",
        }],
      },
    });
    expect(overwritten).toEqual({ ok: false, reason: "ask-cannot-be-allowed" });
    expect(readyCallResults(ruled.state)[0]?.decision).toBe("ask");

    const mapped = mapCallReview(ruled.state, { id: "builtin/human", priority: null }, {
      toolCallId: "call-review",
      decision: "approve",
      reason: "human-approved-exact-call",
    });
    expect(mapped.ok).toBe(true);
    if (!mapped.ok) throw new Error("review approval was rejected");
    expect(mapped.submission.result.decisions).toEqual([]);
    expect(mapped.submission.result.reviews).toEqual([{
      toolCallId: "call-review",
      unitId: "unit-review",
      decision: "approve",
      reason: "human-approved-exact-call",
    }]);

    const reviewed = applyNodeResult(ruled.state, mapped.submission);
    expect(reviewed.ok).toBe(true);
    if (!reviewed.ok) throw new Error("review approval was rejected");
    expect(reviewed.state.calls[0]!.units[0]!.decision).toBe("ask");
    expect(readyCallResults(reviewed.state)[0]!.decision).toBe("allow");

    const denied = mapCallReview(ruled.state, { id: "builtin/decision-approver", priority: null }, {
      toolCallId: "call-review",
      decision: "deny",
      reason: "reviewer-denied-exact-call",
    });
    expect(denied.ok).toBe(true);
    if (!denied.ok) throw new Error("review denial was rejected");
    const deniedState = applyNodeResult(ruled.state, denied.submission);
    expect(deniedState.ok).toBe(true);
    if (!deniedState.ok) throw new Error("review denial was rejected");
    expect(deniedState.state.calls[0]!.units[0]!.decision).toBe("ask");
    expect(readyCallResults(deniedState.state)[0]!.decision).toBe("deny");
    expect(mapCallReview(deniedState.state, { id: "builtin/human", priority: null }, {
      toolCallId: "call-review",
      decision: "approve",
      reason: "attempted-revival",
    })).toEqual({ ok: false, reason: "call-already-denied" });
  });
});
