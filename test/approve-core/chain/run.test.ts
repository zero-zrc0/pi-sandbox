import { describe, expect, it, vi } from "vitest";
import type { ApprovalContext, ChainCallFacts, ChainUnitFacts } from "#approve-core/chain/facts";
import { combineCall, orderHandlers, runChain, type Handler, type UnitVerdict } from "#approve-core/chain/run";
import { allowVerdict, askVerdict, denyVerdict, NO_VERDICT } from "#approve-core/chain/verdict";

function unit(unitId = "call-1:u0", overrides: Partial<ChainUnitFacts> = {}): ChainUnitFacts {
  return {
    unitId,
    toolName: "bash",
    access: [{ kind: "read" }],
    ...overrides,
  };
}

function call(units: readonly ChainUnitFacts[] = [unit()]): ChainCallFacts {
  return { toolCallId: "call-1", toolName: "bash", units };
}

function context(
  overrides: Partial<ApprovalContext> = {},
  target: ChainUnitFacts = unit(),
): ApprovalContext {
  return {
    call: call([target]),
    unit: target,
    mode: "default",
    channel: "normal",
    accumulated: NO_VERDICT,
    ...overrides,
  };
}

function handler(
  id: string,
  priority: number,
  kind: Handler["kind"],
  evaluate: Handler["evaluate"],
): Handler {
  return { id, priority, kind, evaluate };
}

describe("orderHandlers", () => {
  it("sorts by priority and keeps declaration order inside a tie", () => {
    const ordered = orderHandlers([
      handler("c", 30, "restriction", () => ({ action: "pass" })),
      handler("a", 10, "restriction", () => ({ action: "pass" })),
      handler("b1", 20, "restriction", () => ({ action: "pass" })),
      handler("b2", 20, "grant", () => ({ action: "pass" })),
    ]);
    expect(ordered.ok).toBe(true);
    if (!ordered.ok) return;
    expect(ordered.handlers.map((entry) => entry.id)).toEqual(["a", "b1", "b2", "c"]);
  });

  it("rejects a duplicate id", () => {
    const result = orderHandlers([
      handler("same", 1, "restriction", () => ({ action: "pass" })),
      handler("same", 2, "restriction", () => ({ action: "pass" })),
    ]);
    expect(result).toEqual({ ok: false, reason: "duplicate-handler-id" });
  });

  it("rejects a non-integer priority", () => {
    const result = orderHandlers([handler("x", 1.5, "restriction", () => ({ action: "pass" }))]);
    expect(result).toEqual({ ok: false, reason: "invalid-priority" });
  });

  it("rejects an unknown kind", () => {
    const broken = { id: "x", priority: 1, kind: "resolver", evaluate: () => ({ action: "pass" }) };
    const result = orderHandlers([broken as unknown as Handler]);
    expect(result).toEqual({ ok: false, reason: "invalid-kind" });
  });

  it("rejects a handler without evaluate", () => {
    const broken = { id: "x", priority: 1, kind: "restriction" };
    const result = orderHandlers([broken as unknown as Handler]);
    expect(result).toEqual({ ok: false, reason: "invalid-handler" });
  });
});

describe("runChain", () => {
  it("keeps an ask when a later grant allows", async () => {
    const outcome = await runChain(
      [
        handler("base", 0, "base", () => ({ action: "ask", reason: "mode:unknown" })),
        handler("grant", 50, "grant", () => ({ action: "allow", reason: "rules:allow" })),
      ],
      context(),
    );
    expect(outcome.verdict.state).toBe("ask");
    expect(outcome.verdict.source).toBe("base");
    expect(outcome.steps.map((step) => step.handlerId)).toEqual(["base", "grant"]);
  });

  it("short-circuits on deny and never runs the remaining links", async () => {
    const after = vi.fn(() => ({ action: "allow" as const }));
    const outcome = await runChain(
      [
        handler("base", 0, "base", () => ({ action: "allow", reason: "mode:full-access" })),
        handler("danger", 30, "restriction", () => ({ action: "deny", reason: "risk:x" })),
        handler("late", 50, "grant", after),
      ],
      context(),
    );
    expect(outcome.verdict.state).toBe("deny");
    expect(after).not.toHaveBeenCalled();
    expect(outcome.steps.map((step) => step.handlerId)).toEqual(["base", "danger"]);
  });

  it("keeps an escalation ask unliftable through later grants", async () => {
    const outcome = await runChain(
      [
        handler("base", 0, "base", () => ({ action: "ask", askFor: "escalate", reason: "mode:one-time" })),
        handler("grant", 50, "grant", () => ({ action: "allow", reason: "rules:allow" })),
      ],
      context(),
    );
    expect(outcome.verdict.state).toBe("ask");
    expect(outcome.verdict.askFor).toBe("escalate");
    expect(outcome.verdict.locked).toBe(true);
  });

  it("fails closed and stops when a handler throws", async () => {
    const after = vi.fn(() => ({ action: "allow" as const }));
    const outcome = await runChain(
      [
        handler("base", 0, "base", () => ({ action: "ask", reason: "mode:unknown" })),
        handler("boom", 20, "restriction", () => {
          throw new Error("boom");
        }),
        handler("late", 50, "grant", after),
      ],
      context(),
    );
    expect(outcome.fault).toEqual({ handlerId: "boom", reason: "boom" });
    expect(outcome.verdict.state).toBe("ask");
    expect(after).not.toHaveBeenCalled();
    const step = outcome.steps.find((entry) => entry.handlerId === "boom");
    expect(step?.fault).toBe("boom");
  });

  it("fails closed on a malformed result", async () => {
    const outcome = await runChain(
      [handler("bad", 0, "restriction", () => ({ action: "nope" }) as never)],
      context(),
    );
    expect(outcome.fault).toEqual({ handlerId: "bad", reason: "invalid-handler-result" });
    expect(outcome.verdict).toBe(NO_VERDICT);
  });

  it("fails closed when a restriction tries to allow", async () => {
    const outcome = await runChain(
      [handler("sneaky", 0, "restriction", () => ({ action: "allow", reason: "x" }))],
      context(),
    );
    expect(outcome.fault).toEqual({ handlerId: "sneaky", reason: "restriction-cannot-allow" });
    expect(outcome.verdict.state).toBe("ask");
    expect(outcome.verdict.askFor).toBe("escalate");
  });

  it("lets a handler read the verdict accumulated so far", async () => {
    const seen: string[] = [];
    await runChain(
      [
        handler("base", 0, "base", () => ({ action: "ask", reason: "mode:unknown" })),
        handler("reader", 10, "restriction", (ctx) => {
          seen.push(ctx.accumulated.state);
          return { action: "pass" };
        }),
      ],
      context(),
    );
    expect(seen).toEqual(["ask"]);
  });

  it("supports async handlers", async () => {
    const outcome = await runChain(
      [handler("async", 0, "base", async () => ({ action: "allow", reason: "mode:read" }))],
      context(),
    );
    expect(outcome.verdict.state).toBe("allow");
  });
});

describe("combineCall", () => {
  it("returns the strictest unit verdict", () => {
    const units: UnitVerdict[] = [
      { unitId: "a", verdict: allowVerdict("a", "x"), steps: [] },
      { unitId: "b", verdict: askVerdict("b", "y"), steps: [] },
    ];
    expect(combineCall(units).state).toBe("ask");
    units.push({ unitId: "c", verdict: denyVerdict("c", "z"), steps: [] });
    expect(combineCall(units).state).toBe("deny");
  });

  it("keeps the call escalated when one unit needs a host execution", () => {
    const units: UnitVerdict[] = [
      { unitId: "a", verdict: askVerdict("a", "x"), steps: [] },
      { unitId: "b", verdict: askVerdict("b", "y", { askFor: "escalate" }), steps: [] },
    ];
    const verdict = combineCall(units);
    expect(verdict.askFor).toBe("escalate");
    expect(verdict.locked).toBe(true);
  });

  it("has no opinion for an empty call", () => {
    expect(combineCall([]).state).toBe("none");
  });
});
