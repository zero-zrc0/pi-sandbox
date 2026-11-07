import { describe, expect, it } from "vitest";
import {
  ACTION_RANK,
  moreRestrictive,
  pickMostRestrictive,
} from "#approve-core/policy/restrictiveness";

describe("restrictiveness ordering", () => {
  it("ranks deny above ask above allow", () => {
    expect(ACTION_RANK.deny).toBeGreaterThan(ACTION_RANK.ask);
    expect(ACTION_RANK.ask).toBeGreaterThan(ACTION_RANK.allow);
    expect(moreRestrictive("allow", "deny")).toBe("deny");
    expect(moreRestrictive("ask", "ask")).toBe("ask");
  });

  it("keeps the first complete result on ties", () => {
    const first = { state: "ask" as const, target: "first" };
    const second = { state: "ask" as const, target: "second" };
    expect(pickMostRestrictive([first, second])).toBe(first);
  });

  it("picks the most restrictive independent result", () => {
    const allow = { state: "allow" as const, target: "a" };
    const ask = { state: "ask" as const, target: "b" };
    const deny = { state: "deny" as const, target: "c" };
    expect(pickMostRestrictive([allow, ask, deny])).toBe(deny);
    expect(pickMostRestrictive([allow, ask])).toBe(ask);
    expect(pickMostRestrictive([allow, allow])?.target).toBe("a");
  });

  it("returns no restriction for an empty list", () => {
    expect(pickMostRestrictive([])).toBeUndefined();
  });
});
