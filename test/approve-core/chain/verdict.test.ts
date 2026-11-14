import { describe, expect, it } from "vitest";
import {
  allowVerdict,
  askVerdict,
  composeVerdict,
  denyVerdict,
  isHandlerResult,
  isResolverEligible,
  NO_VERDICT,
  strongerAskTarget,
  strongestVerdict,
  unknownVerdict,
} from "#approve-core/chain/verdict";

describe("verdict constructors", () => {
  it("starts with no opinion", () => {
    expect(NO_VERDICT).toEqual({ state: "none", locked: false, reason: "", source: "" });
  });

  it("marks an ordinary ask as eligible for review", () => {
    const verdict = askVerdict("fallback:no-handler", "builtin/fallback");
    expect(verdict.locked).toBe(false);
    expect(verdict.askFor).toBeUndefined();
    expect(isResolverEligible(verdict)).toBe(true);
  });

  it("keeps unknown distinct from no opinion and review asks", () => {
    const verdict = unknownVerdict("mode:default:effect-unproven", "builtin/mode-base");
    expect(verdict.state).toBe("unknown");
    expect(isResolverEligible(verdict)).toBe(false);
  });

  it("keeps an escalation ask eligible for an exact-call reviewer", () => {
    const verdict = askVerdict("risk:host-control:blocked", "builtin/danger-intent", {
      askFor: "escalate",
    });
    expect(verdict.locked).toBe(true);
    expect(isResolverEligible(verdict)).toBe(true);
  });

  it("keeps allow and deny resolver-ineligible", () => {
    expect(isResolverEligible(allowVerdict("mode:default:workspace-read-allow", "base"))).toBe(false);
    expect(isResolverEligible(denyVerdict("mode:read-only:write-forbidden", "base"))).toBe(false);
  });

  it("prefers escalation over a plain approval", () => {
    expect(strongerAskTarget(undefined, undefined)).toBeUndefined();
    expect(strongerAskTarget("allow", undefined)).toBe("allow");
    expect(strongerAskTarget("allow", "escalate")).toBe("escalate");
    expect(strongerAskTarget("escalate", "allow")).toBe("escalate");
  });
});

describe("composition from no opinion", () => {
  it("lets base state an allow", () => {
    const out = composeVerdict(NO_VERDICT, { action: "allow", reason: "mode:r" }, "base", "builtin/mode-base");
    expect(out.verdict).toEqual(allowVerdict("mode:r", "builtin/mode-base"));
    expect(out.violation).toBeUndefined();
  });

  it("lets a grant state an allow", () => {
    const out = composeVerdict(NO_VERDICT, { action: "allow", reason: "rules:allow" }, "grant", "g");
    expect(out.verdict.state).toBe("allow");
  });

  it("fails a restriction that tries to allow", () => {
    const out = composeVerdict(NO_VERDICT, { action: "allow", reason: "sneaky" }, "restriction", "r");
    expect(out.violation).toBe("restriction-cannot-allow");
    expect(out.verdict.state).toBe("ask");
    expect(out.verdict.askFor).toBe("escalate");
  });

  it("accepts an ask from base and restriction", () => {
    for (const kind of ["base", "restriction"] as const) {
      const out = composeVerdict(NO_VERDICT, { action: "ask", reason: "x" }, kind, "h");
      expect(out.verdict.state).toBe("ask");
      expect(out.verdict.askFor).toBeUndefined();
      expect(out.violation).toBeUndefined();
    }
  });

  it("fails a grant that tries to ask", () => {
    const out = composeVerdict(NO_VERDICT, { action: "ask", reason: "grant-ask" }, "grant", "g");
    expect(out.violation).toBe("grant-cannot-ask");
    expect(out.verdict.askFor).toBe("escalate");
  });

  it("accepts a deny from base and restriction", () => {
    for (const kind of ["base", "restriction"] as const) {
      const out = composeVerdict(NO_VERDICT, { action: "deny", reason: "no" }, kind, "h");
      expect(out.verdict).toEqual(denyVerdict("no", "h"));
    }
  });

  it("fails a grant that tries to deny", () => {
    const out = composeVerdict(NO_VERDICT, { action: "deny", reason: "grant-deny" }, "grant", "g");
    expect(out.violation).toBe("grant-cannot-deny");
    expect(out.verdict.state).toBe("ask");
  });

  it("keeps the current verdict on pass", () => {
    const current = allowVerdict("mode:default:workspace-read-allow", "base");
    expect(composeVerdict(current, { action: "pass" }, "restriction", "r").verdict).toBe(current);
  });
});

describe("composition against an allowed verdict", () => {
  const allowed = allowVerdict("mode:default:workspace-write-allow", "builtin/mode-base");

  it("keeps allow when a restriction has no opinion", () => {
    expect(composeVerdict(allowed, { action: "pass" }, "restriction", "r").verdict).toBe(allowed);
  });

  it("tightens allow into ask", () => {
    const out = composeVerdict(allowed, { action: "ask", reason: "rules:ask" }, "restriction", "builtin/explicit-rules-restrict");
    expect(out.verdict).toEqual(askVerdict("rules:ask", "builtin/explicit-rules-restrict"));
  });

  it("tightens allow into deny", () => {
    const out = composeVerdict(allowed, { action: "deny", reason: "risk:blocked" }, "restriction", "builtin/danger-intent");
    expect(out.verdict.state).toBe("deny");
  });
});

describe("composition against an ordinary ask", () => {
  const ordinaryAsk = askVerdict("mode:default:effect-unproven", "builtin/mode-base");

  it("does not let a grant erase it", () => {
    const out = composeVerdict(ordinaryAsk, { action: "allow", reason: "rules:global:allow:x" }, "grant", "g");
    expect(out.verdict).toBe(ordinaryAsk);
  });

  it("does not let a base link erase an ask", () => {
    const out = composeVerdict(ordinaryAsk, { action: "allow", reason: "mode:r" }, "base", "b");
    expect(out.verdict).toBe(ordinaryAsk);
  });

  it("is never lifted by a later restriction asking again", () => {
    const out = composeVerdict(ordinaryAsk, { action: "ask", reason: "sensitive:read" }, "restriction", "s");
    expect(out.verdict.state).toBe("ask");
    expect(out.verdict.reason).toBe("sensitive:read");
    expect(out.verdict.source).toBe("s");
  });

  it("escalates when any link asks for a host execution", () => {
    const out = composeVerdict(ordinaryAsk, { action: "ask", askFor: "escalate", reason: "mode:one-time" }, "restriction", "r");
    expect(out.verdict.askFor).toBe("escalate");
    expect(out.verdict.locked).toBe(true);
  });

  it("keeps escalation when a later plain ask follows", () => {
    const escalated = askVerdict("mode:one-time", "builtin/mode-base", { askFor: "escalate" });
    const out = composeVerdict(escalated, { action: "ask", reason: "later" }, "restriction", "r");
    expect(out.verdict.askFor).toBe("escalate");
    expect(out.verdict.locked).toBe(true);
  });
});

describe("composition with an unknown verdict", () => {
  const unknown = unknownVerdict("mode:default:effect-unproven", "builtin/mode-base");

  it("lets an explicit allow resolve unknown", () => {
    expect(composeVerdict(unknown, { action: "allow", reason: "rules:allow" }, "grant", "rules")
      .verdict).toEqual(allowVerdict("rules:allow", "rules"));
  });

  it("keeps an ask above unknown", () => {
    expect(composeVerdict(unknown, { action: "ask", reason: "rules:ask" }, "restriction", "rules")
      .verdict.state).toBe("ask");
  });
});

describe("composition against an escalation ask", () => {
  const escalated = askVerdict("mode:one-time-host-execution", "builtin/mode-base", {
    askFor: "escalate",
  });

  it("is not lifted by a grant", () => {
    const out = composeVerdict(escalated, { action: "allow", reason: "rules:allow" }, "grant", "g");
    expect(out.verdict).toBe(escalated);
  });

  it("is not lifted by base", () => {
    const out = composeVerdict(escalated, { action: "allow", reason: "mode:allow" }, "base", "b");
    expect(out.verdict).toBe(escalated);
  });

  it("is never turned into an allow by a later deny", () => {
    const out = composeVerdict(escalated, { action: "deny", reason: "risk:blocked" }, "restriction", "d");
    expect(out.verdict.state).toBe("deny");
  });
});

describe("composition against a denied verdict", () => {
  it("never revives a deny", () => {
    const denied = denyVerdict("risk:catastrophic-delete:blocked", "builtin/danger-intent");
    for (const kind of ["base", "restriction", "grant"] as const) {
      const out = composeVerdict(denied, { action: "allow", reason: "late" }, kind, "h");
      expect(out.verdict).toBe(denied);
    }
  });
});

describe("call-level fold", () => {
  it("prefers deny over everything", () => {
    const verdict = strongestVerdict([
      allowVerdict("a", "x"),
      askVerdict("b", "y"),
      denyVerdict("c", "z"),
    ]);
    expect(verdict.state).toBe("deny");
    expect(verdict.reason).toBe("c");
  });

  it("prefers an escalation ask over an ordinary ask", () => {
    const verdict = strongestVerdict([
      askVerdict("plain", "a"),
      askVerdict("escalate", "b", { askFor: "escalate" }),
    ]);
    expect(verdict.state).toBe("ask");
    expect(verdict.askFor).toBe("escalate");
    expect(verdict.locked).toBe(true);
    expect(verdict.reason).toBe("escalate");
  });

  it("falls back to the first allow", () => {
    expect(strongestVerdict([allowVerdict("a", "x"), allowVerdict("b", "y")]).reason).toBe("a");
  });

  it("does not let one allowed unit mask another unknown unit", () => {
    expect(strongestVerdict([
      allowVerdict("explicit-allow", "rules"),
      unknownVerdict("unclassified", "mode-base"),
    ]).state).toBe("unknown");
  });

  it("returns no opinion for an empty list", () => {
    expect(strongestVerdict([])).toBe(NO_VERDICT);
  });
});

describe("handler result shape", () => {
  it("accepts the three actions", () => {
    expect(isHandlerResult({ action: "pass" })).toBe(true);
    expect(isHandlerResult({ action: "unknown", reason: "unclassified" })).toBe(true);
    expect(isHandlerResult({ action: "allow", reason: "x" })).toBe(true);
    expect(isHandlerResult({ action: "ask", reason: "x", askFor: "escalate" })).toBe(true);
    expect(isHandlerResult({ action: "deny", reason: "x" })).toBe(true);
  });

  it("rejects malformed results", () => {
    expect(isHandlerResult(null)).toBe(false);
    expect(isHandlerResult([])).toBe(false);
    expect(isHandlerResult({ action: "escalate" })).toBe(false);
    expect(isHandlerResult({ action: "allow", reason: 7 })).toBe(false);
    expect(isHandlerResult({ action: "ask", askFor: "host" })).toBe(false);
    // askFor describes an ask only.
    expect(isHandlerResult({ action: "allow", askFor: "allow" })).toBe(false);
    // a pass carries no opinion.
    expect(isHandlerResult({ action: "pass", reason: "x" })).toBe(false);
  });
});
