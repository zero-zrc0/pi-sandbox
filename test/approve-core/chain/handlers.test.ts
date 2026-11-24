import { describe, expect, it } from "vitest";
import type { ApprovalContext, ChainCallFacts, ChainUnitFacts } from "#approve-core/chain/facts";
import {
  askVerdict,
  denyVerdict,
  NO_VERDICT,
  type Verdict,
} from "#approve-core/chain/verdict";
import { runChain } from "#approve-core/chain/run";
import { createDefaultChainHandlers } from "#approve-core/chain/defaults";
import type { Handler } from "#approve-core/chain/run";

function unit(overrides: Partial<ChainUnitFacts> = {}): ChainUnitFacts {
  return { unitId: "call-1:u0", toolName: "bash", access: [], ...overrides };
}

function call(units: readonly ChainUnitFacts[]): ChainCallFacts {
  return { toolCallId: "call-1", toolName: "bash", units };
}

async function decide(
  target: ChainUnitFacts,
  options: {
    readonly mode?: ApprovalContext["mode"];
    readonly channel?: ApprovalContext["channel"];
    readonly hostExecutionRequest?: import("../../../src/elevation").ExecutionRequest;
    readonly accumulated?: Verdict;
    readonly handlers?: readonly Handler[];
  } = {},
): Promise<Verdict> {
  const targetCall = call([target]);
  const outcome = await runChain(options.handlers ?? createDefaultChainHandlers(), {
    call: options.hostExecutionRequest === undefined
      ? targetCall
      : { ...targetCall, hostExecutionRequest: options.hostExecutionRequest },
    unit: target,
    mode: options.mode ?? "default",
    channel: options.channel ?? "normal",
    accumulated: options.accumulated ?? NO_VERDICT,
  });
  expect(outcome.fault).toBeUndefined();
  return outcome.verdict;
}

describe("mode-base", () => {
  it.each(["default", "host"] as const)("requires a human for one-time %s elevation from read-only", async tier => {
    const verdict = await decide(unit({ access: [{ kind: "write", path: "notes.txt", external: tier === "host" }] }), {
      mode: "read-only", channel: "elevation",
      hostExecutionRequest: { reason: "save notes", elevation: { tier, scope: [{ path: "notes.txt", access: "write" }] } },
    });
    expect(verdict.state).toBe("ask");
    expect(verdict.askFor).toBe("escalate");
    expect(verdict.locked).toBe(true);
  });

  it("does not let a session deny be lifted by Default elevation", async () => {
    const verdict = await decide(unit({ access: [{ kind: "write" }],
      rule: { decision: "deny", origin: "session", pattern: "*" } }), {
      mode: "read-only", channel: "elevation",
      hostExecutionRequest: { reason: "save notes", elevation: { tier: "default", scope: [{ path: "notes.txt", access: "write" }] } },
    });
    expect(verdict.state).toBe("deny");
  });

  it("allows a proven local read in every non-read-only mode", async () => {
    const target = unit({ access: [{ kind: "read" }] });
    for (const mode of ["default", "auto-review", "full-access"] as const) {
      const verdict = await decide(target, { mode });
      expect(verdict.state).toBe("allow");
      expect(verdict.reason).toContain("mode:");
    }
  });

  it("allows a proven local write in default", async () => {
    const verdict = await decide(unit({ access: [{ kind: "write" }] }));
    expect(verdict).toEqual(
      expect.objectContaining({ state: "allow", reason: "mode:default:workspace-write-allow" }),
    );
  });

  it("denies a proven write in read-only", async () => {
    const verdict = await decide(unit({ access: [{ kind: "write" }] }), { mode: "read-only" });
    expect(verdict.state).toBe("deny");
    expect(verdict.reason).toBe("mode:read-only:write-forbidden");
  });

  it("denies network in read-only", async () => {
    const verdict = await decide(unit({ access: [{ kind: "network" }] }), { mode: "read-only" });
    expect(verdict.reason).toBe("mode:read-only:network-forbidden");
  });

  it("asks for unknown effects in every mode except full-access", async () => {
    for (const mode of ["default", "auto-review", "read-only"] as const) {
      const verdict = await decide(unit({ access: [] }), { mode });
      expect(verdict.state).toBe("ask");
      expect(verdict.askFor).toBeUndefined();
    }
    expect((await decide(unit({ access: [] }), { mode: "full-access" })).state).toBe("allow");
  });

  it("escalates an external write in default", async () => {
    const verdict = await decide(unit({ access: [{ kind: "write", external: true }] }));
    expect(verdict.state).toBe("ask");
    expect(verdict.askFor).toBe("escalate");
  });

  it("escalates an external delete in auto-review", async () => {
    const verdict = await decide(unit({ access: [{ kind: "write", externalDelete: true }] }), {
      mode: "auto-review",
    });
    expect(verdict.askFor).toBe("escalate");
  });

  it("asks (not escalates) for network in default", async () => {
    const verdict = await decide(unit({ access: [{ kind: "network" }] }));
    expect(verdict.state).toBe("ask");
    expect(verdict.askFor).toBeUndefined();
  });

  it("asks for a review-marked destructive shape", async () => {
    const verdict = await decide(unit({
      access: [{ kind: "write" }, { kind: "unknown" }, { kind: "review" }],
    }));
    expect(verdict.state).toBe("ask");
    expect(verdict.reason).toBe("mode:default:destructive-needs-approval");
  });

  it("asks for a Host request in read-only mode", async () => {
    const verdict = await decide(unit({ access: [{ kind: "write" }] }), {
      mode: "read-only",
      hostExecutionRequest: { reason: "bypass", elevation: { tier: "host", scope: [{ path: "/outside/target", access: "write" }] } },
    });
    expect(verdict.state).toBe("ask");
    expect(verdict.reason).toBe("mode:read-only:one-time-host-execution");
  });

  it("asks for a Host request outside read-only mode", async () => {
    const verdict = await decide(unit({ access: [{ kind: "write" }] }), {
      hostExecutionRequest: { reason: "bypass", elevation: { tier: "host", scope: [{ path: "/outside/target", access: "write" }] } },
    });
    expect(verdict.state).toBe("ask");
    expect(verdict.askFor).toBe("escalate");
    expect(verdict.reason).toBe("mode:default:one-time-host-execution");
  });

  it("keeps an explicit Host request reviewable in full-access mode", async () => {
    const verdict = await decide(unit({ access: [{ kind: "write" }] }), {
      mode: "full-access",
      hostExecutionRequest: { reason: "bypass", elevation: { tier: "host", scope: [{ path: "/outside/target", access: "write" }] } },
    });
    expect(verdict.state).toBe("ask");
    expect(verdict.reason).toBe("mode:full-access:one-time-host-execution");
  });

  it("keeps an unproven Host request reviewable instead of denying it", async () => {
    const verdict = await decide(unit({ access: [{ kind: "unknown" }] }), {
      hostExecutionRequest: { reason: "run an unparseable command", elevation: { tier: "host", scope: [] } },
    });
    expect(verdict.state).toBe("ask");
    expect(verdict.askFor).toBe("escalate");
    expect(verdict.reason).toBe("mode:default:one-time-host-execution");
  });

  it("still denies an unproven Default request that widens the sandbox", async () => {
    const verdict = await decide(unit({ access: [{ kind: "unknown" }] }), {
      hostExecutionRequest: { reason: "bypass", elevation: { tier: "default", scope: [] } },
    });
    expect(verdict.state).toBe("deny");
    expect(verdict.reason).toBe("mode:elevation:effects-unproven-or-unsafe");
  });
});

describe("explicit-rules", () => {
  it("denies on a matching deny rule", async () => {
    const verdict = await decide(unit({
      rule: { decision: "deny", pattern: "git push*", origin: "global" },
    }));
    expect(verdict.state).toBe("deny");
    expect(verdict.reason).toBe("rules:global:deny:git push*");
  });

  it("asks on a matching ask rule", async () => {
    const verdict = await decide(unit({
      rule: { decision: "ask", pattern: "npm publish*", origin: "project" },
    }));
    expect(verdict.state).toBe("ask");
    expect(verdict.reason).toBe("rules:project:ask:npm publish*");
  });

  it("grants on a matching allow rule", async () => {
    const verdict = await decide(unit({
      access: [{ kind: "unknown" }],
      rule: { decision: "allow", pattern: "npm run build*", origin: "global" },
    }));
    expect(verdict.state).toBe("allow");
    expect(verdict.reason).toBe("rules:global:allow:npm run build*");
  });

  it("cannot lift an escalation ask with an allow rule", async () => {
    const verdict = await decide(unit({
      access: [{ kind: "write" }],
      rule: { decision: "allow", pattern: "*", origin: "global" },
    }), {
      hostExecutionRequest: { reason: "bypass", elevation: { tier: "host", scope: [{ path: "/outside/target", access: "write" }] } },
    });
    expect(verdict.state).toBe("ask");
    expect(verdict.askFor).toBe("escalate");
  });
});

describe("danger-intent", () => {
  const hit = (action: "deny" | "ask", kind = "catastrophic-delete") => ({
    kind: kind as "catastrophic-delete",
    action,
    reason: `risk:${kind}:root`,
    unitIds: ["call-1:u0"],
  });

  it("denies in full-access", async () => {
    const verdict = await decide(unit({ dangers: [hit("deny")] }), { mode: "full-access" });
    expect(verdict.state).toBe("deny");
    expect(verdict.reason).toContain("risk:catastrophic-delete:blocked:root");
    expect(verdict.reason).not.toContain("request_tool_elevation");
  });

  it("short-circuits before a later allow", async () => {
    const late = { mustNotRun: false };
    const handlers = [
      ...createDefaultChainHandlers(),
      {
        id: "user/allow-all",
        priority: 200,
        kind: "grant" as const,
        evaluate: () => {
          late.mustNotRun = true;
          return { action: "allow" as const };
        },
      },
    ];
    const verdict = await decide(unit({ dangers: [hit("deny")] }), { mode: "full-access", handlers });
    expect(verdict.state).toBe("deny");
    expect(late.mustNotRun).toBe(false);
  });

  it("preserves a risk deny on the elevation channel", async () => {
    const verdict = await decide(unit({ dangers: [hit("deny")] }), { channel: "elevation" });
    expect(verdict.state).toBe("deny");
    expect(verdict.reason).toBe("risk:catastrophic-delete:blocked:root");
  });

  it("escalates a danger the table classifies as ask", async () => {
    const verdict = await decide(unit({ dangers: [hit("ask", "workspace-bulk-delete")] }));
    expect(verdict.state).toBe("ask");
    expect(verdict.askFor).toBe("escalate");
  });
});

describe("sensitive-paths", () => {
  it("denies a write to a protected target", async () => {
    const verdict = await decide(unit({
      access: [{ kind: "write" }],
      sensitive: [{ path: "/ws/.env", category: "dotenv", surface: "write" }],
    }), { mode: "full-access" });
    expect(verdict.state).toBe("deny");
    expect(verdict.reason).toBe("sensitive:dotenv:write:/ws/.env");
  });

  it("denies an upload from a protected target", async () => {
    const verdict = await decide(unit({
      access: [{ kind: "read" }],
      sensitive: [{ path: "/home/me/.ssh/id_rsa", category: "ssh", surface: "upload" }],
    }));
    expect(verdict.state).toBe("deny");
  });

  it("only asks for a read of a protected target", async () => {
    const verdict = await decide(unit({
      access: [{ kind: "read" }],
      sensitive: [{ path: "/ws/.env", category: "dotenv", surface: "read" }],
    }));
    expect(verdict.state).toBe("ask");
    expect(verdict.askFor).toBeUndefined();
  });
});

describe("fallback", () => {
  it("turns no opinion into an ordinary ask", async () => {
    const verdict = await decide(unit({ access: [{ kind: "unknown" }] }), { mode: "read-only" });
    expect(verdict.state).toBe("ask");
    expect(verdict.askFor).toBeUndefined();
  });

  it("asks when no link had an opinion", async () => {
    const handlers = createDefaultChainHandlers();
    const verdict = await decide(unit(), { handlers: [handlers[handlers.length - 1]] });
    expect(verdict.state).toBe("ask");
    expect(verdict.reason).toBe("fallback:no-handler");
    expect(verdict.askFor).toBeUndefined();
  });

  it("leaves an empty chain with no opinion", async () => {
    const verdict = await decide(unit(), { handlers: [] });
    expect(verdict).toEqual(NO_VERDICT);
  });
});

describe("chain order", () => {
  it("runs mode-base first and fallback last", () => {
    const ids = createDefaultChainHandlers().map((handler) => handler.id);
    expect(ids[0]).toBe("builtin/mode-base");
    expect(ids[ids.length - 1]).toBe("builtin/fallback");
  });

  it("keeps the documented priorities", () => {
    const priorities = Object.fromEntries(
      createDefaultChainHandlers().map((handler) => [handler.id, handler.priority]),
    );
    expect(priorities).toEqual({
      "builtin/mode-base": 0,
      "builtin/explicit-rules-restrict": 20,
      "builtin/explicit-rules-grant": 21,
      "builtin/danger-intent": 30,
      "builtin/sensitive-paths": 40,
      "builtin/fallback": 1000,
    });
  });
});

describe("pre-composed accumulated verdicts", () => {
  it("respects a deny already reached before the chain runs", async () => {
    const denied = denyVerdict("earlier", "earlier");
    const verdict = await decide(unit({ access: [{ kind: "read" }] }), {
      accumulated: denied,
      handlers: createDefaultChainHandlers(),
    });
    // The chain never revives a deny; base's allow cannot lift it either.
    expect(verdict.state).toBe("deny");
  });

  it("respects an escalation ask already reached before the chain runs", async () => {
    const ask = askVerdict("earlier", "earlier", { askFor: "escalate" });
    const verdict = await decide(unit({
      rule: { decision: "allow", pattern: "*", origin: "global" },
    }), { accumulated: ask });
    // The reason may be refined by a later ask, but the ask stays escalated.
    expect(verdict.state).toBe("ask");
    expect(verdict.askFor).toBe("escalate");
    expect(verdict.locked).toBe(true);
  });
});
