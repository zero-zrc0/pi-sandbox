/**
 * Decision-table scenarios for the approval responsibility chain
 * (docs/approval-chain-v4-responsibility-chain.md).
 *
 * `verdict.test.ts` pins the composition algebra, `run.test.ts` the runner and
 * `handlers.test.ts` one link at a time. This file sits above them: every case
 * hands frozen call facts to `decideCall` with the real built-in chain and
 * asserts the verdict the host would act on, so the documented examples (§5),
 * the mode baselines (§2), the danger/elevation route (§3), the resolver
 * boundary (§2.1) and the P2 user-handler contract are exercised through the
 * public entry point only.
 *
 * Reasons are asserted by their machine-readable prefix (`mode:` / `rules:` /
 * `risk:` / `sensitive:` / `fallback:` / `chain:`), because the audit trail and
 * the resolver read that namespace, not prose. A user handler owns its own
 * reason namespace, so cases that end in a user-controlled verdict assert the
 * built-in step that stated the opinion instead.
 */
import { describe, expect, it, vi } from "vitest";
import type {
  ChainCallFacts,
  ChainChannel,
  ChainUnitFacts,
  SensitiveRef,
  UnitRuleFact,
} from "#approve-core/chain/facts";
import { decideCall, type DecideResult } from "#approve-core/chain/decide";
import { createDefaultChainHandlers } from "#approve-core/chain/defaults";
import type { Handler } from "#approve-core/chain/run";
import { isResolverEligible, NO_VERDICT, type PermissionMode } from "#approve-core/chain/verdict";
import type { DangerHit } from "#approve-core/risk/danger";

const CALL_ID = "call-1";

/** One unit's frozen facts; `access: []` means "nothing proven", not "read". */
function unit(overrides: Partial<ChainUnitFacts> = {}): ChainUnitFacts {
  return { unitId: `${CALL_ID}:u0`, toolName: "bash", access: [], ...overrides };
}

function call(
  units: readonly ChainUnitFacts[],
  hostExecutionReason?: string,
): ChainCallFacts {
  return {
    toolCallId: CALL_ID,
    toolName: "bash",
    units,
    ...(hostExecutionReason === undefined
      ? {}
      : { hostExecutionRequest: {
        reason: hostExecutionReason,
        elevation: { tier: "host", scope: [{ path: "/outside/target", access: "write" }] },
      } }),
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

/** A danger hit in the shape `risk/danger.ts` reports it. */
function danger(
  kind: DangerHit["kind"],
  action: DangerHit["action"],
  detail: string,
  unitIds: readonly string[] = [`${CALL_ID}:u0`],
): DangerHit {
  return { kind, action, reason: `risk:${kind}:${detail}`, unitIds };
}

function rule(
  decision: UnitRuleFact["decision"],
  pattern: string,
  origin: UnitRuleFact["origin"] = "global",
): UnitRuleFact {
  return { decision, pattern, origin };
}

function sensitive(
  path: string,
  category: string,
  surface: SensitiveRef["surface"],
): SensitiveRef {
  return { path, category, surface };
}

interface DecideOverrides {
  readonly mode?: PermissionMode;
  readonly channel?: ChainChannel;
  /** Set to run the call as a one-time host execution request. */
  readonly hostExecution?: string;
  readonly handlers?: readonly Handler[];
}

/** The host entry point under test: real chain, frozen facts, one verdict. */
async function decide(
  units: readonly ChainUnitFacts[],
  overrides: DecideOverrides = {},
): Promise<DecideResult> {
  return decideCall(call(units, overrides.hostExecution), {
    mode: overrides.mode ?? "default",
    ...(overrides.channel === undefined ? {} : { channel: overrides.channel }),
    handlers: overrides.handlers ?? createDefaultChainHandlers(),
  });
}

function decideUnit(
  target: ChainUnitFacts,
  overrides: DecideOverrides = {},
): Promise<DecideResult> {
  return decide([target], overrides);
}

const defaultStepIds = [
  "builtin/mode-base",
  "builtin/explicit-rules-restrict",
  "builtin/explicit-rules-grant",
  "builtin/danger-intent",
  "builtin/sensitive-paths",
  "builtin/fallback",
] as const;

describe("v4 §5.1 — full-access `tar ... && curl ...` exfiltration", () => {
  const sharedUnitIds = [`${CALL_ID}:u0`, `${CALL_ID}:u1`];
  const tarUnit = unit({
    unitId: `${CALL_ID}:u0`,
    access: [{ kind: "write", path: "/tmp/src.tgz" }],
    dangers: [danger("exfiltration", "deny", "archive-upload", sharedUnitIds)],
  });
  const curlUnit = unit({
    unitId: `${CALL_ID}:u1`,
    access: [{ kind: "network" }],
    dangers: [danger("exfiltration", "deny", "archive-upload", sharedUnitIds)],
  });

  it("denies the call immediately without offering elevation", async () => {
    const result = await decide([tarUnit, curlUnit], { mode: "full-access" });

    expect(result.fault).toBeUndefined();
    expect(result.verdict.state).toBe("deny");
    expect(result.verdict.reason).toBe(
      "risk:exfiltration:blocked:archive-upload",
    );
    expect(result.verdict.reason).toMatch(/^risk:/);
    expect(result.verdict.reason).not.toContain("request_tool_elevation");
    expect(result.verdict.locked).toBe(false);
    expect(isResolverEligible(result.verdict)).toBe(false);
    // Both halves are denied, and full-access never widened either link.
    expect(result.units.map((entry) => entry.verdict.state)).toEqual(["deny", "deny"]);
    expect(result.units[0].verdict.source).toBe("builtin/danger-intent");
    // mode-base allow → rules pass ×2 → danger deny; nothing after danger ran.
    expect(result.units[0].steps.map((step) => step.handlerId)).toEqual([
      ...defaultStepIds.slice(0, 4),
    ]);
  });

  it("preserves an exfiltration deny on the elevation channel", async () => {
    const result = await decide([tarUnit, curlUnit], { mode: "full-access", channel: "elevation" });
    expect(result.verdict.state).toBe("deny");
    expect(result.verdict.reason).toBe("risk:exfiltration:blocked:archive-upload");
    expect(result.units.map(entry => entry.verdict.state)).toEqual(["deny", "deny"]);
  });
});

describe("v4 §5.2 — full-access `rm -rf build` (workspace bulk delete)", () => {
  function bulkDelete(action: DangerHit["action"]): ChainUnitFacts {
    return unit({
      access: [{ kind: "write", path: "build" }],
      dangers: [danger("workspace-bulk-delete", action, "recursive-delete")],
    });
  }

  it("denies the call when the policy says deny (2026-11-10 decision)", async () => {
    const result = await decideUnit(bulkDelete("deny"), { mode: "full-access" });

    expect(result.verdict.state).toBe("deny");
    expect(result.verdict.reason).toBe(
      "risk:workspace-bulk-delete:blocked:recursive-delete",
    );
    expect(result.verdict.reason).toMatch(/^risk:/);
    expect(result.verdict.reason).not.toContain("request_tool_elevation");
    expect(result.units[0].steps.at(-1)?.handlerId).toBe("builtin/danger-intent");
  });

  it("asks for review when the same hit is configured as ask", async () => {
    const result = await decideUnit(bulkDelete("ask"), { mode: "full-access" });

    expect(result.verdict.state).toBe("ask");
    expect(result.verdict.askFor).toBe("escalate");
    expect(result.verdict.locked).toBe(true);
    expect(isResolverEligible(result.verdict)).toBe(true);
    expect(result.verdict.reason).toBe(
      "risk:workspace-bulk-delete:needs-confirmation:recursive-delete",
    );
    expect(result.verdict.source).toBe("builtin/danger-intent");
  });

  it("keeps that escalation ask through a later user grant", async () => {
    const allowAll = handler("user/allow-all", 200, "grant", () => ({
      action: "allow",
      reason: "user:allow-all",
    }));
    const result = await decideUnit(bulkDelete("ask"), {
      mode: "full-access",
      handlers: [...createDefaultChainHandlers(), allowAll],
    });

    expect(result.verdict.state).toBe("ask");
    expect(result.verdict.askFor).toBe("escalate");
    expect(result.verdict.locked).toBe(true);
    expect(result.verdict.reason).toBe(
      "risk:workspace-bulk-delete:needs-confirmation:recursive-delete",
    );
    // The grant did state its allow; the algebra refused to lift the ask.
    expect(
      result.units[0].steps.find((step) => step.handlerId === "user/allow-all")?.result,
    ).toEqual({ action: "allow", reason: "user:allow-all" });
  });

  it("cannot be widened by an allow rule even in full-access", async () => {
    const target = unit({
      access: [{ kind: "read" }],
      rule: rule("allow", "*"),
      dangers: [danger("exfiltration", "deny", "archive-upload")],
    });
    const result = await decideUnit(target, { mode: "full-access" });

    expect(result.verdict.state).toBe("deny");
    expect(result.verdict.reason).toMatch(/^risk:exfiltration:blocked:archive-upload/);
    // full-access + the allow rule are both opinions; the deny is a decision.
    expect(result.units[0].steps.map((step) => step.handlerId)).toEqual([
      ...defaultStepIds.slice(0, 4),
    ]);
  });
});

describe("v4 §5.3 — default-mode `ls`", () => {
  it("allows a proven local read without prompting", async () => {
    const result = await decideUnit(unit({ access: [{ kind: "read", path: "." }] }));

    expect(result.verdict.state).toBe("allow");
    expect(result.verdict.reason).toBe("mode:default:workspace-read-allow");
    expect(result.verdict.reason).toMatch(/^mode:/);
    expect(result.verdict.source).toBe("builtin/mode-base");
    expect(isResolverEligible(result.verdict)).toBe(false);
    // Every later link passes; the fallback has nothing to turn into an ask.
    expect(result.units[0].steps.map((step) => step.handlerId)).toEqual([
      ...defaultStepIds,
    ]);
  });
});

describe("explicit rules end to end", () => {
  const pushRule = rule("ask", "git push*");

  it("tightens the base allow into an ordinary ask", async () => {
    const result = await decideUnit(unit({ access: [{ kind: "read" }], rule: pushRule }));

    expect(result.verdict.state).toBe("ask");
    expect(result.verdict.reason).toBe("rules:global:ask:git push*");
    expect(result.verdict.reason).toMatch(/^rules:/);
    expect(result.verdict.source).toBe("builtin/explicit-rules-restrict");
    expect(result.verdict.askFor).toBeUndefined();
    expect(result.verdict.locked).toBe(false);
    expect(isResolverEligible(result.verdict)).toBe(true);
  });

  it("keeps an explicit ask when a later user grant allows", async () => {
    const grantPush = handler("user/grant-git-push", 200, "grant", (context) =>
      context.unit.rule?.decision === "ask"
        ? { action: "allow", reason: "user:grant-git-push" }
        : { action: "pass" },
    );
    const result = await decideUnit(unit({ access: [{ kind: "read" }], rule: pushRule }), {
      handlers: [...createDefaultChainHandlers(), grantPush],
    });

    expect(result.verdict.state).toBe("ask");
    expect(result.verdict.source).toBe("builtin/explicit-rules-restrict");
    expect(isResolverEligible(result.verdict)).toBe(true);
    // The user grant is an opinion, not a review approval.
    expect(
      result.units[0].steps.find(
        (step) => step.handlerId === "builtin/explicit-rules-restrict",
      )?.result,
    ).toEqual({ action: "ask", reason: "rules:global:ask:git push*" });
    expect(
      result.units[0].steps.find((step) => step.handlerId === "user/grant-git-push")
        ?.result,
    ).toEqual({ action: "allow", reason: "user:grant-git-push" });
  });

  it("deny short-circuits before a later user grant can run", async () => {
    const lateGrant = vi.fn(() => ({ action: "allow" as const, reason: "user:late" }));
    const result = await decideUnit(
      unit({ access: [{ kind: "read" }], rule: rule("deny", "git push*") }),
      {
        handlers: [
          ...createDefaultChainHandlers(),
          handler("user/late-grant", 200, "grant", lateGrant),
        ],
      },
    );

    expect(result.verdict.state).toBe("deny");
    expect(result.verdict.reason).toBe("rules:global:deny:git push*");
    expect(result.verdict.reason).toMatch(/^rules:/);
    expect(result.verdict.source).toBe("builtin/explicit-rules-restrict");
    expect(lateGrant).not.toHaveBeenCalled();
    expect(result.units[0].steps.map((step) => step.handlerId)).toEqual([
      "builtin/mode-base",
      "builtin/explicit-rules-restrict",
    ]);
  });

  it("keeps an explicit deny on the elevation channel", async () => {
    const result = await decideUnit(
      unit({ access: [{ kind: "write" }], rule: rule("deny", "git push*") }),
      { mode: "full-access", channel: "elevation" },
    );

    expect(result.verdict.state).toBe("deny");
    expect(result.verdict.reason).toBe("rules:global:deny:git push*");
    expect(result.verdict.askFor).toBeUndefined();
  });

  it("resolves an unknown unit with an explicit allow", async () => {
    const result = await decideUnit(
      unit({ access: [], rule: rule("allow", "npm run build*") }),
    );

    expect(result.verdict.state).toBe("allow");
    expect(result.verdict.reason).toBe("rules:global:allow:npm run build*");
    expect(result.verdict.reason).toMatch(/^rules:/);
    expect(result.verdict.source).toBe("builtin/explicit-rules-grant");
    // The mode recorded unknown; the explicit allow resolves that unknown.
    expect(result.units[0].steps[0].result).toEqual({
      action: "unknown",
      reason: "mode:default:effect-unproven",
    });
    expect(result.units[0].steps.at(-1)?.handlerId).toBe("builtin/fallback");
    expect(result.units[0].steps.at(-1)?.result).toEqual({ action: "pass" });
  });

  it("cannot lift an escalation ask raised by the mode baseline", async () => {
    const target = unit({ access: [{ kind: "write", external: true }], rule: rule("allow", "*") });
    const result = await decideUnit(target);

    expect(result.verdict.state).toBe("ask");
    expect(result.verdict.askFor).toBe("escalate");
    expect(result.verdict.locked).toBe(true);
    expect(isResolverEligible(result.verdict)).toBe(true);
    expect(result.verdict.reason).toBe("mode:default:external-write-needs-approval");
    // The grant stated its allow, but the escalation ask stayed in place.
    expect(
      result.units[0].steps.find(
        (step) => step.handlerId === "builtin/explicit-rules-grant",
      )?.result,
    ).toEqual({ action: "allow", reason: "rules:global:allow:*" });
  });
});

describe("sensitive paths end to end", () => {
  const dotenv = "/ws/.env";

  it("denies a write to .env", async () => {
    const result = await decideUnit(
      unit({
        access: [{ kind: "write", path: dotenv }],
        sensitive: [sensitive(dotenv, "dotenv", "write")],
      }),
    );

    expect(result.verdict.state).toBe("deny");
    expect(result.verdict.reason).toBe(`sensitive:dotenv:write:${dotenv}`);
    expect(result.verdict.reason).toMatch(/^sensitive:/);
    expect(result.verdict.source).toBe("builtin/sensitive-paths");
    expect(result.units[0].steps.map((step) => step.handlerId)).toEqual([
      ...defaultStepIds.slice(0, 5),
    ]);
  });

  it("denies a delete of .env", async () => {
    const result = await decideUnit(
      unit({
        access: [{ kind: "write", path: dotenv }],
        sensitive: [sensitive(dotenv, "dotenv", "delete")],
      }),
    );

    expect(result.verdict.state).toBe("deny");
    expect(result.verdict.reason).toBe(`sensitive:dotenv:delete:${dotenv}`);
  });

  it("denies an upload of .env (upload is a write, not a read)", async () => {
    const result = await decideUnit(
      unit({
        access: [{ kind: "read", path: dotenv }],
        sensitive: [sensitive(dotenv, "dotenv", "upload")],
      }),
    );

    expect(result.verdict.state).toBe("deny");
    expect(result.verdict.reason).toBe(`sensitive:dotenv:upload:${dotenv}`);
    expect(result.verdict.reason).toMatch(/^sensitive:/);
  });

  it("only asks for a read of .env, and the resolver may approve it", async () => {
    const result = await decideUnit(
      unit({
        access: [{ kind: "read", path: dotenv }],
        sensitive: [sensitive(dotenv, "dotenv", "read")],
      }),
    );

    expect(result.verdict.state).toBe("ask");
    expect(result.verdict.askFor).toBeUndefined();
    expect(result.verdict.locked).toBe(false);
    expect(isResolverEligible(result.verdict)).toBe(true);
    expect(result.verdict.reason).toBe(`sensitive:dotenv:read:${dotenv}`);
    expect(result.verdict.source).toBe("builtin/sensitive-paths");
  });

  it("keeps the deny ahead of an explicit allow rule", async () => {
    const result = await decideUnit(
      unit({
        access: [{ kind: "write", path: dotenv }],
        rule: rule("allow", "*"),
        sensitive: [sensitive(dotenv, "dotenv", "write")],
      }),
    );

    expect(result.verdict.state).toBe("deny");
    expect(result.verdict.reason).toBe(`sensitive:dotenv:write:${dotenv}`);
  });
});

describe("read-only mode decision table", () => {
  it("denies a proven write", async () => {
    const result = await decideUnit(unit({ access: [{ kind: "write" }] }), {
      mode: "read-only",
    });

    expect(result.verdict.state).toBe("deny");
    expect(result.verdict.reason).toBe("mode:read-only:write-forbidden");
    expect(result.verdict.reason).toMatch(/^mode:/);
    expect(result.units[0].steps.map((step) => step.handlerId)).toEqual([
      "builtin/mode-base",
    ]);
  });

  it("denies network access", async () => {
    const result = await decideUnit(unit({ access: [{ kind: "network" }] }), {
      mode: "read-only",
    });

    expect(result.verdict.state).toBe("deny");
    expect(result.verdict.reason).toBe("mode:read-only:network-forbidden");
  });

  it("asks when the effect cannot be proven", async () => {
    const result = await decideUnit(unit({ access: [] }), { mode: "read-only" });

    expect(result.verdict.state).toBe("ask");
    expect(result.verdict.reason).toBe("mode:read-only:effect-unproven");
    expect(result.verdict.askFor).toBeUndefined();
    expect(isResolverEligible(result.verdict)).toBe(true);
  });

  it("allows a proven workspace read", async () => {
    const result = await decideUnit(unit({ access: [{ kind: "read", path: "." }] }), {
      mode: "read-only",
    });

    expect(result.verdict.state).toBe("allow");
    expect(result.verdict.reason).toBe("mode:read-only:workspace-read-allow");
    expect(isResolverEligible(result.verdict)).toBe(false);
  });

  it("does not treat an external read as a workspace read", async () => {
    const result = await decideUnit(
      unit({ access: [{ kind: "read", path: "C:\\Windows\\win.ini", external: true }] }),
      { mode: "read-only" },
    );

    expect(result.verdict.state).toBe("ask");
    expect(result.verdict.reason).toBe("mode:read-only:effect-unproven");
  });
});

describe("default mode decision table", () => {
  it("allows a local write", async () => {
    const result = await decideUnit(unit({ access: [{ kind: "write", path: "src/a.ts" }] }));

    expect(result.verdict.state).toBe("allow");
    expect(result.verdict.reason).toBe("mode:default:workspace-write-allow");
    expect(result.verdict.reason).toMatch(/^mode:/);
    expect(isResolverEligible(result.verdict)).toBe(false);
  });

  it("escalates an external write", async () => {
    const result = await decideUnit(
      unit({ access: [{ kind: "write", path: "C:\\temp\\a.txt", external: true }] }),
    );

    expect(result.verdict.state).toBe("ask");
    expect(result.verdict.askFor).toBe("escalate");
    expect(result.verdict.locked).toBe(true);
    expect(isResolverEligible(result.verdict)).toBe(true);
    expect(result.verdict.reason).toBe("mode:default:external-write-needs-approval");
  });

  it("escalates an external delete", async () => {
    const result = await decideUnit(unit({ access: [{ kind: "write", externalDelete: true }] }));

    expect(result.verdict.state).toBe("ask");
    expect(result.verdict.askFor).toBe("escalate");
    expect(result.verdict.reason).toBe("mode:default:external-delete-needs-approval");
  });

  it("asks (without escalation) for network access", async () => {
    const result = await decideUnit(unit({ access: [{ kind: "network" }] }));

    expect(result.verdict.state).toBe("ask");
    expect(result.verdict.askFor).toBeUndefined();
    expect(result.verdict.locked).toBe(false);
    expect(isResolverEligible(result.verdict)).toBe(true);
    expect(result.verdict.reason).toBe("mode:default:network-needs-approval");
  });

  it("asks an ordinary ask when no access fact exists", async () => {
    const result = await decideUnit(unit({ access: [] }));

    expect(result.verdict.state).toBe("ask");
    expect(result.verdict.askFor).toBeUndefined();
    expect(isResolverEligible(result.verdict)).toBe(true);
    expect(result.verdict.reason).toBe("mode:default:effect-unproven");
  });

  it("asks for a review-marked destructive shape that is not a danger hit", async () => {
    const result = await decideUnit(unit({ access: [{ kind: "review" }] }));

    expect(result.verdict.state).toBe("ask");
    expect(result.verdict.reason).toBe("mode:default:destructive-needs-approval");
    expect(result.verdict.askFor).toBeUndefined();
    expect(isResolverEligible(result.verdict)).toBe(true);
  });
});

describe("one-time host execution request", () => {
  it("escalates to a human in default mode", async () => {
    const result = await decideUnit(unit({ access: [] }), {
      hostExecution: "request_sandbox_bypass",
    });

    expect(result.verdict.state).toBe("ask");
    expect(result.verdict.askFor).toBe("escalate");
    expect(result.verdict.locked).toBe(true);
    expect(isResolverEligible(result.verdict)).toBe(true);
    expect(result.verdict.reason).toBe("mode:default:one-time-host-execution");
    expect(result.verdict.reason).toMatch(/^mode:/);
  });

  it("is denied in read-only mode", async () => {
    const result = await decideUnit(unit({ access: [{ kind: "write" }] }), {
      mode: "read-only",
      hostExecution: "request_sandbox_bypass",
    });

    expect(result.verdict.state).toBe("deny");
    expect(result.verdict.reason).toBe("mode:read-only:host-execution-forbidden");
    expect(result.units[0].steps.map((step) => step.handlerId)).toEqual([
      "builtin/mode-base",
    ]);
  });

  it("is allowed in full-access mode", async () => {
    const result = await decideUnit(unit({ access: [] }), {
      mode: "full-access",
      hostExecution: "request_sandbox_bypass",
    });

    expect(result.verdict.state).toBe("allow");
    expect(result.verdict.reason).toBe("mode:full-access:host-execution-allow");
    expect(isResolverEligible(result.verdict)).toBe(false);
  });

  it("cannot be upgraded by an explicit allow rule", async () => {
    const result = await decideUnit(
      unit({ access: [], rule: rule("allow", "*") }),
      { hostExecution: "request_sandbox_bypass" },
    );

    expect(result.verdict.state).toBe("ask");
    expect(result.verdict.askFor).toBe("escalate");
    expect(result.verdict.locked).toBe(true);
    expect(result.verdict.reason).toBe("mode:default:one-time-host-execution");
  });
});

describe("elevation channel (request_tool_elevation)", () => {
  const bulk = unit({
    access: [{ kind: "write", path: "build" }],
    dangers: [danger("workspace-bulk-delete", "deny", "recursive-delete")],
  });

  it("keeps a danger deny terminal on the elevation channel", async () => {
    const result = await decideUnit(bulk, { channel: "elevation" });

    expect(result.verdict.state).toBe("deny");
    expect(result.verdict.askFor).toBeUndefined();
    expect(result.verdict.locked).toBe(false);
    expect(isResolverEligible(result.verdict)).toBe(false);
    expect(result.verdict.reason).toBe(
      "risk:workspace-bulk-delete:blocked:recursive-delete",
    );
    expect(result.verdict.reason).toMatch(/^risk:/);
    expect(result.verdict.source).toBe("builtin/danger-intent");
  });

  it("does not let a user grant lift a danger deny", async () => {
    const allowAll = handler("user/allow-all", 200, "grant", () => ({
      action: "allow",
      reason: "user:allow-all",
    }));
    const result = await decideUnit(bulk, {
      channel: "elevation",
      handlers: [...createDefaultChainHandlers(), allowAll],
    });

    expect(result.verdict.state).toBe("deny");
    expect(result.verdict.askFor).toBeUndefined();
    expect(result.verdict.locked).toBe(false);
    expect(result.verdict.reason).toBe(
      "risk:workspace-bulk-delete:blocked:recursive-delete",
    );
  });

  it("keeps the ordinary mode baseline when no danger is proven", async () => {
    const result = await decideUnit(unit({ access: [{ kind: "read" }] }), {
      channel: "elevation",
    });

    expect(result.verdict.state).toBe("allow");
    expect(result.verdict.reason).toBe("mode:default:workspace-read-allow");
  });
});

describe("no opinion and the fallback link", () => {
  it("yields none for an empty chain", async () => {
    const result = await decideUnit(unit(), {
      mode: "read-only",
      handlers: [],
    });

    expect(result.ordering).toBeUndefined();
    expect(result.fault).toBeUndefined();
    expect(result.verdict).toEqual(NO_VERDICT);
    expect(result.units).toHaveLength(1);
    expect(result.units[0].verdict).toEqual(NO_VERDICT);
    expect(result.units[0].steps).toEqual([]);
  });

  it("turns the same unit into an ordinary ask with the default chain", async () => {
    // mode-base always states an opinion (here: "effect unproven"), so the
    // fallback has nothing left to say; the ask is still an ordinary one.
    const result = await decideUnit(unit(), { mode: "read-only" });

    expect(result.verdict.state).toBe("ask");
    expect(result.verdict.askFor).toBeUndefined();
    expect(result.verdict.locked).toBe(false);
    expect(isResolverEligible(result.verdict)).toBe(true);
    expect(result.verdict.reason).toBe("mode:read-only:effect-unproven");
    expect(result.verdict.reason).not.toMatch(/^fallback:/);
  });

  it("asks fallback:no-handler when the fallback is the only link", async () => {
    const onlyFallback = createDefaultChainHandlers().filter(
      (entry) => entry.id === "builtin/fallback",
    );
    const result = await decideUnit(unit({ access: [{ kind: "read" }] }), {
      handlers: onlyFallback,
    });

    expect(result.verdict.state).toBe("ask");
    expect(result.verdict.askFor).toBeUndefined();
    expect(result.verdict.reason).toBe("fallback:no-handler");
    expect(result.verdict.reason).toMatch(/^fallback:/);
    expect(result.verdict.source).toBe("builtin/fallback");
    expect(isResolverEligible(result.verdict)).toBe(true);
  });
});

describe("multi-unit calls", () => {
  it("combines an allow and an ask into a call-level ask", async () => {
    const result = await decide([
      unit({ unitId: `${CALL_ID}:u0`, access: [{ kind: "read" }] }),
      unit({ unitId: `${CALL_ID}:u1`, access: [{ kind: "network" }] }),
    ]);

    expect(result.verdict.state).toBe("ask");
    expect(result.verdict.reason).toBe("mode:default:network-needs-approval");
    expect(result.verdict.askFor).toBeUndefined();
    expect(isResolverEligible(result.verdict)).toBe(true);
    expect(result.units.map((entry) => entry.verdict.state)).toEqual(["allow", "ask"]);
    expect(result.units[0].verdict.reason).toBe("mode:default:workspace-read-allow");
    expect(result.units[1].verdict.reason).toBe("mode:default:network-needs-approval");
  });

  it("combines a deny and an allow into a call-level deny", async () => {
    const result = await decide(
      [
        unit({
          unitId: `${CALL_ID}:u0`,
          access: [{ kind: "read" }],
          dangers: [danger("workspace-bulk-delete", "deny", "recursive-delete")],
        }),
        unit({ unitId: `${CALL_ID}:u1`, access: [{ kind: "read" }] }),
      ],
      { mode: "full-access" },
    );

    expect(result.verdict.state).toBe("deny");
    expect(result.verdict.reason).toMatch(/^risk:workspace-bulk-delete:blocked:recursive-delete/);
    expect(result.units.map((entry) => entry.verdict.state)).toEqual(["deny", "allow"]);
    // The denied unit stopped at danger-intent; the allowed unit ran to the end.
    expect(result.units[0].steps.at(-1)?.handlerId).toBe("builtin/danger-intent");
    expect(result.units[1].steps.at(-1)?.handlerId).toBe("builtin/fallback");
  });

  it("keeps the call escalated when one unit needs a human", async () => {
    const result = await decide([
      unit({ unitId: `${CALL_ID}:u0`, access: [{ kind: "network" }] }),
      unit({
        unitId: `${CALL_ID}:u1`,
        access: [{ kind: "write", path: "C:\\temp\\a.txt", external: true }],
      }),
    ]);

    expect(result.verdict.state).toBe("ask");
    expect(result.verdict.askFor).toBe("escalate");
    expect(result.verdict.locked).toBe(true);
    expect(isResolverEligible(result.verdict)).toBe(true);
    expect(result.verdict.reason).toBe("mode:default:external-write-needs-approval");
    expect(result.units.map((entry) => entry.verdict.askFor)).toEqual([
      undefined,
      "escalate",
    ]);
  });
});

describe("handler faults and the P2 user-handler contract", () => {
  it("reports a throwing handler as a fault and stops the chain", async () => {
    const lateGrant = vi.fn(() => ({ action: "allow" as const, reason: "user:late" }));
    const result = await decideUnit(unit({ access: [{ kind: "read" }] }), {
      handlers: [
        ...createDefaultChainHandlers(),
        handler("user/boom", 200, "restriction", () => {
          throw new Error("boom");
        }),
        handler("user/late-grant", 300, "grant", lateGrant),
      ],
    });

    expect(result.fault).toEqual({ handlerId: "user/boom", reason: "boom" });
    expect(result.verdict.state).toBe("ask");
    expect(result.verdict.askFor).toBe("escalate");
    expect(result.verdict.reason).toBe("chain:fault:user/boom:boom");
    expect(result.verdict.reason).toMatch(/^chain:/);
    expect(lateGrant).not.toHaveBeenCalled();
    // The fault happens after mode-base had already allowed the read.
    expect(result.units[0].verdict.state).toBe("allow");
    expect(result.units[0].steps.at(-1)?.handlerId).toBe("user/boom");
    expect(result.units[0].steps.at(-1)?.fault).toBe("boom");
  });

  it("fails closed when a user restriction tries to allow", async () => {
    const sneaky = handler("user/sneaky-allow", 200, "restriction", () => ({
      action: "allow",
      reason: "user:sneaky",
    }));
    const result = await decideUnit(unit({ access: [{ kind: "read" }] }), {
      handlers: [...createDefaultChainHandlers(), sneaky],
    });

    expect(result.fault).toEqual({
      handlerId: "user/sneaky-allow",
      reason: "restriction-cannot-allow",
    });
    expect(result.verdict.state).toBe("ask");
    expect(result.verdict.askFor).toBe("escalate");
    expect(result.verdict.locked).toBe(true);
    expect(result.verdict.reason).toBe(
      "chain:fault:user/sneaky-allow:restriction-cannot-allow",
    );
    expect(isResolverEligible(result.verdict)).toBe(true);
  });

  it("fails closed when a user grant tries to deny", async () => {
    const saboteur = handler("user/saboteur", 200, "grant", () => ({
      action: "deny",
      reason: "user:no",
    }));
    const result = await decideUnit(unit({ access: [{ kind: "read" }] }), {
      handlers: [...createDefaultChainHandlers(), saboteur],
    });

    expect(result.fault).toEqual({
      handlerId: "user/saboteur",
      reason: "grant-cannot-deny",
    });
    expect(result.verdict.reason).toBe("chain:fault:user/saboteur:grant-cannot-deny");
    expect(result.verdict.askFor).toBe("escalate");
  });

  it("fails closed when a user grant tries to ask", async () => {
    const hesitant = handler("user/hesitant", 200, "grant", () => ({
      action: "ask",
      reason: "user:maybe",
    }));
    const result = await decideUnit(unit({ access: [{ kind: "read" }] }), {
      handlers: [...createDefaultChainHandlers(), hesitant],
    });

    expect(result.fault).toEqual({
      handlerId: "user/hesitant",
      reason: "grant-cannot-ask",
    });
    expect(result.verdict.reason).toBe("chain:fault:user/hesitant:grant-cannot-ask");
  });

  it("rejects a user handler that reuses a built-in id", async () => {
    const collision = handler("builtin/fallback", 900, "restriction", () => ({
      action: "pass",
    }));
    const result = await decideUnit(unit({ access: [{ kind: "read" }] }), {
      handlers: [...createDefaultChainHandlers(), collision],
    });

    expect(result.ordering).toBe("duplicate-handler-id");
    expect(result.fault).toBeUndefined();
    expect(result.units).toEqual([]);
    expect(result.verdict.state).toBe("ask");
    expect(result.verdict.askFor).toBe("escalate");
    expect(result.verdict.reason).toBe(
      "chain:invalid-handlers:duplicate-handler-id",
    );
    expect(result.verdict.reason).toMatch(/^chain:/);
  });
});
