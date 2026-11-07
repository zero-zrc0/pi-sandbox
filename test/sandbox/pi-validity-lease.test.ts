import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  SESSION_ID,
  createInvalidationHarness,
  outcomeText,
  useInvalidationCleanup,
} from "./fixtures/invalidation-harness";
import {
  compileTestPlan,
  createTestLayout,
  fixtureEnvironment,
  makeController,
  makeInvocation,
  removeTestLayout,
  waitFor,
  type TestLayout,
} from "./fixtures/harness";
import type { ExecutionController } from "#sandbox/lifecycle";
import {
  createExecutionValidityGuard,
  type ExecutionValidityGuard,
} from "#sandbox/validity";

useInvalidationCleanup();

function planFor(workspace: string, requestId: string) {
  return compileTestPlan({
    invocation: makeInvocation({ cwd: workspace, requestId, toolCallId: requestId }),
    operation: { kind: "shell", command: "ignored" },
    workspace,
    deadlineMs: 10_000,
  });
}

interface Rig {
  readonly layout: TestLayout;
  readonly controller: ExecutionController;
  readonly records: { toolCallId: string; started: unknown; state: string }[];
  readonly marker: string;
}

function controllerRig(scenario: string, maxConcurrent = 1): Rig {
  const layout = createTestLayout("plan11-validity-rig");
  const marker = join(layout.root, "business-marker.txt");
  const records: Rig["records"] = [];
  const controller = makeController({
    layout,
    scenario,
    maxConcurrent,
    startTimeoutMs: 20_000,
    helperEnvironment: fixtureEnvironment(scenario, { FIXTURE_MARKER_FILE: marker }),
    onRecord: (record) => records.push(record),
  });
  return { layout, controller, records, marker };
}

async function teardown(rig: Rig): Promise<void> {
  await rig.controller.dispose();
  removeTestLayout(rig.layout);
}

describe("the validity lease reaches every wait the controller owns", () => {
  it("refuses a queued call before its helper exists, and records nothing", async () => {
    const rig = controllerRig("slow");
    try {
      const holder = rig.controller.execute({ plan: planFor(rig.layout.workspace, "holder") });
      const refused = rig.controller.execute({
        plan: planFor(rig.layout.workspace, "queued-refused"),
        validity: createExecutionValidityGuard(() => ({
          code: "plan-invalidated",
          reason: "the policy revision changed while queued",
        })),
      });
      await waitFor(() => rig.controller.activeCount === 1);
      expect(rig.controller.queuedCount).toBe(1);

      await rig.controller.cancel("holder");
      const outcome = await refused;
      await holder;

      expect(outcome.state).toBe("cancelled");
      if (outcome.state === "cancelled") {
        expect(outcome.code).toBe("plan-invalidated");
        expect(outcome.started).toBe(false);
      }
      // A helper that ever ran publishes exactly one record, so the absence of
      // a record for this plan is the evidence that no process was created.
      expect(rig.records.filter((r) => r.toolCallId === "queued-refused")).toHaveLength(0);
      expect(rig.controller.activeCount).toBe(0);
      expect(rig.controller.queuedCount).toBe(0);
    } finally {
      await teardown(rig);
    }
  }, 20_000);

  it("refuses during the handshake when the lease expires after the dequeue check", async () => {
    const rig = controllerRig("ok");
    try {
      let calls = 0;
      const outcome = await rig.controller.execute({
        plan: planFor(rig.layout.workspace, "handshake-refused"),
        // Valid when the task is dequeued, expired by the time ready arrives.
        validity: createExecutionValidityGuard(() => {
          calls += 1;
          return calls >= 2
            ? { code: "plan-invalidated", reason: "the approval expired before the start" }
            : null;
        }),
      });

      expect(calls).toBeGreaterThanOrEqual(2);
      expect(outcome.state).toBe("cancelled");
      if (outcome.state === "cancelled") {
        expect(outcome.code).toBe("plan-invalidated");
        expect(outcome.started).toBe(false);
      }
      // The marker is written only after the helper acknowledges a start.
      expect(existsSync(rig.marker)).toBe(false);
      expect(rig.records.filter((r) => r.toolCallId === "handshake-refused")).toHaveLength(0);
    } finally {
      await teardown(rig);
    }
  }, 20_000);

  it("starts the business work when the same lease stays valid", async () => {
    const rig = controllerRig("ok");
    try {
      const outcome = await rig.controller.execute({
        plan: planFor(rig.layout.workspace, "always-valid"),
        validity: createExecutionValidityGuard(() => null),
      });

      // This is the control for the test above: the same rig does reach the
      // business start when nothing expired.
      expect(outcome.state).not.toBe("cancelled");
      expect(existsSync(rig.marker)).toBe(true);
      expect(rig.records.filter((r) => r.toolCallId === "always-valid")).toHaveLength(1);
    } finally {
      await teardown(rig);
    }
  });

  it("refuses a lease object the host never issued", async () => {
    const rig = controllerRig("ok");
    try {
      const forged = { check: () => null } as unknown as ExecutionValidityGuard;
      const outcome = await rig.controller.execute({
        plan: planFor(rig.layout.workspace, "forged"),
        validity: forged,
      });

      expect(outcome.state).toBe("failed");
      if (outcome.state === "failed") expect(outcome.code).toBe("invalid-plan");
      expect(existsSync(rig.marker)).toBe(false);
    } finally {
      await teardown(rig);
    }
  });

  it("treats a lease that throws or answers unusably as a refusal", async () => {
    const rig = controllerRig("ok");
    try {
      const throwing = createExecutionValidityGuard(() => {
        throw new Error("the policy owner went away");
      });
      const junk = createExecutionValidityGuard(
        () => ({ code: "not-a-cancellation-code", reason: 42 }) as never,
      );

      for (const [name, validity] of [["throwing", throwing], ["junk", junk]] as const) {
        const outcome = await rig.controller.execute({
          plan: planFor(rig.layout.workspace, `broken-${name}`),
          validity,
        });
        expect(outcome.state, name).toBe("cancelled");
        if (outcome.state === "cancelled") {
          expect(outcome.code, name).toBe("plan-invalidated");
          expect(outcome.started, name).toBe(false);
        }
      }
      expect(existsSync(rig.marker)).toBe(false);
    } finally {
      await teardown(rig);
    }
  });

  it("refuses a call whose final config read advanced the policy", async () => {
    let policy = "r1";
    let armed = false;
    const harness = await createInvalidationHarness({
      policy: () => policy,
      approvedScope: () => {
        armed = true;
        return { filesystem: [] };
      },
      readConfigRevision: () => {
        // The reader's own observable effect moves a different revision, so
        // the policy value read just before it is already stale.
        if (armed) {
          armed = false;
          policy = "r2";
        }
        return "c1";
      },
    });
    const target = join(harness.layout.workspace, "mixed-facts.txt");
    writeFileSync(target, "private-value");

    const result = await outcomeText(
      harness.runCall("read", "mixed-facts", { path: target }),
    );

    expect(result).not.toContain("private-value");
    expect(harness.records).toHaveLength(0);
    expect(policy).toBe("r2");
  });

  it("refuses a host that never reports the same revisions twice, within a bounded number of reads", async () => {
    let config = "c1";
    let configReads = 0;
    const harness = await createInvalidationHarness({
      configRevision: "c1",
      readConfigRevision: () => {
        configReads += 1;
        // Every read hands back a different value, so no two consecutive
        // passes can agree and the snapshot can never settle.
        config = config === "c1" ? "c2" : "c1";
        return config;
      },
    });
    const target = join(harness.layout.workspace, "never-stable.txt");
    writeFileSync(target, "private-value");

    const result = await outcomeText(
      harness.runCall("read", "never-stable", { path: target }),
    );

    expect(result).toContain("stable snapshot");
    expect(result).not.toContain("private-value");
    expect(harness.records).toHaveLength(0);
    // One capture read plus the bounded validation passes; never a spin.
    expect(configReads).toBeLessThanOrEqual(8);
    expect(harness.adapter.outstandingWork()).toEqual({
      leasedSessions: 0,
      capturedExecutions: 0,
      activeCalls: 0,
    });
  });

  it("refuses a real tool call whose policy advanced while it waited in the queue", async () => {
    let policy = "r1";
    const harness = await createInvalidationHarness({
      policy: () => policy,
      scenario: "slow",
      maxConcurrent: 1,
    });
    const target = join(harness.layout.workspace, "queued-policy.txt");
    writeFileSync(target, "stale-read-value");

    const holder = harness.controller.execute({
      plan: planFor(harness.layout.workspace, "queue-holder"),
    });
    await waitFor(() => harness.controller.activeCount === 1);
    const pending = harness.runCall("read", "queued-policy", { path: target });
    await waitFor(() => harness.controller.queuedCount === 1);

    policy = "r2";
    await harness.controller.cancel("queue-holder");
    const result = await outcomeText(pending);
    await holder;

    expect(result).not.toContain("stale-read-value");
    expect(harness.records.filter((r) => r.toolCallId === "queued-policy")).toHaveLength(0);
    expect(harness.controller.queuedCount).toBe(0);
    expect(harness.adapter.outstandingWork()).toEqual({
      leasedSessions: 0,
      capturedExecutions: 0,
      activeCalls: 0,
    });
  }, 20_000);
  it("refuses a call whose approval budget expired while it waited in the queue", async () => {
    const harness = await createInvalidationHarness({
      scenario: "slow",
      maxConcurrent: 1,
      deadlineMs: 2_500,
    });
    const target = join(harness.layout.workspace, "budget-expired.txt");
    writeFileSync(target, "budget-value");

    const holder = harness.controller.execute({
      plan: planFor(harness.layout.workspace, "budget-holder"),
    });
    await waitFor(() => harness.controller.activeCount === 1);
    const pending = harness.runCall("read", "budget-expired", { path: target });
    await waitFor(() => harness.controller.queuedCount === 1);
    // The plan expires while it is still queued: the holder keeps the only
    // slot, so the deadline, not a dequeue, ends this attempt.
    const result = await outcomeText(pending);
    expect(harness.controller.activeCount).toBe(1);
    expect(harness.controller.queuedCount).toBe(0);
    await harness.controller.cancel("budget-holder");
    await holder;

    // The expired budget is refused as it is: no fresh approval, no retry, and
    // the cause is reported instead of being hidden.
    expect(result).not.toContain("budget-value");
    const records = harness.records.filter((r) => r.toolCallId === "budget-expired");
    expect(records).toHaveLength(1);
    expect(records[0]?.started).toBe(false);
    expect(records[0]?.code).toBe("sandbox-deadline-exceeded");
    expect(harness.adapter.outstandingWork()).toEqual({
      leasedSessions: 0,
      capturedExecutions: 0,
      activeCalls: 0,
    });
  }, 30_000);

  it("settles once when the lease itself re-enters session invalidation", async () => {
    const harness = await createInvalidationHarness({
      scenario: "slow",
      maxConcurrent: 1,
    });
    const target = join(harness.layout.workspace, "reentrant.txt");
    writeFileSync(target, "reentrant-value");
    const invalidations: Promise<void>[] = [];

    const holder = harness.controller.execute({
      plan: planFor(harness.layout.workspace, "reentry-holder"),
    });
    await waitFor(() => harness.controller.activeCount === 1);
    const pending = harness.controller.execute({
      plan: planFor(harness.layout.workspace, "reentry-guard"),
      validity: createExecutionValidityGuard(() => {
        // The check runs inside the controller, so a host can invalidate from
        // within it. The task must still settle exactly once.
        invalidations.push(harness.adapter.clearSession(SESSION_ID));
        return { code: "session-disposed", reason: "the session went away during the check" };
      }),
    });
    await waitFor(() => harness.controller.queuedCount === 1);

    await harness.controller.cancel("reentry-holder");
    const outcome = await pending;
    await holder;
    await Promise.all(invalidations);

    expect(invalidations).toHaveLength(1);
    expect(outcome.state).toBe("cancelled");
    if (outcome.state === "cancelled") expect(outcome.started).toBe(false);
    expect(
      harness.records.filter((r) => r.toolCallId === "reentry-guard"),
    ).toHaveLength(0);
    expect(harness.controller.activeCount).toBe(0);
    expect(harness.controller.queuedCount).toBe(0);
  }, 20_000);
});

describe("outstanding work stays bounded", () => {
  it("keeps no session record for a session nobody has claimed", async () => {
    const harness = await createInvalidationHarness();
    for (let index = 0; index < 200; index += 1) {
      await harness.adapter.clearSession(`never-used-session-${index}`);
    }
    expect(harness.adapter.outstandingWork().leasedSessions).toBe(0);

    const target = join(harness.layout.workspace, "after-idle-clears.txt");
    await harness.runCall("write", "after-idle-clears", { path: target, content: "ok" });
    expect(existsSync(target)).toBe(true);
    expect(harness.adapter.outstandingWork()).toEqual({
      leasedSessions: 0,
      capturedExecutions: 0,
      activeCalls: 0,
    });
  });

  it("releases the session index on dispose even with a capture outstanding", async () => {
    const harness = await createInvalidationHarness({ holdVerification: () => true });
    const target = join(harness.layout.workspace, "dispose-pending.txt");
    const pending = harness.pendingCall(
      "write",
      "dispose-pending",
      { path: target, content: "late" },
    );
    await harness.verificationEntered;
    expect(harness.adapter.outstandingWork().leasedSessions).toBe(1);

    await harness.adapter.dispose();
    harness.releaseVerification();
    await pending;

    expect(existsSync(target)).toBe(false);
    expect(harness.adapter.outstandingWork()).toEqual({
      leasedSessions: 0,
      capturedExecutions: 0,
      activeCalls: 0,
    });
  });

  it("keeps an invalidated call registered until it settles and releases it once", async () => {
    const harness = await createInvalidationHarness({
      scenario: "slow",
      maxConcurrent: 1,
    });
    const pending = harness.pendingCall("bash", "settling-owner", { command: "ignored" });
    await waitFor(() => harness.adapter.outstandingWork().activeCalls === 1);

    await harness.adapter.clearSession(SESSION_ID);
    // The abort has been sent but the work is still outstanding, so the
    // registration must survive until the call really settles.
    expect(harness.adapter.outstandingWork().activeCalls).toBe(1);

    await outcomeText(pending);
    expect(harness.adapter.outstandingWork().activeCalls).toBe(0);
    expect(harness.controller.activeCount).toBe(0);
  }, 20_000);

  it("refuses a new call at the outstanding bound without dropping a live owner", async () => {
    const harness = await createInvalidationHarness({
      scenario: "slow",
      maxConcurrent: 1,
      maxOutstandingCalls: 2,
    });
    const holder = join(harness.layout.workspace, "bound-holder.txt");
    const queued = join(harness.layout.workspace, "bound-queued.txt");
    writeFileSync(holder, "holder-value");
    writeFileSync(queued, "queued-value");

    const first = harness.runCall("read", "bound-first", { path: holder });
    await waitFor(() => harness.controller.activeCount === 1);
    const second = harness.runCall("read", "bound-second", { path: queued });
    await waitFor(() => harness.controller.queuedCount === 1);
    expect(harness.adapter.outstandingWork().activeCalls).toBe(2);

    const third = await outcomeText(harness.runCall("read", "bound-third", { path: holder }));

    expect(third).toContain("sandbox-queue-full");
    expect(harness.adapter.outstandingWork().activeCalls).toBe(2);
    // The two owners were never displaced, so both still deliver their result.
    expect(await outcomeText(first)).toContain("holder-value");
    expect(await outcomeText(second)).toContain("queued-value");
    expect(harness.records.filter((r) => r.toolCallId === "bound-third")).toHaveLength(0);
    expect(harness.adapter.outstandingWork()).toEqual({
      leasedSessions: 0,
      capturedExecutions: 0,
      activeCalls: 0,
    });
  }, 20_000);

  it("rejects a repeated tool call id instead of replacing its owner", async () => {
    const harness = await createInvalidationHarness({ scenario: "slow", maxConcurrent: 1 });
    const target = join(harness.layout.workspace, "duplicate-key.txt");
    writeFileSync(target, "duplicate-value");

    const first = harness.runCall("read", "duplicate-key", { path: target });
    await waitFor(() => harness.controller.activeCount === 1);
    const second = await outcomeText(
      harness.runCall("read", "duplicate-key", { path: target }),
    );

    expect(second).toContain("sandbox-queue-full");
    expect(await outcomeText(first)).toContain("duplicate-value");
    expect(harness.adapter.outstandingWork().activeCalls).toBe(0);
  }, 20_000);

  it("refuses an outstanding-call bound outside the module range", async () => {
    for (const invalid of [0, 1.5, 65]) {
      await expect(
        createInvalidationHarness({ maxOutstandingCalls: invalid }),
      ).rejects.toThrow(/maxOutstandingCalls/);
    }
  });

  it("does not let a cleared session id reuse the identity of a new approval", async () => {
    const harness = await createInvalidationHarness({
      holdVerification: (toolCallId) => toolCallId === "aba-old",
    });
    const staleTarget = join(harness.layout.workspace, "aba-stale.txt");
    const freshTarget = join(harness.layout.workspace, "aba-fresh.txt");

    const stale = harness.pendingCall(
      "write",
      "aba-old",
      { path: staleTarget, content: "stale" },
    );
    await harness.verificationEntered;
    await harness.adapter.clearSession(SESSION_ID);

    // A fresh approval taken after the clear gets a different lease object.
    await harness.runCall("write", "aba-new", { path: freshTarget, content: "fresh" });
    harness.releaseVerification();
    await outcomeText(stale);

    expect(readFileSync(freshTarget, "utf8")).toBe("fresh");
    expect(existsSync(staleTarget)).toBe(false);
    expect(harness.records.filter((r) => r.toolCallId === "aba-old")).toHaveLength(0);
    expect(harness.adapter.outstandingWork().leasedSessions).toBe(0);
  });

  it("holds one session claim per session so a clear cannot free another's", async () => {
    const harness = await createInvalidationHarness({
      holdVerification: (toolCallId) => toolCallId.startsWith("mixed-"),
      maxConcurrent: 2,
    });
    const clearedTarget = join(harness.layout.workspace, "mixed-cleared.txt");
    const keptTarget = join(harness.layout.workspace, "mixed-kept.txt");

    const cleared = harness.pendingCall(
      "write",
      "mixed-cleared",
      { path: clearedTarget, content: "x" },
      "session-a",
    );
    const kept = harness.pendingCall(
      "write",
      "mixed-kept",
      { path: keptTarget, content: "y" },
      "session-b",
    );
    await waitFor(() => harness.adapter.outstandingWork().leasedSessions === 2);
    await harness.adapter.clearSession("session-a");
    harness.releaseVerification();

    await outcomeText(cleared);
    await kept;

    expect(existsSync(keptTarget)).toBe(true);
    expect(existsSync(clearedTarget)).toBe(false);
    expect(harness.adapter.outstandingWork()).toEqual({
      leasedSessions: 0,
      capturedExecutions: 0,
      activeCalls: 0,
    });
  });
});
