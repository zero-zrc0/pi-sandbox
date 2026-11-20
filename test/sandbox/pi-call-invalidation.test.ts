import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  SESSION_ID,
  createInvalidationHarness,
  outcomeText,
  useInvalidationCleanup,
} from "./fixtures/invalidation-harness";
import { waitFor, waitForProcessGone } from "./fixtures/harness";

useInvalidationCleanup();

describe("coordinator callback guards", () => {
  it.each(["session", "configuration"] as const)("keeps the original identity when the config reader reenters %s invalidation", async kind => {
    let invalidate = async (): Promise<void> => undefined;
    let once = true;
    const waits: Promise<void>[] = [];
    const harness = await createInvalidationHarness({ readConfigRevision: () => {
      if (once) { once = false; waits.push(invalidate()); }
      return "c1";
    } });
    invalidate = () => kind === "session"
      ? harness.adapter.clearSession(SESSION_ID)
      : harness.adapter.updateConfiguration();
    const target = join(harness.layout.workspace, "guard-read.txt");
    writeFileSync(target, "guard-private-value");
    const result = await outcomeText(harness.runCall("read", "guard-read", { path: target }));
    await Promise.all(waits);
    expect(waits).toHaveLength(1);
    expect(result).not.toContain("guard-private-value");
    expect(harness.records).toHaveLength(0);
  });

  it("checks the config revision after approved-scope derivation", async () => {
    let config = "c1";
    const harness = await createInvalidationHarness({
      readConfigRevision: () => config,
      approvedScope: () => { config = "c2"; return { filesystem: [] }; },
    });
    const target = join(harness.layout.workspace, "scope-config.txt");
    writeFileSync(target, "guard-private-value");
    const result = await outcomeText(harness.runCall("read", "scope-config", { path: target }));
    expect(result).not.toContain("guard-private-value");
    expect(harness.records).toHaveLength(0);
  });
});

describe("whole-call invalidation", () => {
  it("refuses a late scope verification after clearSession and starts nothing", async () => {
    const harness = await createInvalidationHarness({
      holdVerification: () => true,
    });
    const target = join(harness.layout.workspace, "late-session.txt");

    const pending = harness.pendingCall(
      "write",
      "late-session",
      { path: target, content: "late" },
    );
    await harness.verificationEntered;
    await harness.adapter.clearSession(SESSION_ID);
    harness.releaseVerification();
    await pending;

    expect(existsSync(target)).toBe(false);
    expect(harness.records).toHaveLength(0);
    expect(harness.controller.activeCount).toBe(0);
  });

  it("refuses a late scope verification after updateConfiguration with an unchanged revision string", async () => {
    // The configuration string never changes: the public API itself must
    // invalidate, not a revision the caller happened to swap.
    const harness = await createInvalidationHarness({
      holdVerification: () => true,
    });
    const target = join(harness.layout.workspace, "late-config.txt");

    const pending = harness.pendingCall(
      "write",
      "late-config",
      { path: target, content: "late" },
    );
    await harness.verificationEntered;
    await harness.adapter.updateConfiguration();
    harness.releaseVerification();
    await pending;

    expect(existsSync(target)).toBe(false);
    expect(harness.records).toHaveLength(0);
  });

  it("records one complete builtin before a post-completion policy change", async () => {
    let policy = "r1";
    const harness = await createInvalidationHarness({ policy: () => policy, onRecord: () => { policy = "r2"; } });
    const target = join(harness.layout.workspace, "complete-call.txt");
    const result = await outcomeText(harness.runCall("write", "complete-call", { path: target, content: "complete" }));
    expect(result).toContain("Successfully wrote");
    expect(existsSync(target)).toBe(true);
    expect(harness.records).toHaveLength(1);
    expect(harness.records[0]?.state).toBe("completed");
  });

  it("cancels the running native process and its call when the session is cleared", async () => {
    const harness = await createInvalidationHarness({
      scenario: "slow",
      maxConcurrent: 1,
    });
    const pending = harness.pendingCall(
      "bash",
      "running-cancel",
      { command: "ignored" },
    );
    await waitFor(() => existsSync(harness.nativePidFile));
    const pid = Number.parseInt(readFileSync(harness.nativePidFile, "utf8"), 10);
    expect(pid).toBeGreaterThan(0);

    await harness.adapter.clearSession(SESSION_ID);
    const outcome = await outcomeText(pending);

    expect(outcome).toContain("session-disposed");
    const record = harness.records.find(
      (candidate) => candidate.toolCallId === "running-cancel",
    );
    expect(record?.state).toBe("cancelled");
    expect(record?.code).toBe("session-disposed");
    expect(record?.started).toBe(true);
    expect(await waitForProcessGone(pid, 5_000)).toBe(true);
    expect(harness.controller.activeCount).toBe(0);
  });

  it("leaves another session's call running when one session is cleared", async () => {
    const harness = await createInvalidationHarness({
      scenario: "slow",
      maxConcurrent: 2,
    });
    const otherTarget = join(harness.layout.workspace, "other-session.txt");
    const cleared = harness.pendingCall(
      "bash",
      "cleared-session-call",
      { command: "ignored" },
      "session-cleared",
    );
    const kept = harness.pendingCall(
      "write",
      "kept-session-call",
      { path: otherTarget, content: "kept" },
      "session-kept",
    );
    await waitFor(() => harness.controller.activeCount === 2);

    await harness.adapter.clearSession("session-cleared");
    const clearedText = await outcomeText(cleared);
    const keptText = await outcomeText(kept);

    expect(clearedText).toContain("session-disposed");
    expect(keptText).not.toMatch(/session-disposed|plan-invalidated|aborted/);
    expect(existsSync(otherTarget)).toBe(true);
    expect(readFileSync(otherTarget, "utf8")).toBe("kept");
    const clearedRecord = harness.records.find(
      (candidate) => candidate.toolCallId === "cleared-session-call",
    );
    expect(clearedRecord?.code).toBe("session-disposed");
  });

  it("stops a held verification and a running native process when the adapter disposes", async () => {
    const harness = await createInvalidationHarness({
      holdVerification: (toolCallId) => toolCallId === "disposed-verification",
      scenario: "slow",
    });
    const target = join(harness.layout.workspace, "disposed-call.txt");
    const held = harness.pendingCall(
      "write",
      "disposed-verification",
      { path: target, content: "late" },
    );
    await harness.verificationEntered;

    const running = harness.pendingCall(
      "bash",
      "disposed-running",
      { command: "ignored" },
    );
    await waitFor(() => harness.controller.activeCount === 1);
    await harness.adapter.dispose();
    harness.releaseVerification();

    expect(await outcomeText(held)).toMatch(
      /permission-scope-changed|approved-action-unavailable|session-disposed/,
    );
    const runningText = await outcomeText(running);
    expect(runningText).toContain("session-disposed");
    expect(existsSync(target)).toBe(false);
    const runningRecord = harness.records.find(
      (candidate) => candidate.toolCallId === "disposed-running",
    );
    expect(runningRecord?.state).toBe("cancelled");
    expect(harness.controller.activeCount).toBe(0);
  }, 20_000);

  it("runs a fresh approval for a reused session id after clearSession", async () => {
    const harness = await createInvalidationHarness();
    await harness.adapter.clearSession(SESSION_ID);

    const target = join(harness.layout.workspace, "reused-session.txt");
    await harness.runCall("write", "after-reuse", { path: target, content: "fresh" });

    expect(existsSync(target)).toBe(true);
    expect(readFileSync(target, "utf8")).toBe("fresh");
  });

  it("keeps repeated invalidations idempotent and still refuses the old call", async () => {
    const harness = await createInvalidationHarness({
      holdVerification: () => true,
    });
    const target = join(harness.layout.workspace, "repeated.txt");

    const pending = harness.pendingCall(
      "write",
      "repeated",
      { path: target, content: "late" },
    );
    await harness.verificationEntered;
    await harness.adapter.clearSession(SESSION_ID);
    await harness.adapter.clearSession(SESSION_ID);
    await harness.adapter.updateConfiguration();
    harness.releaseVerification();
    await pending;

    expect(existsSync(target)).toBe(false);
    expect(harness.records).toHaveLength(0);
  });


});
