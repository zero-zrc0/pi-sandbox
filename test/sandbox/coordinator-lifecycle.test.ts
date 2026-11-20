import { afterEach, describe, expect, it } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  compileTestRequest, createTestLayout, testExecutionEnvironment, makeController, makeInvocation,
  processExists, removeTestLayout, waitFor,
} from "./fixtures/harness";

const cleanup: Array<() => Promise<void>> = [];
afterEach(async () => { while (cleanup.length) await cleanup.pop()!(); });

function setup(scenario: string) {
  const layout = createTestLayout("plan11-coordinator");
  const pidFile = join(layout.root, "native.pid");
  const controller = makeController({
    layout, maxConcurrent: 1, startTimeoutMs: 10_000, probeTimeoutMs: 10_000, cancelGraceMs: 30,
    scenario,
    environment: testExecutionEnvironment({ FIXTURE_SELF_PID_FILE: pidFile }),
  });
  cleanup.push(async () => { await controller.dispose(); removeTestLayout(layout); });
  const plan = compileTestRequest({
    invocation: makeInvocation({ cwd: layout.workspace, args: { command: "ignored" } }),
    operation: { kind: "shell", command: "ignored" }, workspace: layout.workspace,
  });
  return { controller, plan, pidFile };
}

describe("coordinator execution lifecycle regressions", () => {
  it.each([
    { maxConcurrent: Number.NaN }, { maxConcurrent: Number.POSITIVE_INFINITY },
    { maxConcurrent: 1.5 }, { maxConcurrent: 5 },
    { maxQueue: Number.NaN }, { maxQueue: Number.POSITIVE_INFINITY },
    { maxQueue: 0.5 }, { maxQueue: 17 },
  ])("rejects an invalid physical resource bound %j", bounds => {
    const layout = createTestLayout("plan11-invalid-bound");
    cleanup.push(async () => { removeTestLayout(layout); });
    expect(() => makeController({ layout, ...bounds })).toThrow("queue bounds");
  });

  it("queues execution while a probe occupies the only physical slot", async () => {
    const { controller, plan } = setup("no-ready");
    const probe = controller.probe();
    const running = controller.execute({ request: plan });
    try {
      expect(controller.activeCount).toBe(0);
      expect(controller.queuedCount).toBe(1);
    } finally {
      await controller.dispose();
      await Promise.all([probe, running]);
    }
  });

  it("finishes physical cleanup before configuration invalidation resolves", async () => {
    const { controller, plan, pidFile } = setup("slow");
    const running = controller.execute({ request: plan });
    await waitFor(() => existsSync(pidFile));
    const pid = Number.parseInt(readFileSync(pidFile, "utf8"), 10);
    await controller.updateConfiguration();
    expect(controller.activeCount).toBe(0);
    expect(processExists(pid)).toBe(false);
    expect((await running).state).toBe("cancelled");
  });

  it("session cancellation finishes while another session remains active", async () => {
    const layout = createTestLayout("plan11-cancel-isolation");
    const controller = makeController({ layout, scenario: "slow", maxConcurrent: 2, cancelGraceMs: 30 });
    cleanup.push(async () => { await controller.dispose(); removeTestLayout(layout); });
    const planFor = (sessionId: string) => compileTestRequest({
      invocation: makeInvocation({ cwd: layout.workspace, sessionId, requestId: sessionId, toolCallId: sessionId }),
      operation: { kind: "shell", command: "ignored" }, workspace: layout.workspace,
    });
    const first = controller.execute({ request: planFor("first") });
    const second = controller.execute({ request: planFor("second") });
    let cancelled = false;
    const cancelling = controller.cancelSession("first").then(() => { cancelled = true; });
    try {
      await first;
      await new Promise<void>(resolve => setImmediate(resolve));
      expect(cancelled).toBe(true);
      expect(controller.activeCount).toBe(1);
    } finally {
      await controller.dispose();
      await Promise.all([first, second, cancelling]);
    }
  });
});
