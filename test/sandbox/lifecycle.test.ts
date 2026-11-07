import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  ExecutionController,
  type EgressProvider,
  type HelperProbeResult,
} from "#sandbox/lifecycle";
import type {
  ExecutionPlan,
  ExecutionRecord,
} from "#sandbox/types";
import {
  compileTestPlan,
  createTestLayout,
  fixtureEnvironment,
  installFixtureHelper,
  makeController,
  makeInvocation,
  processExists,
  removeTestLayout,
  runtimeEnvironment,
  waitFor,
  waitForProcessGone,
  type TestLayout,
} from "./fixtures/harness";

const layouts: TestLayout[] = [];
const controllers: ExecutionController[] = [];

afterEach(async () => {
  await Promise.all(controllers.splice(0).map((controller) => controller.dispose()));
  for (const layout of layouts.splice(0)) removeTestLayout(layout);
});

function layout(): TestLayout {
  const created = createTestLayout();
  layouts.push(created);
  return created;
}

function shellPlan(
  workspace: string,
  command: string,
  options: {
    readonly deadlineMs?: number;
    readonly requestId?: string;
    readonly toolCallId?: string;
    readonly sessionId?: string;
  } = {},
): ExecutionPlan {
  const invocation = makeInvocation({
    cwd: workspace,
    toolName: "bash",
    args: { command },
    requestId: options.requestId ?? `request-${Math.random().toString(16).slice(2)}`,
    toolCallId: options.toolCallId ?? `call-${Math.random().toString(16).slice(2)}`,
    ...(options.sessionId === undefined ? {} : { sessionId: options.sessionId }),
  });
  return compileTestPlan({
    invocation,
    operation: { kind: "shell", command },
    workspace,
    environment: runtimeEnvironment(),
    deadlineMs: options.deadlineMs ?? 10_000,
  });
}

function controllerFor(
  testLayout: TestLayout,
  scenario: string,
  options: {
    readonly startTimeoutMs?: number;
    readonly cancelGraceMs?: number;
    readonly maxConcurrent?: number;
    readonly maxQueue?: number;
    readonly onRecord?: (record: ExecutionRecord) => void;
    readonly egress?: EgressProvider;
    readonly extraEnv?: Readonly<Record<string, string>>;
  } = {},
): ExecutionController {
  const controller = makeController({
    layout: testLayout,
    scenario,
    helperEnvironment: fixtureEnvironment(scenario, options.extraEnv ?? {}),
    cancelGraceMs: 300,
    ...options,
  });
  controllers.push(controller);
  return controller;
}

describe("captured plan identity", () => {
  function writeFixturePlan(testLayout: TestLayout, target: string): ExecutionPlan {
    return compileTestPlan({
      invocation: makeInvocation({
        cwd: testLayout.workspace,
        toolName: "write",
        args: { path: "captured.txt", content: "captured" },
        requestId: "request-capture",
        toolCallId: "call-capture",
      }),
      operation: { kind: "write-file", path: target, content: "captured" },
      workspace: testLayout.workspace,
      environment: runtimeEnvironment(),
      deadlineMs: 10_000,
    });
  }

  it("uses the plan captured at entry when the caller mutates it during the handshake", async () => {
    const testLayout = layout();
    const controller = controllerFor(testLayout, "ok");
    const captured = join(testLayout.workspace, "captured.txt");
    const tampered = join(testLayout.workspace, "tampered.txt");
    const forgery = JSON.parse(
      JSON.stringify(writeFixturePlan(testLayout, captured)),
    ) as ExecutionPlan;
    const nested = forgery.operation as unknown as {
      path: string;
      content: string;
    };
    const running = controller.execute({ plan: forgery });
    nested.path = tampered;
    nested.content = "tampered";
    const outcome = await running;
    expect(outcome.state).toBe("completed");
    expect(readFileSync(captured, "utf8")).toBe("captured");
    expect(existsSync(tampered)).toBe(false);
  });

  it("rejects an accessor plan without invoking the getter and starts nothing", async () => {
    const testLayout = layout();
    const marker = join(testLayout.workspace, "accessor-marker.txt");
    const controller = controllerFor(testLayout, "ok");
    const forgery = JSON.parse(
      JSON.stringify(writeFixturePlan(testLayout, marker)),
    ) as ExecutionPlan;
    let touched = 0;
    Object.defineProperty(forgery.operation, "path", {
      get() {
        touched += 1;
        return join(testLayout.workspace, "getter.txt");
      },
    });
    const outcome = await controller.execute({ plan: forgery });
    expect(outcome.state).toBe("failed");
    if (outcome.state !== "failed") return;
    expect(outcome.code).toBe("invalid-plan");
    expect(outcome.started).toBe(false);
    expect(touched).toBe(0);
    expect(existsSync(marker)).toBe(false);
  });

  it("refuses a duplicate request and tool call instead of replacing the active task", async () => {
    const testLayout = layout();
    const controller = controllerFor(testLayout, "slow", { maxConcurrent: 1 });
    const plan = shellPlan(
      testLayout.workspace,
      `"${process.execPath}" -e "0"`,
      { requestId: "duplicate-key" },
    );
    const running = controller.execute({ plan });
    await waitFor(() => controller.activeCount === 1);
    const queuedPlan = shellPlan(testLayout.workspace, "ignored", {
      requestId: "duplicate-queued",
      toolCallId: "call-duplicate-queued",
    });
    const queuedRun = controller.execute({ plan: queuedPlan });
    await waitFor(() => controller.queuedCount === 1);
    const duplicateOfQueued = await controller.execute({ plan: queuedPlan });
    expect(duplicateOfQueued.state).toBe("failed");
    if (duplicateOfQueued.state !== "failed") return;
    expect(duplicateOfQueued.code).toBe("binding-mismatch");
    expect(controller.queuedCount).toBe(1);
    const duplicate = await controller.execute({ plan });
    expect(duplicate.state).toBe("failed");
    if (duplicate.state !== "failed") return;
    expect(duplicate.code).toBe("binding-mismatch");
    expect(duplicate.started).toBe(false);
    expect(controller.activeCount).toBe(1);
    await controller.dispose();
    const queuedOutcome = await queuedRun;
    expect(queuedOutcome.state).toBe("cancelled");
    await running;
    expect(controller.activeCount).toBe(0);
  });
});

describe("session cancellation and pre-start abort", () => {
  it("starts nothing when the request is already aborted", async () => {
    const testLayout = layout();
    const marker = join(testLayout.workspace, "aborted-marker.txt");
    const controller = makeController({
      layout: testLayout,
      scenario: "ok",
      helperEnvironment: fixtureEnvironment("ok", {
        FIXTURE_MARKER_FILE: marker,
      }),
    });
    controllers.push(controller);
    const abort = new AbortController();
    abort.abort();
    const outcome = await controller.execute({
      plan: shellPlan(
        testLayout.workspace,
        `"${process.execPath}" -e "0"`,
      ),
      signal: abort.signal,
    });
    expect(outcome.state).toBe("cancelled");
    if (outcome.state !== "cancelled") return;
    expect(outcome.code).toBe("execution-cancelled");
    expect(outcome.started).toBe(false);
    expect(outcome.impact).toBe("none");
    expect(controller.activeCount).toBe(0);
    expect(existsSync(marker)).toBe(false);
  });

  it("cancels a session's running and queued plans without touching another session", async () => {
    const testLayout = layout();
    const controller = controllerFor(testLayout, "slow", {
      maxConcurrent: 1,
      maxQueue: 2,
    });
    const runningPlan = shellPlan(testLayout.workspace, "ignored", {
      requestId: "session-a-running",
      sessionId: "session-1",
    });
    const queuedPlan = shellPlan(testLayout.workspace, "ignored", {
      requestId: "session-a-queued",
      toolCallId: "call-queued",
      sessionId: "session-1",
    });
    const otherPlan = shellPlan(testLayout.workspace, "ignored", {
      requestId: "session-b",
      toolCallId: "call-other",
      sessionId: "session-2",
      deadlineMs: 800,
    });
    const running = controller.execute({ plan: runningPlan });
    await waitFor(() => controller.activeCount === 1);
    const queued = controller.execute({ plan: queuedPlan });
    const other = controller.execute({ plan: otherPlan });
    await waitFor(() => controller.queuedCount === 2);
    await controller.cancelSession("session-1", "session disposed");
    const runningOutcome = await running;
    const queuedOutcome = await queued;
    expect(runningOutcome.state).toBe("cancelled");
    if (runningOutcome.state !== "cancelled") return;
    expect(runningOutcome.code).toBe("session-disposed");
    expect(queuedOutcome.record.code).toBe("session-disposed");
    expect(queuedOutcome.started).toBe(false);
    const otherOutcome = await other;
    expect(otherOutcome.record.code).not.toBe("session-disposed");
    expect(controller.activeCount).toBe(0);
  });
});

describe("observer isolation", () => {
  function outputPlan(testLayout: TestLayout, requestId: string): ExecutionPlan {
    return shellPlan(
      testLayout.workspace,
      `"${process.execPath}" -e "process.stdout.write('chunk-one')"`,
      { requestId },
    );
  }

  it("keeps streaming, settling and recording intact when an output observer throws", async () => {
    const testLayout = layout();
    const records: ExecutionRecord[] = [];
    const controller = controllerFor(testLayout, "ok", {
      onRecord: (record) => records.push(record),
    });
    let observed = 0;
    const outcome = await controller.execute({
      plan: outputPlan(testLayout, "observer-output-throws"),
      onOutput: () => {
        observed += 1;
        throw new Error("observer failed");
      },
    });
    expect(observed).toBeGreaterThan(0);
    expect(outcome.state).toBe("completed");
    if (outcome.state !== "completed") return;
    expect(outcome.stdout).toContain("chunk-one");
    expect(records).toHaveLength(1);
    expect(controller.activeCount).toBe(0);
    expect(controller.queuedCount).toBe(0);
  });

  it("still resolves and releases resources when the record observer throws", async () => {
    const testLayout = layout();
    const controller = controllerFor(testLayout, "ok", {
      onRecord: () => {
        throw new Error("logger is down");
      },
    });
    const outcome = await controller.execute({
      plan: outputPlan(testLayout, "observer-record-throws"),
    });
    expect(outcome.state).toBe("completed");
    expect(controller.activeCount).toBe(0);
  });

  it("does not deadlock when the record observer re-enters dispose", async () => {
    const testLayout = layout();
    let reference!: ExecutionController;
    let reentered = false;
    const controller = controllerFor(testLayout, "ok", {
      onRecord: () => {
        if (reentered) return;
        reentered = true;
        void reference.dispose();
      },
    });
    reference = controller;
    const outcome = await controller.execute({
      plan: outputPlan(testLayout, "observer-reentrant-dispose"),
    });
    expect(outcome.state).toBe("completed");
    await waitFor(() => reentered);
    await controller.dispose();
    const after = await controller.execute({
      plan: outputPlan(testLayout, "observer-after-dispose"),
    });
    expect(after.state).toBe("failed");
    if (after.state !== "failed") return;
    expect(after.code).toBe("invalid-plan");
    expect(controller.activeCount).toBe(0);
  });
});

describe("start state classification", () => {
  it("reports a generic helper error after start as an unknown start", async () => {
    const testLayout = layout();
    const controller = controllerFor(testLayout, "start-fail");
    const outcome = await controller.execute({
      plan: shellPlan(testLayout.workspace, "ignored", {
        requestId: "error-without-ack",
      }),
    });
    expect(outcome.state).toBe("failed");
    if (outcome.state !== "failed") return;
    expect(outcome.started).toBe("unknown");
    expect(outcome.impact).toBe("unknown");
    expect(outcome.code).toBe("sandbox-setup-failed");
    expect(outcome.record.started).toBe("unknown");
    expect(outcome.record.impact).toBe("unknown");
  });

  it("reports a generic helper error after an acknowledged start as a failure", async () => {
    const testLayout = layout();
    const controller = controllerFor(testLayout, "error-after-start");
    const outcome = await controller.execute({
      plan: shellPlan(testLayout.workspace, "ignored", {
        requestId: "error-after-ack",
      }),
    });
    expect(outcome.state).toBe("failed");
    if (outcome.state !== "failed") return;
    expect(outcome.started).toBe(true);
    expect(outcome.code).toBe("execution-failed");
    expect(outcome.impact).toBe("unknown");
  });
});

describe("probe and physical concurrency bounds", () => {
  it("spawns nothing when probing after dispose", async () => {
    const testLayout = layout();
    const controller = controllerFor(testLayout, "ok");
    await controller.dispose();
    const result = await controller.probe();
    expect(result.status).toBe("setup-failed");
    if (result.status === "available") return;
    expect(result.reason).toContain("disposed");
  });

  it("counts a probe against the same concurrency bound as an execution", async () => {
    const testLayout = layout();
    const controller = controllerFor(testLayout, "slow", { maxConcurrent: 1 });
    const plan = shellPlan(testLayout.workspace, "ignored", {
      requestId: "probe-bound",
    });
    const running = controller.execute({ plan });
    await waitFor(() => controller.activeCount === 1);
    const result = await controller.probe();
    expect(result.status).toBe("setup-failed");
    if (result.status === "available") return;
    expect(result.reason).toContain("probe limit");
    await controller.cancel("probe-bound", "test finished");
    await running;
  });

  it("reclaims an in-flight probe instead of waiting for its full timeout", async () => {
    const testLayout = layout();
    const controller = makeController({
      layout: testLayout,
      scenario: "no-ready",
      helperEnvironment: fixtureEnvironment("no-ready"),
      probeTimeoutMs: 60_000,
      cancelGraceMs: 200,
    });
    controllers.push(controller);
    const startedAt = Date.now();
    const pending = controller.probe();
    await new Promise((resolve) => setTimeout(resolve, 150));
    await controller.dispose();
    const elapsed = Date.now() - startedAt;
    const result = await pending;
    expect(result.status).not.toBe("available");
    expect(elapsed).toBeLessThan(15_000);
  });

  it("has already closed the helper when a cancelled execution resolves", async () => {
    const testLayout = layout();
    const pidFile = join(testLayout.root, "stubborn-helper.pid");
    const controller = makeController({
      layout: testLayout,
      scenario: "stubborn",
      helperEnvironment: fixtureEnvironment("stubborn", {
        FIXTURE_SELF_PID_FILE: pidFile,
      }),
      cancelGraceMs: 300,
    });
    controllers.push(controller);
    const abort = new AbortController();
    const running = controller.execute({
      plan: shellPlan(testLayout.workspace, "ignored", {
        requestId: "close-before-release",
      }),
      signal: abort.signal,
    });
    await waitFor(() => existsSync(pidFile));
    const pid = Number.parseInt(readFileSync(pidFile, "utf8"), 10);
    expect(pid).toBeGreaterThan(0);
    abort.abort();
    const outcome = await running;
    expect(outcome.state).toBe("cancelled");
    expect(controller.activeCount).toBe(0);
    expect(processExists(pid)).toBe(false);
  });
});

describe("helper probe", () => {
  it("reports unavailable isolation before starting a workload", async () => {
    const testLayout = layout();
    const controller = controllerFor(testLayout, "unavailable");
    expect(await controller.probe()).toMatchObject({ status: "missing", reason: "native sandbox unavailable" });
    const outcome = await controller.execute({ plan: shellPlan(testLayout.workspace, "ignored", { requestId: "unavailable" }) });
    expect(outcome).toMatchObject({ state: "failed", code: "sandbox-unavailable", started: false, impact: "none" });
  });
  it("reports the negotiated backend and capabilities", async () => {
    const testLayout = layout();
    const controller = controllerFor(testLayout, "ok");
    const result: HelperProbeResult = await controller.probe();
    expect(result).toMatchObject({
      status: "available",
      backend: { id: "fixture-helper", version: "1.0.0" },
      protocolVersion: 2,
    });
    if (result.status === "available") {
      expect(result.capabilities.processTree).toBe(true);
      expect(result.capabilities.filesystem.granularity).toBe("file");
    }
  });

  it("distinguishes a missing helper from a version mismatch", async () => {
    const missingLayout = layout();
    const missing = makeController({
      layout: missingLayout,
      installation: {
        installRoot: join(missingLayout.root, "missing"),
        executable: process.execPath,
      },
    });
    controllers.push(missing);
    expect((await missing.probe()).status).toBe("missing");

    const wrongLayout = layout();
    const wrong = controllerFor(wrongLayout, "wrong-version");
    expect((await wrong.probe()).status).toBe("version-mismatch");
  });
});

describe("execution lifecycle", () => {
  it("streams a real subprocess result and records exactly one execution", async () => {
    const testLayout = layout();
    const records: ExecutionRecord[] = [];
    const controller = controllerFor(testLayout, "ok", {
      onRecord: (record) => records.push(record),
    });
    const plan = shellPlan(
      testLayout.workspace,
      `"${process.execPath}" -e "process.stdout.write('hello-out');process.stderr.write('hello-err')"`,
    );
    const chunks: string[] = [];
    const outcome = await controller.execute({
      plan,
      onOutput: (chunk) => chunks.push(chunk.data),
    });
    expect(outcome.state).toBe("completed");
    if (outcome.state !== "completed") return;
    expect(outcome.exitCode).toBe(0);
    expect(outcome.stdout).toContain("hello-out");
    expect(outcome.stderr).toContain("hello-err");
    expect(chunks.join("")).toContain("hello-out");
    expect(outcome.record).toMatchObject({
      requestId: plan.requestId,
      toolCallId: plan.toolCallId,
      planDigest: plan.digest,
      state: "completed",
      started: true,
      impact: "known",
      exitCode: 0,
    });
    expect(records).toHaveLength(1);
    expect(records[0]!.planDigest).toBe(plan.digest);
  });

  it("reports a business non-zero exit as a completed execution", async () => {
    const testLayout = layout();
    const controller = controllerFor(testLayout, "ok");
    const plan = shellPlan(
      testLayout.workspace,
      `"${process.execPath}" -e "process.stderr.write('bad');process.exit(7)"`,
    );
    const outcome = await controller.execute({ plan });
    expect(outcome.state).toBe("completed");
    if (outcome.state !== "completed") return;
    expect(outcome.exitCode).toBe(7);
    expect(outcome.stderr).toContain("bad");
    expect(outcome.record.state).toBe("completed");
    expect(outcome.record.exitCode).toBe(7);
  });

  it("refuses a plan compiled for another backend before starting", async () => {
    const testLayout = layout();
    const controller = makeController({
      layout: testLayout,
      installation: {
        ...installFixtureHelper(testLayout),
        expectedBackendId: "another-helper",
      },
      helperEnvironment: fixtureEnvironment("ok"),
    });
    controllers.push(controller);
    const outcome = await controller.execute({
      plan: shellPlan(testLayout.workspace, "echo never"),
    });
    expect(outcome.state).toBe("failed");
    if (outcome.state !== "failed") return;
    expect(outcome.code).toBe("binding-mismatch");
    expect(outcome.started).toBe(false);
    expect(outcome.impact).toBe("none");
  });

  it("never starts when the helper rejects the plan", async () => {
    const testLayout = layout();
    const controller = controllerFor(testLayout, "reject");
    const plan = shellPlan(testLayout.workspace, "echo never");
    const outcome = await controller.execute({ plan });
    expect(outcome.state).toBe("failed");
    if (outcome.state !== "failed") return;
    expect(outcome.code).toBe("sandbox-denied");
    expect(outcome.started).toBe(false);
    expect(outcome.impact).toBe("none");
  });

  it("fails before start when the backend cannot express the plan", async () => {
    const testLayout = layout();
    const controller = controllerFor(testLayout, "unsupported");
    const plan = shellPlan(testLayout.workspace, "echo never");
    const outcome = await controller.execute({ plan });
    expect(outcome.state).toBe("failed");
    if (outcome.state !== "failed") return;
    expect(outcome.code).toBe("sandbox-capability-unsupported");
    expect(outcome.started).toBe(false);
    expect(outcome.impact).toBe("none");
  });

  it("reports a start timeout with an unknown start state", async () => {
    const testLayout = layout();
    const controller = controllerFor(testLayout, "no-start", {
      startTimeoutMs: 250,
      cancelGraceMs: 150,
    });
    const plan = shellPlan(testLayout.workspace, "echo never");
    const outcome = await controller.execute({ plan });
    expect(outcome.state).toBe("failed");
    if (outcome.state !== "failed") return;
    expect(outcome.code).toBe("sandbox-start-failed");
    expect(outcome.started).toBe("unknown");
    expect(outcome.impact).toBe("unknown");
  });

  it("cancels a running helper once and keeps repeated cancellation idempotent", async () => {
    const testLayout = layout();
    const controller = controllerFor(testLayout, "slow", {
      cancelGraceMs: 300,
    });
    const plan = shellPlan(testLayout.workspace, "ignored");
    const abort = new AbortController();
    const chunks: string[] = [];
    const running = controller.execute({
      plan,
      signal: abort.signal,
      onOutput: (chunk) => chunks.push(chunk.data),
    });
    await waitFor(() => controller.activeCount === 1);
    // The slow fixture only streams after acknowledging `started`.
    await waitFor(() => chunks.length > 0);
    abort.abort();
    const outcome = await running;
    expect(outcome.state).toBe("cancelled");
    if (outcome.state !== "cancelled") return;
    expect(outcome.code).toBe("execution-cancelled");
    expect(outcome.started).toBe(true);
    expect(outcome.impact).toBe("unknown");
    await controller.cancel(plan.requestId);
    await controller.cancel(plan.requestId);
    expect(controller.activeCount).toBe(0);
  });

  it("reports a lost transport without inventing a start state", async () => {
    const testLayout = layout();
    const controller = controllerFor(testLayout, "eof");
    const plan = shellPlan(testLayout.workspace, "echo never");
    const outcome = await controller.execute({ plan });
    expect(outcome.state).toBe("failed");
    if (outcome.state !== "failed") return;
    expect(outcome.code).toBe("sandbox-transport-lost");
    expect(outcome.started).toBe(true);
    expect(outcome.impact).toBe("unknown");
  });

  it("bounds helper output and reports the protocol error for bad ordering", async () => {
    const testLayout = layout();
    const huge = controllerFor(testLayout, "huge", { cancelGraceMs: 200 });
    const hugeOutcome = await huge.execute({
      plan: shellPlan(testLayout.workspace, "ignored"),
    });
    expect(hugeOutcome.state).toBe("failed");
    if (hugeOutcome.state === "failed") {
      expect(hugeOutcome.code).toBe("sandbox-output-limit");
    }

    const orderingLayout = layout();
    const ordering = controllerFor(orderingLayout, "out-of-order");
    const orderingOutcome = await ordering.execute({
      plan: shellPlan(orderingLayout.workspace, "ignored"),
    });
    expect(orderingOutcome.state).toBe("failed");
    if (orderingOutcome.state === "failed") {
      expect(orderingOutcome.code).toBe("sandbox-protocol-error");
      expect(orderingOutcome.started).toBe(true);
    }
  });

  it("keeps a partial execution with unknown impact distinct from zero start", async () => {
    const testLayout = layout();
    const controller = controllerFor(testLayout, "partial-error");
    const outcome = await controller.execute({
      plan: shellPlan(testLayout.workspace, "ignored"),
    });
    expect(outcome.state).toBe("failed");
    if (outcome.state !== "failed") return;
    expect(outcome.code).toBe("execution-failed");
    expect(outcome.started).toBe(true);
    expect(outcome.impact).toBe("unknown");
    expect(outcome.stdout).toContain("partial output");
  });

  it("reclaims a stubborn helper's grandchild process tree", async () => {
    const testLayout = layout();
    const pidFile = join(testLayout.root, "grandchild.pid");
    const controller = makeController({
      layout: testLayout,
      scenario: "grandchild",
      helperEnvironment: fixtureEnvironment("grandchild", {
        FIXTURE_PID_FILE: pidFile,
      }),
      cancelGraceMs: 250,
    });
    controllers.push(controller);
    const plan = shellPlan(testLayout.workspace, "ignored");
    const running = controller.execute({ plan });
    await waitFor(() => controller.activeCount === 1);
    let grandchildPid = 0;
    await waitFor(() => {
      try {
        grandchildPid = Number.parseInt(readFileSync(pidFile, "utf8"), 10);
        return Number.isInteger(grandchildPid) && grandchildPid > 0;
      } catch {
        return false;
      }
    });
    await controller.cancel(plan.requestId);
    const outcome = await running;
    expect(outcome.state).toBe("cancelled");
    expect(await waitForProcessGone(grandchildPid, 5_000)).toBe(true);
  });

  it("ignores a late result from an older execution generation", async () => {
    const testLayout = layout();
    const controller = controllerFor(testLayout, "late-generation");
    const outcome = await controller.execute({
      plan: shellPlan(testLayout.workspace, "ignored"),
    });
    expect(outcome.state).toBe("completed");
    if (outcome.state !== "completed") return;
    expect(outcome.exitCode).toBe(0);
    expect(outcome.record.state).toBe("completed");
  });

  it("enforces the queue bound without starting another helper", async () => {
    const testLayout = layout();
    const controller = controllerFor(testLayout, "slow", {
      maxConcurrent: 1,
      maxQueue: 0,
    });
    const first = controller.execute({
      plan: shellPlan(testLayout.workspace, "ignored", { requestId: "first" }),
    });
    await waitFor(() => controller.activeCount === 1);
    const second = await controller.execute({
      plan: shellPlan(testLayout.workspace, "ignored", { requestId: "second" }),
    });
    expect(second.state).toBe("failed");
    if (second.state === "failed") {
      expect(second.code).toBe("sandbox-queue-full");
      expect(second.started).toBe(false);
    }
    await controller.cancel("first");
    await first;
  });

  it("invalidates queued and running plans after a configuration change", async () => {
    const testLayout = layout();
    const controller = controllerFor(testLayout, "slow", {
      maxConcurrent: 1,
      maxQueue: 2,
    });
    const first = controller.execute({
      plan: shellPlan(testLayout.workspace, "ignored", { requestId: "first" }),
    });
    await waitFor(() => controller.activeCount === 1);
    const second = controller.execute({
      plan: shellPlan(testLayout.workspace, "ignored", { requestId: "second" }),
    });
    await waitFor(() => controller.queuedCount === 1);
    await controller.updateConfiguration();
    const [firstOutcome, secondOutcome] = await Promise.all([first, second]);
    expect(firstOutcome.state).toBe("cancelled");
    expect(secondOutcome.state).toBe("cancelled");
    if (firstOutcome.state === "cancelled") {
      expect(firstOutcome.code).toBe("plan-invalidated");
    }
    if (secondOutcome.state === "cancelled") {
      expect(secondOutcome.code).toBe("plan-invalidated");
      expect(secondOutcome.started).toBe(false);
    }
  });
});

describe("egress lease seam", () => {
  function destinationsPlan(workspace: string, requestId: string): ExecutionPlan {
    const invocation = makeInvocation({
      cwd: workspace,
      toolName: "bash",
      args: { command: "curl https://api.example.com" },
      requestId,
      toolCallId: `call-${requestId}`,
      scopes: [
        {
          id: "scope-net-1",
          surface: "test",
          target: "api.example.com:443",
          access: "network",
          state: "allow",
          source: "test",
        },
      ],
    });
    return compileTestPlan({
      invocation,
      operation: { kind: "shell", command: "curl https://api.example.com" },
      workspace,
      environment: runtimeEnvironment(),
      approved: { filesystem: [], network: [{ host: "api.example.com", port: 443 }] },
      deadlineMs: 10_000,
    });
  }

  function egressStub() {
    const acquired: string[] = [];
    const revoked: string[] = [];
    const provider: EgressProvider = {
      acquire: async (plan) => {
        acquired.push(plan.requestId);
        return {
          leaseId: `lease-${plan.requestId}`,
          proxyHost: "127.0.0.1",
          proxyPort: 19090,
          credential: `cred-${plan.requestId}`,
        };
      },
      revoke: (leaseId) => {
        revoked.push(leaseId);
      },
    };
    return { provider, acquired, revoked };
  }

  it("passes the grant to the helper and revokes it after settle", async () => {
    const testLayout = createTestLayout();
    layouts.push(testLayout);
    installFixtureHelper(testLayout);
    const { provider, acquired, revoked } = egressStub();
    const controller = controllerFor(testLayout, "echo-egress", {
      egress: provider,
      extraEnv: { FIXTURE_NETWORK: "domains" },
    });
    const outcome = await controller.execute({
      plan: destinationsPlan(testLayout.workspace, "request-egress-ok"),
    });
    expect(outcome.state).toBe("completed");
    expect(outcome.stdout).toContain("egress:lease-request-egress-ok");
    expect(acquired).toEqual(["request-egress-ok"]);
    expect(revoked).toEqual(["lease-request-egress-ok"]);
  });

  it("refuses the launch when the host cannot grant egress", async () => {
    const testLayout = createTestLayout();
    layouts.push(testLayout);
    installFixtureHelper(testLayout);
    const revoked: string[] = [];
    const provider: EgressProvider = {
      acquire: async () => null,
      revoke: (leaseId) => {
        revoked.push(leaseId);
      },
    };
    const controller = controllerFor(testLayout, "ok", {
      egress: provider,
      extraEnv: { FIXTURE_NETWORK: "domains" },
    });
    const outcome = await controller.execute({
      plan: destinationsPlan(testLayout.workspace, "request-egress-missing"),
    });
    expect(outcome.state).toBe("failed");
    if (outcome.state === "failed") {
      expect(outcome.code).toBe("sandbox-capability-unsupported");
      expect(outcome.started).toBe(false);
      expect(outcome.impact).toBe("none");
    }
    expect(revoked).toEqual([]);
  });

  it("revokes the lease when the execution is cancelled", async () => {
    const testLayout = createTestLayout();
    layouts.push(testLayout);
    installFixtureHelper(testLayout);
    const { provider, acquired, revoked } = egressStub();
    const controller = controllerFor(testLayout, "slow", {
      egress: provider,
      extraEnv: { FIXTURE_NETWORK: "domains" },
    });
    const abort = new AbortController();
    const running = controller.execute({
      plan: destinationsPlan(testLayout.workspace, "request-egress-cancel"),
      signal: abort.signal,
    });
    await waitFor(() => acquired.includes("request-egress-cancel"));
    abort.abort();
    const outcome = await running;
    expect(outcome.state).toBe("cancelled");
    expect(revoked).toEqual(["lease-request-egress-cancel"]);
  });
});
