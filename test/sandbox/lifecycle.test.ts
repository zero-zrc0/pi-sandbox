import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { ExecutionController, type EgressProvider } from "#sandbox/lifecycle";
import type { ExecutionRequest, NetworkScope } from "#sandbox/types";
import type { DirectBackendDriver } from "#sandbox/backend/direct";
import {
  compileTestRequest,
  createTestLayout,
  makeController,
  makeInvocation,
  processExists,
  removeTestLayout,
  runtimeEnvironment,
  testExecutionEnvironment,
  waitFor,
  waitForProcessGone,
  type TestLayout,
} from "./fixtures/harness";
import { createTestDirectBackend } from "./fixtures/direct-backend";

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

function shellRequest(
  workspace: string,
  command = "ignored",
  options: {
    readonly deadlineMs?: number;
    readonly requestId?: string;
    readonly toolCallId?: string;
    readonly sessionId?: string;
    readonly network?: NetworkScope;
  } = {},
): ExecutionRequest {
  const invocation = makeInvocation({
    cwd: workspace,
    toolName: "bash",
    args: { command },
    requestId: options.requestId ?? `request-${Math.random().toString(16).slice(2)}`,
    toolCallId: options.toolCallId ?? `call-${Math.random().toString(16).slice(2)}`,
    ...(options.sessionId === undefined ? {} : { sessionId: options.sessionId }),
  });
  return compileTestRequest({
    invocation,
    operation: { kind: "shell", command },
    workspace,
    environment: runtimeEnvironment(),
    deadlineMs: options.deadlineMs ?? 10_000,
    ...(options.network === undefined ? {} : { network: options.network }),
  });
}

function controllerFor(
  testLayout: TestLayout,
  options: {
    readonly scenario?: string;
    readonly directBackend?: DirectBackendDriver;
    readonly startTimeoutMs?: number;
    readonly cancelGraceMs?: number;
    readonly maxConcurrent?: number;
    readonly maxQueue?: number;
    readonly probeTimeoutMs?: number;
    readonly environment?: Readonly<Record<string, string>>;
    readonly egress?: EgressProvider;
    readonly onRecord?: ConstructorParameters<typeof ExecutionController>[0]["onRecord"];
  } = {},
): ExecutionController {
  const controller = makeController({
    layout: testLayout,
    scenario: options.scenario,
    directBackend: options.directBackend,
    environment: options.environment,
    startTimeoutMs: options.startTimeoutMs ?? 5_000,
    cancelGraceMs: options.cancelGraceMs ?? 100,
    maxConcurrent: options.maxConcurrent ?? 2,
    maxQueue: options.maxQueue ?? 4,
    ...(options.probeTimeoutMs === undefined ? {} : { probeTimeoutMs: options.probeTimeoutMs }),
    ...(options.onRecord === undefined ? {} : { onRecord: options.onRecord }),
    ...(options.egress === undefined ? {} : { egress: options.egress }),
  });
  controllers.push(controller);
  return controller;
}

function egressStub() {
  const acquired: string[] = [];
  const revoked: string[] = [];
  const provider: EgressProvider = {
    acquire: async () => {
      const grant = {
        leaseId: `lease-${acquired.length + 1}`,
        proxyHost: "127.0.0.1",
        proxyPort: 43123,
        credential: "fixture-secret",
      };
      acquired.push(grant.leaseId);
      return grant;
    },
    revoke: (leaseId) => revoked.push(leaseId),
  };
  return { provider, acquired, revoked };
}

describe("direct backend lifecycle", () => {
  it("uses the captured request while the backend probe is pending", async () => {
    const testLayout = layout();
    let releaseProbe!: () => void;
    let enteredProbe!: () => void;
    const entered = new Promise<void>((resolve) => { enteredProbe = resolve; });
    const held = new Promise<void>((resolve) => { releaseProbe = resolve; });
    const base = createTestDirectBackend();
    const probeResult = await base.probe();
    if (!probeResult.ok) throw new Error("test backend probe failed");
    const directBackend: DirectBackendDriver = {
      ...base,
      async probe() {
        enteredProbe();
        await held;
        return probeResult;
      },
    };
    const controller = controllerFor(testLayout, { directBackend });
    const target = join(testLayout.workspace, "captured.txt");
    const tampered = join(testLayout.workspace, "tampered.txt");
    const request = compileTestRequest({
      invocation: makeInvocation({ cwd: testLayout.workspace, toolName: "write", args: { path: "captured.txt", content: "captured" } }),
      operation: { kind: "write-file", path: target, content: "captured" },
      workspace: testLayout.workspace,
      environment: runtimeEnvironment(),
    });
    const forge = JSON.parse(JSON.stringify(request)) as ExecutionRequest;
    const running = controller.execute({ request: forge });
    await entered;
    (forge.start.operation as { path: string; content: string }).path = tampered;
    (forge.start.operation as { path: string; content: string }).content = "tampered";
    releaseProbe();

    const outcome = await running;
    expect(outcome.state).toBe("completed");
    expect(readFileSync(target, "utf8")).toBe("captured");
    expect(existsSync(tampered)).toBe(false);
  });

  it("rejects accessors without invoking them", async () => {
    const testLayout = layout();
    const controller = controllerFor(testLayout);
    const request = JSON.parse(JSON.stringify(shellRequest(testLayout.workspace))) as ExecutionRequest;
    let touched = 0;
    Object.defineProperty(request.start.operation, "command", {
      get() { touched += 1; return "echo forbidden"; },
    });

    const outcome = await controller.execute({ request });
    expect(outcome.state).toBe("failed");
    if (outcome.state === "failed") expect(outcome.code).toBe("invalid-plan");
    expect(outcome.started).toBe(false);
    expect(touched).toBe(0);
  });

  it("reports an unavailable backend without launching a process", async () => {
    const testLayout = layout();
    const controller = controllerFor(testLayout, { scenario: "unavailable" });
    expect(await controller.probe()).toMatchObject({ status: "unavailable" });
    const outcome = await controller.execute({ request: shellRequest(testLayout.workspace) });
    expect(outcome.state).toBe("failed");
    if (outcome.state === "failed") expect(outcome.code).toBe("sandbox-unavailable");
    expect(outcome.started).toBe(false);
  });

  it("streams process output and records exactly one result", async () => {
    const testLayout = layout();
    const records: unknown[] = [];
    const base = createTestDirectBackend();
    const directBackend: DirectBackendDriver = {
      ...base,
      async prepare(request) {
        return {
          executable: process.execPath,
          args: ["-e", "process.stdout.write('hello-out');process.stderr.write('hello-err')"],
          cwd: request.start.cwd,
          environment: request.start.environment,
          outputMode: "stream",
        };
      },
    };
    const controller = controllerFor(testLayout, { directBackend, onRecord: (record) => records.push(record) });
    const chunks: string[] = [];
    const outcome = await controller.execute({
      request: shellRequest(testLayout.workspace),
      onOutput: (chunk) => chunks.push(`${chunk.stream}:${chunk.data}`),
    });
    expect(outcome.state).toBe("completed");
    expect(outcome.stdout).toContain("hello-out");
    expect(outcome.stderr).toContain("hello-err");
    expect(chunks.join("")).toContain("stdout:hello-out");
    expect(records).toHaveLength(1);
  });

  it("keeps a business nonzero exit as a completed execution", async () => {
    const testLayout = layout();
    const base = createTestDirectBackend();
    const directBackend: DirectBackendDriver = {
      ...base,
      async prepare(request) {
        return {
          executable: process.execPath,
          args: ["-e", "process.exit(7)"],
          cwd: request.start.cwd,
          environment: request.start.environment,
          outputMode: "stream",
        };
      },
    };
    const controller = controllerFor(testLayout, { directBackend });
    const outcome = await controller.execute({ request: shellRequest(testLayout.workspace) });
    expect(outcome.state).toBe("completed");
    if (outcome.state === "completed") expect(outcome.exitCode).toBe(7);
  });

  it("maps backend startup rejection and preserves unknown-start classification", async () => {
    const rejectedLayout = layout();
    const rejected = controllerFor(rejectedLayout, { scenario: "reject" });
    const refusal = await rejected.execute({ request: shellRequest(rejectedLayout.workspace) });
    expect(refusal.state).toBe("failed");
    if (refusal.state === "failed") expect(refusal.code).toBe("sandbox-denied");
    expect(refusal.started).toBe(false);

    const timeoutLayout = layout();
    const base = createTestDirectBackend();
    const directBackend: DirectBackendDriver = {
      ...base,
      async prepare(request) {
        return {
          executable: process.execPath,
          args: ["-e", "setInterval(() => {}, 1000)"],
          cwd: request.start.cwd,
          environment: request.start.environment,
          readyMarker: "marker-that-never-arrives",
          outputMode: "stream",
        };
      },
    };
    const timed = controllerFor(timeoutLayout, { directBackend, startTimeoutMs: 80, cancelGraceMs: 10 });
    const timeout = await timed.execute({ request: shellRequest(timeoutLayout.workspace) });
    expect(timeout.state).toBe("failed");
    if (timeout.state === "failed") {
      expect(timeout.code).toBe("sandbox-start-failed");
      expect(timeout.started).toBe("unknown");
    }
  });

  it("bounds streamed output and cancels the native process", async () => {
    const testLayout = layout();
    const controller = controllerFor(testLayout, { scenario: "huge", cancelGraceMs: 10 });
    const outcome = await controller.execute({ request: shellRequest(testLayout.workspace) });
    expect(outcome.state).toBe("failed");
    if (outcome.state === "failed") {
      expect(outcome.code).toBe("sandbox-output-limit");
      expect(outcome.started).toBe(true);
      expect(Buffer.byteLength(outcome.stdout, "utf8")).toBeLessThanOrEqual(4 * 1024 * 1024);
    }
  });

  it("cancels a running process tree before resolving", async () => {
    const testLayout = layout();
    const pidFile = join(testLayout.root, "native-child.pid");
    const controller = controllerFor(testLayout, {
      scenario: "stubborn",
      cancelGraceMs: 30,
      environment: testExecutionEnvironment({ FIXTURE_PID_FILE: pidFile }),
    });
    const request = shellRequest(testLayout.workspace, "ignored", { requestId: "cancel-tree" });
    const running = controller.execute({ request });
    await waitFor(() => existsSync(pidFile));
    const childPid = Number.parseInt(readFileSync(pidFile, "utf8"), 10);
    await controller.cancel(request.requestId);
    const outcome = await running;
    expect(outcome.state).toBe("cancelled");
    expect(controller.activeCount).toBe(0);
    expect(await waitForProcessGone(childPid, 2_000)).toBe(true);
    expect(processExists(childPid)).toBe(false);
  });

  it("enforces the execution deadline", async () => {
    const testLayout = layout();
    const controller = controllerFor(testLayout, { scenario: "slow", cancelGraceMs: 10 });
    const outcome = await controller.execute({
      request: shellRequest(testLayout.workspace, "ignored", { deadlineMs: 100 }),
    });
    expect(outcome.state).toBe("cancelled");
    if (outcome.state === "cancelled") expect(outcome.code).toBe("execution-timeout");
    expect(controller.activeCount).toBe(0);
  });

  it("limits concurrency and resolves queued executions after a slot opens", async () => {
    const testLayout = layout();
    const base = createTestDirectBackend();
    const directBackend: DirectBackendDriver = {
      ...base,
      async prepare(request, egress, signal) {
        if (request.requestId === "long") {
          return {
            executable: process.execPath,
            args: ["-e", "setInterval(() => {}, 1000)"],
            cwd: request.start.cwd,
            environment: request.start.environment,
            outputMode: "stream",
          };
        }
        return base.prepare(request, egress, signal);
      },
    };
    const controller = controllerFor(testLayout, { directBackend, maxConcurrent: 1, maxQueue: 1, cancelGraceMs: 10 });
    const firstRequest = shellRequest(testLayout.workspace, "ignored", { requestId: "long" });
    const secondRequest = shellRequest(testLayout.workspace, "ignored", { requestId: "queued" });
    const first = controller.execute({ request: firstRequest });
    await waitFor(() => controller.activeCount === 1);
    const second = controller.execute({ request: secondRequest });
    await waitFor(() => controller.queuedCount === 1);
    const overflow = await controller.execute({ request: shellRequest(testLayout.workspace, "ignored", { requestId: "overflow" }) });
    expect(overflow.state).toBe("failed");
    if (overflow.state === "failed") expect(overflow.code).toBe("sandbox-queue-full");
    await controller.cancel(firstRequest.requestId);
    expect((await first).state).toBe("cancelled");
    expect((await second).state).toBe("completed");
  });

  it("acquires egress before launch and revokes the lease after settle", async () => {
    const testLayout = layout();
    const { provider, acquired, revoked } = egressStub();
    const controller = controllerFor(testLayout, { scenario: "echo-egress", egress: provider });
    const outcome = await controller.execute({
      request: shellRequest(testLayout.workspace, "ignored", {
        network: { kind: "destinations", destinations: [{ host: "api.example.com", port: 443 }] },
      }),
    });
    expect(outcome.state).toBe("completed");
    expect(outcome.stdout).toContain(acquired[0]);
    expect(acquired).toHaveLength(1);
    expect(revoked).toEqual(acquired);
  });

  it("refuses destination networking when no egress grant is available", async () => {
    const testLayout = layout();
    const controller = controllerFor(testLayout);
    const outcome = await controller.execute({
      request: shellRequest(testLayout.workspace, "ignored", {
        network: { kind: "destinations", destinations: [{ host: "api.example.com", port: 443 }] },
      }),
    });
    expect(outcome.state).toBe("failed");
    if (outcome.state === "failed") expect(outcome.code).toBe("sandbox-capability-unsupported");
    expect(outcome.started).toBe(false);
  });

  it("revokes egress immediately when a running operation is cancelled", async () => {
    const testLayout = layout();
    const { provider, acquired, revoked } = egressStub();
    const controller = controllerFor(testLayout, { scenario: "slow", egress: provider, cancelGraceMs: 10 });
    const request = shellRequest(testLayout.workspace, "ignored", {
      requestId: "egress-cancel",
      network: { kind: "destinations", destinations: [{ host: "api.example.com", port: 443 }] },
    });
    const running = controller.execute({ request });
    await waitFor(() => controller.activeCount === 1 && acquired.length === 1);
    await controller.cancel(request.requestId);
    expect((await running).state).toBe("cancelled");
    expect(revoked).toEqual(acquired);
  });
});
