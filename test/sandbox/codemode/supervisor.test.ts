import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { CodemodeResult } from "@earendil-works/pi-codemode";
import { describe, expect, it, vi } from "vitest";
import {
  CodemodeRuntimeSupervisor,
  createPiCodemodeRuntimeFactory,
  type CodemodeRuntimeFactoryInput,
  type CodemodeRuntimeSession,
} from "#sandbox/codemode/supervisor";
import { windowsRuntimeFiles } from "../fixtures/runtime";

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function success(value: unknown): CodemodeResult {
  return { ok: true, value, output: [], calls: [], storeWrites: { set: {}, delete: [] } };
}

function fakeFactory() {
  const executions: Array<{ code: string; resolve(result: CodemodeResult): void }> = [];
  const exits: Array<ReturnType<typeof deferred<void>>> = [];
  const factory = vi.fn(async (input: CodemodeRuntimeFactoryInput) => {
    const exit = deferred<void>();
    exits.push(exit);
    let transferred = false;
    return {
      execute: (code: string) => {
        if (!transferred) {
          if (!input.transferRuntime(exit.promise)) throw new Error("Runtime admission expired");
          transferred = true;
        }
        return new Promise<CodemodeResult>(resolve => executions.push({ code, resolve }));
      },
      close: vi.fn(async () => undefined),
    };
  });
  return { factory, executions, exits };
}

describe("Codemode Runtime supervisor", () => {
  it("returns a result before worker exit but keeps the shared Runtime slot until exit is confirmed", async () => {
    const fake = fakeFactory();
    const supervisor = new CodemodeRuntimeSupervisor({
      createRuntime: fake.factory,
      maxActiveRuntimes: 1,
      maxQueuedRuntimes: 1,
    });

    const first = supervisor.execute({ backend: "full-access", code: "first" });
    await vi.waitFor(() => expect(fake.executions).toHaveLength(1));
    const second = supervisor.execute({ backend: "restricted", code: "second" });
    expect(supervisor.snapshot).toEqual({ activeRuntimes: 1, queuedRuntimes: 1 });

    fake.executions[0]!.resolve(success("first-result"));
    await expect(first).resolves.toMatchObject({ ok: true, value: "first-result" });
    expect(fake.executions).toHaveLength(1);

    fake.exits[0]!.resolve();
    await vi.waitFor(() => expect(fake.executions).toHaveLength(2));
    expect(fake.executions[1]!.code).toBe("second");
    fake.executions[1]!.resolve(success("second-result"));
    fake.exits[1]!.resolve();
    await expect(second).resolves.toMatchObject({ ok: true, value: "second-result" });
    await vi.waitFor(() => expect(supervisor.snapshot).toEqual({ activeRuntimes: 0, queuedRuntimes: 0 }));
  });

  it("admits queued executions in FIFO order and rejects work beyond the bounded queue", async () => {
    const fake = fakeFactory();
    const supervisor = new CodemodeRuntimeSupervisor({
      createRuntime: fake.factory,
      maxActiveRuntimes: 1,
      maxQueuedRuntimes: 2,
    });

    const first = supervisor.execute({ backend: "full-access", code: "first" });
    await vi.waitFor(() => expect(fake.executions).toHaveLength(1));
    const second = supervisor.execute({ backend: "full-access", code: "second" });
    const third = supervisor.execute({ backend: "full-access", code: "third" });
    const rejected = await supervisor.execute({ backend: "full-access", code: "fourth" });
    expect(rejected).toMatchObject({ ok: false, error: { kind: "sandbox", message: expect.stringContaining("queue is full") } });

    fake.executions[0]!.resolve(success("first"));
    fake.exits[0]!.resolve();
    await expect(first).resolves.toMatchObject({ ok: true });
    await vi.waitFor(() => expect(fake.executions).toHaveLength(2));
    expect(fake.executions[1]!.code).toBe("second");
    fake.executions[1]!.resolve(success("second"));
    fake.exits[1]!.resolve();
    await expect(second).resolves.toMatchObject({ ok: true });
    await vi.waitFor(() => expect(fake.executions).toHaveLength(3));
    expect(fake.executions[2]!.code).toBe("third");
    fake.executions[2]!.resolve(success("third"));
    fake.exits[2]!.resolve();
    await expect(third).resolves.toMatchObject({ ok: true });
  });

  it("times out while queued without starting a Runtime and removes the stale waiter", async () => {
    const fake = fakeFactory();
    const supervisor = new CodemodeRuntimeSupervisor({
      createRuntime: fake.factory,
      maxActiveRuntimes: 1,
      maxQueuedRuntimes: 1,
      queueWaitMs: 1_000,
    });

    const first = supervisor.execute({ backend: "full-access", code: "first" });
    await vi.waitFor(() => expect(fake.executions).toHaveLength(1));
    const second = supervisor.execute({ backend: "restricted", code: "second", timeoutMs: 20 });
    await expect(second).resolves.toMatchObject({ ok: false, error: { kind: "timeout" } });
    expect(fake.factory).toHaveBeenCalledTimes(1);
    expect(supervisor.snapshot).toEqual({ activeRuntimes: 1, queuedRuntimes: 0 });

    fake.executions[0]!.resolve(success("first"));
    fake.exits[0]!.resolve();
    await first;
    await vi.waitFor(() => expect(supervisor.snapshot.activeRuntimes).toBe(0));
    expect(fake.factory).toHaveBeenCalledTimes(1);
  });

  it("keeps the slot occupied after cleanup failure and does not replace the Runtime", async () => {
    const fake = fakeFactory();
    const onCleanupFailure = vi.fn();
    const supervisor = new CodemodeRuntimeSupervisor({
      createRuntime: fake.factory,
      maxActiveRuntimes: 1,
      maxQueuedRuntimes: 1,
      queueWaitMs: 1_000,
      onCleanupFailure,
    });

    const first = supervisor.execute({ backend: "full-access", code: "first" });
    await vi.waitFor(() => expect(fake.executions).toHaveLength(1));
    const cancelSecond = new AbortController();
    const second = supervisor.execute({ backend: "full-access", code: "second", signal: cancelSecond.signal });
    fake.executions[0]!.resolve(success("first"));
    await first;
    fake.exits[0]!.reject(new Error("exit confirmation failed"));
    await vi.waitFor(() => expect(onCleanupFailure).toHaveBeenCalledWith(expect.objectContaining({ message: "exit confirmation failed" })));

    expect(supervisor.snapshot).toEqual({ activeRuntimes: 1, queuedRuntimes: 1 });
    expect(fake.factory).toHaveBeenCalledTimes(1);
    cancelSecond.abort();
    await expect(second).resolves.toMatchObject({ ok: false, error: { kind: "aborted" } });
    expect(supervisor.snapshot).toEqual({ activeRuntimes: 1, queuedRuntimes: 0 });
    expect(fake.factory).toHaveBeenCalledTimes(1);
  });

  it("includes asynchronous Runtime setup in the script deadline and blocks a late start", async () => {
    const creation = deferred<CodemodeRuntimeSession>();
    const execute = vi.fn(async (_code: string) => success("must-not-run"));
    const close = vi.fn(async () => undefined);
    const supervisor = new CodemodeRuntimeSupervisor({
      createRuntime: () => creation.promise,
      maxActiveRuntimes: 1,
      queueWaitMs: 1_000,
    });

    const execution = supervisor.execute({ backend: "full-access", code: "late", timeoutMs: 20 });
    await expect(execution).resolves.toMatchObject({ ok: false, error: { kind: "timeout" } });
    expect(supervisor.snapshot.activeRuntimes).toBe(1);

    creation.resolve({ execute, close });
    await vi.waitFor(() => expect(supervisor.snapshot.activeRuntimes).toBe(0));
    expect(execute).not.toHaveBeenCalled();
    expect(close).toHaveBeenCalledOnce();
  });
});

const windowsRuntime = fileURLToPath(new URL("../../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url));
const hasWindowsRuntime = process.platform === "win32" && existsSync(windowsRuntime);

describe.each([
  ["host worker", "full-access" as const],
  ["Windows restricted process", "restricted" as const],
])("real %s Runtime supervisor contract", (_label, backend) => {
  it.skipIf(backend === "restricted" && !hasWindowsRuntime)("round-trips calls and errors, hard-cancels a loop, and isolates a late tool result", async () => {
    const supervisor = new CodemodeRuntimeSupervisor({
      createRuntime: createPiCodemodeRuntimeFactory(() => windowsRuntimeFiles()),
      maxActiveRuntimes: 1,
      maxQueuedRuntimes: 1,
    });

    const roundTrip = await supervisor.execute({
      backend,
      code: 'const value = await tools.echo({ text: "ok" }); text(value.text); return value;',
      tools: [{ name: "echo", execute: args => args }],
      timeoutMs: 10_000,
    });
    expect(roundTrip, JSON.stringify(roundTrip)).toMatchObject({
      ok: true,
      value: { text: "ok" },
      output: [{ type: "text", text: "ok" }],
      calls: [{ name: "echo", status: "ok" }],
    });

    const scriptError = await supervisor.execute({ backend, code: 'throw new Error("script-failure");', timeoutMs: 10_000 });
    expect(scriptError).toMatchObject({ ok: false, error: { kind: "script", message: "script-failure" } });

    const lateResult = deferred<unknown>();
    let callSignal: AbortSignal | undefined;
    const abort = new AbortController();
    const running = supervisor.execute({
      backend,
      code: 'void tools.delayed({}); while (true) {}',
      signal: abort.signal,
      timeoutMs: Infinity,
      tools: [{
        name: "delayed",
        execute: (_args, context) => {
          callSignal = context.signal;
          return lateResult.promise;
        },
      }],
    });
    await vi.waitFor(() => expect(callSignal).toBeDefined());
    abort.abort();
    await expect(running).resolves.toMatchObject({ ok: false, error: { kind: "aborted" } });
    expect(callSignal?.aborted).toBe(true);
    lateResult.resolve({ message: "late" });

    const afterCancel = await supervisor.execute({ backend, code: "return 7;", timeoutMs: 10_000 });
    expect(afterCancel).toMatchObject({ ok: true, value: 7 });
    await vi.waitFor(() => expect(supervisor.snapshot.activeRuntimes).toBe(0));
  }, 30_000);
});
