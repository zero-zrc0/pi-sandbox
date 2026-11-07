import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";

import {
  ControlledOperationError,
  createControlledOperations,
  detectImageMimeType,
  type RunControlledOperation,
} from "#sandbox/operations";
import type {
  ExecutionOperation,
  ExecutionOutcome,
  ExecutionRecord,
} from "#sandbox/types";

function record(state: ExecutionRecord["state"]): ExecutionRecord {
  return {
    requestId: "request-1",
    toolCallId: "call-1",
    actionDigest: "action",
    planDigest: "plan",
    generation: 1,
    toolName: "bash",
    started: state === "failed" ? false : true,
    state,
    impact: state === "completed" ? "known" : "none",
    ...(state === "completed" ? { exitCode: 0 } : { code: "execution-failed" }),
  };
}

function completed(
  fields: Partial<Extract<ExecutionOutcome, { state: "completed" }>> = {},
): ExecutionOutcome {
  return {
    state: "completed",
    started: true,
    exitCode: 0,
    stdout: "",
    stderr: "",
    truncated: false,
    record: record("completed"),
    ...fields,
  };
}

function refused(code: string): ExecutionOutcome {
  return {
    state: "failed",
    started: false,
    code: code as Extract<ExecutionOutcome, { state: "failed" }>["code"],
    reason: "fixture failure",
    impact: "none",
    stdout: "",
    stderr: "",
    truncated: false,
    record: record("failed"),
  };
}

describe("controlled Pi operations", () => {
  it("streams shell output and returns the helper exit code", async () => {
    const calls: ExecutionOperation[] = [];
    const run: RunControlledOperation = async (operation, options) => {
      calls.push(operation);
      options.onOutput?.({ stream: "stdout", data: "hello" });
      options.onOutput?.({ stream: "stderr", data: "warning" });
      return completed({ exitCode: 3, stdout: "hello", stderr: "warning" });
    };
    const operations = createControlledOperations(run);
    const chunks: string[] = [];
    const result = await operations.bash.exec("echo hello", "C:\\work", {
      onData: (data) => chunks.push(data.toString("utf8")),
      timeout: 2,
    });
    expect(result).toEqual({ exitCode: 3 });
    expect(chunks).toEqual(["hello", "warning"]);
    expect(calls[0]).toEqual({
      kind: "shell",
      command: "echo hello",
      timeoutMs: 2_000,
    });
    expect(calls[0]).not.toHaveProperty("environment");
  });

  it("maps abort and timeout to Pi's shell error conventions", async () => {
    const aborted = createControlledOperations(async () => ({
      state: "cancelled",
      started: false,
      code: "execution-cancelled",
      reason: "request aborted",
      impact: "none",
      stdout: "",
      stderr: "",
      truncated: false,
      record: {
        ...record("cancelled"),
        state: "cancelled",
        started: false,
        impact: "none",
        code: "execution-cancelled",
      },
    }));
    await expect(
      aborted.bash.exec("echo x", "C:\\work", { onData: () => undefined }),
    ).rejects.toThrow("aborted");

    const timedOut = createControlledOperations(async () => ({
      state: "cancelled",
      started: true,
      code: "execution-timeout",
      reason: "deadline expired",
      impact: "unknown",
      stdout: "",
      stderr: "",
      truncated: false,
      record: {
        ...record("cancelled"),
        state: "cancelled",
        started: true,
        impact: "unknown",
        code: "execution-timeout",
      },
    }));
    await expect(
      timedOut.bash.exec("echo x", "C:\\work", {
        onData: () => undefined,
        timeout: 2,
      }),
    ).rejects.toThrow("timeout:2");
  });

  it("reads bytes and sniffs image types only from helper data", async () => {
    const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x01]);
    const calls: ExecutionOperation[] = [];
    const operations = createControlledOperations(async (operation) => {
      calls.push(operation);
      return completed({ dataBase64: png.toString("base64") });
    });
    const buffer = await operations.read.readFile("C:\\work\\image.png");
    expect(buffer.equals(png)).toBe(true);
    expect(await operations.read.detectImageMimeType?.("C:\\work\\image.png")).toBe(
      "image/png",
    );
    expect(calls.every((call) => call.kind === "read-file")).toBe(true);
    expect(detectImageMimeType(Buffer.from("plain"))).toBeNull();
    expect(detectImageMimeType(Buffer.from([0xff, 0xd8, 0xff, 0xe0]))).toBe(
      "image/jpeg",
    );
  });

  it("fails closed on helper failures and invalid file data", async () => {
    const failing = createControlledOperations(async () => refused("sandbox-denied"));
    await expect(failing.write.writeFile("C:\\work\\out.txt", "x")).rejects.toMatchObject({
      code: "sandbox-denied",
    });

    const invalid = createControlledOperations(async () =>
      completed({ dataBase64: "not base64" }),
    );
    await expect(invalid.read.readFile("C:\\work\\out.txt")).rejects.toBeInstanceOf(
      ControlledOperationError,
    );
  });

  it("uses helper operations for write, mkdir and edit access", async () => {
    const calls: ExecutionOperation[] = [];
    const operations = createControlledOperations(async (operation) => {
      calls.push(operation);
      return completed();
    });
    await operations.write.mkdir("C:\\work");
    await operations.write.writeFile("C:\\work\\out.txt", "new");
    await operations.edit.access("C:\\work\\out.txt");
    expect(calls).toEqual([
      { kind: "mkdir", path: "C:\\work" },
      { kind: "write-file", path: "C:\\work\\out.txt", content: "new" },
      { kind: "access-file", path: "C:\\work\\out.txt", mode: "read-write" },
    ]);
  });

  it("checks an approved file's existing parent instead of creating it", async () => {
    const calls: ExecutionOperation[] = [];
    const parent = process.platform === "win32" ? "D:\\data" : "/data";
    const target = join(parent, "report.txt");
    const operations = createControlledOperations(
      async (operation) => {
        calls.push(operation);
        return completed();
      },
      { getApprovedWriteTarget: () => target },
    );
    await operations.write.mkdir(parent);
    expect(calls).toEqual([
      { kind: "access-dir", path: parent, forFile: target },
    ]);
  });

  it("creates the parent through mkdir when the approved parent is missing", async () => {
    const calls: ExecutionOperation[] = [];
    const parent = process.platform === "win32" ? "D:\\data" : "/data";
    const target = join(parent, "report.txt");
    const operations = createControlledOperations(
      async (operation) => {
        calls.push(operation);
        if (operation.kind === "access-dir") return refused("sandbox-path-missing");
        return completed();
      },
      { getApprovedWriteTarget: () => target },
    );
    await operations.write.mkdir(parent);
    expect(calls).toEqual([
      { kind: "access-dir", path: parent, forFile: target },
      { kind: "mkdir", path: parent },
    ]);
  });

  it("inherits the ambient call signal for every file operation", async () => {
    const abort = new AbortController();
    const signals: (AbortSignal | undefined)[] = [];
    const operations = createControlledOperations(
      async (_operation, options) => {
        signals.push(options.signal);
        return completed({ dataBase64: "" });
      },
      { getSignal: () => abort.signal },
    );
    await operations.read.readFile("C:\\work\\a.txt");
    await operations.read.access("C:\\work\\a.txt");
    const detectImage = operations.read.detectImageMimeType;
    if (!detectImage) throw new Error("read operations must expose the detector");
    await detectImage("C:\\work\\a.txt");
    await operations.write.writeFile("C:\\work\\a.txt", "x");
    await operations.write.mkdir("C:\\work");
    await operations.edit.readFile("C:\\work\\a.txt");
    await operations.edit.writeFile("C:\\work\\a.txt", "x");
    await operations.edit.access("C:\\work\\a.txt");
    expect(signals).toHaveLength(8);
    expect(signals.filter((signal) => signal === abort.signal)).toHaveLength(8);
  });

  it("does not accept a Pi environment as helper input", async () => {
    const observed: unknown[] = [];
    const operations = createControlledOperations(async (operation, options) => {
      observed.push({ operation, options });
      return completed();
    });
    await operations.bash.exec("echo x", "C:\\work", {
      onData: () => undefined,
      env: { CONTROLLER_API_KEY: "secret" },
    });
    const entry = observed[0] as {
      readonly operation: ExecutionOperation;
      readonly options: { readonly cwd?: string };
    };
    expect(entry.options.cwd).toBe("C:\\work");
    expect(entry.operation).not.toHaveProperty("env");
    expect(JSON.stringify(entry)).not.toContain("CONTROLLER_API_KEY");
  });

  it("rejects invalid shell timeouts before running", async () => {
    const run = vi.fn(async () => completed());
    const operations = createControlledOperations(run);
    await expect(
      operations.bash.exec("echo x", "C:\\work", {
        onData: () => undefined,
        timeout: 0,
      }),
    ).rejects.toMatchObject({ code: "invalid-plan" });
    expect(run).not.toHaveBeenCalled();
  });
});
