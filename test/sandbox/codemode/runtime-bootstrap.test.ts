import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  CODEMODE_PROTOCOL_VERSION,
  RuntimeFrameDecoder,
  createRuntimeFrameSequence,
} from "#sandbox/codemode/protocol";

function writeSequence(child: ReturnType<typeof spawn>, frames: Iterable<Buffer>): Promise<void> {
  return (async () => {
    for (const frame of frames) {
      await new Promise<void>((resolve, reject) => {
        child.stdin!.write(frame, (error?: Error | null) => error ? reject(error) : resolve());
      });
    }
  })();
}

function timeout<T>(promise: Promise<T>, milliseconds: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout>;
  const expired = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error("Codemode bootstrap test timed out")), milliseconds);
  });
  return Promise.race([promise, expired]).finally(() => clearTimeout(timer!));
}

describe("generated Codemode bootstrap", () => {
  it("starts from a local QuickJS file reference without embedding its bytes", async () => {
    const bootstrap = readFileSync(
      fileURLToPath(new URL("../../../src/sandbox/codemode/runtime-worker.bundle.cjs", import.meta.url)),
      "utf8",
    );
    const child = spawn(process.execPath, ["-e", bootstrap], { stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
    const decoder = new RuntimeFrameDecoder("bootstrap-run");
    let resolveMessage!: (value: unknown) => void;
    let rejectMessage!: (error: Error) => void;
    let resolveStopped!: () => void;
    let rejectStopped!: (error: Error) => void;
    const message = new Promise<unknown>((resolve, reject) => {
      resolveMessage = resolve;
      rejectMessage = reject;
    });
    const stopped = new Promise<void>((resolve, reject) => {
      resolveStopped = resolve;
      rejectStopped = reject;
    });
    const exited = new Promise<void>((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => {
        try {
          decoder.finish();
        } catch (error) {
          reject(error);
          return;
        }
        if (code !== 0) {
          reject(new Error(`Codemode bootstrap exited with ${code ?? signal}`));
          return;
        }
        resolve();
      });
    });
    void message.catch(() => undefined);
    void stopped.catch(() => undefined);
    void exited.catch(() => undefined);
    child.stdout!.on("data", (chunk: Buffer) => {
      try {
        for (const frame of decoder.push(Buffer.from(chunk))) {
          if (frame.type === "failure") {
            rejectMessage(new Error(frame.error?.message ?? "Codemode bootstrap failed"));
            rejectStopped(new Error(frame.error?.message ?? "Codemode bootstrap failed"));
          } else if (frame.type === "message") {
            resolveMessage(frame.message);
          } else if (frame.type === "stopped") {
            resolveStopped();
          }
        }
      } catch (error) {
        rejectMessage(error instanceof Error ? error : new Error(String(error)));
        rejectStopped(error instanceof Error ? error : new Error(String(error)));
      }
    });

    const payload = "🌐".repeat(2_097_200);
    const wasmDirectory = mkdtempSync(join(tmpdir(), "codemode-bootstrap-"));
    const wasmPath = join(wasmDirectory, "quickjs.wasm");
    writeFileSync(wasmPath, Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]));
    const workerSource = "const { parentPort, workerData } = require('node:worker_threads'); parentPort.postMessage({ type: 'done', payload: workerData.payload, compiled: workerData.wasm instanceof WebAssembly.Module });";
    try {
      await writeSequence(child, createRuntimeFrameSequence({
        version: CODEMODE_PROTOCOL_VERSION,
        generation: "bootstrap-run",
        type: "start",
        data: { payload },
        workerSource,
        wasmPath,
      }, "bootstrap-run", 1).frames);
      const result = await timeout(message, 30_000);
      expect(result).toEqual({ type: "done", payload, compiled: true });
      await writeSequence(child, createRuntimeFrameSequence({
        version: CODEMODE_PROTOCOL_VERSION,
        generation: "bootstrap-run",
        type: "stop",
      }, "bootstrap-run", 2).frames);
      child.stdin!.end();
      await timeout(stopped, 10_000);
      await timeout(exited, 10_000);
    } finally {
      if (child.exitCode === null) child.kill();
      rmSync(wasmDirectory, { recursive: true, force: true });
    }
  }, 60_000);
});
