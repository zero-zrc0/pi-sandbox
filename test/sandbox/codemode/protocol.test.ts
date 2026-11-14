import { describe, expect, it } from "vitest";
import { FrameDecoder } from "../../../src/sandbox/codemode/physical-codec.js";
import {
  CODEMODE_MAX_FRAME_BYTES,
  CODEMODE_MAX_LOGICAL_MESSAGE_BYTES,
  RuntimeFrameDecoder,
  createRuntimeFrameSequence,
  decodeRuntimeFrame,
  encodeRuntimeFrame,
} from "#sandbox/codemode/protocol";

describe("Codemode Runtime IPC", () => {
  it("reassembles split UTF-8 frames without crossing generations", () => {
    const decoder = new RuntimeFrameDecoder("run-2");
    const frame = encodeRuntimeFrame({
      version: 1,
      generation: "run-2",
      type: "message",
      message: { type: "output", item: { type: "text", text: "中文 🙂" } },
    });
    const split = frame.indexOf(Buffer.from("\xF0\x9F", "binary"));

    expect(decoder.push(frame.subarray(0, split))).toEqual([]);
    expect(decoder.push(frame.subarray(split))).toEqual([{
      version: 1,
      generation: "run-2",
      type: "message",
      message: { type: "output", item: { type: "text", text: "中文 🙂" } },
    }]);
  });

  it("rejects a delayed frame from a retired Runtime generation", () => {
    const decoder = new RuntimeFrameDecoder("run-new");
    const stale = encodeRuntimeFrame({ version: 1, generation: "run-old", type: "ready" });

    expect(() => decoder.push(stale)).toThrow("generation or version");
  });

  it("accepts one initial start generation and then keeps it fixed", () => {
    const decoder = new FrameDecoder({ allowInitialGeneration: true });
    expect(() => decoder.push(encodeRuntimeFrame({ version: 1, generation: "run-1", type: "message" })))
      .toThrow("generation or version");
    expect(decoder.generation).toBeUndefined();
    decoder.push(encodeRuntimeFrame({ version: 1, generation: "run-1", type: "start" }));
    expect(decoder.generation).toBe("run-1");
    expect(() => decoder.push(encodeRuntimeFrame({ version: 1, generation: "run-2", type: "message" })))
      .toThrow("generation or version");
  });

  it("rejects invalid fragment identifiers and base64 before reassembly", () => {
    const negativeId = encodeRuntimeFrame({
      version: 1,
      generation: "run-1",
      type: "fragment",
      id: -1,
      index: 0,
      final: true,
      data: Buffer.from("{}").toString("base64"),
    });
    const invalidBase64 = encodeRuntimeFrame({
      version: 1,
      generation: "run-1",
      type: "fragment",
      id: 1,
      index: 0,
      final: true,
      data: "%%%",
    });

    expect(() => decodeRuntimeFrame(negativeId, "run-1")).toThrow("fragment is invalid");
    expect(() => decodeRuntimeFrame(invalidBase64, "run-1")).toThrow("fragment is invalid");
  });

  it("rejects nested logical fragments after decoding the outer fragment once", () => {
    const nested = {
      version: 1,
      generation: "run-1",
      type: "fragment",
      id: 2,
      index: 0,
      final: true,
      data: Buffer.from("{}", "utf8").toString("base64"),
    };
    const outer = encodeRuntimeFrame({
      version: 1,
      generation: "run-1",
      type: "fragment",
      id: 1,
      index: 0,
      final: true,
      data: Buffer.from(JSON.stringify(nested), "utf8").toString("base64"),
    });
    const decoder = new RuntimeFrameDecoder("run-1");

    expect(() => decoder.push(outer)).toThrow("fragments cannot be nested");
  });

  it("rejects an incomplete physical line at end of input", () => {
    const decoder = new RuntimeFrameDecoder("run-1");
    decoder.push(Buffer.from("{\"version\":1", "utf8"));

    expect(() => decoder.finish()).toThrow("frame is incomplete");
  });

  it("rejects unknown envelope types and accepts the exact physical frame limit", () => {
    const unknown = encodeRuntimeFrame({ version: 1, generation: "run-1", type: "future" });
    expect(() => decodeRuntimeFrame(unknown.subarray(0, -1), "run-1")).toThrow("generation or version");

    const largest = encodeRuntimeFrame("x".repeat(CODEMODE_MAX_FRAME_BYTES - 3));
    expect(largest.byteLength).toBe(CODEMODE_MAX_FRAME_BYTES);
    expect(() => encodeRuntimeFrame("x".repeat(CODEMODE_MAX_FRAME_BYTES - 2))).toThrow("exceeds 16 MiB");
  });

  it("counts the newline in the physical frame limit for every chunk split", () => {
    const base = { version: 1, generation: "run-boundary", type: "ready", padding: "" };
    const baseBytes = Buffer.byteLength(JSON.stringify(base));
    const valueWithBodyBytes = (byteLength: number) => {
      const paddingBytes = byteLength - baseBytes;
      return { ...base, padding: "x".repeat(paddingBytes) };
    };
    const decodeChunks = (chunks: readonly Buffer[]): unknown[] => {
      const decoder = new FrameDecoder({ generation: "run-boundary" });
      return chunks.flatMap((chunk) => decoder.push(chunk));
    };
    const newline = Buffer.from("\n");
    const exactFrame = encodeRuntimeFrame(valueWithBodyBytes(CODEMODE_MAX_FRAME_BYTES - 1));
    const exactBody = exactFrame.subarray(0, -1);
    expect(exactFrame.byteLength).toBe(CODEMODE_MAX_FRAME_BYTES);
    for (const chunks of [
      [exactFrame],
      [exactBody, newline],
      [exactFrame.subarray(0, exactFrame.byteLength - 7), exactFrame.subarray(exactFrame.byteLength - 7)],
    ]) {
      const decoded = decodeChunks(chunks) as { padding: string }[];
      expect(decoded).toHaveLength(1);
      expect(decoded[0]?.padding).toHaveLength(CODEMODE_MAX_FRAME_BYTES - 1 - baseBytes);
    }

    const overLimitValue = valueWithBodyBytes(CODEMODE_MAX_FRAME_BYTES);
    const overLimitBody = Buffer.from(JSON.stringify(overLimitValue), "utf8");
    const overLimitFrame = Buffer.concat([overLimitBody, newline]);
    expect(overLimitFrame.byteLength).toBe(CODEMODE_MAX_FRAME_BYTES + 1);
    expect(() => encodeRuntimeFrame(overLimitValue)).toThrow("exceeds 16 MiB");
    for (const chunks of [
      [overLimitFrame],
      [overLimitFrame.subarray(0, -2), overLimitFrame.subarray(-2)],
      [overLimitBody, newline],
      [overLimitFrame.subarray(0, 1_234_567), overLimitFrame.subarray(1_234_567)],
    ]) {
      expect(() => decodeChunks(chunks)).toThrow("exceeds 16 MiB");
    }
  });

  it("rejects an oversized unterminated frame before JSON parsing", () => {
    const decoder = new RuntimeFrameDecoder("run-1");

    expect(() => decoder.push(Buffer.alloc(CODEMODE_MAX_FRAME_BYTES + 1, 0x61))).toThrow("exceeds 16 MiB");
  });

  it("scans fragmented input once and merges a physical frame only after its final byte", () => {
    const value = {
      version: 1,
      generation: "run-small-chunks",
      type: "ready",
      data: "x".repeat(32 * 1024),
    };
    const frame = encodeRuntimeFrame(value);
    const decoder = new FrameDecoder({ generation: value.generation });
    const received = [];
    for (let offset = 0; offset < frame.byteLength; offset += 1) {
      received.push(...decoder.push(frame.subarray(offset, offset + 1)));
    }

    expect(received).toEqual([value]);
    expect(decoder.stats()).toEqual({
      scannedBytes: frame.byteLength,
      copiedBytes: frame.byteLength - 1,
      mergeCount: 1,
    });
  });

  it("rejects a logical JSON message one byte above 128 MiB", () => {
    const value = "x".repeat(CODEMODE_MAX_LOGICAL_MESSAGE_BYTES - 1);

    expect(() => createRuntimeFrameSequence(value, "run-large", 1)).toThrow("exceeds 128 MiB");
  }, 30_000);

  it("reassembles a Unicode message split below the physical frame limit", () => {
    const message = {
      version: 1,
      generation: "run-large",
      type: "message",
      message: { type: "output", item: { type: "text", text: "中".repeat(CODEMODE_MAX_FRAME_BYTES / 3 + 32) } },
    };
    const sequence = createRuntimeFrameSequence(message, "run-large", 1);
    const decoder = new RuntimeFrameDecoder("run-large");
    const frames = [...sequence.frames];

    expect(frames.length).toBeGreaterThan(1);
    expect(frames.every(frame => frame.byteLength <= CODEMODE_MAX_FRAME_BYTES)).toBe(true);
    expect(frames.flatMap(frame => decoder.push(frame))).toEqual([message]);

    const outOfOrder = new RuntimeFrameDecoder("run-large");
    expect(() => outOfOrder.push(frames[1]!)).toThrow("fragment sequence");

    const interrupted = new RuntimeFrameDecoder("run-large");
    interrupted.push(frames[0]!);
    expect(() => interrupted.push(encodeRuntimeFrame({
      version: 1,
      generation: "run-large",
      type: "ready",
    }))).toThrow("interrupted by another frame");
  });
});
