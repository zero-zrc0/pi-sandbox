import { describe, expect, it } from "vitest";

import {
  HelperLineDecoder,
  decodeHelperMessage,
  encodeHostMessage,
  helloMessage,
} from "#sandbox/protocol";
import {
  MAX_HELPER_MESSAGE_BYTES,
  MAX_HELPER_OUTPUT_CHUNK_BYTES,
} from "#sandbox/types";

const capabilities = {
  filesystem: {
    read: true,
    write: true,
    granularity: "file",
    protectedPaths: true,
    environment: true,
  },
  network: "domains",
  cancel: true,
  streamOutput: true,
  startedNotification: true,
  processTree: true,
};

describe("helper protocol", () => {
  it("encodes host messages with one newline and rejects oversized values", () => {
    const encoded = encodeHostMessage(helloMessage("request-1", 1));
    expect(encoded.ok).toBe(true);
    if (encoded.ok) {
      expect(encoded.line.endsWith("\n")).toBe(true);
      expect(encoded.line.trimEnd().split("\n")).toHaveLength(1);
    }

    const huge = encodeHostMessage({
      type: "cancel",
      requestId: "request-1",
      generation: 1,
      reason: "x".repeat(MAX_HELPER_MESSAGE_BYTES),
    });
    expect(huge).toEqual(
      expect.objectContaining({ ok: false, reason: "message-too-large" }),
    );
  });

  it("decodes every helper message kind", () => {
    const ready = decodeHelperMessage(
      JSON.stringify({
        type: "ready",
        protocolVersion: 2,
        requestId: "r1",
        generation: 1,
        backend: { id: "fixture-helper", version: "1.0.0" },
        capabilities,
      }),
    );
    expect(ready.ok).toBe(true);

    const started = decodeHelperMessage(
      JSON.stringify({
        type: "started",
        requestId: "r1",
        generation: 1,
        pid: 123,
        startedAt: "2026-10-20T00:00:00.000Z",
      }),
    );
    expect(started.ok).toBe(true);

    const output = decodeHelperMessage(
      JSON.stringify({
        type: "output",
        requestId: "r1",
        generation: 1,
        sequence: 0,
        stream: "stdout",
        data: "hello",
      }),
    );
    expect(output.ok).toBe(true);

    const result = decodeHelperMessage(
      JSON.stringify({
        type: "result",
        requestId: "r1",
        generation: 1,
        started: true,
        exitCode: 0,
        impact: "known",
        dataBase64: "aGVsbG8=",
      }),
    );
    expect(result.ok).toBe(true);

    const rejected = decodeHelperMessage(
      JSON.stringify({
        type: "rejected",
        requestId: "r1",
        generation: 1,
        started: false,
        code: "denied",
        reason: "blocked",
      }),
    );
    expect(rejected.ok).toBe(true);

    const cancelled = decodeHelperMessage(
      JSON.stringify({
        type: "cancelled",
        requestId: "r1",
        generation: 1,
        started: "unknown",
      }),
    );
    expect(cancelled.ok).toBe(true);

    const error = decodeHelperMessage(
      JSON.stringify({ type: "error", code: "setup", message: "failed" }),
    );
    expect(error.ok).toBe(true);
  });

  it("rejects unknown fields, wrong shapes and uncorrelated envelopes", () => {
    expect(
      decodeHelperMessage(
        JSON.stringify({
          type: "started",
          requestId: "r1",
          generation: 1,
          pid: 1,
          startedAt: "now",
          extra: true,
        }),
      ),
    ).toEqual(expect.objectContaining({ ok: false }));

    expect(
      decodeHelperMessage(
        JSON.stringify({
          type: "output",
          requestId: "",
          generation: 1,
          sequence: 0,
          stream: "stdout",
          data: "",
        }),
      ),
    ).toEqual(expect.objectContaining({ ok: false }));

    expect(
      decodeHelperMessage(
        JSON.stringify({
          type: "output",
          requestId: "r1",
          generation: 1,
          sequence: 0,
          stream: "stdout",
          data: "x".repeat(MAX_HELPER_OUTPUT_CHUNK_BYTES + 1),
        }),
      ),
    ).toEqual(
      expect.objectContaining({ ok: false, reason: "invalid-output" }),
    );

    expect(
      decodeHelperMessage(
        JSON.stringify({ type: "unknown", requestId: "r1", generation: 1 }),
      ),
    ).toEqual(
      expect.objectContaining({ ok: false, reason: "unknown-message-type" }),
    );

    expect(decodeHelperMessage("not-json")).toEqual(
      expect.objectContaining({ ok: false, reason: "invalid-json" }),
    );
  });

  it("splits lines across chunks and strips carriage returns", () => {
    const decoder = new HelperLineDecoder();
    expect(decoder.push('{"a":1}\r').lines).toEqual([]);
    expect(decoder.push('\n{"b":2}\n').lines).toEqual(['{"a":1}', '{"b":2}']);
    expect(decoder.pendingBytes).toBe(0);
  });

  it("stops a partial line that exceeds the message bound", () => {
    const decoder = new HelperLineDecoder();
    const result = decoder.push("x".repeat(MAX_HELPER_MESSAGE_BYTES + 1));
    expect(result).toEqual({ lines: [], error: "message-too-large" });
    expect(decoder.pendingBytes).toBe(0);
  });
});
