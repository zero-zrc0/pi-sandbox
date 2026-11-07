/**
 * Phase 12 step facts capture (specs/host-integration.md §3).
 *
 * The resolver turns one host event into either a complete-manifest capture or
 * a per-call capture. The injected capture port is a recording fake: every
 * assertion compares the exact input object the resolver handed it against a
 * worked example from the spec, never against a re-implementation. Manifest
 * digests are the public `reviewDigest` identity from the reviewer context.
 */
import { describe, expect, it } from "vitest";
import { reviewDigest } from "#approve-core/context/types";
import type { ReviewStepManifest } from "#approve-core/context/types";
import type {
  CaptureStepResult,
  StepCapture,
  StepCaptureInput,
} from "#approve-core/contracts";
import {
  PER_CALL_STEP_KEY_PREFIX,
  createStepFacts,
  type StepFactsCapturePort,
  type StepFactsEvent,
} from "#approve-core/host/step-facts";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const SESSION_ID = "sess-1";
const LS_ARGS = { command: "ls -la" };
const LS_DIGEST = reviewDigest(LS_ARGS);
const READ_ARGS = { path: "/tmp/x" };
const READ_DIGEST = reviewDigest(READ_ARGS);
const PWD_ARGS = { command: "pwd" };

const WORKED_CAPTURE: StepCapture = {
  stepKey: "step-7",
  sessionId: SESSION_ID,
  sourceEntryId: "entry-9",
  manifestRevision: 4,
  complete: true,
  directCalls: [],
  digest: "capture-digest",
};

function buildManifest(overrides: Partial<ReviewStepManifest> = {}): ReviewStepManifest {
  return {
    stepKey: "step-7",
    sourceEntryId: "entry-9",
    revision: 4,
    complete: true,
    directCalls: [
      { toolCallId: "call-ls", toolName: "bash", arguments: LS_ARGS, argumentsDigest: LS_DIGEST },
      {
        toolCallId: "call-read",
        toolName: "read",
        arguments: READ_ARGS,
        argumentsDigest: READ_DIGEST,
        parentToolCallId: "parent-2",
      },
    ],
    ...overrides,
  };
}

function directEvent(overrides: Partial<StepFactsEvent> = {}): StepFactsEvent {
  return {
    sessionId: SESSION_ID,
    toolCallId: "call-ls",
    toolName: "bash",
    input: LS_ARGS,
    ...overrides,
  };
}

interface RecordingPort {
  readonly port: StepFactsCapturePort;
  readonly inputs: StepCaptureInput[];
}

function recordingPort(
  outcome: (input: StepCaptureInput) => CaptureStepResult = () => ({ ok: true, capture: WORKED_CAPTURE }),
): RecordingPort {
  const inputs: StepCaptureInput[] = [];
  const port: StepFactsCapturePort = (input) => {
    inputs.push(input);
    return outcome(input);
  };
  return { port, inputs };
}

// ---------------------------------------------------------------------------
// Complete-manifest path
// ---------------------------------------------------------------------------

describe("createStepFacts manifest path", () => {
  it("captures a registered direct call from the complete manifest", () => {
    const recording = recordingPort();
    const resolver = createStepFacts({ capture: recording.port });

    const result = resolver.capture({
      event: directEvent({ input: LS_ARGS, hostExecutionRequest: { reason: "needs root" } }),
      manifest: buildManifest(),
      registeredTools: ["bash", "read"],
    });

    expect(result).toEqual({ ok: true, capture: WORKED_CAPTURE, source: "manifest" });
    expect(recording.inputs).toHaveLength(1);
    expect(recording.inputs[0]).toStrictEqual({
      stepKey: "step-7",
      sessionId: SESSION_ID,
      sourceEntryId: "entry-9",
      manifestRevision: 4,
      complete: true,
      directCalls: [
        {
          toolCallId: "call-ls",
          toolName: "bash",
          arguments: LS_ARGS,
          argumentsDigest: LS_DIGEST,
          hostExecutionRequest: { reason: "needs root" },
        },
        {
          toolCallId: "call-read",
          toolName: "read",
          arguments: READ_ARGS,
          argumentsDigest: READ_DIGEST,
          parentToolCallId: "parent-2",
        },
      ],
    });
  });

  it("omits hostExecutionRequest when the event carries none", () => {
    const recording = recordingPort();
    const resolver = createStepFacts({ capture: recording.port });

    resolver.capture({
      event: directEvent(),
      manifest: buildManifest(),
      registeredTools: ["bash", "read"],
    });

    expect(recording.inputs[0]!.directCalls[0]).toStrictEqual({
      toolCallId: "call-ls",
      toolName: "bash",
      arguments: LS_ARGS,
      argumentsDigest: LS_DIGEST,
    });
  });

  it("rejects a stale manifest revision", () => {
    for (const revision of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1, Number.NaN, Number.POSITIVE_INFINITY]) {
      const recording = recordingPort();
      const resolver = createStepFacts({ capture: recording.port });

      const result = resolver.capture({
        event: directEvent(),
        manifest: buildManifest({ revision }),
        registeredTools: ["bash", "read"],
      });

      expect(result).toEqual({ ok: false, reason: "invalid" });
      expect(recording.inputs).toHaveLength(0);
    }
  });

  it("rejects a mutated tool name instead of falling back to per-call", () => {
    const recording = recordingPort();
    const resolver = createStepFacts({ capture: recording.port });

    const result = resolver.capture({
      event: directEvent({ toolName: "read" }),
      manifest: buildManifest(),
      registeredTools: ["bash", "read"],
    });

    expect(result).toEqual({ ok: false, reason: "invalid" });
    expect(recording.inputs).toHaveLength(0);
  });

  it("rejects tampered arguments by digest mismatch instead of falling back", () => {
    const recording = recordingPort();
    const resolver = createStepFacts({ capture: recording.port });

    const result = resolver.capture({
      event: directEvent({ input: { command: "rm -rf /" } }),
      manifest: buildManifest(),
      registeredTools: ["bash", "read"],
    });

    expect(result).toEqual({ ok: false, reason: "invalid" });
    expect(recording.inputs).toHaveLength(0);
  });

  it("rejects a manifest whose direct tool is not registered", () => {
    const recording = recordingPort();
    const resolver = createStepFacts({ capture: recording.port });

    const result = resolver.capture({
      event: directEvent(),
      manifest: buildManifest(),
      registeredTools: ["bash"],
    });

    expect(result).toEqual({ ok: false, reason: "invalid" });
    expect(recording.inputs).toHaveLength(0);
  });

  it("accepts the manifest path when no tool registry is provided", () => {
    const recording = recordingPort();
    const resolver = createStepFacts({ capture: recording.port });

    const result = resolver.capture({ event: directEvent(), manifest: buildManifest() });

    expect(result).toMatchObject({ ok: true, source: "manifest" });
    expect(recording.inputs).toHaveLength(1);
    expect(recording.inputs[0]!.manifestRevision).toBe(4);
  });
});

// ---------------------------------------------------------------------------
// Per-call fallback path
// ---------------------------------------------------------------------------

describe("createStepFacts per-call path", () => {
  it("captures a brand-new call without a manifest", () => {
    const recording = recordingPort();
    const resolver = createStepFacts({ capture: recording.port });

    const result = resolver.capture({
      event: {
        sessionId: SESSION_ID,
        toolCallId: "call-new",
        toolName: "bash",
        input: PWD_ARGS,
      },
      registeredTools: ["bash"],
    });

    expect(result).toEqual({ ok: true, capture: WORKED_CAPTURE, source: "per-call" });
    expect(recording.inputs).toHaveLength(1);
    expect(recording.inputs[0]).toStrictEqual({
      stepKey: "call:call-new",
      sessionId: SESSION_ID,
      sourceEntryId: "call-new",
      manifestRevision: 0,
      complete: true,
      directCalls: [
        {
          toolCallId: "call-new",
          toolName: "bash",
          arguments: PWD_ARGS,
          argumentsDigest: reviewDigest(PWD_ARGS),
        },
      ],
    });
  });

  it("keeps a nested call independent even when the manifest lists it", () => {
    const recording = recordingPort();
    const resolver = createStepFacts({ capture: recording.port });

    const result = resolver.capture({
      event: directEvent({ toolCallId: "call-read", toolName: "read", input: READ_ARGS, parentToolCallId: "parent-9" }),
      manifest: buildManifest(),
      registeredTools: ["bash", "read"],
    });

    expect(result).toMatchObject({ ok: true, source: "per-call" });
    expect(recording.inputs[0]).toStrictEqual({
      stepKey: "call:call-read",
      sessionId: SESSION_ID,
      sourceEntryId: "call-read",
      manifestRevision: 0,
      complete: true,
      directCalls: [
        {
          toolCallId: "call-read",
          toolName: "read",
          arguments: READ_ARGS,
          argumentsDigest: READ_DIGEST,
          parentToolCallId: "parent-9",
        },
      ],
    });
  });

  it("falls back per-call for an incomplete manifest", () => {
    const recording = recordingPort();
    const resolver = createStepFacts({ capture: recording.port });

    const result = resolver.capture({
      event: directEvent(),
      manifest: buildManifest({ complete: false }),
      registeredTools: ["bash", "read"],
    });

    expect(result).toMatchObject({ ok: true, source: "per-call" });
    expect(recording.inputs[0]!.stepKey).toBe("call:call-ls");
    expect(recording.inputs[0]!.manifestRevision).toBe(0);
  });

  it("falls back per-call for a manifest without direct calls", () => {
    const recording = recordingPort();
    const resolver = createStepFacts({ capture: recording.port });

    const result = resolver.capture({
      event: directEvent(),
      manifest: buildManifest({ directCalls: [] }),
      registeredTools: ["bash", "read"],
    });

    expect(result).toMatchObject({ ok: true, source: "per-call" });
    expect(recording.inputs[0]!.stepKey).toBe("call:call-ls");
  });

  it("falls back per-call when the event is outside the manifest", () => {
    const recording = recordingPort();
    const resolver = createStepFacts({ capture: recording.port });

    const result = resolver.capture({
      event: directEvent({ toolCallId: "call-other", toolName: "bash", input: PWD_ARGS }),
      manifest: buildManifest(),
      registeredTools: ["bash", "read"],
    });

    expect(result).toMatchObject({ ok: true, source: "per-call" });
    expect(recording.inputs[0]!.stepKey).toBe("call:call-other");
    expect(recording.inputs[0]!.sourceEntryId).toBe("call-other");
  });

  it("preserves hostExecutionRequest on the per-call capture", () => {
    const recording = recordingPort();
    const resolver = createStepFacts({ capture: recording.port });

    resolver.capture({
      event: {
        sessionId: SESSION_ID,
        toolCallId: "call-new",
        toolName: "bash",
        input: PWD_ARGS,
        hostExecutionRequest: { reason: "elevated" },
      },
    });

    expect(recording.inputs[0]!.directCalls[0]!.hostExecutionRequest).toStrictEqual({ reason: "elevated" });
  });
});

// ---------------------------------------------------------------------------
// Event validation
// ---------------------------------------------------------------------------

describe("createStepFacts event validation", () => {
  const manifest = buildManifest();

  it("rejects events with a missing identity field", () => {
    const cases: Partial<StepFactsEvent>[] = [
      { sessionId: "" },
      { sessionId: "  " },
      { toolCallId: "" },
      { toolName: "" },
      { toolName: "   " },
    ];

    for (const overrides of cases) {
      const recording = recordingPort();
      const resolver = createStepFacts({ capture: recording.port });

      const result = resolver.capture({ event: directEvent(overrides), manifest, registeredTools: ["bash", "read"] });

      expect(result).toEqual({ ok: false, reason: "invalid" });
      expect(recording.inputs).toHaveLength(0);
    }
  });

  it("rejects inputs that are not JSON objects", () => {
    const inputs: unknown[] = [null, "text", 42, true, ["ls"], new Date("2026-01-01T00:00:00.000Z")];

    for (const input of inputs) {
      const recording = recordingPort();
      const resolver = createStepFacts({ capture: recording.port });

      const result = resolver.capture({ event: directEvent({ input }), manifest });

      expect(result).toEqual({ ok: false, reason: "invalid" });
      expect(recording.inputs).toHaveLength(0);
    }
  });

  it("rejects inputs that are not JSON-serializable", () => {
    const cyclic: Record<string, unknown> = {};
    cyclic["self"] = cyclic;
    const inputs: unknown[] = [{ n: 1n }, cyclic];

    for (const input of inputs) {
      const recording = recordingPort();
      const resolver = createStepFacts({ capture: recording.port });

      const result = resolver.capture({ event: directEvent({ input }), manifest });

      expect(result).toEqual({ ok: false, reason: "invalid" });
      expect(recording.inputs).toHaveLength(0);
    }
  });

  it("rejects a tool name that is not in the registered tool list", () => {
    const recording = recordingPort();
    const resolver = createStepFacts({ capture: recording.port });

    const result = resolver.capture({
      event: directEvent({ toolName: "unknown-tool" }),
      manifest: undefined,
      registeredTools: ["bash", "read"],
    });

    expect(result).toEqual({ ok: false, reason: "invalid" });
    expect(recording.inputs).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Capture port outcomes
// ---------------------------------------------------------------------------

describe("createStepFacts capture port outcomes", () => {
  it("maps a thrown capture failure to capture-failed", () => {
    const resolver = createStepFacts({
      capture: () => {
        throw new Error("freeze failed");
      },
    });

    expect(resolver.capture({ event: directEvent() })).toEqual({ ok: false, reason: "capture-failed" });
  });

  it("maps an incomplete-step port result to incomplete", () => {
    const resolver = createStepFacts({ capture: () => ({ ok: false, reason: "incomplete-step" }) });

    expect(resolver.capture({ event: directEvent() })).toEqual({ ok: false, reason: "incomplete" });
  });

  it("maps any other invalid port result to invalid", () => {
    const resolver = createStepFacts({ capture: () => ({ ok: false, reason: "invalid-arguments" }) });

    expect(resolver.capture({ event: directEvent() })).toEqual({ ok: false, reason: "invalid" });
  });

  it("calls the port exactly once per capture", () => {
    const recording = recordingPort();
    const resolver = createStepFacts({ capture: recording.port });

    resolver.capture({ event: directEvent(), manifest: buildManifest(), registeredTools: ["bash", "read"] });

    expect(recording.inputs).toHaveLength(1);
  });
});

describe("PER_CALL_STEP_KEY_PREFIX", () => {
  it("is the call: boundary used for per-call captures", () => {
    expect(PER_CALL_STEP_KEY_PREFIX).toBe("call:");
  });
});
