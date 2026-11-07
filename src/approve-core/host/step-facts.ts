/**
 * Step facts capture (specs/host-integration.md §3).
 *
 * One host event becomes one frozen step capture. A complete step manifest is
 * the only evidence that may cover sibling calls; a nested call, a missing or
 * incomplete manifest, an empty manifest and an event outside the manifest all
 * fall back to a per-call capture bounded by that call alone. A manifest that
 * exists but disagrees with the event is invalid — evidence is never borrowed
 * from another step and never silently re-derived.
 */
import type {
  CaptureStepResult,
  StepCapture,
  StepCaptureInput,
} from "#approve-core/contracts";
import { reviewDigest } from "#approve-core/context/types";
import type { ReviewManifestCall, ReviewStepManifest } from "#approve-core/context/types";

/** Step key boundary of a per-call capture; the rest of the key is the call id. */
export const PER_CALL_STEP_KEY_PREFIX = "call:";

/** One host tool event as the host observed it. */
export interface StepFactsEvent {
  readonly sessionId: string;
  readonly toolCallId: string;
  readonly toolName: string;
  readonly input: unknown;
  readonly parentToolCallId?: string;
  readonly hostExecutionRequest?: { readonly reason: string };
}

export type StepFactsFailure = "incomplete" | "invalid" | "capture-failed";

export type StepFactsResult =
  | { readonly ok: true; readonly capture: StepCapture; readonly source: "manifest" | "per-call" }
  | { readonly ok: false; readonly reason: StepFactsFailure };

/** Injected frozen-capture constructor (contracts.captureStep in production). */
export type StepFactsCapturePort = (input: StepCaptureInput) => CaptureStepResult;

export interface StepFactsOptions {
  readonly capture: StepFactsCapturePort;
}

export interface StepFactsResolver {
  capture(input: {
    readonly event: StepFactsEvent;
    readonly manifest?: ReviewStepManifest;
    readonly registeredTools?: readonly string[];
  }): StepFactsResult;
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim() !== "";
}

function isPlainJsonObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  try {
    return typeof JSON.stringify(value) === "string";
  } catch {
    return false;
  }
}

/** The event must carry a usable identity and a JSON object input. */
function validEvent(event: StepFactsEvent, registeredTools: readonly string[] | undefined): boolean {
  if (!nonEmptyString(event.sessionId)) return false;
  if (!nonEmptyString(event.toolCallId)) return false;
  if (!nonEmptyString(event.toolName)) return false;
  if (!isPlainJsonObject(event.input)) return false;
  if (event.parentToolCallId !== undefined) {
    if (!nonEmptyString(event.parentToolCallId) || event.parentToolCallId === event.toolCallId) {
      return false;
    }
  }
  return registeredTools === undefined || registeredTools.includes(event.toolName);
}

/** The manifest call this event covers, when the complete-manifest path applies. */
function directManifestCall(
  event: StepFactsEvent,
  manifest: ReviewStepManifest | undefined,
): ReviewManifestCall | undefined {
  if (event.parentToolCallId !== undefined) return undefined;
  if (manifest === undefined || !manifest.complete) return undefined;
  if (manifest.directCalls.length === 0) return undefined;
  return manifest.directCalls.find((call) => call.toolCallId === event.toolCallId);
}

function hostExecutionRequestOf(
  event: StepFactsEvent,
  toolCallId: string,
): { readonly hostExecutionRequest: { readonly reason: string } } | undefined {
  if (event.hostExecutionRequest === undefined || event.toolCallId !== toolCallId) return undefined;
  return { hostExecutionRequest: event.hostExecutionRequest };
}

function perCallCaptureInput(event: StepFactsEvent, input: Record<string, unknown>): StepCaptureInput {
  return {
    stepKey: `${PER_CALL_STEP_KEY_PREFIX}${event.toolCallId}`,
    sessionId: event.sessionId,
    sourceEntryId: event.toolCallId,
    manifestRevision: 0,
    complete: true,
    directCalls: [
      {
        toolCallId: event.toolCallId,
        toolName: event.toolName,
        arguments: input,
        argumentsDigest: reviewDigest(input),
        ...(event.parentToolCallId === undefined
          ? {}
          : { parentToolCallId: event.parentToolCallId }),
        ...(hostExecutionRequestOf(event, event.toolCallId) ?? {}),
      },
    ],
  };
}

/**
 * Build the manifest capture input, or `undefined` when the manifest and the
 * event disagree on any frozen identity.
 */
function manifestCaptureInput(
  event: StepFactsEvent,
  manifest: ReviewStepManifest,
  manifestCall: ReviewManifestCall,
  registeredTools: readonly string[] | undefined,
): StepCaptureInput | undefined {
  if (!Number.isSafeInteger(manifest.revision) || manifest.revision < 0) return undefined;
  if (manifestCall.toolName !== event.toolName) return undefined;
  if (manifestCall.argumentsDigest !== reviewDigest(event.input)) return undefined;
  if (
    registeredTools !== undefined &&
    manifest.directCalls.some((call) => !registeredTools.includes(call.toolName))
  ) {
    return undefined;
  }

  return {
    stepKey: manifest.stepKey,
    sessionId: event.sessionId,
    sourceEntryId: manifest.sourceEntryId,
    manifestRevision: manifest.revision,
    complete: true,
    directCalls: manifest.directCalls.map((call) => ({
      toolCallId: call.toolCallId,
      toolName: call.toolName,
      arguments: call.arguments,
      argumentsDigest: call.argumentsDigest,
      ...(call.parentToolCallId === undefined
        ? {}
        : { parentToolCallId: call.parentToolCallId }),
      ...(hostExecutionRequestOf(event, call.toolCallId) ?? {}),
    })),
  };
}

/** Run the injected capture port and fold its outcome into the resolver result. */
function runCapture(
  port: StepFactsCapturePort,
  input: StepCaptureInput,
  source: "manifest" | "per-call",
): StepFactsResult {
  let result: CaptureStepResult;
  try {
    result = port(input);
  } catch {
    return { ok: false, reason: "capture-failed" };
  }
  if (result.ok) return { ok: true, capture: result.capture, source };
  return { ok: false, reason: result.reason === "incomplete-step" ? "incomplete" : "invalid" };
}

export function createStepFacts(options: StepFactsOptions): StepFactsResolver {
  return {
    capture({ event, manifest, registeredTools }): StepFactsResult {
      if (!validEvent(event, registeredTools)) return { ok: false, reason: "invalid" };
      const input = event.input as Record<string, unknown>;

      const manifestCall = directManifestCall(event, manifest);
      if (manifestCall !== undefined && manifest !== undefined) {
        const captureInput = manifestCaptureInput(event, manifest, manifestCall, registeredTools);
        if (captureInput === undefined) return { ok: false, reason: "invalid" };
        return runCapture(options.capture, captureInput, "manifest");
      }

      return runCapture(options.capture, perCallCaptureInput(event, input), "per-call");
    },
  };
}
