import {
  CODEMODE_MAX_FRAME_BYTES,
  CODEMODE_MAX_LOGICAL_MESSAGE_BYTES,
  CODEMODE_MAX_QUEUED_BYTES,
  CODEMODE_FRAGMENT_BYTES,
} from "./protocol";

export const CODEMODE_RUNTIME_LIMITS = Object.freeze({
  protocolVersion: 1,
  maxFrameBytes: CODEMODE_MAX_FRAME_BYTES,
  fragmentBytes: CODEMODE_FRAGMENT_BYTES,
  maxLogicalMessageBytes: CODEMODE_MAX_LOGICAL_MESSAGE_BYTES,
  maxQueuedMessageBytes: CODEMODE_MAX_QUEUED_BYTES,
  maxDiagnosticBytes: 16 * 1024,
  defaultMaxActiveRuntimes: 2,
  maxConfiguredActiveRuntimes: 8,
  maxQueuedRuntimes: 8,
  runtimeQueueWaitMs: 60_000,
  maxNestedCallsPerRuntime: 100_000,
  maxConcurrentNestedCallsPerRuntime: 64,
  maxConcurrentModelCallsPerRuntime: 4,
  quickJsMemoryBytes: 256 * 1024 * 1024,
});
