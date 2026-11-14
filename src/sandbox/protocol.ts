import {
  HELPER_PROTOCOL_VERSION,
  MAX_FILE_CONTENT_BYTES,
  MAX_HELPER_MESSAGE_BYTES,
  MAX_HELPER_OUTPUT_CHUNK_BYTES,
  type BackendCapabilities,
  type BackendIdentity,
  type ExecutionPlan,
} from "#sandbox/types";

export interface HelloMessage {
  readonly type: "hello";
  readonly protocolVersion: number;
  readonly requestId: string;
  readonly generation: number;
}

export interface StartMessage {
  readonly type: "start";
  readonly requestId: string;
  readonly generation: number;
  readonly plan: ExecutionPlan;
  /**
   * Host-issued egress grant for plans whose network scope is `destinations`.
   * The private credential travels on this channel only: it never enters the
   * plan, its digest, the audit log, or any command line.
   */
  readonly egress?: {
    readonly proxyHost: string;
    readonly proxyPort: number;
    readonly leaseId: string;
    readonly credential: string;
  };
}

export interface CancelMessage {
  readonly type: "cancel";
  readonly requestId: string;
  readonly generation: number;
  readonly reason: string;
}

export interface ShutdownMessage {
  readonly type: "shutdown";
}

export type HostMessage =
  | HelloMessage
  | StartMessage
  | CancelMessage
  | ShutdownMessage;

export interface ReadyMessage {
  readonly type: "ready";
  readonly protocolVersion: number;
  readonly requestId: string;
  readonly generation: number;
  readonly backend: BackendIdentity;
  readonly capabilities: BackendCapabilities;
}

export interface StartedMessage {
  readonly type: "started";
  readonly requestId: string;
  readonly generation: number;
  readonly pid: number | null;
  readonly startedAt: string;
}

export interface OutputMessage {
  readonly type: "output";
  readonly requestId: string;
  readonly generation: number;
  readonly sequence: number;
  readonly stream: "stdout" | "stderr";
  readonly data: string;
}

export interface ResultMessage {
  readonly type: "result";
  readonly requestId: string;
  readonly generation: number;
  readonly started: true;
  readonly exitCode: number | null;
  readonly impact: "known" | "unknown";
  readonly errorCode?: string;
  readonly error?: string;
  readonly dataBase64?: string;
}

export interface RejectedMessage {
  readonly type: "rejected";
  readonly requestId: string;
  readonly generation: number;
  readonly started: false;
  readonly code: string;
  readonly reason: string;
}

export interface CancelledMessage {
  readonly type: "cancelled";
  readonly requestId: string;
  readonly generation: number;
  readonly started: boolean | "unknown";
}

export interface HelperErrorMessage {
  readonly type: "error";
  readonly requestId?: string;
  readonly generation?: number;
  readonly code: string;
  readonly message: string;
}

export type HelperMessage =
  | ReadyMessage
  | StartedMessage
  | OutputMessage
  | ResultMessage
  | RejectedMessage
  | CancelledMessage
  | HelperErrorMessage;

export type HelperDecodeResult =
  | { readonly ok: true; readonly message: HelperMessage }
  | { readonly ok: false; readonly reason: string };

export type HostEncodeResult =
  | { readonly ok: true; readonly line: string }
  | { readonly ok: false; readonly reason: string };

type JsonRecord = Record<string, unknown>;

const CAPABILITY_KEYS = [
  "filesystem",
  "network",
  "cancel",
  "streamOutput",
  "startedNotification",
  "processTree",
] as const;
const FILESYSTEM_CAPABILITY_KEYS = [
  "read",
  "write",
  "granularity",
  "protectedPaths",
  "environment",
] as const;
const READY_KEYS = [
  "type",
  "protocolVersion",
  "requestId",
  "generation",
  "backend",
  "capabilities",
] as const;
const STARTED_KEYS = [
  "type",
  "requestId",
  "generation",
  "pid",
  "startedAt",
] as const;
const OUTPUT_KEYS = [
  "type",
  "requestId",
  "generation",
  "sequence",
  "stream",
  "data",
] as const;
const RESULT_KEYS = [
  "type",
  "requestId",
  "generation",
  "started",
  "exitCode",
  "impact",
  "errorCode",
  "error",
  "dataBase64",
] as const;
const REJECTED_KEYS = [
  "type",
  "requestId",
  "generation",
  "started",
  "code",
  "reason",
] as const;
const CANCELLED_KEYS = [
  "type",
  "requestId",
  "generation",
  "started",
] as const;
const ERROR_KEYS = ["type", "requestId", "generation", "code", "message"] as const;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nonempty(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function nonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

function positiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value > 0;
}

function onlyKeys(record: JsonRecord, allowed: readonly string[]): boolean {
  const keys = Object.keys(record);
  return keys.every((key) => allowed.includes(key));
}

function hasRequiredKeys(
  record: JsonRecord,
  required: readonly string[],
): boolean {
  return required.every((key) => key in record);
}

function decodeCapabilities(value: unknown): BackendCapabilities | null {
  if (!isRecord(value)) return null;
  if (
    !onlyKeys(value, CAPABILITY_KEYS) ||
    !hasRequiredKeys(value, CAPABILITY_KEYS)
  ) {
    return null;
  }
  const filesystem = value.filesystem;
  if (
    !isRecord(filesystem) ||
    !onlyKeys(filesystem, FILESYSTEM_CAPABILITY_KEYS) ||
    !hasRequiredKeys(filesystem, FILESYSTEM_CAPABILITY_KEYS)
  ) {
    return null;
  }
  if (
    typeof filesystem.read !== "boolean" ||
    typeof filesystem.write !== "boolean" ||
    (filesystem.granularity !== "file" &&
      filesystem.granularity !== "directory") ||
    typeof filesystem.protectedPaths !== "boolean" ||
    typeof filesystem.environment !== "boolean"
  ) {
    return null;
  }
  if (
    value.network !== "none" &&
    value.network !== "all" &&
    value.network !== "domains"
  ) {
    return null;
  }
  if (
    typeof value.cancel !== "boolean" ||
    typeof value.streamOutput !== "boolean" ||
    typeof value.startedNotification !== "boolean" ||
    typeof value.processTree !== "boolean"
  ) {
    return null;
  }
  return {
    filesystem: {
      read: filesystem.read,
      write: filesystem.write,
      granularity: filesystem.granularity,
      protectedPaths: filesystem.protectedPaths,
      environment: filesystem.environment,
    },
    network: value.network,
    cancel: value.cancel,
    streamOutput: value.streamOutput,
    startedNotification: value.startedNotification,
    processTree: value.processTree,
  };
}

function baseEnvelope(
  record: JsonRecord,
  type: "ready" | "started" | "output" | "result" | "rejected" | "cancelled",
): boolean {
  return (
    record.type === type &&
    nonempty(record.requestId) &&
    positiveInteger(record.generation)
  );
}

/** Decode one protocol line, rejecting unknown fields and malformed values. */
export function decodeHelperMessage(line: string): HelperDecodeResult {
  if (typeof line !== "string" || line.length === 0) {
    return { ok: false, reason: "empty-message" };
  }
  if (Buffer.byteLength(line, "utf8") > MAX_HELPER_MESSAGE_BYTES) {
    return { ok: false, reason: "message-too-large" };
  }
  let raw: unknown;
  try {
    raw = JSON.parse(line);
  } catch {
    return { ok: false, reason: "invalid-json" };
  }
  if (!isRecord(raw) || typeof raw.type !== "string") {
    return { ok: false, reason: "invalid-envelope" };
  }

  switch (raw.type) {
    case "ready": {
      if (
        !baseEnvelope(raw, "ready") ||
        !onlyKeys(raw, READY_KEYS)
      ) {
        return { ok: false, reason: "invalid-ready" };
      }
      if (!positiveInteger(raw.protocolVersion)) {
        return { ok: false, reason: "invalid-ready" };
      }
      const backend = raw.backend;
      if (
        !isRecord(backend) ||
        !onlyKeys(backend, ["id", "version"]) ||
        !nonempty(backend.id) ||
        !nonempty(backend.version)
      ) {
        return { ok: false, reason: "invalid-ready" };
      }
      const capabilities = decodeCapabilities(raw.capabilities);
      if (!capabilities) return { ok: false, reason: "invalid-capabilities" };
      return {
        ok: true,
        message: {
          type: "ready",
          protocolVersion: raw.protocolVersion,
          requestId: raw.requestId as string,
          generation: raw.generation as number,
          backend: { id: backend.id, version: backend.version },
          capabilities,
        },
      };
    }
    case "started": {
      if (
        !baseEnvelope(raw, "started") ||
        !onlyKeys(raw, STARTED_KEYS)
      ) {
        return { ok: false, reason: "invalid-started" };
      }
      if (
        !(raw.pid === null || positiveInteger(raw.pid)) ||
        !nonempty(raw.startedAt)
      ) {
        return { ok: false, reason: "invalid-started" };
      }
      return {
        ok: true,
        message: {
          type: "started",
          requestId: raw.requestId as string,
          generation: raw.generation as number,
          pid: raw.pid as number | null,
          startedAt: raw.startedAt as string,
        },
      };
    }
    case "output": {
      if (
        !baseEnvelope(raw, "output") ||
        !onlyKeys(raw, OUTPUT_KEYS)
      ) {
        return { ok: false, reason: "invalid-output" };
      }
      if (
        !nonNegativeInteger(raw.sequence) ||
        (raw.stream !== "stdout" && raw.stream !== "stderr") ||
        typeof raw.data !== "string" ||
        Buffer.byteLength(raw.data, "utf8") > MAX_HELPER_OUTPUT_CHUNK_BYTES
      ) {
        return { ok: false, reason: "invalid-output" };
      }
      return {
        ok: true,
        message: {
          type: "output",
          requestId: raw.requestId as string,
          generation: raw.generation as number,
          sequence: raw.sequence,
          stream: raw.stream,
          data: raw.data,
        },
      };
    }
    case "result": {
      if (
        !baseEnvelope(raw, "result") ||
        !onlyKeys(raw, RESULT_KEYS)
      ) {
        return { ok: false, reason: "invalid-result" };
      }
      if (
        raw.started !== true ||
        !(raw.exitCode === null || Number.isInteger(raw.exitCode)) ||
        (raw.impact !== "known" && raw.impact !== "unknown") ||
        (raw.errorCode !== undefined && !nonempty(raw.errorCode)) ||
        (raw.error !== undefined && typeof raw.error !== "string") ||
        (raw.dataBase64 !== undefined && typeof raw.dataBase64 !== "string")
      ) {
        return { ok: false, reason: "invalid-result" };
      }
      if (
        typeof raw.dataBase64 === "string" &&
        raw.dataBase64.length > Math.ceil((MAX_FILE_CONTENT_BYTES * 4) / 3) + 8
      ) {
        return { ok: false, reason: "result-data-too-large" };
      }
      return {
        ok: true,
        message: {
          type: "result",
          requestId: raw.requestId as string,
          generation: raw.generation as number,
          started: true,
          exitCode: raw.exitCode as number | null,
          impact: raw.impact,
          ...(raw.errorCode === undefined
            ? {}
            : { errorCode: raw.errorCode as string }),
          ...(raw.error === undefined ? {} : { error: raw.error as string }),
          ...(raw.dataBase64 === undefined
            ? {}
            : { dataBase64: raw.dataBase64 as string }),
        },
      };
    }
    case "rejected": {
      if (
        !baseEnvelope(raw, "rejected") ||
        !onlyKeys(raw, REJECTED_KEYS) ||
        raw.started !== false ||
        !nonempty(raw.code) ||
        !nonempty(raw.reason)
      ) {
        return { ok: false, reason: "invalid-rejected" };
      }
      return {
        ok: true,
        message: {
          type: "rejected",
          requestId: raw.requestId as string,
          generation: raw.generation as number,
          started: false,
          code: raw.code as string,
          reason: raw.reason as string,
        },
      };
    }
    case "cancelled": {
      if (
        !baseEnvelope(raw, "cancelled") ||
        !onlyKeys(raw, CANCELLED_KEYS) ||
        !(
          raw.started === true ||
          raw.started === false ||
          raw.started === "unknown"
        )
      ) {
        return { ok: false, reason: "invalid-cancelled" };
      }
      return {
        ok: true,
        message: {
          type: "cancelled",
          requestId: raw.requestId as string,
          generation: raw.generation as number,
          started: raw.started,
        },
      };
    }
    case "error": {
      if (
        !onlyKeys(raw, ERROR_KEYS) ||
        (raw.requestId !== undefined && !nonempty(raw.requestId)) ||
        (raw.generation !== undefined && !positiveInteger(raw.generation)) ||
        !nonempty(raw.code) ||
        typeof raw.message !== "string"
      ) {
        return { ok: false, reason: "invalid-error" };
      }
      return {
        ok: true,
        message: {
          type: "error",
          ...(raw.requestId === undefined
            ? {}
            : { requestId: raw.requestId as string }),
          ...(raw.generation === undefined
            ? {}
            : { generation: raw.generation as number }),
          code: raw.code as string,
          message: raw.message as string,
        },
      };
    }
    default:
      return { ok: false, reason: "unknown-message-type" };
  }
}

export function encodeHostMessage(message: HostMessage): HostEncodeResult {
  let line: string;
  try {
    line = JSON.stringify(message);
  } catch {
    return { ok: false, reason: "unserializable-message" };
  }
  if (Buffer.byteLength(line, "utf8") > MAX_HELPER_MESSAGE_BYTES) {
    return { ok: false, reason: "message-too-large" };
  }
  return { ok: true, line: `${line}\n` };
}

export function helloMessage(
  requestId: string,
  generation: number,
): HelloMessage {
  return {
    type: "hello",
    protocolVersion: HELPER_PROTOCOL_VERSION,
    requestId,
    generation,
  };
}

/**
 * Bounded line splitter. It refuses to grow a partial line past the protocol
 * maximum and reports that as a protocol failure instead of buffering forever.
 */
export class HelperLineDecoder {
  private buffered: Buffer = Buffer.alloc(0);

  push(chunk: Buffer | string): {
    readonly lines: readonly string[];
    readonly error?: "message-too-large";
  } {
    const incoming = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, "utf8");
    const combined = Buffer.concat([this.buffered, incoming]);
    if (combined.length > MAX_HELPER_MESSAGE_BYTES && !combined.includes(0x0a)) {
      this.buffered = Buffer.alloc(0);
      return { lines: [], error: "message-too-large" };
    }
    const lines: string[] = [];
    let start = 0;
    for (let index = 0; index < combined.length; index += 1) {
      if (combined[index] !== 0x0a) continue;
      const line = combined.subarray(start, index).toString("utf8");
      lines.push(line.endsWith("\r") ? line.slice(0, -1) : line);
      start = index + 1;
    }
    const rest = combined.subarray(start);
    if (rest.length > MAX_HELPER_MESSAGE_BYTES) {
      this.buffered = Buffer.alloc(0);
      return { lines: [], error: "message-too-large" };
    }
    this.buffered = Buffer.from(rest);
    return { lines };
  }

  get pendingBytes(): number {
    return this.buffered.length;
  }
}
