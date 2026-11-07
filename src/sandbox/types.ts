/**
 * Contracts for controlled tool execution.
 *
 * This module plans and orchestrates execution through a trusted helper. It
 * does not provide OS isolation: a helper that cannot enforce every limit of a
 * plan must be reported as unsupported before the plan starts. The
 * `fixture`-backed helper used by the tests proves the protocol and lifecycle,
 * not a sandbox boundary.
 */
import type { PermissionMode } from "../contracts";
import type { JsonObject } from "../json";

export const BUILTIN_TOOL_NAMES = ["bash", "powershell", "read", "write", "edit", "grep", "find", "ls"] as const;
export type BuiltinToolName = (typeof BUILTIN_TOOL_NAMES)[number];

/** Version of the structured host <-> helper protocol. */
export const HELPER_PROTOCOL_VERSION = 2 as const;
export const EXECUTION_PLAN_VERSION = 2 as const;

/** Bounds are part of the protocol, not tuning knobs for a caller. */
export const MAX_HELPER_MESSAGE_BYTES = 8 * 1024 * 1024;
export const MAX_HELPER_DIAGNOSTIC_BYTES = 64 * 1024;
export const MAX_HELPER_MESSAGES = 16_384;
export const MAX_HELPER_OUTPUT_CHUNK_BYTES = 64 * 1024;
export const MAX_EXECUTION_STDOUT_BYTES = 4 * 1024 * 1024;
export const MAX_EXECUTION_STDERR_BYTES = 1024 * 1024;
export const MAX_FILE_CONTENT_BYTES = 4 * 1024 * 1024;
export const MAX_ENVIRONMENT_ENTRIES = 64;
export const MAX_ENVIRONMENT_VALUE_BYTES = 16 * 1024;
export const MAX_DEADLINE_HORIZON_MS = 24 * 60 * 60 * 1000;
export const DEFAULT_START_TIMEOUT_MS = 10_000;
export const DEFAULT_EXECUTION_DEADLINE_MS = 120_000;
export const DEFAULT_CANCEL_GRACE_MS = 3_000;
export const MAX_CONCURRENT_EXECUTIONS = 4;
export const MAX_QUEUED_EXECUTIONS = 16;

/**
 * Environment handed to a helper. Nothing is inherited implicitly: the host
 * adds names explicitly and the plan records only the filtered result.
 */
export const DEFAULT_HELPER_ENVIRONMENT_ALLOWLIST = Object.freeze([
  "PATH",
  "PATHEXT",
  "SystemRoot",
  "SystemDrive",
  "windir",
  "ComSpec",
  "TEMP",
  "TMP",
  "TMPDIR",
  "HOME",
  "USERPROFILE",
  "LANG",
  "LC_ALL",
  "TERM",
]);

export type AccessDirection = "read" | "write";
export type GrantGranularity = "file" | "directory";
export type GrantSource = "baseline" | "approved-extension";

export interface ExecutionScopeGrant {
  readonly path: string;
  readonly access: AccessDirection;
  readonly granularity: GrantGranularity;
  readonly source: GrantSource;
}

export interface FilesystemGrantInput {
  readonly path: string;
  readonly access: AccessDirection;
  readonly granularity: GrantGranularity;
}

export interface NetworkDestination {
  readonly host: string;
  readonly port?: number;
  /** Where this destination entered the plan. */
  readonly source?: "baseline" | "approved-extension";
}

export type NetworkScope =
  | { readonly kind: "none" }
  | { readonly kind: "all" }
  | { readonly kind: "destinations"; readonly destinations: readonly NetworkDestination[] };

export type ExecutionOperation =
  | {
      readonly kind: "builtin-tool";
      readonly name: BuiltinToolName;
      readonly arguments: JsonObject;
      readonly context?: JsonObject;
    }
  | {
      readonly kind: "shell";
      readonly command: string;
      readonly timeoutMs?: number;
      /** Host-approved shell interpreter; set by the plan compiler. */
      readonly shell?: string;
    }
  | { readonly kind: "read-file"; readonly path: string }
  | {
      readonly kind: "access-file";
      readonly path: string;
      readonly mode: "read" | "read-write";
    }
  | {
      readonly kind: "write-file";
      readonly path: string;
      readonly content: string;
    }
  | { readonly kind: "mkdir"; readonly path: string }
  | {
      /**
       * Metadata-only check: does `path` exist as a directory? It must be
       * bound to an exact approved file write at `forFile`; it never creates.
       */
      readonly kind: "access-dir";
      readonly path: string;
      readonly forFile: string;
    };

export type ExecutionOperationKind = ExecutionOperation["kind"];

export interface BackendCapabilities {
  readonly filesystem: {
    readonly read: boolean;
    readonly write: boolean;
    /** The finest granularity the backend can express. */
    readonly granularity: GrantGranularity;
    /** True only when protected control paths can be denied explicitly. */
    readonly protectedPaths: boolean;
    readonly environment: boolean;
  };
  readonly network: "none" | "all" | "domains";
  readonly cancel: boolean;
  readonly streamOutput: boolean;
  readonly startedNotification: boolean;
  readonly processTree: boolean;
}

export interface BackendIdentity {
  readonly id: string;
  readonly version: string;
}

export interface ExecutionPlan {
  readonly version: typeof EXECUTION_PLAN_VERSION;
  readonly requestId: string;
  readonly toolCallId: string;
  readonly actionDigest: string;
  readonly sessionId: string;
  readonly tool: {
    readonly name: string;
    readonly owner: string;
    readonly revision: string;
    readonly bindingId: string;
  };
  readonly mode: PermissionMode;
  readonly policyRevision: string;
  readonly configRevision: string;
  readonly cwd: string;
  readonly operation: ExecutionOperation;
  /** Filtered environment; no controller credentials or model keys. */
  readonly environment: Readonly<Record<string, string>>;
  readonly filesystem: readonly ExecutionScopeGrant[];
  /** Absolute protected control paths the helper must deny for writes. */
  readonly protectedPaths: readonly string[];
  readonly network: NetworkScope;
  readonly deadlineAt: number;
  readonly backend: {
    readonly id: string;
  };
  readonly digest: string;
}

export type ExecutionFailureCode =
  | "invalid-plan"
  | "binding-mismatch"
  | "full-access-no-sandbox"
  | "sandbox-unavailable"
  | "sandbox-version-mismatch"
  | "sandbox-setup-failed"
  | "sandbox-capability-unsupported"
  | "sandbox-start-failed"
  | "sandbox-denied"
  | "sandbox-path-missing"
  | "sandbox-protocol-error"
  | "sandbox-transport-lost"
  | "sandbox-output-limit"
  | "sandbox-queue-full"
  | "sandbox-deadline-exceeded"
  | "execution-failed";

export type CancellationCode =
  | "execution-cancelled"
  | "execution-timeout"
  | "plan-invalidated"
  | "session-disposed";

export type ExecutionStarted = boolean | "unknown";

export type ImpactState = "none" | "known" | "unknown";

export interface ExecutionRecord {
  readonly executionMode?: "sandbox" | "host";
  readonly requestId: string;
  readonly toolCallId: string;
  readonly actionDigest: string;
  readonly planDigest: string;
  readonly generation: number;
  readonly toolName: string;
  readonly started: ExecutionStarted;
  readonly state: "completed" | "failed" | "cancelled";
  readonly code?: ExecutionFailureCode | CancellationCode;
  readonly exitCode?: number;
  readonly impact: ImpactState;
}

interface ExecutionOutcomeBase {
  readonly stdout: string;
  readonly stderr: string;
  readonly truncated: boolean;
  readonly record: ExecutionRecord;
  readonly dataBase64?: string;
}

export type ExecutionOutcome =
  | (ExecutionOutcomeBase & {
      readonly state: "completed";
      readonly started: true;
      readonly exitCode: number;
      readonly dataBase64?: string;
    })
  | (ExecutionOutcomeBase & {
      readonly state: "failed";
      readonly started: ExecutionStarted;
      readonly code: ExecutionFailureCode;
      readonly reason: string;
      readonly impact: ImpactState;
    })
  | (ExecutionOutcomeBase & {
      readonly state: "cancelled";
      readonly started: ExecutionStarted;
      readonly code: CancellationCode;
      readonly reason: string;
      readonly impact: ImpactState;
    });

/** Host-side mode description. Full access has no module sandbox at all. */
export interface ExecutionModeDescription {
  readonly mode: PermissionMode;
  readonly sandboxed: boolean;
  readonly boundary: string;
  readonly reason: string;
}

/**
 * MCP coverage is stated separately from shell/file takeover. The local
 * transport target can be bounded by this module; a server that already
 * started and the remote side effects of a call cannot.
 */
export interface McpExecutionCoverage {
  readonly localStarted: {
    readonly controlled: false;
    readonly reason: string;
  };
  readonly remote: {
    readonly controlled: false;
    readonly boundary: "local-transport-only";
    readonly reason: string;
  };
}

export const MCP_EXECUTION_COVERAGE: McpExecutionCoverage = Object.freeze({
  localStarted: Object.freeze({
    controlled: false,
    reason:
      "a local MCP server that already started is outside this call's process boundary",
  }),
  remote: Object.freeze({
    controlled: false,
    boundary: "local-transport-only",
    reason:
      "only the local request target and authorization can be bounded; remote files and processes cannot",
  }),
});

export interface ExecutionCoverage {
  readonly sandboxed: boolean;
  readonly boundary: string;
  /** Built-in tools whose final operations this module controls. */
  readonly controlled: readonly string[];
  /** Built-in tools that keep their default Pi operations. */
  readonly uncontrolledBuiltins: readonly string[];
  /** Categories that cannot be taken over by this module. */
  readonly unsupported: readonly string[];
  readonly mcp: McpExecutionCoverage;
}

export function describeExecutionMode(
  mode: PermissionMode,
): ExecutionModeDescription {
  if (mode === "full-access") {
    return {
      mode,
      sandboxed: false,
      boundary: "none",
      reason: "full-access: this module applies no filesystem or network sandbox",
    };
  }
  return {
    mode,
    sandboxed: true,
    boundary: "trusted-helper",
    reason: `${mode}: execution must be enforced by a negotiated helper backend`,
  };
}
