import type { ExecutionRequest } from "../types";
import type { EgressGrantRef } from "../lifecycle";

export interface DirectBackendProbe {
  readonly ok: true;
  readonly capabilities: import("../types").BackendCapabilities;
}

export interface DirectBackendUnavailable {
  readonly ok: false;
  readonly code: string;
  readonly reason: string;
}

export interface NativeCompletionInput {
  readonly exitCode: number | null;
  readonly signal: string | null;
  readonly stdout: Buffer;
  readonly stderr: string;
  readonly workerResult?: Record<string, unknown>;
}

export interface NativeCompletion {
  readonly exitCode: number | null;
  readonly impact: "known" | "unknown";
  readonly errorCode?: string;
  readonly error?: string;
  readonly dataBase64?: string;
}

export interface NativeLaunchPlan {
  readonly executable: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly environment: Readonly<Record<string, string>>;
  readonly input?: string;
  readonly readyMarker?: string;
  readonly outputMode: "stream" | "worker" | "capture";
  readonly outputLimitBytes?: number;
  readonly outputLimitError?: { readonly code: string; readonly reason: string };
  readonly complete?: (input: NativeCompletionInput) => NativeCompletion;
}

export interface DirectBackendDriver {
  readonly id: string;
  readonly version: string;
  probe(signal?: AbortSignal): Promise<DirectBackendProbe | DirectBackendUnavailable>;
  prepare(
    request: ExecutionRequest,
    egress?: EgressGrantRef,
    signal?: AbortSignal,
  ): Promise<NativeLaunchPlan | DirectBackendUnavailable>;
}
