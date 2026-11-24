import type { ExecutionRequest } from "../types";
import type { EgressGrantRef } from "../lifecycle";

export interface DirectBackendProbe {
  readonly ok: true;
  readonly capabilities: import("../types").BackendCapabilities;
  readonly linuxBubblewrap?: import("../runtime-store").LinuxBubblewrapSelection;
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
  /** Stable process-level identity for this backend capability observation. */
  readonly probeCacheKey?: string;
  probe(signal?: AbortSignal): Promise<DirectBackendProbe | DirectBackendUnavailable>;
  prepare(
    request: ExecutionRequest,
    egress?: EgressGrantRef,
    signal?: AbortSignal,
  ): Promise<NativeLaunchPlan | DirectBackendUnavailable>;
}
const processProbeCache = new Map<string, DirectBackendProbe>();

export function probeDirectBackendOnce(
  backend: DirectBackendDriver,
  signal?: AbortSignal,
): Promise<DirectBackendProbe | DirectBackendUnavailable> {
  const key = backend.probeCacheKey;
  if (key === undefined) return backend.probe(signal);
  if (signal?.aborted) {
    return Promise.resolve({ ok: false, code: "unavailable", reason: "native backend probe was cancelled" });
  }
  const cached = processProbeCache.get(key);
  if (cached !== undefined) return Promise.resolve(cached);
  const pending = Promise.resolve().then(() => backend.probe(signal)).then(result => {
    if (result.ok && !signal?.aborted) processProbeCache.set(key, result);
    return result;
  });
  if (signal === undefined) return pending;
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (result: DirectBackendProbe | DirectBackendUnavailable) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      resolve(result);
    };
    const onAbort = () => finish({
      ok: false,
      code: "unavailable",
      reason: "native backend probe was cancelled",
    });
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) onAbort();
    pending!.then(finish, error => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      reject(error);
    });
  });
}
