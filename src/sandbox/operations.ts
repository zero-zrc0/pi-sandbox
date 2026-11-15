import { formatPiSandboxError } from "../error-format";

export interface OperationOutputChunk {
  readonly stream: "stdout" | "stderr";
  readonly data: string;
}

export interface OperationRunOptions {
  readonly signal?: AbortSignal;
  /** Pi's shell timeout, already converted from seconds to milliseconds. */
  readonly timeoutMs?: number;
  readonly onOutput?: (chunk: OperationOutputChunk) => void;
  /** Pi's requested cwd. The runner must verify it against the approved plan. */
  readonly cwd?: string;
}

/** A controlled operation could not produce a normal Pi result. */
export class ControlledOperationError extends Error {
  readonly code: string;
  readonly reason: string;

  constructor(code: string, reason: string) {
    // Pi's shell tool matches these two messages exactly, so preserve them.
    const message = code === "aborted" || code === "timeout"
      ? code === "aborted" ? "aborted" : reason
      : formatPiSandboxError(`[${code}] ${reason}`);
    super(message);
    this.name = "ControlledOperationError";
    this.code = code;
    this.reason = reason;
  }
}
