import { dirname, resolve } from "node:path";
import type {
  BashOperations,
  EditOperations,
  ReadOperations,
  WriteOperations,
} from "@earendil-works/pi-coding-agent";
import {
  createReadToolDefinition,
  DEFAULT_MAX_BYTES,
  formatSize,
  truncateHead,
  type ReadToolDetails,
} from "@earendil-works/pi-coding-agent";

import { isSamePath, normalizeHostPath } from "#sandbox/path";
import { formatPiSandboxError } from "../error-format";
import {
  MAX_FILE_CONTENT_BYTES,
  type ExecutionOperation,
  type ExecutionOutcome,
} from "#sandbox/types";

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

/**
 * Compile one plan for this operation and run it through the execution
 * controller. Implementations must fail closed before any helper starts.
 */
export type RunControlledOperation = (
  operation: ExecutionOperation,
  options: OperationRunOptions,
) => Promise<ExecutionOutcome>;

export interface ControlledPiOperations {
  readonly bash: BashOperations;
  readonly read: ReadOperations;
  readonly write: WriteOperations;
  readonly edit: EditOperations;
}

/** A controlled operation could not produce a normal Pi result. */
export class ControlledOperationError extends Error {
  readonly code: string;
  readonly reason: string;

  constructor(code: string, reason: string) {
    // Pi's shell tool matches these two messages exactly, so keep them
    // compatible instead of wrapping them in the diagnostic prefix.
    const message = code === "aborted" || code === "timeout"
      ? code === "aborted" ? "aborted" : reason
      : formatPiSandboxError(`[${code}] ${reason}`);
    super(message);
    this.name = "ControlledOperationError";
    this.code = code;
    this.reason = reason;
  }
}

function completed(outcome: ExecutionOutcome): Extract<ExecutionOutcome, { state: "completed" }> {
  if (outcome.state === "completed") return outcome;
  throw operationError(outcome);
}

function operationError(
  outcome: Exclude<ExecutionOutcome, { state: "completed" }>,
): ControlledOperationError {
  if (outcome.state === "cancelled") {
    if (outcome.code === "execution-cancelled") {
      return new ControlledOperationError("aborted", outcome.reason);
    }
    if (outcome.code === "execution-timeout") {
      return new ControlledOperationError(
        "timeout",
        outcome.reason,
      );
    }
    return new ControlledOperationError(outcome.code, outcome.reason);
  }
  const detail =
    outcome.stderr.length > 0
      ? `${outcome.reason}\n${outcome.stderr}`
      : outcome.reason;
  return new ControlledOperationError(outcome.code, detail);
}

/** Map a timeout cancellation to Pi's `timeout:<seconds>` shell convention. */
function timeoutError(
  outcome: ExecutionOutcome,
  timeoutMs: number | undefined,
): ControlledOperationError {
  if (
    outcome.state === "cancelled" &&
    outcome.code === "execution-timeout"
  ) {
    const seconds = timeoutMs === undefined ? 0 : timeoutMs / 1000;
    return new ControlledOperationError(
      "timeout",
      `timeout:${seconds}`,
    );
  }
  return operationError(outcome as Exclude<ExecutionOutcome, { state: "completed" }>);
}

function decodeBase64(data: string | undefined): Buffer {
  if (typeof data !== "string") {
    throw new ControlledOperationError(
      "sandbox-protocol-error",
      "helper did not return file data",
    );
  }
  if (
    data.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]*={0,2}$/u.test(data)
  ) {
    throw new ControlledOperationError(
      "sandbox-protocol-error",
      "helper returned invalid base64 file data",
    );
  }
  const buffer = Buffer.from(data, "base64");
  if (buffer.length > MAX_FILE_CONTENT_BYTES) {
    throw new ControlledOperationError(
      "sandbox-output-limit",
      "file data exceeds the protocol limit",
    );
  }
  return buffer;
}

const IMAGE_SIGNATURES: ReadonlyArray<{
  readonly mimeType: string;
  readonly matches: (buffer: Buffer) => boolean;
}> = [
  {
    mimeType: "image/png",
    matches: (buffer) =>
      buffer.length >= 8 &&
      buffer[0] === 0x89 &&
      buffer[1] === 0x50 &&
      buffer[2] === 0x4e &&
      buffer[3] === 0x47 &&
      buffer[4] === 0x0d &&
      buffer[5] === 0x0a &&
      buffer[6] === 0x1a &&
      buffer[7] === 0x0a,
  },
  {
    mimeType: "image/jpeg",
    matches: (buffer) =>
      buffer.length >= 3 &&
      buffer[0] === 0xff &&
      buffer[1] === 0xd8 &&
      buffer[2] === 0xff,
  },
  {
    mimeType: "image/gif",
    matches: (buffer) =>
      buffer.length >= 6 &&
      buffer.subarray(0, 6).toString("ascii") === "GIF87a",
  },
  {
    mimeType: "image/gif",
    matches: (buffer) =>
      buffer.length >= 6 &&
      buffer.subarray(0, 6).toString("ascii") === "GIF89a",
  },
  {
    mimeType: "image/webp",
    matches: (buffer) =>
      buffer.length >= 12 &&
      buffer.subarray(0, 4).toString("ascii") === "RIFF" &&
      buffer.subarray(8, 12).toString("ascii") === "WEBP",
  },
  {
    mimeType: "image/bmp",
    matches: (buffer) => buffer.length >= 2 && buffer[0] === 0x42 && buffer[1] === 0x4d,
  },
];

/**
 * Sniff the same formats Pi's read tool supports from bytes read through the
 * helper. This avoids the public package's file-path detector, which would read
 * the host filesystem outside the controlled executor.
 */
export function detectImageMimeType(buffer: Buffer): string | null {
  for (const signature of IMAGE_SIGNATURES) {
    if (signature.matches(buffer)) return signature.mimeType;
  }
  return null;
}

function secondsToMilliseconds(timeout: number | undefined): number | undefined {
  if (timeout === undefined) return undefined;
  if (!Number.isFinite(timeout) || timeout <= 0) {
    throw new ControlledOperationError(
      "invalid-plan",
      "timeout must be a finite number of seconds",
    );
  }
  const milliseconds = Math.round(timeout * 1000);
  if (!Number.isSafeInteger(milliseconds) || milliseconds <= 0) {
    throw new ControlledOperationError("invalid-plan", "timeout is out of range");
  }
  return milliseconds;
}

function nonzeroResult(outcome: ExecutionOutcome): { readonly exitCode: number } {
  const result = completed(outcome);
  return { exitCode: result.exitCode };
}

/**
 * Build Pi's public operations so every default filesystem/shell side effect
 * goes through the injected runner. The dependency on Pi's own factories is
 * in `pi.ts`; this module only implements the operation contracts.
 */
export interface ControlledOperationOptions {
  /** Ambient signal for Pi operations that do not receive one directly. */
  readonly getSignal?: () => AbortSignal | undefined;
  /**
   * Absolute path of the file this call was approved to write, when the
   * approval names one exact file. Used to tell "the parent already exists"
   * apart from "the parent must be created".
   */
  readonly getApprovedWriteTarget?: () => string | undefined;
}

/**
 * Keep forwarded shell output comfortably below Pi's OutputAccumulator
 * persistence thresholds (2000 lines / 50 KiB). Pi would otherwise create a
 * host temp file outside the helper. A larger result fails explicitly.
 */
const MAX_FORWARDED_BASH_BYTES = 40 * 1024;
const MAX_FORWARDED_BASH_LINES = 1_500;

export function createControlledOperations(
  run: RunControlledOperation,
  operationOptions: ControlledOperationOptions = {},
): ControlledPiOperations {
  const ambientSignal = (): AbortSignal | undefined => operationOptions.getSignal?.();
  const readFileBytes = async (
    path: string,
    signal: AbortSignal | undefined,
  ): Promise<Buffer> => {
    const effectiveSignal = signal ?? ambientSignal();
    const outcome = await run(
      { kind: "read-file", path },
      effectiveSignal === undefined ? {} : { signal: effectiveSignal },
    );
    return decodeBase64(completed(outcome).dataBase64);
  };

  const access = async (
    path: string,
    mode: "read" | "read-write",
    signal: AbortSignal | undefined,
  ): Promise<void> => {
    const effectiveSignal = signal ?? ambientSignal();
    const outcome = await run(
      { kind: "access-file", path, mode },
      effectiveSignal === undefined ? {} : { signal: effectiveSignal },
    );
    completed(outcome);
  };

  const writeFile = async (
    path: string,
    content: string,
    signal: AbortSignal | undefined,
  ): Promise<void> => {
    const effectiveSignal = signal ?? ambientSignal();
    const outcome = await run(
      { kind: "write-file", path, content },
      effectiveSignal === undefined ? {} : { signal: effectiveSignal },
    );
    completed(outcome);
  };

  const bash: BashOperations = {
    exec: async (command, cwd, options) => {
      if (typeof command !== "string" || command.trim().length === 0) {
        throw new ControlledOperationError("invalid-plan", "shell command is empty");
      }
      const timeoutMs = secondsToMilliseconds(options.timeout);
      const signal = options.signal ?? ambientSignal();
      let forwardedBytes = 0;
      let forwardedLines = 0;
      let outputLimit = false;
      const outcome = await run(
        {
          kind: "shell",
          command,
          ...(timeoutMs === undefined ? {} : { timeoutMs }),
        },
        {
          cwd,
          ...(signal === undefined ? {} : { signal }),
          ...(timeoutMs === undefined ? {} : { timeoutMs }),
          onOutput: (chunk) => {
            if (outputLimit) return;
            const data = Buffer.from(chunk.data, "utf8");
            const newlines = (chunk.data.match(/\n/gu) ?? []).length;
            if (
              forwardedBytes + data.length > MAX_FORWARDED_BASH_BYTES ||
              forwardedLines + newlines > MAX_FORWARDED_BASH_LINES
            ) {
              // Never feed Pi's OutputAccumulator past its persistence
              // threshold: it would write an unplanned host temp file.
              outputLimit = true;
              return;
            }
            forwardedBytes += data.length;
            forwardedLines += newlines;
            options.onData(data);
          },
        },
      );
      if (outcome.state === "cancelled" && outcome.code === "execution-timeout") {
        throw timeoutError(outcome, timeoutMs);
      }
      if (outputLimit) {
        throw new ControlledOperationError(
          "sandbox-output-limit",
          "shell output exceeds the controlled tool display limit",
        );
      }
      return nonzeroResult(outcome);
    },
  };

  const read: ReadOperations = {
    readFile: (path) => readFileBytes(path, ambientSignal()),
    access: (path) => access(path, "read", ambientSignal()),
    detectImageMimeType: async (path) => {
      const signal = ambientSignal();
      const outcome = await run(
        { kind: "read-file", path },
        signal === undefined ? {} : { signal },
      );
      return detectImageMimeType(decodeBase64(completed(outcome).dataBase64));
    },
  };

  const write: WriteOperations = {
    writeFile: (path, content) => writeFile(path, content, ambientSignal()),
    mkdir: async (dir) => {
      const signal = ambientSignal();
      const runOptions = signal === undefined ? {} : { signal };
      const approvedFile = operationOptions.getApprovedWriteTarget?.();
      const approvedParent = approvedFile
        ? normalizeHostPath(dirname(approvedFile))
        : null;
      const requestedDir = normalizeHostPath(dir);
      if (
        approvedFile !== undefined &&
        approvedParent &&
        requestedDir &&
        isSamePath(approvedParent, requestedDir)
      ) {
        // Pi's write tool always calls mkdir first. When the parent already
        // exists that must not require a directory write grant: check it
        // instead, and never create anything here.
        try {
          completed(
            await run(
              { kind: "access-dir", path: dir, forFile: approvedFile },
              runOptions,
            ),
          );
          return;
        } catch (error) {
          const missing =
            error instanceof ControlledOperationError &&
            error.code === "sandbox-path-missing";
          if (!missing) throw error;
          // The parent really is absent: creating it is a directory write and
          // must be authorized as one, or the plan refuses before any start.
          completed(await run({ kind: "mkdir", path: dir }, runOptions));
          return;
        }
      }
      completed(await run({ kind: "mkdir", path: dir }, runOptions));
    },
  };

  const edit: EditOperations = {
    readFile: (path) => readFileBytes(path, ambientSignal()),
    writeFile: (path, content) => writeFile(path, content, ambientSignal()),
    access: (path) => access(path, "read-write", ambientSignal()),
  };

  return { bash, read, write, edit };
}

/**
 * Pi's read definition resolves host path variants before it calls the
 * injected operations, which would probe the host filesystem outside the
 * helper. Keep Pi's schema/renderers, but resolve the exact path without a
 * host probe and read bytes through the controlled operations. Images need an
 * SDK image processor that is not part of the public contract; they fail closed
 * instead of falling back to host I/O.
 */
export function createControlledReadToolDefinition(
  cwd: string,
  read: ReadOperations,
): ReturnType<typeof createReadToolDefinition> {
  const base = createReadToolDefinition(cwd);
  return {
    ...base,
    execute: async (_toolCallId, { path, offset, limit }, signal, _onUpdate, ctx) => {
      if (signal?.aborted) throw new Error("Operation aborted");
      const absolutePath = normalizeHostPath(resolve(ctx?.cwd || cwd, path));
      if (!absolutePath) throw new Error("Path cannot be resolved");
      const buffer = await read.readFile(absolutePath);
      if (signal?.aborted) throw new Error("Operation aborted");
      const mimeType = detectImageMimeType(buffer);
      if (mimeType) {
        throw new ControlledOperationError(
          "sandbox-capability-unsupported",
          `image reads (${mimeType}) require host image processing; use a text file or bash`,
        );
      }

      const textContent = buffer.toString("utf-8");
      const allLines = textContent.split("\n");
      const totalFileLines = allLines.length;
      const startLine = offset ? Math.max(0, offset - 1) : 0;
      const startLineDisplay = startLine + 1;
      if (startLine >= allLines.length) {
        throw new Error(
          `Offset ${offset} is beyond end of file (${allLines.length} lines total)`,
        );
      }
      let selectedContent: string;
      let userLimitedLines: number | undefined;
      if (limit !== undefined) {
        const endLine = Math.min(startLine + limit, allLines.length);
        selectedContent = allLines.slice(startLine, endLine).join("\n");
        userLimitedLines = endLine - startLine;
      } else {
        selectedContent = allLines.slice(startLine).join("\n");
      }

      const truncation = truncateHead(selectedContent);
      let outputText: string;
      let details: ReadToolDetails | undefined;
      if (truncation.firstLineExceedsLimit) {
        const firstLineSize = formatSize(
          Buffer.byteLength(allLines[startLine], "utf-8"),
        );
        outputText = `[Line ${startLineDisplay} is ${firstLineSize}, exceeds ${formatSize(DEFAULT_MAX_BYTES)} limit. Use bash: sed -n '${startLineDisplay}p' ${path} | head -c ${DEFAULT_MAX_BYTES}]`;
        details = { truncation };
      } else if (truncation.truncated) {
        const endLineDisplay = startLineDisplay + truncation.outputLines - 1;
        const nextOffset = endLineDisplay + 1;
        outputText = truncation.content;
        if (truncation.truncatedBy === "lines") {
          outputText += `\n\n[Showing lines ${startLineDisplay}-${endLineDisplay} of ${totalFileLines}. Use offset=${nextOffset} to continue.]`;
        } else {
          outputText += `\n\n[Showing lines ${startLineDisplay}-${endLineDisplay} of ${totalFileLines} (${formatSize(DEFAULT_MAX_BYTES)} limit). Use offset=${nextOffset} to continue.]`;
        }
        details = { truncation };
      } else if (
        userLimitedLines !== undefined &&
        startLine + userLimitedLines < allLines.length
      ) {
        const remaining = allLines.length - (startLine + userLimitedLines);
        const nextOffset = startLine + userLimitedLines + 1;
        outputText = `${truncation.content}\n\n[${remaining} more lines in file. Use offset=${nextOffset} to continue.]`;
      } else {
        outputText = truncation.content;
      }
      return { content: [{ type: "text" as const, text: outputText }], details };
    },
  };
}
