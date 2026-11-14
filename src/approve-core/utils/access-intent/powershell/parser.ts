import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { StringDecoder } from "node:string_decoder";

export interface PowerShellEngine {
  readonly id: string;
  readonly executable: string;
  readonly args: readonly string[];
}

export interface PowerShellParserLimits {
  readonly timeoutMs: number;
  readonly maxInputBytes: number;
  readonly maxOutputBytes: number;
  readonly maxAstNodes: number;
  readonly maxDepth: number;
  readonly maxUnits: number;
}

export interface PowerShellExtent {
  readonly start: number;
  readonly end: number;
}

export interface PowerShellProgramCall extends PowerShellExtent {
  readonly commandName: string | null;
  readonly arguments: readonly string[] | null;
  readonly dynamic: boolean;
  readonly dotSource: boolean;
}

export type PowerShellLanguageOperationKind =
  | "assignment"
  | "alias-change"
  | "location-change"
  | "environment-change"
  | "function-definition"
  | "control-flow"
  | "dynamic-execution"
  | "process-spawn"
  | "dot-source"
  | "redirection"
  | "provider-access"
  | "file-read"
  | "file-write"
  | "file-delete"
  | "network-access"
  | "dynamic-command"
  | "dynamic-argument"
  | "unknown";

export interface PowerShellLanguageOperation extends PowerShellExtent {
  readonly kind: PowerShellLanguageOperationKind;
  readonly target: string | null;
}

export interface PowerShellParseSummary {
  readonly engineIdentity: string;
  readonly completeness: "complete" | "failed";
  readonly parseErrors: readonly { readonly id: string; readonly start: number; readonly end: number }[];
  readonly units: readonly PowerShellExtent[];
  readonly programCalls: readonly PowerShellProgramCall[];
  readonly languageOperations: readonly PowerShellLanguageOperation[];
  readonly features: readonly string[];
  readonly astNodeCount: number;
  readonly maxDepth: number;
}

export type PowerShellParseResult =
  | { readonly ok: true; readonly summary: PowerShellParseSummary }
  | { readonly ok: false; readonly reason: string };

export interface PowerShellParserPort {
  parse(request: PowerShellParseRequest, signal?: AbortSignal): Promise<PowerShellParseResult>;
}

export interface PowerShellHelperProcess {
  write(line: string): void;
  onStdout(listener: (chunk: Uint8Array) => void): () => void;
  onError(listener: (error: Error) => void): () => void;
  onExit(listener: (code: number | null) => void): () => void;
  kill(): void;
}

export interface PowerShellParserOptions {
  readonly engine?: PowerShellEngine;
  readonly limits?: Partial<PowerShellParserLimits>;
  readonly helperScriptPath?: string;
  readonly spawnHelper?: (engine: PowerShellEngine) => PowerShellHelperProcess;
  readonly createRequestId?: () => string;
}

export interface PowerShellParseRequest {
  readonly source: string;
  readonly limits?: Partial<PowerShellParserLimits>;
}

export const DEFAULT_POWERSHELL_PARSER_LIMITS: PowerShellParserLimits = Object.freeze({
  timeoutMs: 3_000,
  maxInputBytes: 262_144,
  maxOutputBytes: 1_048_576,
  maxAstNodes: 20_000,
  maxDepth: 128,
  maxUnits: 256,
});

const HARD_LIMITS: PowerShellParserLimits = Object.freeze({
  timeoutMs: 10_000,
  maxInputBytes: 1_048_576,
  maxOutputBytes: 4_194_304,
  maxAstNodes: 100_000,
  maxDepth: 512,
  maxUnits: 256,
});

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isExtent(value: unknown, sourceLength: number): value is PowerShellExtent {
  if (!isRecord(value)) return false;
  return Number.isSafeInteger(value.start) && Number.isSafeInteger(value.end) &&
    (value.start as number) >= 0 && (value.end as number) >= (value.start as number) &&
    (value.end as number) <= sourceLength;
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function normalizedLimits(
  base: Partial<PowerShellParserLimits> | undefined,
  request: Partial<PowerShellParserLimits> | undefined,
): PowerShellParserLimits | undefined {
  const values = { ...DEFAULT_POWERSHELL_PARSER_LIMITS, ...base, ...request };
  for (const value of Object.values(values)) {
    if (!Number.isSafeInteger(value) || value < 1) return undefined;
  }
  return {
    timeoutMs: Math.min(values.timeoutMs, HARD_LIMITS.timeoutMs),
    maxInputBytes: Math.min(values.maxInputBytes, HARD_LIMITS.maxInputBytes),
    maxOutputBytes: Math.min(values.maxOutputBytes, HARD_LIMITS.maxOutputBytes),
    maxAstNodes: Math.min(values.maxAstNodes, HARD_LIMITS.maxAstNodes),
    maxDepth: Math.min(values.maxDepth, HARD_LIMITS.maxDepth),
    maxUnits: Math.min(values.maxUnits, HARD_LIMITS.maxUnits),
  };
}

function parseReply(
  value: unknown,
  requestId: string,
  source: string,
  trustedEngineId: string,
  previousIdentity: string | undefined,
): { readonly ok: true; readonly summary: PowerShellParseSummary } |
   { readonly ok: false; readonly reason: string } {
  if (!isRecord(value) || value.protocolVersion !== 1 || value.requestId !== requestId ||
      typeof value.engineIdentity !== "string" || value.engineIdentity.length === 0) {
    return { ok: false, reason: "invalid-response" };
  }
  if (previousIdentity !== undefined && value.engineIdentity !== previousIdentity) {
    return { ok: false, reason: "engine-identity-changed" };
  }
  if (value.completeness !== "complete" && value.completeness !== "failed") {
    return { ok: false, reason: "invalid-response" };
  }
  if (!Array.isArray(value.parseErrors) || !Array.isArray(value.units) ||
      !Array.isArray(value.programCalls) || !Array.isArray(value.languageOperations) ||
      !isStringArray(value.features) ||
      !Number.isSafeInteger(value.astNodeCount) || (value.astNodeCount as number) < 0 ||
      !Number.isSafeInteger(value.maxDepth) || (value.maxDepth as number) < 0) {
    return { ok: false, reason: "invalid-response" };
  }

  const parseErrors: Array<{ id: string; start: number; end: number }> = [];
  for (const error of value.parseErrors) {
    if (!isRecord(error) || typeof error.id !== "string" || !isExtent(error, source.length)) {
      return { ok: false, reason: "invalid-response" };
    }
    parseErrors.push(Object.freeze({ id: error.id, start: error.start, end: error.end }));
  }

  const units: PowerShellExtent[] = [];
  let previousEnd = 0;
  for (const unit of value.units) {
    if (!isExtent(unit, source.length) || unit.start < previousEnd) {
      return { ok: false, reason: "invalid-response" };
    }
    units.push(Object.freeze({ start: unit.start, end: unit.end }));
    previousEnd = unit.end;
  }

  const programCalls: PowerShellProgramCall[] = [];
  for (const call of value.programCalls) {
    if (!isRecord(call) || !isExtent(call, source.length) ||
        !(call.commandName === null || typeof call.commandName === "string") ||
        !(call.arguments === null || isStringArray(call.arguments)) ||
        typeof call.dynamic !== "boolean" || typeof call.dotSource !== "boolean") {
      return { ok: false, reason: "invalid-response" };
    }
    programCalls.push(Object.freeze({
      start: call.start,
      end: call.end,
      commandName: call.commandName,
      arguments: call.arguments === null ? null : [...call.arguments],
      dynamic: call.dynamic,
      dotSource: call.dotSource,
    }));
  }

  const operationKinds = new Set<PowerShellLanguageOperationKind>([
    "assignment", "alias-change", "location-change", "environment-change",
    "function-definition", "control-flow", "dynamic-execution", "process-spawn",
    "dot-source", "redirection", "provider-access", "dynamic-command", "dynamic-argument",
    "file-read", "file-write", "file-delete", "network-access", "unknown",
  ]);
  const languageOperations: PowerShellLanguageOperation[] = [];
  for (const operation of value.languageOperations) {
    if (!isRecord(operation) || !isExtent(operation, source.length) ||
        typeof operation.kind !== "string" || !operationKinds.has(operation.kind as PowerShellLanguageOperationKind) ||
        !(operation.target === null || typeof operation.target === "string")) {
      return { ok: false, reason: "invalid-response" };
    }
    languageOperations.push(Object.freeze({
      start: operation.start,
      end: operation.end,
      kind: operation.kind as PowerShellLanguageOperationKind,
      target: operation.target,
    }));
  }

  return {
    ok: true,
    summary: Object.freeze({
      engineIdentity: `${trustedEngineId}/${value.engineIdentity}`,
      completeness: value.completeness,
      parseErrors: Object.freeze(parseErrors),
      units: Object.freeze(units),
      programCalls: Object.freeze(programCalls),
      languageOperations: Object.freeze(languageOperations),
      features: Object.freeze([...value.features]),
      astNodeCount: value.astNodeCount as number,
      maxDepth: value.maxDepth as number,
    }),
  };
}

class JsonlHelperSession {
  private readonly decoder = new StringDecoder("utf8");
  private buffer = "";
  private closed = false;
  private removeListeners: Array<() => void> = [];
  private active?: {
    requestId: string;
    maxOutputBytes: number;
    resolve(value: unknown): void;
    reject(error: Error): void;
    timeout?: ReturnType<typeof setTimeout>;
    signal?: AbortSignal;
    onAbort?: () => void;
  };

  constructor(private readonly child: PowerShellHelperProcess) {
    this.removeListeners.push(
      child.onStdout((chunk) => this.onStdout(chunk)),
      child.onError((error) => this.fail(error)),
      child.onExit((code) => this.fail(new Error(`helper-exited:${code ?? "unknown"}`))),
    );
  }

  get isClosed(): boolean {
    return this.closed;
  }

  request(
    requestId: string,
    line: string,
    limits: PowerShellParserLimits,
    signal?: AbortSignal,
  ): Promise<unknown> {
    if (this.closed) return Promise.reject(new Error("helper-closed"));
    if (this.active !== undefined) return Promise.reject(new Error("helper-busy"));
    if (signal?.aborted) return Promise.reject(new Error("cancelled"));

    return new Promise((resolve, reject) => {
      const active: NonNullable<JsonlHelperSession["active"]> = {
        requestId,
        maxOutputBytes: limits.maxOutputBytes,
        resolve,
        reject,
        ...(signal === undefined ? {} : { signal }),
      };
      if (signal !== undefined) {
        active.onAbort = () => this.fail(new Error("cancelled"));
        signal.addEventListener("abort", active.onAbort, { once: true });
      }
      active.timeout = setTimeout(() => this.fail(new Error("timeout")), limits.timeoutMs);
      this.active = active;
      try {
        this.child.write(`${line}\n`);
      } catch (error) {
        this.fail(error instanceof Error ? error : new Error(String(error)));
      }
    });
  }

  close(error: Error = new Error("helper-closed")): void {
    this.terminate(error);
  }

  private terminate(error: Error): void {
    if (this.closed) return;
    this.closed = true;
    const active = this.active;
    this.active = undefined;
    this.clearActive(active);
    active?.reject(error);
    for (const remove of this.removeListeners) remove();
    this.removeListeners = [];
    this.child.kill();
  }

  private onStdout(chunk: Uint8Array): void {
    if (this.closed) return;
    this.buffer += this.decoder.write(Buffer.from(chunk));
    while (true) {
      const lineBreak = this.buffer.indexOf("\n");
      if (lineBreak < 0) break;
      const line = this.buffer.slice(0, lineBreak).replace(/\r$/u, "");
      this.buffer = this.buffer.slice(lineBreak + 1);
      this.onLine(line);
      if (this.closed) return;
    }
    if (this.active !== undefined && Buffer.byteLength(this.buffer, "utf8") > this.active.maxOutputBytes) {
      this.fail(new Error("output-limit-exceeded"));
    }
  }

  private onLine(line: string): void {
    const active = this.active;
    if (active === undefined) {
      this.fail(new Error("protocol-unsolicited-output"));
      return;
    }
    if (Buffer.byteLength(line, "utf8") > active.maxOutputBytes) {
      this.fail(new Error("output-limit-exceeded"));
      return;
    }
    let value: unknown;
    try {
      value = JSON.parse(line);
    } catch {
      this.fail(new Error("protocol-invalid-json"));
      return;
    }
    if (!isRecord(value) || value.protocolVersion !== 1 || value.requestId !== active.requestId) {
      this.fail(new Error("protocol-request-mismatch"));
      return;
    }
    this.active = undefined;
    this.clearActive(active);
    active.resolve(value);
  }

  private fail(error: Error): void {
    this.terminate(error);
  }

  private clearActive(active = this.active): void {
    if (active?.timeout !== undefined) clearTimeout(active.timeout);
    if (active?.signal !== undefined && active.onAbort !== undefined) {
      active.signal.removeEventListener("abort", active.onAbort);
    }
  }
}

function minimalEnvironment(): NodeJS.ProcessEnv {
  if (process.platform !== "win32") return { PATH: "/usr/bin:/bin", HOME: process.env.HOME };
  const systemRoot = process.env.SystemRoot ?? "C:\\Windows";
  return {
    SystemRoot: systemRoot,
    windir: systemRoot,
    PATH: join(systemRoot, "System32"),
    TEMP: process.env.TEMP,
    TMP: process.env.TMP,
    PSModulePath: "",
  };
}

function spawnPowerShellHelper(
  engine: PowerShellEngine,
  helperScriptPath: string,
): PowerShellHelperProcess {
  const child = spawn(engine.executable, [
    ...engine.args,
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    helperScriptPath,
  ], {
    cwd: dirname(engine.executable),
    env: minimalEnvironment(),
    windowsHide: true,
    stdio: ["pipe", "pipe", "ignore"],
  });
  return {
    write: (line) => child.stdin.write(line, "utf8"),
    onStdout: (listener) => {
      child.stdout.on("data", listener);
      return () => child.stdout.off("data", listener);
    },
    onError: (listener) => {
      child.on("error", listener);
      return () => child.off("error", listener);
    },
    onExit: (listener) => {
      child.on("exit", listener);
      return () => child.off("exit", listener);
    },
    kill: () => { child.kill(); },
  };
}

function errorReason(error: unknown): string {
  return error instanceof Error ? error.message : "helper-failed";
}

export class PowerShellParser {
  private readonly engine: PowerShellEngine | undefined;
  private readonly limits: Partial<PowerShellParserLimits> | undefined;
  private readonly helperScriptPath: string;
  private readonly spawnHelper: (engine: PowerShellEngine) => PowerShellHelperProcess;
  private readonly createRequestId: () => string;
  private session: JsonlHelperSession | undefined;
  private engineIdentity: string | undefined;
  private queue: Promise<void> = Promise.resolve();
  private disposed = false;

  constructor(options: PowerShellParserOptions = {}) {
    this.engine = options.engine ?? resolveTrustedPowerShellEngine();
    this.limits = options.limits;
    this.helperScriptPath = options.helperScriptPath ?? fileURLToPath(new URL("./parser-helper.ps1", import.meta.url));
    this.spawnHelper = options.spawnHelper ?? ((engine) => spawnPowerShellHelper(engine, this.helperScriptPath));
    this.createRequestId = options.createRequestId ?? randomUUID;
  }

  parse(request: PowerShellParseRequest, signal?: AbortSignal): Promise<PowerShellParseResult> {
    const task = this.queue.then(() => this.parseSerial(request, signal));
    this.queue = task.then(() => undefined, () => undefined);
    return task;
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.session?.close(new Error("parser-disposed"));
    this.session = undefined;
  }

  private async parseSerial(
    request: PowerShellParseRequest,
    signal?: AbortSignal,
  ): Promise<PowerShellParseResult> {
    if (signal?.aborted) return { ok: false, reason: "cancelled" };
    if (this.disposed) return { ok: false, reason: "parser-disposed" };
    if (this.engine === undefined) return { ok: false, reason: "engine-unavailable" };
    if (typeof request.source !== "string") return { ok: false, reason: "invalid-source" };
    const limits = normalizedLimits(this.limits, request.limits);
    if (limits === undefined) return { ok: false, reason: "invalid-limits" };
    if (Buffer.byteLength(request.source, "utf8") > limits.maxInputBytes) {
      return { ok: false, reason: "input-limit-exceeded" };
    }

    const requestId = this.createRequestId();
    const payload = {
      protocolVersion: 1,
      requestId,
      source: request.source,
      limits: {
        maxAstNodes: limits.maxAstNodes,
        maxDepth: limits.maxDepth,
        maxUnits: limits.maxUnits,
        maxInputBytes: limits.maxInputBytes,
      },
    };
    const line = JSON.stringify(payload);
    if (Buffer.byteLength(line, "utf8") > limits.maxInputBytes) {
      return { ok: false, reason: "input-limit-exceeded" };
    }

    let lastReason = "helper-failed";
    for (let attempt = 0; attempt < 2; attempt += 1) {
      if (signal?.aborted) return { ok: false, reason: "cancelled" };
      if (this.disposed) return { ok: false, reason: "parser-disposed" };
      try {
        const session = this.getSession();
        const raw = await session.request(requestId, line, limits, signal);
        if (signal?.aborted) return { ok: false, reason: "cancelled" };
        if (this.disposed) return { ok: false, reason: "parser-disposed" };
        const parsed = parseReply(raw, requestId, request.source, this.engine.id, this.engineIdentity);
        if (parsed.ok) {
          this.engineIdentity = parsed.summary.engineIdentity.slice(this.engine.id.length + 1);
          return parsed;
        }
        lastReason = parsed.reason;
        this.resetSession();
      } catch (error) {
        lastReason = signal?.aborted ? "cancelled" : errorReason(error);
        this.resetSession();
        if (signal?.aborted) return { ok: false, reason: "cancelled" };
        if (this.disposed) return { ok: false, reason: "parser-disposed" };
      }
    }
    return { ok: false, reason: this.disposed ? "parser-disposed" : lastReason };
  }

  private getSession(): JsonlHelperSession {
    if (this.disposed) throw new Error("parser-disposed");
    if (this.session !== undefined && !this.session.isClosed) return this.session;
    if (this.engine === undefined) throw new Error("engine-unavailable");
    this.session = new JsonlHelperSession(this.spawnHelper(this.engine));
    return this.session;
  }

  private resetSession(): void {
    this.session?.close();
    this.session = undefined;
  }
}

export function resolveTrustedPowerShellEngine(
  platform: string = process.platform,
  systemRoot: string | undefined = process.env.SystemRoot,
): PowerShellEngine | undefined {
  const candidates = platform === "win32"
    ? [
      join(systemRoot ?? "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
      join(systemRoot ?? "C:\\Windows", "Sysnative", "WindowsPowerShell", "v1.0", "powershell.exe"),
    ]
    : platform === "linux" || platform === "darwin"
      ? ["/usr/bin/pwsh", "/usr/local/bin/pwsh"]
      : [];
  const executable = candidates.find((candidate) => existsSync(candidate));
  if (executable === undefined) return undefined;
  return {
    id: platform === "win32" ? "windows-powershell" : "powershell-core",
    executable,
    args: [],
  };
}
