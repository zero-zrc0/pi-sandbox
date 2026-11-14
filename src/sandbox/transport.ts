import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { MAX_HELPER_DIAGNOSTIC_BYTES } from "#sandbox/types";
import { HelperLineDecoder } from "#sandbox/protocol";

export interface HelperProcessSpec {
  readonly executable: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly environment: Readonly<Record<string, string>>;
}

export interface HelperExitInfo {
  readonly code: number | null;
  readonly signal: string | null;
}

export interface HelperSendResult {
  readonly ok: boolean;
  readonly reason?: string;
}

export type HelperLineHandler = (line: string) => void;
export type HelperExitHandler = (info: HelperExitInfo) => void;
export type HelperErrorHandler = (error: Error) => void;

/**
 * One helper process. The transport only frames lines and owns the process; it
 * does not interpret approvals or plans.
 */
export class HelperTransport {
  private readonly child: ChildProcessWithoutNullStreams;
  private readonly decoder = new HelperLineDecoder();
  private readonly lineHandlers = new Set<HelperLineHandler>();
  private readonly exitHandlers = new Set<HelperExitHandler>();
  private readonly errorHandlers = new Set<HelperErrorHandler>();
  private diagnosticText = "";
  private closed = false;
  private exited = false;
  private readonly exitPromise: Promise<HelperExitInfo>;
  private resolveExit!: (info: HelperExitInfo) => void;
  private killTimer: NodeJS.Timeout | undefined;

  constructor(spec: HelperProcessSpec) {
    this.child = spawn(spec.executable, [...spec.args], {
      cwd: spec.cwd,
      env: { ...spec.environment },
      stdio: ["pipe", "pipe", "pipe"],
      shell: false,
      windowsHide: true,
      detached: process.platform !== "win32",
    });
    this.exitPromise = new Promise<HelperExitInfo>((resolve) => {
      this.resolveExit = resolve;
    });
    this.child.stdout.on("data", (chunk: Buffer) => {
      const decoded = this.decoder.push(chunk);
      if (decoded.error) {
        this.emitError(new Error(decoded.error));
        this.kill();
        return;
      }
      for (const line of decoded.lines) {
        for (const handler of this.lineHandlers) handler(line);
      }
    });
    this.child.stderr.on("data", (chunk: Buffer) => {
      if (typeof chunk === "string") {
        this.appendDiagnostic(chunk);
      } else {
        this.appendDiagnostic(chunk.toString("utf8"));
      }
    });
    this.child.on("error", (error) => {
      this.emitError(error instanceof Error ? error : new Error(String(error)));
    });
    this.child.on("exit", (code, signal) => {
      this.exited = true;
      if (this.killTimer) {
        clearTimeout(this.killTimer);
        this.killTimer = undefined;
      }
      const info = { code, signal };
      this.resolveExit(info);
      for (const handler of this.exitHandlers) handler(info);
    });
    this.child.stdin.on("error", () => {
      // A helper that exits early surfaces through `exit`; a write failure is
      // reported by `send`.
    });
  }

  get pid(): number | undefined {
    return this.child.pid;
  }

  get isExited(): boolean {
    return this.exited;
  }

  get diagnostics(): string {
    return this.diagnosticText;
  }

  onLine(handler: HelperLineHandler): () => void {
    this.lineHandlers.add(handler);
    return () => this.lineHandlers.delete(handler);
  }

  onExit(handler: HelperExitHandler): () => void {
    if (this.exited) {
      queueMicrotask(() => handler({ code: null, signal: null }));
    }
    this.exitHandlers.add(handler);
    return () => this.exitHandlers.delete(handler);
  }

  onError(handler: HelperErrorHandler): () => void {
    this.errorHandlers.add(handler);
    return () => this.errorHandlers.delete(handler);
  }

  waitForExit(): Promise<HelperExitInfo> {
    return this.exitPromise;
  }

  send(line: string): HelperSendResult {
    if (this.closed || this.exited || !this.child.stdin.writable) {
      return { ok: false, reason: "helper-stdin-closed" };
    }
    try {
      this.child.stdin.write(line);
      return { ok: true };
    } catch (error) {
      return {
        ok: false,
        reason: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /** Ask the helper to terminate, escalating to a tree kill if it does not. */
  kill(graceMs = 1_000): void {
    this.closed = true;
    if (this.exited) return;
    try {
      this.child.stdin.end();
    } catch {
      // Already closed.
    }
    try {
      this.child.kill();
    } catch {
      // Ignore: exit is observed through the exit handler.
    }
    if (this.killTimer) return;
    this.killTimer = setTimeout(() => {
      this.killTimer = undefined;
      this.forceTreeKill();
    }, graceMs);
    this.killTimer.unref?.();
  }

  /** Close stdin, then bound the wait and force-kill this helper's tree. */
  async close(graceMs = 1_000): Promise<void> {
    this.closed = true;
    try {
      this.child.stdin.end();
    } catch {
      // Already closed.
    }
    const finished = await Promise.race([
      this.exitPromise.then(() => true),
      new Promise<false>((resolve) => {
        const timer = setTimeout(() => resolve(false), graceMs);
        timer.unref?.();
      }),
    ]);
    if (finished) return;
    this.forceTreeKill();
    await Promise.race([
      this.exitPromise.then(() => true),
      new Promise<false>((resolve) => {
        const timer = setTimeout(() => resolve(false), graceMs);
        timer.unref?.();
      }),
    ]);
  }

  private forceTreeKill(): void {
    if (this.child.pid === undefined) return;
    if (process.platform === "win32") {
      // Kill only this helper's process tree; the PID belongs to this child.
      try {
        const killer = spawn("taskkill", ["/PID", String(this.child.pid), "/T", "/F"], {
          stdio: "ignore",
          windowsHide: true,
          shell: false,
        });
        killer.unref();
      } catch {
        // Fall through to the direct kill.
      }
    } else {
      // The helper is its own process-group leader; kill the whole group so a
      // descendant cannot survive the parent.
      try {
        process.kill(-this.child.pid, "SIGKILL");
        return;
      } catch {
        // Fall through to the direct kill.
      }
    }
    try {
      this.child.kill("SIGKILL");
    } catch {
      // Ignore.
    }
  }

  private appendDiagnostic(chunk: string): void {
    if (!chunk) return;
    if (Buffer.byteLength(this.diagnosticText, "utf8") >= MAX_HELPER_DIAGNOSTIC_BYTES) {
      return;
    }
    this.diagnosticText += chunk;
    if (Buffer.byteLength(this.diagnosticText, "utf8") > MAX_HELPER_DIAGNOSTIC_BYTES) {
      this.diagnosticText = Buffer.from(this.diagnosticText, "utf8")
        .subarray(0, MAX_HELPER_DIAGNOSTIC_BYTES)
        .toString("utf8");
    }
  }

  private emitError(error: Error): void {
    for (const handler of this.errorHandlers) handler(error);
  }
}

export function spawnHelper(spec: HelperProcessSpec): HelperTransport {
  return new HelperTransport(spec);
}
