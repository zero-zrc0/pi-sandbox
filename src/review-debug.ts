import { appendFileSync, existsSync, mkdirSync, renameSync, statSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { dirname, join } from "node:path";
import { homedir } from "node:os";

const MAX_LOG_BYTES = 5 * 1024 * 1024;

export interface ReviewDebugSink {
  write(event: Record<string, unknown>): void;
}

export function createReviewDebugReporter(sink?: ReviewDebugSink): (event: Record<string, unknown>) => void {
  if (sink === undefined) return () => undefined;
  return (event) => {
    try {
      sink.write(event);
    } catch {
      return;
    }
  };
}

export function writeReviewDebug(event: Record<string, unknown>, directory = join(homedir(), ".pi", "agents", "pi-sandbox")): void {
  const file = join(directory, "debug.txt");
  let line = `${JSON.stringify({ time: new Date().toISOString(), ...event })}\n`;
  if (Buffer.byteLength(line) > MAX_LOG_BYTES) {
    line = `${JSON.stringify({ time: new Date().toISOString(), event: "log-entry-too-large" })}\n`;
  }
  mkdirSync(dirname(file), { recursive: true });
  if (existsSync(file) && statSync(file).size + Buffer.byteLength(line) > MAX_LOG_BYTES) {
    renameSync(file, join(directory, `debug-${Date.now()}-${randomUUID()}.txt`));
  }
  appendFileSync(file, line);
}
