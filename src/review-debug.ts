import { appendFileSync, existsSync, mkdirSync, renameSync, statSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { basename, dirname, extname, join } from "node:path";
import { homedir } from "node:os";
import type { AuditEvent, AuditSinkPort } from "#approve-core/host/pi-extension";
import { BUILTIN_REVIEW_DEBUG_NODE } from "#approve-core/node-ids";

const MAX_LOG_BYTES = 5 * 1024 * 1024;

export interface ReviewDebugSink {
  write(event: Record<string, unknown>): void;
}

export function isReviewDebugEnabled(nodes: readonly { readonly id: string; readonly enabled: boolean }[]): boolean {
  return nodes.find((node) => node.id === BUILTIN_REVIEW_DEBUG_NODE)?.enabled ?? true;
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

function auditRecord(event: AuditEvent): Record<string, unknown> | undefined {
  switch (event.kind) {
    case "chain-node":
      return { event: "approval_chain", kind: event.kind, sessionId: event.sessionId,
        generation: event.generation, stepKey: event.stepKey, nodeId: event.nodeId, outcome: event.outcome };
    case "step":
      return { event: "approval_chain", kind: event.kind, sessionId: event.sessionId,
        requestId: event.requestId, stepKey: event.stepKey, generation: event.generation,
        toolCallId: event.toolCallId, toolName: event.toolName, decision: event.decision };
    case "human":
      return { event: "approval_chain", kind: event.kind, sessionId: event.sessionId,
        toolCallId: event.toolCallId, askFor: event.askFor, decision: event.decision,
        escalation: event.escalation };
    case "publication":
      return { event: "approval_chain", kind: event.kind, sessionId: event.sessionId,
        generation: event.generation, mode: event.mode };
    case "invalidate":
      return { event: "approval_chain", kind: event.kind, sessionId: event.sessionId, reason: event.reason };
    case "execution":
      return { event: "approval_chain", kind: event.kind, sessionId: event.sessionId,
        phase: event.phase, toolCallId: event.toolCallId, toolName: event.toolName,
        ...(event.parentToolCallId === undefined ? {} : { parentToolCallId: event.parentToolCallId }),
        ...(event.isError === undefined ? {} : { isError: event.isError }) };
    case "session-decision":
      return { event: "approval_chain", kind: event.kind, sessionId: event.sessionId,
        toolCallId: event.toolCallId, toolName: event.toolName, decision: event.decision,
        requestId: event.requestId };
    case "error":
      return { event: "approval_chain", kind: event.kind, sessionId: event.sessionId, area: event.area };
    default:
      return undefined;
  }
}

export function createReviewDebugAuditObserver(
  report: (event: Record<string, unknown>) => void,
  enabled: (sessionId: string) => boolean,
): AuditSinkPort {
  return {
    write(event) {
      if (!enabled(event.sessionId)) return;
      const record = auditRecord(event);
      if (record !== undefined) report(record);
    },
  };
}

/** Append one JSONL line. Hosts pass `paths.debugLogFile`; the argument defaults to the legacy location. */
export function writeReviewDebug(
  event: Record<string, unknown>,
  file = join(homedir(), ".pi", "agent", "pi-sandbox", "debug.txt"),
): void {
  let line = `${JSON.stringify({ time: new Date().toISOString(), ...event })}\n`;
  if (Buffer.byteLength(line) > MAX_LOG_BYTES) {
    line = `${JSON.stringify({ time: new Date().toISOString(), event: "log-entry-too-large" })}\n`;
  }
  const directory = dirname(file);
  mkdirSync(directory, { recursive: true });
  if (existsSync(file) && statSync(file).size + Buffer.byteLength(line) > MAX_LOG_BYTES) {
    const extension = extname(file);
    renameSync(file, join(directory, `${basename(file, extension)}-${Date.now()}-${randomUUID()}${extension}`));
  }
  appendFileSync(file, line);
}
