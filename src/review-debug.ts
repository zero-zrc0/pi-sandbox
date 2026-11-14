import { appendFileSync, existsSync, mkdirSync, renameSync, statSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { dirname, join } from "node:path";
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
