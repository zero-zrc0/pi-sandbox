/**
 * Approval chain audit log.
 *
 * The log records structural facts only: which node ran, which units changed,
 * which original call became final, which human prompt was shown and which
 * model request was actually sent. It never stores original argument bodies,
 * reviewer transcripts or credentials. Events are bounded in memory; an
 * optional sink receives the same sanitized event objects.
 */
import type { ChainAuditEntry } from "#approve-core/runtime";
import type { AskTarget, CallDecision, FinalCallResult } from "#approve-core/contracts";

export type ApprovalAuditEvent =
  | {
      readonly kind: "node-start";
      readonly at: number;
      readonly generation: number;
      readonly stepKey: string;
      /** Digest of the captured step manifest this evaluate started against. */
      readonly captureDigest: string;
      readonly nodeId: string;
      readonly position: ChainAuditEntry["position"];
      readonly priority: number | null;
      readonly revision: number;
    }
  | {
      readonly kind: "node";
      readonly at: number;
      readonly generation: number;
      readonly stepKey: string;
      readonly nodeId: string;
      readonly position: ChainAuditEntry["position"];
      readonly priority: number | null;
      readonly revisionBefore: number;
      readonly revisionAfter: number;
      readonly outcome: ChainAuditEntry["outcome"];
      /** Sanitized fault reason; present only when the node ended in a fault. */
      readonly reason?: string;
    }
  | {
      readonly kind: "unit";
      readonly at: number;
      readonly generation: number;
      readonly stepKey: string;
      readonly toolCallId: string;
      readonly unitId: string;
      readonly revision: number;
      readonly nodeId: string;
      readonly decision: CallDecision;
      readonly askFor?: AskTarget;
      readonly reason: string;
    }
  | {
      readonly kind: "call";
      readonly at: number;
      readonly generation: number;
      readonly stepKey: string;
      readonly toolCallId: string;
      readonly decision: FinalCallResult["decision"];
      readonly revision: number;
      readonly reasons: readonly string[];
    }
  | {
      readonly kind: "human";
      readonly at: number;
      readonly generation: number;
      readonly stepKey: string;
      readonly toolCallId: string;
      readonly phase: "prompt" | "response" | "unavailable";
      readonly decision?: "approve" | "deny" | "cancel";
      readonly askFor?: AskTarget;
      readonly reason?: string;
    }
  | {
      readonly kind: "model";
      readonly at: number;
      readonly generation: number;
      readonly stepKey: string;
      readonly nodeId: string;
      readonly owner: string;
      readonly requests: number;
      readonly outcome: "sent" | "failed";
    }
  | {
      readonly kind: "execution";
      readonly at: number;
      readonly generation: number;
      readonly stepKey: string;
      readonly toolCallId: string;
      readonly toolName: string;
      readonly phase: "start" | "end";
      readonly isError?: boolean;
    }
  | {
      readonly kind: "lifecycle";
      readonly at: number;
      readonly generation: number;
      readonly action: "publish" | "reload" | "invalidate" | "dispose";
      readonly detail?: string;
    };

export interface ApprovalAuditLog {
  record(event: ApprovalAuditEvent): void;
  snapshot(): readonly ApprovalAuditEvent[];
  size(): number;
  dispose(): void;
}

export interface ApprovalAuditLogOptions {
  readonly now?: () => number;
  readonly maxEvents?: number;
  readonly sink?: (event: ApprovalAuditEvent) => void;
}

const DEFAULT_MAX_EVENTS = 4_096;

export function createApprovalAuditLog(
  options: ApprovalAuditLogOptions = {},
): ApprovalAuditLog {
  const now = options.now ?? Date.now;
  const maxEvents = Number.isSafeInteger(options.maxEvents) && options.maxEvents! > 0
    ? options.maxEvents!
    : DEFAULT_MAX_EVENTS;
  const events: ApprovalAuditEvent[] = [];
  let disposed = false;

  function record(event: ApprovalAuditEvent): void {
    if (disposed) return;
    const stamped = Object.freeze({ ...event, at: now() }) as ApprovalAuditEvent;
    events.push(stamped);
    if (events.length > maxEvents) events.shift();
    if (options.sink !== undefined) {
      try {
        options.sink(stamped);
      } catch {
        // A broken audit sink never changes an approval decision.
      }
    }
  }

  return {
    record,
    snapshot: () => Object.freeze([...events]),
    size: () => events.length,
    dispose: () => {
      disposed = true;
      events.length = 0;
    },
  };
}
