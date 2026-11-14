/**
 * Session-scoped memory for `ask` decisions (design §5.6).
 *
 * When the rule table yields `ask`, the human prompt may offer to remember the
 * choice for the rest of the session. Only an explicit human selection writes
 * here; reviewer-model decisions never do, so an automated approval cannot
 * widen its own authority. The memory lives in one host session, never touches
 * disk, and is dropped when the session ends.
 *
 * The key is the tool name plus the canonical JSON of the call arguments, so
 * any argument change asks again.
 */
import { canonicalJson } from "#approve-core/policy/project-rules/types";

export type AskSessionDecision = "allow" | "deny";

export interface AskSessionRecord {
  readonly decision: AskSessionDecision;
  /** The request id of the first decision, cited by later audit records. */
  readonly requestId: string;
}

export interface AskSessionMemory {
  /** How many decisions are currently remembered. */
  readonly size: number;
  lookup(toolName: string, args: unknown): AskSessionRecord | undefined;
  remember(toolName: string, args: unknown, decision: AskSessionDecision, requestId: string): void;
  clear(): void;
}

/** Bounded so a long session cannot grow one entry per distinct argument set. */
export const ASK_SESSION_LIMIT = 512;

/** Stable key for one tool call: the tool name and its canonical arguments. */
export function askSessionKey(toolName: string, args: unknown): string {
  let canonical: string;
  try {
    canonical = canonicalJson(args);
  } catch {
    canonical = "<unrepresentable>";
  }
  return `${toolName}\u0000${canonical}`;
}

export function createAskSessionMemory(limit = ASK_SESSION_LIMIT): AskSessionMemory {
  const entries = new Map<string, AskSessionRecord>();
  const cap = Number.isSafeInteger(limit) && limit > 0 ? limit : ASK_SESSION_LIMIT;
  return {
    get size(): number {
      return entries.size;
    },
    lookup(toolName: string, args: unknown): AskSessionRecord | undefined {
      if (typeof toolName !== "string" || toolName.length === 0) return undefined;
      return entries.get(askSessionKey(toolName, args));
    },
    remember(toolName: string, args: unknown, decision: AskSessionDecision, requestId: string): void {
      if (typeof toolName !== "string" || toolName.length === 0) return;
      if (decision !== "allow" && decision !== "deny") return;
      if (typeof requestId !== "string" || requestId.length === 0) return;
      const key = askSessionKey(toolName, args);
      // Re-inserting moves the key to the newest position for FIFO eviction.
      entries.delete(key);
      entries.set(key, Object.freeze({ decision, requestId }));
      while (entries.size > cap) {
        const oldest = entries.keys().next();
        if (oldest.done === true) break;
        entries.delete(oldest.value);
      }
    },
    clear(): void {
      entries.clear();
    },
  };
}
