import type { Message } from "@earendil-works/pi-ai";

/**
 * Bounded, in-memory reviewer conversation state and per-key serialization.
 * This is model progress, not shared session evidence: the context store owns
 * the evidence cursor, while this store owns only the reviewer's own messages.
 */

export interface ReviewerConversation {
  readonly key: string;
  messages: Message[];
  /** Context generation this conversation was built from. */
  generation: number;
  /** Set by a technical failure or a context generation change. */
  forceFull: boolean;
  completedReviewCount: number;
  lastUsedAt: number;
}

export interface ConversationLease {
  readonly state: ReviewerConversation;
  release(instant: number): void;
}

interface Entry {
  readonly state: ReviewerConversation;
  leases: number;
  timer?: ReturnType<typeof setTimeout>;
}

export function createConversationStore(input: {
  readonly maxReviewers: number;
  readonly retentionMs: number;
  readonly now?: () => number;
}) {
  const now = input.now ?? Date.now;
  const maxReviewers = Number.isSafeInteger(input.maxReviewers) && input.maxReviewers > 0
    ? Math.min(32, input.maxReviewers)
    : 1;
  const retentionMs = Number.isFinite(input.retentionMs) && input.retentionMs > 0
    ? Math.max(1, Math.min(30 * 60_000, Math.floor(input.retentionMs)))
    : 1;
  const entries = new Map<string, Entry>();

  function cancelExpiry(entry: Entry): void {
    if (entry.timer !== undefined) clearTimeout(entry.timer);
    entry.timer = undefined;
  }

  function expire(key: string, entry: Entry): void {
    if (entries.get(key) !== entry || entry.leases !== 0) return;
    const remaining = entry.state.lastUsedAt + retentionMs - now();
    if (remaining > 0) {
      entry.timer = setTimeout(() => expire(key, entry), remaining);
      entry.timer.unref?.();
      return;
    }
    entries.delete(key);
    entry.timer = undefined;
  }

  function removeEntry(key: string, entry: Entry): void {
    cancelExpiry(entry);
    if (entries.get(key) === entry) entries.delete(key);
  }

  function prune(instant: number): void {
    for (const [key, entry] of entries) {
      if (entry.leases === 0 && instant - entry.state.lastUsedAt >= retentionMs) {
        removeEntry(key, entry);
      }
    }
    if (entries.size > maxReviewers) {
      const idle = [...entries.entries()]
        .filter(([, entry]) => entry.leases === 0)
        .sort(([, left], [, right]) => left.state.lastUsedAt - right.state.lastUsedAt);
      while (entries.size > maxReviewers && idle.length > 0) {
        const [key, entry] = idle.shift()!;
        removeEntry(key, entry);
      }
    }
  }

  return {
    acquire(key: string, instant: number): ConversationLease | undefined {
      prune(instant);
      let entry = entries.get(key);
      if (entry === undefined) {
        if (entries.size >= maxReviewers) {
          const idle = [...entries.entries()]
            .filter(([, candidate]) => candidate.leases === 0)
            .sort(([, left], [, right]) => left.state.lastUsedAt - right.state.lastUsedAt)[0];
          if (idle === undefined) return undefined;
          removeEntry(idle[0], idle[1]);
        }
        entry = {
          state: {
            key,
            messages: [],
            generation: 0,
            forceFull: true,
            completedReviewCount: 0,
            lastUsedAt: instant,
          },
          leases: 0,
        };
        entries.set(key, entry);
      } else {
        cancelExpiry(entry);
      }
      entry.leases += 1;
      entry.state.lastUsedAt = instant;
      let released = false;
      return {
        state: entry.state,
        release(releasedAt) {
          if (released) return;
          released = true;
          if (entries.get(key) !== entry) return;
          entry!.leases = Math.max(0, entry!.leases - 1);
          entry!.state.lastUsedAt = releasedAt;
          if (entry!.leases === 0) {
            entry!.timer = setTimeout(() => expire(key, entry!), retentionMs);
            entry!.timer.unref?.();
          }
        },
      };
    },
    size() {
      return entries.size;
    },
    clear() {
      for (const entry of entries.values()) cancelExpiry(entry);
      entries.clear();
    },
  };
}

export type QueueFailure = "queue-full" | "queue-timeout" | "cancelled" | "disposed";

export type QueueAcquire =
  | { readonly ok: true; readonly release: () => void }
  | { readonly ok: false; readonly reason: QueueFailure };

/** A per-key serial gate with a bounded queue and a wait deadline. */
export function createKeyedQueue(input: {
  readonly now: () => number;
  readonly maxQueueLength: number;
  readonly defaultWaitMs: number;
}) {
  interface Waiter {
    settle(result: QueueAcquire): void;
  }
  const active = new Map<string, boolean>();
  const waiters = new Map<string, Waiter[]>();
  let disposed = false;

  function releaseFor(key: string): () => void {
    let released = false;
    return () => {
      if (released) return;
      released = true;
      const queue = waiters.get(key);
      if (!queue || queue.length === 0) {
        active.delete(key);
        waiters.delete(key);
        return;
      }
      const waiter = queue.shift()!;
      waiter.settle({ ok: true, release: releaseFor(key) });
    };
  }

  function removeWaiter(key: string, waiter: Waiter): void {
    const queue = waiters.get(key);
    if (!queue) return;
    const index = queue.indexOf(waiter);
    if (index >= 0) queue.splice(index, 1);
    if (queue.length === 0) waiters.delete(key);
  }

  return {
    async acquire(key: string, options: {
      readonly signal?: AbortSignal;
      readonly deadline: number;
      readonly waitMs?: number;
    }): Promise<QueueAcquire> {
      if (disposed) return { ok: false, reason: "disposed" };
      if (options.signal?.aborted) return { ok: false, reason: "cancelled" };
      if (!active.get(key)) {
        active.set(key, true);
        return { ok: true, release: releaseFor(key) };
      }
      const queue = waiters.get(key) ?? [];
      if (queue.length >= input.maxQueueLength) return { ok: false, reason: "queue-full" };
      const waitMs = options.waitMs ?? input.defaultWaitMs;
      return await new Promise<QueueAcquire>((resolve) => {
        let settled = false;
        let timer: ReturnType<typeof setTimeout> | undefined;
        const finish = (result: QueueAcquire): void => {
          if (settled) return;
          settled = true;
          if (timer !== undefined) clearTimeout(timer);
          options.signal?.removeEventListener("abort", onAbort);
          resolve(result);
        };
        const waiter: Waiter = { settle: finish };
        const onAbort = (): void => {
          removeWaiter(key, waiter);
          finish(disposed ? { ok: false, reason: "disposed" } : { ok: false, reason: "cancelled" });
        };
        queue.push(waiter);
        waiters.set(key, queue);
        options.signal?.addEventListener("abort", onAbort, { once: true });
        if (options.signal?.aborted) {
          onAbort();
          return;
        }
        const budget = Math.min(waitMs, options.deadline - input.now());
        if (budget <= 0) {
          removeWaiter(key, waiter);
          finish({ ok: false, reason: "queue-timeout" });
          return;
        }
        timer = setTimeout(() => {
          removeWaiter(key, waiter);
          finish({ ok: false, reason: "queue-timeout" });
        }, budget);
      });
    },
    dispose() {
      if (disposed) return;
      disposed = true;
      for (const [key, queue] of waiters) {
        for (const waiter of queue) waiter.settle({ ok: false, reason: "disposed" });
        waiters.delete(key);
      }
      active.clear();
    },
  };
}

/** Link the node signal, caller signal and node lifetime without leaks. */
export function linkSignals(...signals: (AbortSignal | undefined)[]): {
  readonly signal: AbortSignal;
  dispose(): void;
} {
  const controller = new AbortController();
  const sources = [...new Set(signals.filter((signal): signal is AbortSignal => signal !== undefined))];
  const onAbort = (): void => controller.abort();
  for (const signal of sources) {
    if (signal.aborted) controller.abort();
    else signal.addEventListener("abort", onAbort, { once: true });
  }
  let disposed = false;
  return {
    signal: controller.signal,
    dispose() {
      if (disposed) return;
      disposed = true;
      for (const signal of sources) signal.removeEventListener("abort", onAbort);
    },
  };
}

export function awaitSignal<T>(promise: PromiseLike<T>, signal?: AbortSignal): Promise<T> {
  const pending = Promise.resolve(promise);
  if (!signal) return pending;
  if (signal.aborted) {
    void pending.catch(() => undefined);
    return Promise.reject(new Error("aborted"));
  }
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const finish = (action: () => void): void => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      action();
    };
    const onAbort = (): void => finish(() => reject(new Error("aborted")));
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) {
      onAbort();
      void pending.catch(() => undefined);
      return;
    }
    pending.then(
      (value) => finish(() => resolve(value)),
      (error: unknown) => finish(() => reject(error)),
    );
  });
}

/** Release a physical-task reservation when the dependency itself settles. */
export function trackSettlement<T>(value: T | PromiseLike<T>, release: () => void): Promise<T> {
  let settled = false;
  return new Promise<T>((resolve, reject) => {
    const finish = (complete: () => void): void => {
      if (settled) return;
      settled = true;
      release();
      complete();
    };
    const onResolve = (result: T | PromiseLike<T>): void => finish(() => resolve(result));
    const onReject = (error: unknown): void => finish(() => reject(error));

    if (value !== null && (typeof value === "object" || typeof value === "function")) {
      let then: unknown;
      try {
        then = (value as { readonly then?: unknown }).then;
      } catch (error) {
        onReject(error);
        return;
      }
      if (typeof then === "function") {
        try {
          Reflect.apply(then, value, [onResolve, onReject]);
        } catch (error) {
          onReject(error);
        }
        return;
      }
    }
    onResolve(value as T);
  });
}

export function createSettlementAdmission(globalLimit: number): {
  reserve(key: string): (() => void) | undefined;
} {
  const byKey = new Map<string, number>();
  let active = 0;
  return {
    reserve(key) {
      const count = byKey.get(key) ?? 0;
      if (count >= 1 || active >= globalLimit) return undefined;
      byKey.set(key, count + 1);
      active += 1;
      let released = false;
      return () => {
        if (released) return;
        released = true;
        const remaining = (byKey.get(key) ?? 1) - 1;
        if (remaining <= 0) byKey.delete(key);
        else byKey.set(key, remaining);
        active = Math.max(0, active - 1);
      };
    },
  };
}

export function conversationRounds(messages: readonly Message[]): number {
  let rounds = 0;
  for (const message of messages) {
    if (message.role === "user") rounds += 1;
  }
  return rounds;
}
