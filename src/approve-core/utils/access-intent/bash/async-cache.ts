/**
 * Async memoization for expensive one-time initialization.
 *
 * A successful result is cached; a rejected attempt is forgotten so the next
 * caller retries. Concurrent callers share the same in-flight promise.
 */

export interface AsyncMemo<T> {
  /** Resolve the value, starting the factory on the first call. */
  get(): Promise<T>;
  /** Resolved value, or undefined when the factory has not succeeded yet. */
  peek(): T | undefined;
  /** Drop the cached result and any in-flight attempt. */
  reset(): void;
}

export function createAsyncMemo<T>(factory: () => Promise<T>): AsyncMemo<T> {
  let pending: Promise<T> | undefined;
  let resolved: T | undefined;
  let hasValue = false;
  let generation = 0;

  return {
    get(): Promise<T> {
      if (pending) return pending;
      const current = ++generation;
      pending = factory().then(
        (value) => {
          if (current === generation) {
            resolved = value;
            hasValue = true;
          }
          return value;
        },
        (error: unknown) => {
          if (current === generation) {
            pending = undefined;
            hasValue = false;
            resolved = undefined;
          }
          throw error;
        },
      );
      return pending;
    },
    peek(): T | undefined {
      return hasValue ? resolved : undefined;
    },
    reset(): void {
      generation += 1;
      pending = undefined;
      resolved = undefined;
      hasValue = false;
    },
  };
}
