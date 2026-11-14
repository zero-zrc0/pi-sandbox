import { describe, expect, it } from "vitest";
import { createAsyncMemo } from "#approve-core/utils/access-intent/bash/async-cache";

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe("async memo", () => {
  it("runs the factory once for concurrent callers", async () => {
    let calls = 0;
    const gate = deferred<number>();
    const memo = createAsyncMemo(async () => {
      calls += 1;
      return gate.promise;
    });

    const first = memo.get();
    const second = memo.get();
    expect(calls).toBe(1);

    gate.resolve(7);
    await expect(first).resolves.toBe(7);
    await expect(second).resolves.toBe(7);
    expect(memo.peek()).toBe(7);
    await expect(memo.get()).resolves.toBe(7);
    expect(calls).toBe(1);
  });

  it("clears a rejected attempt and retries on the next call", async () => {
    let calls = 0;
    const memo = createAsyncMemo(async () => {
      calls += 1;
      if (calls === 1) throw new Error("boom");
      return calls;
    });

    await expect(memo.get()).rejects.toThrow("boom");
    expect(memo.peek()).toBeUndefined();
    await expect(memo.get()).resolves.toBe(2);
    expect(calls).toBe(2);
  });

  it("resets cached state without touching other in-flight callers", async () => {
    let calls = 0;
    const gate = deferred<string>();
    const memo = createAsyncMemo(async () => {
      calls += 1;
      return calls === 1 ? gate.promise : "second";
    });

    const first = memo.get();
    memo.reset();
    await expect(memo.get()).resolves.toBe("second");
    gate.resolve("first");
    await expect(first).resolves.toBe("first");
    expect(calls).toBe(2);
    expect(memo.peek()).toBe("second");
  });

  it("keeps a resolved value until reset", async () => {
    const memo = createAsyncMemo(async () => 3);
    await memo.get();
    memo.reset();
    expect(memo.peek()).toBeUndefined();
  });
});
