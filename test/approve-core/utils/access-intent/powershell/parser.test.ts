import { describe, expect, it } from "vitest";
import {
  PowerShellParser,
  type PowerShellEngine,
  type PowerShellHelperProcess,
} from "#approve-core/utils/access-intent/powershell/parser";

const engine: PowerShellEngine = { id: "test-engine", executable: "fake-powershell", args: [] };

function response(request: Record<string, unknown>, source: string, requestId = request.requestId) {
  return {
    protocolVersion: 1,
    requestId,
    engineIdentity: "test-engine/5.1",
    completeness: "complete",
    parseErrors: [],
    units: [{ start: 0, end: source.length }],
    programCalls: [{ commandName: "git", arguments: ["status"], dynamic: false, dotSource: false, start: 0, end: source.length }],
    languageOperations: [],
    features: [],
    astNodeCount: 2,
    maxDepth: 2,
  };
}

function fakeFactory(
  respond: (request: Record<string, unknown>, attempt: number) => Record<string, unknown> | undefined,
) {
  let attempts = 0;
  const spawn = (): PowerShellHelperProcess => {
    attempts += 1;
    const stdout = new Set<(chunk: Uint8Array) => void>();
    const errors = new Set<(error: Error) => void>();
    const exits = new Set<(code: number | null) => void>();
    return {
      write(line) {
        const request = JSON.parse(line) as Record<string, unknown>;
        const reply = respond(request, attempts);
        if (reply === undefined) return;
        queueMicrotask(() => {
          for (const listener of stdout) listener(new TextEncoder().encode(`${JSON.stringify(reply)}\n`));
        });
      },
      onStdout(listener) {
        stdout.add(listener);
        return () => stdout.delete(listener);
      },
      onError(listener) {
        errors.add(listener);
        return () => errors.delete(listener);
      },
      onExit(listener) {
        exits.add(listener);
        return () => exits.delete(listener);
      },
      kill() {
        for (const listener of exits) listener(null);
      },
    };
  };
  return { spawn, count: () => attempts };
}

describe("PowerShellParser protocol", () => {
  it("sends source as JSONL and validates source extents", async () => {
    const factory = fakeFactory((request) => response(request, request.source as string));
    const parser = new PowerShellParser({ engine, spawnHelper: factory.spawn });
    const source = "Get-Content 'a;b'";

    const result = await parser.parse({ source });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.summary.units).toEqual([{ start: 0, end: source.length }]);
      expect(result.summary.programCalls[0]?.arguments).toEqual(["status"]);
    }
    expect(factory.count()).toBe(1);
    parser.dispose();
  });

  it("rejects oversized input before starting the helper", async () => {
    const factory = fakeFactory((request) => response(request, request.source as string));
    const parser = new PowerShellParser({ engine, limits: { maxInputBytes: 4 }, spawnHelper: factory.spawn });

    const result = await parser.parse({ source: "12345" });

    expect(result).toEqual({ ok: false, reason: "input-limit-exceeded" });
    expect(factory.count()).toBe(0);
    parser.dispose();
  });

  it("rebuilds once after a response with the wrong request id", async () => {
    const factory = fakeFactory((request, attempt) => {
      const source = request.source as string;
      return attempt === 1
        ? response(request, source, "wrong-request")
        : response(request, source);
    });
    const parser = new PowerShellParser({ engine, spawnHelper: factory.spawn });

    const result = await parser.parse({ source: "git status" });

    expect(result.ok).toBe(true);
    expect(factory.count()).toBe(2);
    parser.dispose();
  });

  it("fails closed after the output limit and one helper rebuild", async () => {
    const factory = fakeFactory((request) => ({
      ...response(request, request.source as string),
      features: ["x".repeat(500)],
    }));
    const parser = new PowerShellParser({ engine, limits: { maxOutputBytes: 160 }, spawnHelper: factory.spawn });

    const result = await parser.parse({ source: "git status" });

    expect(result).toMatchObject({ ok: false, reason: "output-limit-exceeded" });
    expect(factory.count()).toBe(2);
    parser.dispose();
  });

  it("discards an in-flight response when the caller cancels", async () => {
    const factory = fakeFactory(() => undefined);
    const parser = new PowerShellParser({ engine, spawnHelper: factory.spawn });
    const controller = new AbortController();
    const pending = parser.parse({ source: "git status" }, controller.signal);
    await Promise.resolve();
    expect(factory.count()).toBe(1);
    controller.abort();

    const result = await pending;

    expect(result).toEqual({ ok: false, reason: "cancelled" });
    expect(factory.count()).toBe(1);
    parser.dispose();
  });

  it("ends active and queued requests when disposed without rebuilding the helper", async () => {
    const factory = fakeFactory(() => undefined);
    const parser = new PowerShellParser({ engine, spawnHelper: factory.spawn });
    const active = parser.parse({ source: "git status" });
    const queued = parser.parse({ source: "Get-Content notes.txt" });
    await Promise.resolve();
    expect(factory.count()).toBe(1);

    parser.dispose();

    const result = await Promise.race([
      Promise.all([active, queued]),
      new Promise<null>((resolve) => setTimeout(() => resolve(null), 50)),
    ]);
    expect(result).toEqual([
      { ok: false, reason: "parser-disposed" },
      { ok: false, reason: "parser-disposed" },
    ]);
    expect(factory.count()).toBe(1);
    expect(await parser.parse({ source: "git diff" })).toEqual({
      ok: false,
      reason: "parser-disposed",
    });
    expect(factory.count()).toBe(1);
  });
});
