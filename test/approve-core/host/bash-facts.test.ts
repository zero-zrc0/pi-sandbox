/**
 * Phase 12 Bash fact view (specs/host-integration.md §2).
 *
 * The host already holds one parsed BashProgram per call. This module projects
 * that program into a frozen plain dictionary for node consumers, and collects
 * the per-call views of one step through the shared provider without ever
 * parsing a call twice. Fixtures are fake programs that count reads; expected
 * values are the worked examples from the spec, never recomputed by the
 * implementation's own logic.
 */
import { describe, expect, it } from "vitest";
import type { BashProgram } from "#approve-core/utils/access-intent/bash/program";
import type {
  BashProgramProvider,
  BashProgramRequest,
} from "#approve-core/nodes/analysis";
import {
  BASH_FACT_KEYS,
  bashProgramFactsView,
  collectStepBashFacts,
} from "#approve-core/host/bash-facts";

// ---------------------------------------------------------------------------
// Fake program with read counters
// ---------------------------------------------------------------------------

interface ReadCounts {
  source: number;
  commands: number;
  pathRuleCandidates: number;
  externalAccesses: number;
}

interface FakeProgram {
  readonly program: BashProgram;
  readonly counts: ReadCounts;
  readonly commands: readonly object[];
  readonly candidates: readonly object[];
  readonly externals: readonly object[];
}

function fakeProgram(source: string): FakeProgram {
  const commands = [{ commandText: "ls", executable: "ls" }];
  const candidates = [{ path: { value: () => "/tmp/a" }, effect: { effect: "read" } }];
  const externals = [{ path: { value: () => "/etc/hosts" }, effect: { effect: "read" } }];
  const counts: ReadCounts = {
    source: 0,
    commands: 0,
    pathRuleCandidates: 0,
    externalAccesses: 0,
  };
  const program = {
    baseDir: "C:/workspace",
    get source(): string {
      counts.source += 1;
      return source;
    },
    commands(): readonly object[] {
      counts.commands += 1;
      return commands;
    },
    pathRuleCandidates(): readonly object[] {
      counts.pathRuleCandidates += 1;
      return candidates;
    },
    externalAccesses(): readonly object[] {
      counts.externalAccesses += 1;
      return externals;
    },
  } as unknown as BashProgram;
  return { program, counts, commands, candidates, externals };
}

// ---------------------------------------------------------------------------
// bashProgramFactsView
// ---------------------------------------------------------------------------

describe("bashProgramFactsView", () => {
  it("projects the built-in keys from the program", () => {
    const fake = fakeProgram("ls -la /tmp");
    const view = bashProgramFactsView(fake.program);

    expect(view.commandText).toBe("ls -la /tmp");
    expect(view.commands).toBe(fake.commands);
    expect(view.programCalls).toMatchObject([{ programName: null, arguments: [], dynamic: true }]);
    expect(view.workingDirectory).toBe("C:/workspace");
    expect(view.pathRuleCandidates).toBe(fake.candidates);
    expect(view.externalAccesses).toBe(fake.externals);
  });

  it("is an ordinary frozen null-prototype dictionary with own data properties", () => {
    const fake = fakeProgram("ls");
    const view = bashProgramFactsView(fake.program);
    const record = view as unknown as Record<string, unknown>;

    expect(Object.getPrototypeOf(view)).toBeNull();
    expect(Object.isFrozen(view)).toBe(true);
    expect(Object.keys(record)).toEqual([
      "commandText", "commands", "programCalls", "workingDirectory", "pathRuleCandidates", "externalAccesses",
    ]);
    expect(Object.hasOwn(record, "commandText")).toBe(true);
    expect("toString" in record).toBe(false);

    for (const key of BASH_FACT_KEYS) {
      const descriptor = Object.getOwnPropertyDescriptor(record, key);
      expect(descriptor).toBeDefined();
      expect(descriptor!.get).toBeUndefined();
      expect(descriptor!.writable).toBe(false);
    }
  });

  it("does not recompute arrays when the view is read (no getters)", () => {
    const fake = fakeProgram("ls");
    const view = bashProgramFactsView(fake.program);

    expect(fake.counts).toEqual({
      source: 1,
      commands: 1,
      pathRuleCandidates: 1,
      externalAccesses: 1,
    });

    expect(view.commands).toBe(fake.commands);
    expect(view.pathRuleCandidates).toBe(fake.candidates);
    expect(view.externalAccesses).toBe(fake.externals);
    expect(fake.counts).toEqual({
      source: 1,
      commands: 1,
      pathRuleCandidates: 1,
      externalAccesses: 1,
    });
  });

  it("reads unknown keys as undefined", () => {
    const view = bashProgramFactsView(fakeProgram("ls").program);
    const record = view as unknown as Record<string, unknown>;

    expect(record["customKey"]).toBeUndefined();
    expect(record["__proto__"]).toBeUndefined();
  });
});

describe("BASH_FACT_KEYS", () => {
  it("re-exports the reserved built-in key tuple in order", () => {
    expect(BASH_FACT_KEYS).toEqual([
      "commandText",
      "commands",
      "programCalls",
      "workingDirectory",
      "pathRuleCandidates",
      "externalAccesses",
    ]);
    expect(Object.isFrozen(BASH_FACT_KEYS)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// collectStepBashFacts
// ---------------------------------------------------------------------------

interface CallResult {
  readonly program?: BashProgram;
  readonly reject?: Error;
}

function fakeProvider(
  results: ReadonlyMap<string, CallResult>,
): { provider: BashProgramProvider; calls: BashProgramRequest[] } {
  const calls: BashProgramRequest[] = [];
  const provider: BashProgramProvider = async (call) => {
    calls.push(call);
    const result = results.get(call.toolCallId);
    if (result === undefined) return undefined;
    if (result.reject !== undefined) throw result.reject;
    return result.program;
  };
  return { provider, calls };
}

function request(toolCallId: string): BashProgramRequest {
  return { toolCallId, toolName: "bash", arguments: { command: "ls" } };
}

describe("collectStepBashFacts", () => {
  it("returns one frozen null-prototype view per resolved call", async () => {
    const first = fakeProgram("ls -la");
    const second = fakeProgram("git status");
    const { provider, calls } = fakeProvider(new Map([
      ["call-1", { program: first.program }],
      ["call-2", { program: second.program }],
    ]));

    const views = await collectStepBashFacts({
      calls: [request("call-1"), request("call-2")],
      provider,
    });

    expect(calls).toEqual([request("call-1"), request("call-2")]);
    expect(views).toBeDefined();
    expect(Object.getPrototypeOf(views)).toBeNull();
    expect(Object.isFrozen(views)).toBe(true);
    expect(Object.keys(views!)).toEqual(["call-1", "call-2"]);
    expect(views!["call-1"]!.commandText).toBe("ls -la");
    expect(views!["call-1"]!.commands).toBe(first.commands);
    expect(views!["call-2"]!.commandText).toBe("git status");
    expect(views!["call-2"]!.externalAccesses).toBe(second.externals);
  });

  it("omits a call whose provider answers undefined without retrying it", async () => {
    const kept = fakeProgram("ls");
    const { provider, calls } = fakeProvider(new Map([
      ["call-1", { program: kept.program }],
    ]));

    const views = await collectStepBashFacts({
      calls: [request("call-missing"), request("call-1")],
      provider,
    });

    expect(calls).toHaveLength(2);
    expect(Object.keys(views!)).toEqual(["call-1"]);
    expect(views!["call-missing"]).toBeUndefined();
  });

  it("omits a call whose provider rejects after exactly one attempt", async () => {
    const kept = fakeProgram("ls");
    const { provider, calls } = fakeProvider(new Map([
      ["call-broken", { reject: new Error("parse failed") }],
      ["call-1", { program: kept.program }],
    ]));

    const views = await collectStepBashFacts({
      calls: [request("call-broken"), request("call-1")],
      provider,
    });

    expect(calls).toHaveLength(2);
    expect(calls.map((call) => call.toolCallId)).toEqual(["call-broken", "call-1"]);
    expect(Object.keys(views!)).toEqual(["call-1"]);
  });

  it("returns undefined when every call is omitted", async () => {
    const { provider, calls } = fakeProvider(new Map([
      ["call-a", { reject: new Error("parse failed") }],
    ]));

    const views = await collectStepBashFacts({
      calls: [request("call-a"), request("call-b")],
      provider,
    });

    expect(calls).toHaveLength(2);
    expect(views).toBeUndefined();
  });

  it("returns undefined for an empty step", async () => {
    const { provider, calls } = fakeProvider(new Map());

    const views = await collectStepBashFacts({ calls: [], provider });

    expect(calls).toEqual([]);
    expect(views).toBeUndefined();
  });
});
