import { describe, expect, it, vi } from "vitest";
import { reviewDigest } from "#approve-core/context/types";
import { captureStep } from "#approve-core/contracts";
import {
  analyzeStep,
  createPowerShellProgramProvider,
  fragmentsForCall,
} from "#approve-core/nodes/analysis";
import type { PowerShellParserPort, PowerShellParseResult } from "#approve-core/utils/access-intent/powershell/parser";
import { analyzePowerShellParse } from "#approve-core/utils/access-intent/powershell/analysis";

function capturedCall(command: string) {
  const args = { command };
  const captured = captureStep({
    stepKey: "step-1",
    sessionId: "session-1",
    sourceEntryId: "entry-1",
    manifestRevision: 1,
    complete: true,
    directCalls: [{
      toolCallId: "call-1",
      toolName: "powershell",
      arguments: args,
      argumentsDigest: reviewDigest(args),
    }],
  });
  if (!captured.ok) throw new Error("valid PowerShell call was rejected");
  return { capture: captured.capture, call: captured.capture.directCalls[0]! };
}

function parsed(source: string, completeness: "complete" | "failed" = "complete"): PowerShellParseResult {
  const delimiter = source.indexOf(";");
  return {
    ok: true,
    summary: {
      engineIdentity: "test/7.4",
      completeness,
      parseErrors: [],
      units: delimiter < 0
        ? [{ start: 0, end: source.length }]
        : [{ start: 0, end: delimiter }, { start: delimiter + 2, end: source.length }],
      programCalls: [],
      languageOperations: [],
      features: [],
      astNodeCount: 4,
      maxDepth: 3,
    },
  };
}

describe("PowerShell structure analysis", () => {
  it("shares the parse and source-range unit ids with later consumers", async () => {
    const source = "Write-Output first; git status";
    const { capture, call } = capturedCall(source);
    const parser: PowerShellParserPort = { parse: vi.fn(async () => parsed(source)) };
    const provider = createPowerShellProgramProvider(capture.directCalls, { parser });

    const units = await analyzeStep(capture, { getPowerShellParse: provider });
    const fragments = await fragmentsForCall(call, { getPowerShellParse: provider });

    expect(parser.parse).toHaveBeenCalledTimes(1);
    expect(fragments.map((fragment) => fragment.unitId)).toEqual(units.map((unit) => unit.unitId));
    expect(units.map((unit) => unit.unitId)).toEqual([
      expect.stringContaining("call-1:u0-18:"),
      expect.stringContaining(`call-1:u${source.indexOf(";") + 2}-${source.length}:`),
    ]);
  });

  it("binds a parse provider to the captured digest and command", async () => {
    const source = "git status";
    const { capture, call } = capturedCall(source);
    const parser: PowerShellParserPort = { parse: vi.fn(async () => parsed(source)) };
    const provider = createPowerShellProgramProvider(capture.directCalls, { parser });

    expect(await provider({ ...call, digest: "changed" })).toBeUndefined();
    expect(parser.parse).not.toHaveBeenCalled();
  });

  it("keeps parser failures and incomplete ASTs as a whole-call unit", async () => {
    const source = "git status; Set-Content output.txt";
    const { capture } = capturedCall(source);
    const parser: PowerShellParserPort = {
      parse: vi.fn(async () => ({ ok: false as const, reason: "timeout" })),
    };
    const provider = createPowerShellProgramProvider(capture.directCalls, { parser });

    const units = await analyzeStep(capture, { getPowerShellParse: provider });

    expect(units).toHaveLength(1);
    expect(units[0]).toMatchObject({
      unitId: "call-1:whole",
      actionDigest: capture.directCalls[0]!.digest,
    });
  });

  it("extracts literal FileSystem targets without treating cmdlets as native executables", () => {
    const source = "Get-Content -LiteralPath input.txt";
    const call = capturedCall(source).capture.directCalls[0]!;
    const result: PowerShellParseResult = {
      ok: true,
      summary: {
        engineIdentity: "test/5.1",
        completeness: "complete",
        parseErrors: [],
        units: [{ start: 0, end: source.length }],
        programCalls: [{
          start: 0,
          end: source.length,
          commandName: "Get-Content",
          arguments: ["-LiteralPath", "input.txt"],
          dynamic: false,
          dotSource: false,
        }],
        languageOperations: [{
          kind: "file-read",
          start: 0,
          end: source.length,
          target: "input.txt",
        }],
        features: ["file-read"],
        astNodeCount: 4,
        maxDepth: 3,
      },
    };

    const analysis = analyzePowerShellParse({
      call,
      commandText: source,
      cwd: "C:\\workspace",
      result,
      platform: "win32",
    });

    expect(analysis.programInvocations).toMatchObject([{
      program: { status: "known", value: "Get-Content" },
      argv: { status: "known", value: ["-LiteralPath", "input.txt"] },
    }]);
    expect(analysis.operations[0]).toMatchObject({
      owner: "powershell",
      effects: { status: "known", value: ["file.read"] },
      fileTargets: { status: "known", value: [{ path: "C:\\workspace\\input.txt", effect: "file.read" }] },
      complete: true,
    });
  });

  it("keeps later path facts incomplete after the script changes location", () => {
    const source = "Set-Location subdir; Get-Content -LiteralPath input.txt";
    const call = capturedCall(source).capture.directCalls[0]!;
    const result: PowerShellParseResult = {
      ok: true,
      summary: {
        engineIdentity: "test/7.4",
        completeness: "complete",
        parseErrors: [],
        units: [
          { start: 0, end: 19 },
          { start: 21, end: source.length },
        ],
        programCalls: [
          { start: 0, end: 19, commandName: "Set-Location", arguments: ["subdir"], dynamic: false, dotSource: false },
          { start: 21, end: source.length, commandName: "Get-Content", arguments: ["-LiteralPath", "input.txt"], dynamic: false, dotSource: false },
        ],
        languageOperations: [
          { kind: "location-change", start: 0, end: 19, target: "subdir" },
          { kind: "file-read", start: 21, end: source.length, target: "input.txt" },
        ],
        features: ["location-change", "file-read"],
        astNodeCount: 8,
        maxDepth: 4,
      },
    };

    const analysis = analyzePowerShellParse({ call, commandText: source, cwd: "C:\\workspace", result, platform: "win32" });

    expect(analysis.operations[1]).toMatchObject({
      effects: { status: "known", value: ["file.read"] },
      fileTargets: { status: "unknown", reason: "script-context-changed" },
      complete: false,
    });
    expect(analysis.programInvocations.find((invocation) => invocation.program.status === "known" &&
      invocation.program.value === "Get-Content")?.cwd).toMatchObject({ status: "unknown" });
  });

  it("uses source positions for prior changes even when parser facts are unordered", () => {
    const source = "x".repeat(64);
    const call = capturedCall(source).capture.directCalls[0]!;
    const result: PowerShellParseResult = {
      ok: true,
      summary: {
        engineIdentity: "test/7.4",
        completeness: "complete",
        parseErrors: [],
        units: [{ start: 0, end: source.length }],
        programCalls: [{ start: 20, end: 30, commandName: "git", arguments: ["status"], dynamic: false, dotSource: false }],
        languageOperations: [
          { kind: "file-read", start: 20, end: 30, target: "later.txt" },
          { kind: "location-change", start: 10, end: 19, target: "subdir" },
          { kind: "file-read", start: 10, end: 19, target: "same-position.txt" },
        ],
        features: ["file-read", "location-change"],
        astNodeCount: 8,
        maxDepth: 4,
      },
    };

    const analysis = analyzePowerShellParse({ call, commandText: source, cwd: "C:\\workspace", result, platform: "win32" });

    // Output follows source order. The unresolved location-change itself is
    // unknown, the read at the same offset uses the context before it, and the
    // later read is incomplete because the script changed location first.
    expect(analysis.operations[0]).toMatchObject({
      fileTargets: { status: "unknown", reason: "language-operation:location-change" },
      complete: false,
    });
    expect(analysis.operations[1]).toMatchObject({
      fileTargets: { status: "known", value: [{ path: "C:\\workspace\\same-position.txt", effect: "file.read" }] },
      complete: true,
    });
    expect(analysis.operations[2]).toMatchObject({
      fileTargets: { status: "unknown", reason: "script-context-changed" },
      complete: false,
    });
    expect(analysis.programInvocations[0]?.cwd).toMatchObject({ status: "unknown" });
  });

  it("checks prior context changes with a single pass over long fact lists", () => {
    const count = 1_000;
    const source = "x".repeat(count + 1);
    const call = capturedCall(source).capture.directCalls[0]!;
    let startReads = 0;
    const languageOperations = Array.from({ length: count }, (_, start) => new Proxy({
      kind: "file-read" as const,
      start,
      end: start + 1,
      target: "input.txt",
    }, {
      get(target, property, receiver) {
        if (property === "start") startReads += 1;
        return Reflect.get(target, property, receiver);
      },
    }));
    const result: PowerShellParseResult = {
      ok: true,
      summary: {
        engineIdentity: "test/7.4",
        completeness: "complete",
        parseErrors: [],
        units: [{ start: 0, end: source.length }],
        programCalls: [],
        languageOperations,
        features: ["file-read"],
        astNodeCount: count,
        maxDepth: 1,
      },
    };

    const analysis = analyzePowerShellParse({ call, commandText: source, cwd: "C:\\workspace", result, platform: "win32" });

    expect(analysis.operations).toHaveLength(count);
    expect(startReads).toBeLessThan(count * 10);
    expect(analysis.operations.every((operation) => operation.complete)).toBe(true);
  });

  it("keeps a known web request destination incomplete because redirects can change it", () => {
    const source = "Invoke-WebRequest -Uri https://example.com";
    const call = capturedCall(source).capture.directCalls[0]!;
    const result: PowerShellParseResult = {
      ok: true,
      summary: {
        engineIdentity: "test/7.4",
        completeness: "complete",
        parseErrors: [],
        units: [{ start: 0, end: source.length }],
        programCalls: [{
          start: 0,
          end: source.length,
          commandName: "Invoke-WebRequest",
          arguments: ["-Uri", "https://example.com"],
          dynamic: false,
          dotSource: false,
        }],
        languageOperations: [{ kind: "network-access", start: 0, end: source.length, target: "https://example.com" }],
        features: ["network-access"],
        astNodeCount: 5,
        maxDepth: 3,
      },
    };

    const analysis = analyzePowerShellParse({ call, commandText: source, cwd: "C:\\workspace", result, platform: "win32" });

    expect(analysis.operations[0]).toMatchObject({
      effects: { status: "known", value: ["network"] },
      networkTargets: { status: "known", value: [{ host: "example.com" }] },
      complete: false,
    });
  });
});
