import { describe, expect, it, vi } from "vitest";
import { reviewDigest } from "#approve-core/context/types";
import { captureStep } from "#approve-core/contracts";
import { collectStepPowerShellFacts } from "#approve-core/host/powershell-facts";
import type { PowerShellProgramProvider } from "#approve-core/nodes/analysis";

describe("PowerShell fact projection", () => {
  it("collects the same cached parse and binds it to the captured call digest", async () => {
    const commandText = "__pi_missing_external__ status";
    const args = { command: commandText };
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

    const result = {
      ok: true as const,
      summary: {
        engineIdentity: "windows-powershell/5.1",
        completeness: "complete" as const,
        parseErrors: [],
        units: [{ start: 0, end: commandText.length }],
        programCalls: [{
          start: 0,
          end: commandText.length,
          commandName: "__pi_missing_external__",
          arguments: ["status"],
          dynamic: false,
          dotSource: false,
        }],
        languageOperations: [],
        features: [],
        astNodeCount: 3,
        maxDepth: 2,
      },
    };
    const provider: PowerShellProgramProvider = vi.fn(async () => result);
    const views = await collectStepPowerShellFacts({
      calls: captured.capture.directCalls,
      provider,
      cwd: "C:/workspace",
    });

    expect(provider).toHaveBeenCalledTimes(1);
    expect(views && Object.getPrototypeOf(views)).toBeNull();
    expect(views?.["call-1"]).toMatchObject({
      callDigest: captured.capture.directCalls[0]!.digest,
      commandText,
      cwd: "C:/workspace",
      result,
      analysis: {
        completeness: "uncertain",
        units: [{ text: commandText }],
        programInvocations: [{
          program: { status: "known", value: "__pi_missing_external__" },
          executable: { status: "unknown" },
          argv: { status: "known", value: ["status"] },
          cwd: { status: "known", value: "C:/workspace" },
        }],
      },
    });
    expect(Object.isFrozen(views?.["call-1"])).toBe(true);
  });
});
