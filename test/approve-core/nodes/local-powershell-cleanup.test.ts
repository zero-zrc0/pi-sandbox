import { describe, expect, it } from "vitest";
import { captureStep, prepareStep, applyNodeResult, readyCallResults } from "#approve-core/contracts";
import { analyzeStep, createPowerShellProgramProvider } from "#approve-core/nodes/analysis";
import { collectStepPowerShellFacts } from "#approve-core/host/powershell-facts";
import { createDecisionNode } from "#approve-core/nodes/decision";
import { PowerShellParser, resolveTrustedPowerShellEngine } from "#approve-core/utils/access-intent/powershell/parser";
import { projectShellFacts } from "#approve-core/chain/facts/shell";
import { jsonDigest } from "../../../src/json";

describe.skipIf(resolveTrustedPowerShellEngine() === undefined)("local PowerShell cleanup", () => {
  it.each([
    ['Remove-Item "E:\\AGENT\\pi_workspace_test.txt" -ErrorAction SilentlyContinue; Write-Output done', true],
    ['Remove-Item "E:\\AGENT\\pi_workspace_test.txt" -Force -ErrorAction SilentlyContinue; Write-Output done', true],
    ['Write-Verbose done; Write-Debug finished', true],
    ['Write-Output $(Remove-Item "E:\\outside\\file.txt")', false],
    ['Write-Output done > "E:\\outside\\file.txt"', false],
    ['function Write-Output { Remove-Item "E:\\outside\\file.txt" }; Write-Output done', true],
  ] as const)("judges the complete command without executing it: %s", async (command, allowed) => {
    const cwd = "E:\\AGENT";
    const args = { command };
    const captured = captureStep({ stepKey: "cleanup", sessionId: "cleanup", sourceEntryId: "test",
      manifestRevision: 0, complete: true, directCalls: [{ toolCallId: "call", toolName: "powershell", arguments: args, argumentsDigest: jsonDigest(args) }] });
    if (!captured.ok) throw Error(captured.reason);
    const parser = new PowerShellParser();
    try {
      const provider = createPowerShellProgramProvider(captured.capture.directCalls, { parser });
      const units = await analyzeStep(captured.capture, { cwd, getPowerShellParse: provider });
      const prepared = prepareStep(captured.capture, units);
      if (!prepared.ok) throw Error(prepared.reason);
      const powershellPrograms = await collectStepPowerShellFacts({ calls: captured.capture.directCalls, provider, cwd });
      const node = createDecisionNode({ mode: "auto-review", cwd, workspaceRoot: cwd, platform: "win32", rules: [],
        sandboxRun: { backend: "windows-mxc", available: true, networkPolicy: "none", planRevision: "test",
          sessionId: "cleanup", workspaceRoot: cwd },
      });
      const result = await node.evaluate({ capture: captured.capture, state: prepared.state,
        node: { id: node.id, position: "front", priority: null }, powershellPrograms,
        signal: new AbortController().signal, deadlineAt: null } as never, {} as never);
      const applied = applyNodeResult(prepared.state, { node: { id: node.id, priority: null }, evaluatedRevision: prepared.state.revision, result });
      if (!applied.ok) throw Error(applied.reason);
      const facts = await projectShellFacts({ call: prepared.state.calls[0]!, powershellView: powershellPrograms?.call,
        options: { cwd, workspaceRoot: cwd, platform: "win32" } });
      const summary = readyCallResults(applied.state)[0]!;
      if (allowed) expect(summary.decision).toBe("allow");
      else expect(summary.decision).not.toBe("allow");
      if (command.startsWith("function ")) {
        expect(facts && [...facts.access.values()].flat().some(fact => fact.kind === "unknown")).toBe(true);
      }
    } finally {
      parser.dispose();
    }
  });
});
