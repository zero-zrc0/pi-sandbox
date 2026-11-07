import { describe, expect, it } from "vitest";
import { captureStep } from "#approve-core/contracts";
import { reviewDigest } from "#approve-core/context/types";
import { analyzeStep, createPowerShellProgramProvider } from "#approve-core/nodes/analysis";
import { createModeNode } from "#approve-core/nodes/mode";
import { collectStepPowerShellFacts } from "#approve-core/host/powershell-facts";
import { PowerShellParser, resolveTrustedPowerShellEngine } from "#approve-core/utils/access-intent/powershell/parser";
import type { StepContext } from "#approve-core/runtime";

describe.skipIf(process.platform !== "win32" || !resolveTrustedPowerShellEngine())("PowerShell delete approval", () => {
  it.each(["Remove-Item", "rm", "del", "erase", "rd", "rmdir"])("escalates an external delete through %s", async (program) => {
    const command = `${program} -LiteralPath 'C:\\outside\\target.txt' -Force`;
    const args = { command };
    const captured = captureStep({ stepKey: "s", sessionId: "s", sourceEntryId: "e", manifestRevision: 1,
      complete: true, directCalls: [{ toolCallId: "c", toolName: "powershell", arguments: args, argumentsDigest: reviewDigest(args) }] });
    if (!captured.ok) throw new Error("capture failed");
    const parser = new PowerShellParser();
    try {
      const provider = createPowerShellProgramProvider(captured.capture.directCalls, { parser });
      const units = await analyzeStep(captured.capture, { getPowerShellParse: provider });
      const powershellPrograms = await collectStepPowerShellFacts({ calls: captured.capture.directCalls, provider, cwd: "C:\\workspace" });
      const call = captured.capture.directCalls[0]!;
      const context = { state: { calls: [{ ...call, units: units.map(unit => ({ ...unit, decision: "ask", history: [] })) }] }, powershellPrograms } as unknown as StepContext;
      const result = await createModeNode({ mode: "default", cwd: "C:\\workspace", platform: "win32",
        shellPolicy: { version: 1, rules: [], modes: { default: { uncertain: "ask", unmatched: "ask" } } } }).evaluate(context, {} as never);
      expect(result.decisions).toMatchObject([{ decision: "ask", askFor: "escalate" }]);
    } finally { parser.dispose(); }
  }, 15_000);
});
