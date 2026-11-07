import { describe, expect, it } from "vitest";
import type { CallState } from "#approve-core/contracts";
import { createExternalCommandApprovalNode } from "#approve-core/nodes/shell-policy";
import type { StepContext } from "#approve-core/runtime";
import type { PowerShellProgramFactsView } from "#approve-core/utils/access-intent/powershell/analysis";
import type { BashProgramFactsView } from "#approve-core/contracts";
import type { ShellPolicy } from "#config/shell-policy-schema";

const rulePolicy: ShellPolicy = {
  version: 1,
  rules: [{
    id: "deny-git",
    node: "builtin/external-command",
    when: { all: [{ program: "git" }, { args: { exact: ["status"] } }] },
    then: { decision: "deny" },
  }],
};

function call(toolName: string, command: string): CallState {
  return {
    toolCallId: "call-1",
    toolName,
    arguments: { command },
    argumentsDigest: "args-digest",
    digest: "call-digest",
    units: [{ unitId: "call-1:u0:unit", decision: "ask", reason: "initial", source: "initial", history: [] }],
  } as unknown as CallState;
}

function powershellView(callState: CallState): PowerShellProgramFactsView {
  const operationId = "call-1:op:0-10:operation";
  return {
    callDigest: callState.digest,
    commandText: "git status",
    cwd: "C:\\workspace",
    result: { ok: true, summary: { completeness: "complete" } },
    analysis: {
      completeness: "uncertain",
      units: [{ unitId: "call-1:u0:unit", start: 0, end: 10, text: "git status" }],
      programInvocations: [{
        operationId,
        unitId: "call-1:u0:unit",
        shell: "powershell",
        program: { status: "known", value: "git" },
        executable: { status: "unknown", reason: "runtime-resolution" },
        argv: { status: "known", value: ["status"] },
        cwd: { status: "known", value: "C:\\workspace" },
        extent: { start: 0, end: 10 },
      }],
      operations: [{
        operationId,
        unitId: "call-1:u0:unit",
        owner: "external-command",
        effects: { status: "unknown", reason: "program-effects-unresolved" },
        fileTargets: { status: "unknown", reason: "targets-unresolved" },
        networkTargets: { status: "unknown", reason: "targets-unresolved" },
        complete: false,
        source: "powershell-parser",
      }],
      diagnostics: [],
    },
  } as unknown as PowerShellProgramFactsView;
}

async function decisions(input: {
  readonly call: CallState;
  readonly policy?: ShellPolicy;
  readonly bash?: BashProgramFactsView;
  readonly powershell?: PowerShellProgramFactsView;
}) {
  const node = createExternalCommandApprovalNode({ policy: input.policy });
  const context = {
    state: { calls: [input.call] },
    ...(input.bash === undefined ? {} : { bashPrograms: { [input.call.toolCallId]: input.bash } }),
    ...(input.powershell === undefined ? {} : { powershellPrograms: { [input.call.toolCallId]: input.powershell } }),
  } as unknown as StepContext;
  return node.evaluate(context, {} as never);
}

describe("external command shell policy node", () => {
  it("applies the same program and argv rule to Bash and PowerShell calls", async () => {
    const bashCall = call("bash", "git status");
    const bashView = {
      commandText: "git status",
      commands: [],
      programCalls: [{
        unitIndex: 0,
        text: "git status",
        programName: "git",
        arguments: ["status"],
        dynamic: false,
        wrapperComplete: true,
      }],
      workingDirectory: "C:\\workspace",
      pathRuleCandidates: [],
      externalAccesses: [],
    } as unknown as BashProgramFactsView;
    const bashResult = await decisions({ call: bashCall, policy: rulePolicy, bash: bashView });

    const powershellCall = call("powershell", "git status");
    const powershellResult = await decisions({
      call: powershellCall,
      policy: rulePolicy,
      powershell: powershellView(powershellCall),
    });

    expect(bashResult.decisions.map((decision) => decision.decision)).toEqual(["deny"]);
    expect(powershellResult.decisions.map((decision) => decision.decision)).toEqual(["deny"]);
  });

  it("keeps an allow candidate at ask when external identity and effects are incomplete", async () => {
    const allowPolicy: ShellPolicy = {
      version: 1,
      rules: [{ id: "allow-git", node: "builtin/external-command", when: { program: "git" }, then: { decision: "allow" } }],
    };
    const powershellCall = call("powershell", "git status");
    const result = await decisions({
      call: powershellCall,
      policy: allowPolicy,
      powershell: powershellView(powershellCall),
    });

    expect(result.decisions.map((decision) => decision.decision)).toEqual(["ask"]);
  });
});
