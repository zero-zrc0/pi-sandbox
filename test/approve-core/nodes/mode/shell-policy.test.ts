import { describe, expect, it } from "vitest";
import type { BashProgramFactsView, CallState } from "#approve-core/contracts";
import { createModeNode } from "#approve-core/nodes/mode";
import { createPowerShellApprovalNode } from "#approve-core/nodes/shell-policy";
import type { StepContext } from "#approve-core/runtime";
import type { PowerShellProgramFactsView } from "#approve-core/utils/access-intent/powershell/analysis";
import type { ShellPolicy, ShellPolicyRule } from "#config/shell-policy-schema";
import type { ShellExecutionPermissions } from "#config/execution-source-schema";

const CALL_ID = "call-1";
const UNIT_ID = `${CALL_ID}:u0-28:unit`;
const OPERATION_ID = `${CALL_ID}:op:0-28:operation`;
const COMMAND = "Set-Content -Path output.txt";

function policy(rule?: ShellPolicyRule, modes?: ShellPolicy["modes"]): ShellPolicy {
  return { version: 1, ...(modes === undefined ? {} : { modes }), rules: rule === undefined ? [] : [rule] };
}

function state(overrides: {
  mode?: "read-only" | "default" | "auto-review" | "full-access";
  operation?: PowerShellProgramFactsView["analysis"]["operations"][number];
  policy?: ShellPolicy;
  enabledShellNodes?: readonly string[];
  invocationProgram?: string;
  shellGrants?: ShellExecutionPermissions;
  platform?: NodeJS.Platform;
} = {}) {
  const mode = overrides.mode ?? "read-only";
  const operation = overrides.operation ?? {
    operationId: OPERATION_ID,
    unitId: UNIT_ID,
    owner: "powershell" as const,
    effects: { status: "known" as const, value: ["file.create", "file.write"] as const },
    fileTargets: { status: "known" as const, value: [
      { path: "C:\\workspace\\output.txt", effect: "file.create" as const },
      { path: "C:\\workspace\\output.txt", effect: "file.write" as const },
    ] },
    networkTargets: { status: "known" as const, value: [] },
    dynamicExecution: { status: "known" as const, value: false },
    processSpawn: { status: "known" as const, value: false },
    complete: true,
    source: "powershell-parser" as const,
  };
  const call = {
    toolCallId: CALL_ID,
    toolName: "powershell",
    arguments: { command: COMMAND },
    argumentsDigest: "arguments-digest",
    digest: "call-digest",
    units: [{ unitId: UNIT_ID, decision: "ask", reason: "initial", source: "initial", history: [] }],
  } as unknown as CallState;
  const view = {
    callDigest: call.digest,
    commandText: COMMAND,
    cwd: "C:\\workspace",
    result: { ok: true, summary: { completeness: "complete" } },
    analysis: {
      completeness: "complete",
      units: [{ unitId: UNIT_ID, start: 0, end: COMMAND.length, text: COMMAND }],
      programInvocations: [{
        operationId: OPERATION_ID,
        unitId: UNIT_ID,
        shell: "powershell",
        program: { status: "known", value: overrides.invocationProgram ?? "Set-Content" },
        executable: { status: "unknown", reason: "test" },
        argv: { status: "known", value: ["-Path", "output.txt"] },
        cwd: { status: "known", value: "C:\\workspace" },
        extent: { start: 0, end: COMMAND.length },
      }],
      operations: [operation],
      diagnostics: [],
    },
  } as unknown as PowerShellProgramFactsView;
  const context = {
    state: { calls: [call] },
    powershellPrograms: { [CALL_ID]: view },
  } as unknown as StepContext;
  return {
    context,
    options: {
      mode,
      cwd: "C:\\workspace",
      shellPolicy: overrides.policy,
      enabledShellNodes: overrides.enabledShellNodes ?? ["builtin/powershell"],
      shellGrants: overrides.shellGrants,
      platform: overrides.platform ?? "win32",
    },
  };
}

async function evaluate(options: ReturnType<typeof state>) {
  const node = createModeNode(options.options);
  return node.evaluate(options.context, {} as never);
}

describe("PowerShell mode policy", () => {
  it("denies a proven write in read-only even when the optional node is disabled", async () => {
    const result = await evaluate(state({ enabledShellNodes: [] }));

    expect(result.decisions).toMatchObject([{ decision: "deny", reason: "mode:read-only:write-forbidden" }]);
  });

  it("applies a complete global read-only exception only when its node is enabled", async () => {
    const allowRule: ShellPolicyRule = {
      id: "allow-workspace-write",
      node: "builtin/powershell",
      scope: { modes: ["read-only"] },
      when: { all: [
        { program: "Set-Content" },
        { effects: { only: ["file.create", "file.write"] } },
        { targets: { fileWrites: { allWithin: ["C:\\workspace"] } } },
      ] },
      then: { decision: "allow" },
    };
    const shellPolicy = policy(allowRule, {
      "read-only": { exceptions: [{ ruleId: allowRule.id, effects: ["file.create", "file.write"] }] },
    });

    const enabled = await evaluate(state({ policy: shellPolicy }));
    const disabled = await evaluate(state({ policy: shellPolicy, enabledShellNodes: [] }));

    expect(enabled.decisions).toEqual([]);
    expect(disabled.decisions[0]?.decision).toBe("deny");
  });

  it("asks when effects are incomplete and honors full-access uncertain restrictions", async () => {
    const operation = {
      operationId: OPERATION_ID,
      unitId: UNIT_ID,
      owner: "powershell" as const,
      effects: { status: "unknown" as const, reason: "unresolved" },
      fileTargets: { status: "unknown" as const, reason: "unresolved" },
      networkTargets: { status: "unknown" as const, reason: "unresolved" },
      complete: false,
      source: "powershell-parser" as const,
    };
    const defaultMode = await evaluate(state({ operation }));
    const fullAccess = await evaluate(state({
      mode: "full-access",
      operation,
      policy: policy(undefined, { "full-access": { uncertain: "ask" } }),
    }));

    expect(defaultMode.decisions[0]?.decision).toBe("ask");
    expect(fullAccess.decisions[0]?.decision).toBe("ask");
  });

  it("does not escalate a known external write already inside a shell grant", async () => {
    const operation = {
      operationId: OPERATION_ID,
      unitId: UNIT_ID,
      owner: "powershell" as const,
      effects: { status: "known" as const, value: ["file.create", "file.write"] as const },
      fileTargets: { status: "known" as const, value: [
        { path: "C:\\shared\\output.txt", effect: "file.create" as const },
        { path: "C:\\shared\\output.txt", effect: "file.write" as const },
      ] },
      networkTargets: { status: "known" as const, value: [] },
      dynamicExecution: { status: "known" as const, value: false },
      processSpawn: { status: "known" as const, value: false },
      complete: true,
      source: "powershell-parser" as const,
    };
    const granted = await evaluate(state({
      mode: "default",
      operation,
      shellGrants: {
        filesystem: { read: [], write: [{ path: "C:\\shared", granularity: "directory" }] },
        network: { mode: "none" },
      },
    }));
    const ungranted = await evaluate(state({ mode: "default", operation }));

    expect(granted.decisions).toEqual([]);
    expect(ungranted.decisions).toMatchObject([{ decision: "ask", askFor: "escalate" }]);
  });

  it("escalates external PowerShell deletes even with a shell grant and preserves read-only denial", async () => {
    const operation = {
      operationId: OPERATION_ID, unitId: UNIT_ID, owner: "powershell" as const,
      effects: { status: "known" as const, value: ["file.delete"] as const },
      fileTargets: { status: "known" as const, value: [{ path: "C:\\shared\\target.txt", effect: "file.delete" as const }] },
      networkTargets: { status: "known" as const, value: [] }, complete: true, source: "powershell-parser" as const,
    };
    const shellGrants: ShellExecutionPermissions = { filesystem: { read: [], write: [{ path: "C:\\shared", granularity: "directory" }] }, network: { mode: "none" } };
    expect((await evaluate(state({ mode: "default", operation, shellGrants }))).decisions).toMatchObject([{ decision: "ask", askFor: "escalate" }]);
    expect((await evaluate(state({ mode: "read-only", operation, shellGrants }))).decisions).toMatchObject([{ decision: "deny" }]);
    const inside = { ...operation, fileTargets: { status: "known" as const, value: [{ path: "C:\\workspace\\target.txt", effect: "file.delete" as const }] } };
    expect((await evaluate(state({ mode: "default", operation: inside }))).decisions).toEqual([]);
  });

  it("does not let full-access erase an explicit shell policy ask", async () => {
    const askRule: ShellPolicyRule = {
      id: "ask-command",
      node: "builtin/powershell",
      when: { program: "Set-Content" },
      then: { decision: "ask" },
    };
    const operation = {
      operationId: OPERATION_ID,
      unitId: UNIT_ID,
      owner: "powershell" as const,
      effects: { status: "known" as const, value: ["file.read"] as const },
      fileTargets: { status: "known" as const, value: [] },
      networkTargets: { status: "known" as const, value: [] },
      dynamicExecution: { status: "known" as const, value: false },
      processSpawn: { status: "known" as const, value: false },
      complete: true,
      source: "powershell-parser" as const,
    };

    const result = await evaluate(state({ mode: "full-access", operation, policy: policy(askRule) }));

    expect(result.decisions).toEqual([]);
  });

  it("enforces a configured PowerShell cmdlet deny on POSIX in full-access", async () => {
    const denyRule: ShellPolicyRule = {
      id: "deny-set-content",
      node: "builtin/powershell",
      scope: { modes: ["full-access"] },
      when: { program: "Set-Content" },
      then: { decision: "deny" },
    };
    const input = state({
      mode: "full-access",
      policy: policy(denyRule),
      invocationProgram: "set-content",
      platform: "linux",
    });
    const node = createPowerShellApprovalNode({
      policy: input.options.shellPolicy,
      mode: input.options.mode,
      platform: input.options.platform,
    });
    const result = await node.evaluate(input.context, {} as never);

    expect(result.decisions).toMatchObject([{ decision: "deny" }]);
  });
});

describe("Bash shell mode policy", () => {
  it("applies configurable unmatched handling to complete external command facts", async () => {
    const command = "git status";
    const call = {
      toolCallId: CALL_ID,
      toolName: "bash",
      arguments: { command },
      argumentsDigest: "arguments-digest",
      digest: "call-digest",
      units: [{ unitId: UNIT_ID, decision: "ask", reason: "initial", source: "initial", history: [] }],
    } as unknown as CallState;
    const bashView = {
      commandText: command,
      commands: [],
      programCalls: [{
        unitIndex: 0,
        text: command,
        programName: "git",
        arguments: ["status"],
        dynamic: false,
        wrapperComplete: true,
      }],
      workingDirectory: "C:\\workspace",
      pathRuleCandidates: [],
      externalAccesses: [],
    } as unknown as BashProgramFactsView;
    const context = {
      state: { calls: [call] },
      bashPrograms: { [CALL_ID]: bashView },
    } as unknown as StepContext;
    const node = createModeNode({
      mode: "default",
      cwd: "C:\\workspace",
      platform: "win32",
      shellPolicy: policy(undefined, { default: { unmatched: "deny" } }),
    });

    const result = await node.evaluate(context, {} as never);

    expect(result.decisions).toMatchObject([{ decision: "deny", reason: "shell-policy:mode:default:unmatched" }]);
  });
});
