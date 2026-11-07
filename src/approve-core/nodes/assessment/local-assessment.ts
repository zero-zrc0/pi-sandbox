import type { BashCommand } from "#approve-core/utils/access-intent/bash/command-enumeration";
import { classifyToolKind } from "#approve-core/utils/access-intent/tool-kind";
import { assessMcpAnnotations, type McpAnnotations } from "#approve-core/nodes/assessment/mcp";
import { assessShellCommand } from "#approve-core/nodes/assessment/shell";
import type { AssessmentCapabilities, LocalAssessment } from "#approve-core/nodes/assessment/types";
import { isBuiltinDefaultAsk, PermissionCheckResult } from "../../contracts";

export type {
  AssessmentInvocationSnapshot,
  AssessmentCapabilities,
  AssessmentCause,
  AssessmentRoute,
  BoundAssessmentExecution,
  LocalAssessment,
  McpConflictFacts,
  McpExecutionCapability,
  ShellSandboxCapability,
} from "#approve-core/nodes/assessment/types";
export {
  type AssessmentInvocationCapture,
  type AssessmentInvocationContext,
  type ShellAssessmentIdentity,
} from "#approve-core/utils/tool-access/invocation-snapshot";
export { assessMcpAnnotations, type McpAnnotations } from "#approve-core/nodes/assessment/mcp";
export { type ShellRisk, type ShellRiskKind } from "#approve-core/nodes/assessment/risks";
export { assessShellCommand, type ShellAssessmentInput } from "#approve-core/nodes/assessment/shell";

/** One gate's check, as the pipeline resolved it, with its surface for context. */
export interface LocalGateCheck {
  readonly surface: string;
  readonly check: PermissionCheckResult;
}

/** What the shell assessment needs from the parsed program and the bash gate. */
export interface ShellCallFacts {
  readonly command: string;
  readonly units: readonly BashCommand[];
  /** The `bash` command-pattern gate's check (also present in `checks`). */
  readonly commandCheck: PermissionCheckResult;
  /** Full-program result used when the parser could not enumerate units. */
  readonly wholeProgramCheck?: PermissionCheckResult;
  readonly defaultPolicyEligible: boolean;
  readonly language: "bash" | "unknown";
  readonly toolName: string;
  readonly registrationRevision: string;
  readonly actionDigest: string;
}

export interface LocalAssessmentInput {
  readonly toolName: string;
  /** Every gate check the call produced, in the pipeline's order. */
  readonly checks: readonly LocalGateCheck[];
  readonly shell?: ShellCallFacts;
  readonly mcpAnnotations?: McpAnnotations;
  readonly mcpConflicts?: readonly string[];
  /**
   * The host-probed capabilities. Absent means the host did not opt into local
   * assessment, and this returns `null` so the caller keeps its pre-existing
   * conservative path.
   */
  readonly capabilities?: AssessmentCapabilities;
}

/**
 * Assess one call locally, or answer `null` when this module does not own it.
 *
 * A `null` return is the honest "no opinion": a non-shell, non-MCP tool, or a
 * call whose host exposed no capabilities, is left to the gate's existing
 * behavior. A non-null result is one of run/review/block/defer and never a
 * model request (design §19/§40).
 */
export function assessLocalCall(
  input: LocalAssessmentInput,
): LocalAssessment | null {
  if (input.capabilities === undefined) {
    return null;
  }

  // A deterministic deny is absorbing whatever the tool is; say so here so a
  // caller that reaches this module with a deny still blocks (design §35.2).
  if (input.checks.some(({ check }) => check.state === "deny")) {
    return result("block", "explicit-rule", "explicit-deny");
  }

  const kind = classifyToolKind(input.toolName);
  if (kind === "mcp" || kind === "mcp-tool") {
    return assessMcpCall(input);
  }
  if (input.shell) {
    return assessShellCommand({
      command: input.shell.command,
      units: input.shell.units,
      commandCheck: input.shell.commandCheck,
      wholeProgramCheck: input.shell.wholeProgramCheck,
      defaultPolicyEligible: input.shell.defaultPolicyEligible,
      language: input.shell.language,
      toolName: input.shell.toolName,
      registrationRevision: input.shell.registrationRevision,
      actionDigest: input.shell.actionDigest,
      additionalChecks: input.checks
        .filter(({ check }) => check !== input.shell?.commandCheck)
        .map(({ check }) => check),
      sandbox: input.capabilities.shellSandbox,
    });
  }
  return null;
}

/**
 * The MCP default policy, gated on the state of the tool's own rule.
 *
 * An explicit allow (or the synthesized MCP metadata baseline) runs the call.
 * Any non-default ask — an explicit rule, or a floor — keeps the call in
 * review. Only an ask that is purely the builtin default reaches the
 * annotation table (design §40.4).
 */
function assessMcpCall(input: LocalAssessmentInput): LocalAssessment {
  if (input.mcpConflicts !== undefined && input.mcpConflicts.length > 0) {
    return assessMcpAnnotations({
      annotations: input.mcpAnnotations,
      conflicts: input.mcpConflicts,
    });
  }

  const nonAllow = input.checks.filter(({ check }) => check.state !== "allow");
  if (nonAllow.length === 0) {
    return result("run", "all-gates-allow", "explicit-allow");
  }
  if (nonAllow.some(({ surface }) => surface !== "mcp")) {
    return result("review", "not-default-eligible", "non-mcp-scope-needs-review");
  }
  if (nonAllow.some(({ check }) => !isBuiltinDefaultAsk(check))) {
    return result("review", "not-default-eligible", "explicit-rule-needs-review");
  }
  return assessMcpAnnotations({
    annotations: input.mcpAnnotations,
    conflicts: input.mcpConflicts,
  });
}

function result(
  route: LocalAssessment["route"],
  cause: LocalAssessment["cause"],
  reason: string,
): LocalAssessment {
  return { route, cause, reason, modelRequests: 0 };
}
