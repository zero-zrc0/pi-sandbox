import type { BashCommand } from "#approve-core/utils/access-intent/bash/command-enumeration";
import { detectShellRisks } from "#approve-core/nodes/assessment/risks";
import { validateShellSandboxCapability } from "#approve-core/utils/tool-access/invocation-snapshot";
import type { LocalAssessment, ShellSandboxCapability } from "#approve-core/nodes/assessment/types";
import { isBuiltinDefaultAsk, PermissionCheckResult } from "../../contracts";

export interface ShellAssessmentInput {
  /** The original command text, kept whole for the reason strings. */
  readonly command: string;
  /** The parsed command units the rules were resolved against. */
  readonly units: readonly BashCommand[];
  /** The `bash` command-pattern gate's own check. */
  readonly commandCheck: PermissionCheckResult;
  /** The full command's rule result when the parser found no units. */
  readonly wholeProgramCheck?: PermissionCheckResult;
  /**
   * Whether every asking unit of the chain resolved through the builtin
   * universal default (see `resolveBashCommandCheckFacts`). False keeps the
   * chain's ask on the prompt path.
   */
  readonly defaultPolicyEligible: boolean;
  /** The actual language and exact invocation digest the host capability covers. */
  readonly language: "bash" | "unknown";
  readonly toolName: string;
  /** Registration revision the host execution binding must cover. */
  readonly registrationRevision: string;
  readonly actionDigest: string;
  /**
   * The other gates' checks for the same call — path, external_directory, and
   * their bash-specific siblings. A shell program's file effects are judged
   * together with its commands (design §35.4).
   */
  readonly additionalChecks?: readonly PermissionCheckResult[];
  /** The sandbox the host proved. Absent or unsatisfied means `defer`. */
  readonly sandbox?: ShellSandboxCapability;
}

/**
 * Judge one shell call locally and aggregate the whole program (design §35.2).
 *
 * The order is fixed by the design:
 *
 * 1. any explicit `deny` blocks the whole call;
 * 2. a recognized risk requires review — it does not fabricate a denial;
 * 3. a chain that is not fully builtin-default (`not-default-eligible`), or a
 *    path scope an explicit rule asked for, requires review;
 * 4. only when every necessary result is settled does the sandbox capability
 *    decide between `run` and `defer`.
 *
 * The command is never split for execution and no prefix runs early: this is a
 * decision over the parser's own units, not an execution trace (design §35.7).
 */
export function assessShellCommand(
  input: ShellAssessmentInput,
): LocalAssessment {
  const additional = input.additionalChecks ?? [];
  const commandCheck = input.wholeProgramCheck ?? input.commandCheck;
  if (
    input.commandCheck.state === "deny" ||
    input.wholeProgramCheck?.state === "deny" ||
    additional.some((check) => check.state === "deny")
  ) {
    return result("block", "explicit-rule", "explicit-deny");
  }

  if (input.language !== "bash") {
    return result("defer", "incomplete-facts", "shell-language-unavailable");
  }

  const risks = commandCheck.state === "allow"
    ? []
    : detectShellRisks(input.units, {
        // Existing explicit rules and exact session grants keep their adjudication.
        // An incomplete wrapper walk only blocks a builtin-default sandbox run.
        includeIncompleteExecution:
          commandCheck.state === "ask" && input.defaultPolicyEligible,
      });
  if (risks.length > 0) {
    return result(
      "review",
      "shell-risk",
      `shell-risk:${[...new Set(risks.map((risk) => risk.kind))].join(",")}`,
    );
  }

  if (
    input.wholeProgramCheck?.state === "ask" &&
    isBuiltinDefaultAsk(input.wholeProgramCheck)
  ) {
    return result(
      "defer",
      "incomplete-facts",
      "shell-command-units-unavailable",
    );
  }

  if (!isCommandDimensionSettled({ ...input, commandCheck })) {
    return result(
      "review",
      commandCheck.floor !== undefined
        ? "synthetic-floor"
        : "not-default-eligible",
      "command-rule-needs-review",
    );
  }

  const unsettled = additional.filter(
    (check) => check.state !== "allow" && !isBuiltinDefaultAsk(check),
  );
  if (unsettled.length > 0) {
    return result("review", "not-default-eligible", "path-scope-needs-review");
  }

  const sandbox = validateShellSandboxCapability(
    input.sandbox,
    input.actionDigest,
    input.toolName,
    input.registrationRevision,
  );
  if (
    !sandbox?.available ||
    !sandbox.enforcesAllLimits ||
    sandbox.boundary.trim().length === 0
  ) {
    return result(
      "defer",
      "capability-unavailable",
      sandbox?.reason ?? "shell-sandbox-unavailable",
    );
  }

  const usedDefault =
    commandCheck.state === "ask" ||
    additional.some((check) => check.state === "ask");
  return usedDefault
    ? result("run", "shell-default-policy", `sandbox:${sandbox.boundary}`)
    : result("run", "all-gates-allow", "explicit-allow");
}

/**
 * The command dimension is settled either by an explicit allow or by an ask
 * every asking unit of which is the builtin universal default.
 */
function isCommandDimensionSettled(input: ShellAssessmentInput): boolean {
  if (input.commandCheck.state === "allow") return true;
  return input.commandCheck.state === "ask" && input.defaultPolicyEligible;
}

function result(
  route: LocalAssessment["route"],
  cause: LocalAssessment["cause"],
  reason: string,
): LocalAssessment {
  return { route, cause, reason, modelRequests: 0 };
}
