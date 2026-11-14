import type {
  BoundAssessmentExecution,
  ShellSandboxCapability,
} from "#approve-core/nodes/assessment/types";
import { capabilityGap, type RequiredCapabilities } from "#sandbox/helper";
import type { HelperProbeResult } from "#sandbox/lifecycle";

export interface ShellCapabilityInput {
  readonly probe: HelperProbeResult;
  /** Digest used by the assessment snapshot for this exact action. */
  readonly actionDigest: string;
  readonly executionBinding: BoundAssessmentExecution;
  readonly requirements: RequiredCapabilities;
  /**
   * Host-owned name of the boundary the probe actually enforces (for example a
   * native Windows backend). This module never invents an isolation name.
   */
  readonly boundary: string;
}

/**
 * Map a real helper probe to the local-assessment capability contract. A
 * fixture backend can be reported, but only the host's `boundary` name is
 * recorded; this function never upgrades a probe into an OS-isolation claim.
 */
export function shellSandboxCapability(
  input: ShellCapabilityInput,
): ShellSandboxCapability {
  const base = {
    actionDigest: input.actionDigest,
    executionBinding: input.executionBinding,
  };
  if (!input.boundary.trim()) {
    return {
      ...base,
      available: false,
      enforcesAllLimits: false,
      boundary: "none",
      reason: "host did not name an enforced boundary",
    };
  }
  if (input.probe.status !== "available") {
    return {
      ...base,
      available: false,
      enforcesAllLimits: false,
      boundary: "none",
      reason: input.probe.reason,
    };
  }
  const gaps = capabilityGap(input.probe.capabilities, input.requirements);
  if (gaps.length > 0) {
    return {
      ...base,
      available: false,
      enforcesAllLimits: false,
      boundary: "none",
      reason: `backend cannot express: ${gaps.join(", ")}`,
    };
  }
  return {
    ...base,
    available: true,
    enforcesAllLimits: true,
    boundary: input.boundary,
  };
}
