import type { EgressGrantRef } from "../../lifecycle";
import type { ExecutionPlan, ExecutionStartParameters } from "../../types";

export interface LinuxLaunchArguments {
  readonly args: readonly string[];
  readonly operationInput?: string;
  readonly egressEnv?: Readonly<Record<string, string>>;
}

export function buildLaunchArgs(
  plan: ExecutionPlan,
  start: ExecutionStartParameters,
  toolCallId: string,
  egress?: EgressGrantRef,
  context?: { readonly installRoot?: string },
): LinuxLaunchArguments;

export function probeBubblewrap(path: string, expectedVersion?: string): string | undefined;
