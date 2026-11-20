import type {
  BackendCapabilities,
  ExecutionOperation,
  ExecutionPlan,
  ExecutionStartParameters,
} from "../types";

export interface RequiredCapabilities {
  readonly read: boolean;
  readonly write: boolean;
  readonly fileGranularity: boolean;
  readonly protectedPaths: boolean;
  readonly environment: boolean;
  readonly metadataRead: "none" | "all";
  readonly network: "none" | "all" | "domains";
  readonly cancel: boolean;
  readonly streamOutput: boolean;
  readonly startedNotification: boolean;
  readonly processTree: boolean;
}

function operationNeedsRead(operation: ExecutionOperation): boolean {
  return operation.kind === "read-file" || operation.kind === "access-file" || operation.kind === "access-dir";
}

function operationNeedsWrite(operation: ExecutionOperation): boolean {
  return operation.kind === "write-file" || operation.kind === "mkdir";
}

export function requiredCapabilities(plan: ExecutionPlan, start: ExecutionStartParameters): RequiredCapabilities {
  const writes = plan.filesystem.filter((grant) => grant.access === "write");
  const reads = plan.filesystem.filter((grant) => grant.access === "read");
  return {
    read: reads.length > 0 || operationNeedsRead(start.operation),
    write: writes.length > 0 || operationNeedsWrite(start.operation),
    fileGranularity: plan.filesystem.some((grant) => grant.granularity === "file"),
    protectedPaths: plan.filesystem.some(rule => rule.access === "deny-write" || rule.access === "deny-access"),
    environment: Object.keys(start.environment).length > 0,
    metadataRead: plan.metadataRead,
    network: plan.network.kind === "destinations" ? "domains" : plan.network.kind === "all" ? "all" : "none",
    cancel: true,
    streamOutput: true,
    startedNotification: true,
    processTree: true,
  };
}

export function capabilityGap(
  capabilities: BackendCapabilities,
  required: RequiredCapabilities,
): readonly string[] {
  const gaps: string[] = [];
  if (required.read && !capabilities.filesystem.read) gaps.push("filesystem-read");
  if (required.write && !capabilities.filesystem.write) gaps.push("filesystem-write");
  if (required.fileGranularity && capabilities.filesystem.granularity !== "file") gaps.push("filesystem-file-granularity");
  if (required.protectedPaths && !capabilities.filesystem.protectedPaths) gaps.push("protected-path-deny");
  if (required.environment && !capabilities.filesystem.environment) gaps.push("environment-filter");
  if (required.metadataRead === "all" && capabilities.filesystem.metadataRead !== "all") gaps.push("filesystem-metadata-read");
  if (required.network === "all" && capabilities.network !== "all" && capabilities.network !== "domains") gaps.push("network-all");
  if (required.network === "domains" && capabilities.network !== "domains") gaps.push("network-domains");
  if (required.cancel && !capabilities.cancel) gaps.push("cancel");
  if (required.streamOutput && !capabilities.streamOutput) gaps.push("stream-output");
  if (required.startedNotification && !capabilities.startedNotification) gaps.push("started-notification");
  if (required.processTree && !capabilities.processTree) gaps.push("process-tree");
  return gaps;
}

export function backendFailureCode(
  code: string,
): "sandbox-capability-unsupported" | "sandbox-unavailable" | "sandbox-setup-failed" | "sandbox-start-failed" | "sandbox-denied" | "sandbox-path-missing" {
  switch (code) {
    case "unavailable": return "sandbox-unavailable";
    case "unsupported":
    case "capability": return "sandbox-capability-unsupported";
    case "setup":
    case "setup-failed": return "sandbox-setup-failed";
    case "denied": return "sandbox-denied";
    case "missing":
    case "not-found": return "sandbox-path-missing";
    default: return "sandbox-start-failed";
  }
}
