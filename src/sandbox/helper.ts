import { basename, isAbsolute } from "node:path";
import { accessSync, constants, lstatSync, realpathSync, statSync } from "node:fs";

import {
  HELPER_PROTOCOL_VERSION,
  type BackendCapabilities,
  type ExecutionPlan,
  type ExecutionFailureCode,
} from "#sandbox/types";
import {
  isPathWithin,
  normalizeHostPath,
  pathKey,
} from "#sandbox/path";

export interface TrustedHelperInstallation {
  /** Absolute host-owned installation directory. Never selected from PATH. */
  readonly installRoot: string;
  /** Absolute executable fixed by the host installation. */
  readonly executable: string;
  /** Fixed arguments. A script argument must live under `installRoot`. */
  readonly args?: readonly string[];
  readonly expectedProtocolVersion?: number;
  readonly expectedBackendId?: string;
  readonly expectedBackendVersion?: string;
}

export type HelperResolution =
  | {
      readonly ok: true;
      readonly installation: TrustedHelperInstallation;
    }
  | {
      readonly ok: false;
      readonly code: "sandbox-unavailable" | "sandbox-setup-failed";
      readonly reason: string;
    };

export interface HelperResolutionProbe {
  readonly cwd: string;
  /** The agent workspace; an install root inside it is never trusted. */
  readonly workspace?: string;
  readonly exists?: (path: string) => boolean;
  readonly isFile?: (path: string) => boolean;
  readonly isDirectory?: (path: string) => boolean;
  /** Canonicalize an existing path; null means it could not be proven. */
  readonly realpath?: (path: string) => string | null;
}

function defaultExists(path: string): boolean {
  try {
    accessSync(path, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

function defaultIsFile(path: string): boolean {
  try {
    const info = lstatSync(path);
    if (!info.isFile() && !info.isSymbolicLink()) return false;
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

function defaultIsDirectory(path: string): boolean {
  try {
    const info = lstatSync(path);
    return info.isDirectory() || (info.isSymbolicLink() && statSync(path).isDirectory());
  } catch {
    return false;
  }
}

function defaultRealpath(path: string): string | null {
  try {
    return realpathSync.native(path);
  } catch {
    return null;
  }
}

function sameOrWithin(parent: string, child: string): boolean {
  return pathKey(parent) === pathKey(child) || isPathWithin(parent, child);
}

/**
 * Resolve the helper from the host installation only. The workspace, cwd,
 * PATH, and model arguments cannot choose the executable.
 */
export function resolveTrustedHelper(
  installation: TrustedHelperInstallation,
  probe: HelperResolutionProbe,
): HelperResolution {
  const root = normalizeHostPath(installation.installRoot);
  const cwd = normalizeHostPath(probe.cwd);
  if (!root || !cwd) {
    return {
      ok: false,
      code: "sandbox-setup-failed",
      reason: "helper install root and cwd must be absolute paths",
    };
  }
  const exists = probe.exists ?? defaultExists;
  const isFile = probe.isFile ?? defaultIsFile;
  const isDirectory = probe.isDirectory ?? defaultIsDirectory;
  const canonical = probe.realpath ?? defaultRealpath;
  const canonicalExisting = (path: string): string | null => {
    const resolved = canonical(path);
    return resolved === null ? null : normalizeHostPath(resolved);
  };
  const canonicalOrSelf = (path: string): string =>
    canonicalExisting(path) ?? path;

  if (!exists(root) || !isDirectory(root)) {
    return {
      ok: false,
      code: "sandbox-unavailable",
      reason: `helper installation directory is missing: ${root}`,
    };
  }
  const rootReal = canonicalExisting(root);
  if (!rootReal) {
    return {
      ok: false,
      code: "sandbox-setup-failed",
      reason: "helper installation directory could not be canonicalized",
    };
  }
  const cwdReal = canonicalOrSelf(cwd);
  if (sameOrWithin(cwdReal, rootReal) || sameOrWithin(rootReal, cwdReal)) {
    return {
      ok: false,
      code: "sandbox-setup-failed",
      reason: "helper installation must not be selected from the helper cwd",
    };
  }
  const workspace = probe.workspace
    ? normalizeHostPath(probe.workspace)
    : null;
  const workspaceReal = workspace ? canonicalOrSelf(workspace) : null;
  if (
    workspaceReal &&
    (sameOrWithin(workspaceReal, rootReal) ||
      sameOrWithin(rootReal, workspaceReal))
  ) {
    return {
      ok: false,
      code: "sandbox-setup-failed",
      reason: "helper installation must not be selected from the workspace",
    };
  }
  const executable = normalizeHostPath(installation.executable);
  if (!executable || !exists(executable) || !isFile(executable)) {
    return {
      ok: false,
      code: "sandbox-unavailable",
      reason: `helper executable is missing: ${String(installation.executable)}`,
    };
  }
  const executableReal = canonicalExisting(executable);
  if (!executableReal) {
    return {
      ok: false,
      code: "sandbox-setup-failed",
      reason: "helper executable could not be canonicalized",
    };
  }
  if (
    sameOrWithin(cwdReal, executableReal) ||
    (workspaceReal && sameOrWithin(workspaceReal, executableReal))
  ) {
    return {
      ok: false,
      code: "sandbox-setup-failed",
      reason: "helper executable must not be selected from the workspace or cwd",
    };
  }
  const runtime = basename(executableReal).toLowerCase().replace(/\.exe$/u, "");
  const args = installation.args ?? [];
  let scriptReal: string | null = null;
  if (runtime === "node") {
    const script = args[0];
    if (typeof script !== "string" || !isAbsolute(script)) {
      return {
        ok: false,
        code: "sandbox-setup-failed",
        reason: "node helper requires an absolute script argument",
      };
    }
    const scriptPath = normalizeHostPath(script);
    if (!scriptPath) {
      return {
        ok: false,
        code: "sandbox-setup-failed",
        reason: "node helper script path is invalid",
      };
    }
    if (!isPathWithin(root, scriptPath)) {
      return {
        ok: false,
        code: "sandbox-setup-failed",
        reason: "node helper script must live under the install root",
      };
    }
    if (!exists(scriptPath) || !isFile(scriptPath)) {
      return {
        ok: false,
        code: "sandbox-unavailable",
        reason: `node helper script is missing: ${scriptPath}`,
      };
    }
    scriptReal = canonicalExisting(scriptPath);
    if (!scriptReal || !isPathWithin(rootReal, scriptReal)) {
      return {
        ok: false,
        code: "sandbox-setup-failed",
        reason: "node helper script must live under the install root",
      };
    }
  } else if (!isPathWithin(rootReal, executableReal)) {
    return {
      ok: false,
      code: "sandbox-setup-failed",
      reason: "helper executable must live under the install root",
    };
  }

  const resolvedArgs = args.map((arg) => {
    if (typeof arg !== "string") return arg;
    if (!isAbsolute(arg)) return arg;
    const normalized = normalizeHostPath(arg);
    if (!normalized) return arg;
    return canonicalExisting(normalized) ?? normalized;
  });
  if (runtime === "node" && scriptReal) resolvedArgs[0] = scriptReal;
  for (const argumentPath of resolvedArgs) {
    if (!isAbsolute(argumentPath) || argumentPath.startsWith("-")) continue;
    if (
      sameOrWithin(cwdReal, argumentPath) ||
      (workspaceReal && sameOrWithin(workspaceReal, argumentPath))
    ) {
      return {
        ok: false,
        code: "sandbox-setup-failed",
        reason: "helper arguments must not point into the workspace or cwd",
      };
    }
  }

  return {
    ok: true,
    installation: Object.freeze({
      ...installation,
      installRoot: rootReal,
      executable: executableReal,
      args: Object.freeze([...resolvedArgs]),
    }),
  };
}

export interface RequiredCapabilities {
  readonly read: boolean;
  readonly write: boolean;
  readonly fileGranularity: boolean;
  readonly protectedPaths: boolean;
  readonly environment: boolean;
  readonly network: "none" | "all" | "domains";
  readonly cancel: boolean;
  readonly streamOutput: boolean;
  readonly startedNotification: boolean;
  readonly processTree: boolean;
}

export function requiredCapabilities(plan: ExecutionPlan): RequiredCapabilities {
  const writes = plan.filesystem.filter((grant) => grant.access === "write");
  const reads = plan.filesystem.filter((grant) => grant.access === "read");
  const fileGranularity = plan.filesystem.some(
    (grant) => grant.granularity === "file",
  );
  return {
    read:
      reads.length > 0 ||
      plan.operation.kind === "read-file" ||
      plan.operation.kind === "access-file" ||
      plan.operation.kind === "access-dir",
    write: writes.length > 0 || plan.operation.kind === "write-file" || plan.operation.kind === "mkdir",
    fileGranularity,
    protectedPaths: plan.protectedPaths.length > 0,
    environment: Object.keys(plan.environment).length > 0,
    network:
      plan.network.kind === "destinations"
        ? "domains"
        : plan.network.kind === "all"
          ? "all"
          : "none",
    cancel: true,
    streamOutput: true,
    startedNotification: true,
    processTree: true,
  };
}

/** List every requirement the reported backend cannot express. */
export function capabilityGap(
  capabilities: BackendCapabilities,
  required: RequiredCapabilities,
): readonly string[] {
  const gaps: string[] = [];
  if (required.read && !capabilities.filesystem.read) gaps.push("filesystem-read");
  if (required.write && !capabilities.filesystem.write) gaps.push("filesystem-write");
  if (
    required.fileGranularity &&
    capabilities.filesystem.granularity !== "file"
  ) {
    gaps.push("filesystem-file-granularity");
  }
  if (required.protectedPaths && !capabilities.filesystem.protectedPaths) {
    gaps.push("protected-path-deny");
  }
  if (required.environment && !capabilities.filesystem.environment) {
    gaps.push("environment-filter");
  }
  if (
    required.network === "all" &&
    capabilities.network !== "all" &&
    capabilities.network !== "domains"
  ) {
    gaps.push("network-all");
  }
  // A backend that merely allows all traffic cannot enforce a domain/port
  // allowlist. Only an exact `domains` capability satisfies a precise need.
  if (required.network === "domains" && capabilities.network !== "domains") {
    gaps.push("network-domains");
  }
  if (required.cancel && !capabilities.cancel) gaps.push("cancel");
  if (required.streamOutput && !capabilities.streamOutput) {
    gaps.push("stream-output");
  }
  if (required.startedNotification && !capabilities.startedNotification) {
    gaps.push("started-notification");
  }
  if (required.processTree && !capabilities.processTree) {
    gaps.push("process-tree");
  }
  return gaps;
}

export function versionMatches(
  installation: TrustedHelperInstallation,
  reportedProtocol: number,
  reportedBackendVersion: string,
  reportedBackendId?: string,
): boolean {
  const expectedProtocol =
    installation.expectedProtocolVersion ?? HELPER_PROTOCOL_VERSION;
  if (reportedProtocol !== expectedProtocol) return false;
  if (
    installation.expectedBackendId !== undefined &&
    installation.expectedBackendId !== reportedBackendId
  ) {
    return false;
  }
  if (
    installation.expectedBackendVersion !== undefined &&
    installation.expectedBackendVersion !== reportedBackendVersion
  ) {
    return false;
  }
  return true;
}

export function helperFailureCode(
  code: string,
):
  | "sandbox-capability-unsupported"
  | "sandbox-unavailable"
  | "sandbox-setup-failed"
  | "sandbox-start-failed"
  | "sandbox-denied"
  | "sandbox-path-missing" {
  switch (code) {
    case "unavailable":
      return "sandbox-unavailable";
    case "unsupported":
    case "capability":
      return "sandbox-capability-unsupported";
    case "setup":
    case "setup-failed":
      return "sandbox-setup-failed";
    case "denied":
      return "sandbox-denied";
    case "missing":
    case "not-found":
      return "sandbox-path-missing";
    default:
      return "sandbox-start-failed";
  }
}

export type { ExecutionFailureCode };
