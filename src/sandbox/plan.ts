import { dirname } from "node:path";
import { builtinToolPath } from "./builtin-path";
import type { PermissionScope } from "../action";
import {
  toolInvocationDigestMatches,
  type ToolInvocationFacts,
} from "../invocation";
import type { PermissionMode } from "../contracts";
import {
  DEFAULT_HELPER_ENVIRONMENT_ALLOWLIST,
  BUILTIN_TOOL_NAMES,
  EXECUTION_PLAN_VERSION,
  MAX_DEADLINE_HORIZON_MS,
  MAX_ENVIRONMENT_ENTRIES,
  MAX_ENVIRONMENT_VALUE_BYTES,
  MAX_FILE_CONTENT_BYTES,
  type ExecutionOperation,
  type ExecutionPlan,
  type ExecutionScopeGrant,
  type FilesystemGrantInput,
  type NetworkDestination,
  type NetworkScope,
} from "#sandbox/types";
import {
  PROTECTED_CONTROL_DIRECTORY_NAMES,
  findProtectedControlRoot,
  isPathWithin,
  isSamePath,
  normalizeHostPath,
  protectedPathsForGrant,
} from "#sandbox/path";
import { jsonDigest } from "../json";
import { intersectNetworkScopes } from "./network-scope";

export type PlanFailureCode =
  | "action-mismatch"
  | "invalid-plan"
  | "scope-expansion"
  | "protected-path"
  | "environment-not-allowed"
  | "deadline-invalid"
  | "mode-not-sandboxed"
  | "unsupported-operation";

export type PlanCompileResult =
  | { readonly ok: true; readonly plan: ExecutionPlan }
  | {
      readonly ok: false;
      readonly code: PlanFailureCode;
      readonly reason: string;
    };

export interface PlanBaselineScope {
  readonly filesystem: readonly FilesystemGrantInput[];
  readonly network: NetworkScope;
}

export interface PlanApprovedScope {
  readonly filesystem: readonly FilesystemGrantInput[];
  /** Only destinations explicitly present in an allow network scope. */
  readonly network?: readonly NetworkDestination[];
}

export interface CompileExecutionPlanInput {
  readonly invocation: ToolInvocationFacts;
  readonly operation: ExecutionOperation;
  readonly mode: PermissionMode;
  readonly owner: string;
  readonly bindingId: string;
  readonly baseline: PlanBaselineScope;
  readonly networkCeiling?: NetworkScope;
  readonly approved: PlanApprovedScope;
  readonly backendId: string;
  readonly policyRevision: string;
  readonly configRevision: string;
  readonly deadlineAt: number;
  readonly now?: number;
  readonly environment: Readonly<Record<string, string>>;
  readonly environmentAllowlist?: readonly string[];
  readonly protectedControlNames?: readonly string[];
  readonly expectedToolRevision?: string;
  /** Host-approved interpreter recorded in a shell plan. */
  readonly shell?: string;
  /**
   * Host-owned canonicalizer (for example realpath/reparse resolution). It must
   * return null when the host cannot prove the target identity.
   */
  readonly resolvePath?: (path: string) => string | null;
}

interface OperationTargets {
  readonly read: readonly string[];
  readonly write: readonly string[];
  /** Exact approved file whose parent directory is being checked. */
  readonly parentOfFile?: string;
}

/** Host default used only when the caller did not pin a shell interpreter. */
function defaultExecutionShell(): string {
  if (process.platform === "win32") {
    const comspec = process.env.ComSpec;
    return typeof comspec === "string" && comspec.trim()
      ? comspec.trim()
      : "cmd.exe";
  }
  const shell = process.env.SHELL;
  return typeof shell === "string" && shell.trim() ? shell.trim() : "/bin/sh";
}

function resolvePlanPath(
  path: string,
  resolver: CompileExecutionPlanInput["resolvePath"],
): string | null {
  const normalized = normalizeHostPath(path);
  if (!normalized) return null;
  if (!resolver) return normalized;
  let resolved: string | null;
  try {
    resolved = resolver(normalized);
  } catch {
    return null;
  }
  return normalizeHostPath(resolved);
}

function nonempty(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function fail(
  code: PlanFailureCode,
  reason: string,
): { readonly ok: false; readonly code: PlanFailureCode; readonly reason: string } {
  return { ok: false, code, reason };
}

/**
 * Validate requested values against the host's explicit allowlist. The helper
 * never inherits the controller environment, so a credential name that is not
 * allowlisted fails the plan before any process starts.
 */
export function filterExecutionEnvironment(
  environment: Readonly<Record<string, string>> | undefined,
  allowlist: readonly string[] = DEFAULT_HELPER_ENVIRONMENT_ALLOWLIST,
): {
  readonly ok: true;
  readonly environment: Readonly<Record<string, string>>;
} | {
  readonly ok: false;
  readonly reason: string;
} {
  if (environment === undefined) {
    return { ok: true, environment: Object.freeze({}) };
  }
  if (typeof environment !== "object" || environment === null) {
    return { ok: false, reason: "environment must be an object" };
  }
  const allowed = new Set(allowlist.map(name => process.platform === "win32" ? name.toUpperCase() : name));
  const entries = Object.entries(environment);
  if (entries.length > MAX_ENVIRONMENT_ENTRIES) {
    return { ok: false, reason: "environment has too many entries" };
  }
  const result: Record<string, string> = Object.create(null);
  for (const [name, value] of entries) {
    const normalizedName = process.platform === "win32" ? name.toUpperCase() : name;
    if (!allowed.has(normalizedName)) {
      return {
        ok: false,
        reason: `environment name is not allowlisted: ${name}`,
      };
    }
    if (typeof value !== "string") {
      return { ok: false, reason: `environment value is not a string: ${name}` };
    }
    if (Buffer.byteLength(value, "utf8") > MAX_ENVIRONMENT_VALUE_BYTES) {
      return { ok: false, reason: `environment value is too large: ${name}` };
    }
    result[normalizedName] = value;
  }
  return { ok: true, environment: Object.freeze(result) };
}

/**
 * Keep only allowlisted names from a trusted action environment. This is the
 * derivation used when the host did not configure the helper environment
 * explicitly; it never widens what the plan records.
 */
export function selectExecutionEnvironment(
  environment: Readonly<Record<string, string>>,
  allowlist: readonly string[] = DEFAULT_HELPER_ENVIRONMENT_ALLOWLIST,
): Readonly<Record<string, string>> {
  const allowed = new Set(allowlist.map(name => process.platform === "win32" ? name.toUpperCase() : name));
  const result: Record<string, string> = Object.create(null);
  for (const [name, value] of Object.entries(environment)) {
    const normalizedName = process.platform === "win32" ? name.toUpperCase() : name;
    if (allowed.has(normalizedName) && typeof value === "string") result[normalizedName] = value;
  }
  return Object.freeze(result);
}

function grantSourceFromScope(
  scope: PermissionScope,
): "read" | "write" | null {
  if (scope.state !== "allow") return null;
  if (scope.access === "read") return "read";
  if (scope.access === "write") return "write";
  return null;
}

/**
 * Approved grants must be backed by an allow scope of the exact action. A host
 * cannot turn one approved read file into a directory write grant.
 */
function approvedGrantsAreCovered(
  invocation: ToolInvocationFacts,
  grants: readonly FilesystemGrantInput[],
  resolvePath: CompileExecutionPlanInput["resolvePath"],
): string | null {
  const scopes = invocation.action.scopes;
  for (const grant of grants) {
    const lexical = normalizeHostPath(grant.path);
    if (!lexical) return `approved grant is not an absolute path: ${grant.path}`;
    const path = resolvePlanPath(lexical, resolvePath);
    if (!path) return `approved grant cannot be resolved: ${grant.path}`;
    if (!isSamePath(lexical, path)) {
      return `approved ${grant.access} grant resolves to a different target: ${grant.path}`;
    }
    const covered = scopes.some((scope) => {
      const direction = grantSourceFromScope(scope);
      if (direction !== grant.access) return false;
      const target = resolvePlanPath(scope.target, resolvePath);
      return target !== null && isSamePath(target, path);
    });
    if (!covered) {
      return `approved ${grant.access} grant has no matching allow scope: ${grant.path}`;
    }
  }
  return null;
}

function normalizeGrants(
  grants: readonly FilesystemGrantInput[],
  source: "baseline" | "approved-extension",
  resolvePath: CompileExecutionPlanInput["resolvePath"],
): readonly ExecutionScopeGrant[] {
  const result: ExecutionScopeGrant[] = [];
  for (const grant of grants) {
    const path = resolvePlanPath(grant.path, resolvePath);
    if (!path) continue;
    result.push(
      Object.freeze({
        path,
        access: grant.access,
        granularity: grant.granularity,
        source,
      }),
    );
  }
  return result;
}

function targetGrants(
  planGrants: readonly ExecutionScopeGrant[],
  target: string,
  direction: "read" | "write",
): readonly ExecutionScopeGrant[] {
  return planGrants.filter((grant) => {
    if (grant.access !== direction) return false;
    if (grant.granularity === "file") return isSamePath(grant.path, target);
    return isPathWithin(grant.path, target);
  });
}

function validateOperation(
  operation: ExecutionOperation,
  resolvePath: CompileExecutionPlanInput["resolvePath"],
  approvedShell: string | undefined,
  invocation: ToolInvocationFacts,
): { readonly ok: true; readonly operation: ExecutionOperation; readonly targets: OperationTargets } | { readonly ok: false; readonly reason: string } {
  if (typeof operation !== "object" || operation === null) {
    return { ok: false, reason: "operation must be an object" };
  }
  switch (operation.kind) {
    case "builtin-tool": {
      if (!BUILTIN_TOOL_NAMES.includes(operation.name) ||
          operation.name !== invocation.action.tool.name ||
          jsonDigest(operation.arguments) !== jsonDigest(invocation.action.effectiveArguments)) {
        return { ok: false, reason: "builtin invocation differs from the approved tool or arguments" };
      }
      if (operation.name === "bash" || operation.name === "powershell") {
        return { ok: true, operation, targets: { read: [], write: [] } };
      }
      const path = operation.arguments.path ?? ".";
      if (typeof path !== "string" || path.includes("\0")) return { ok: false, reason: "invalid builtin path" };
      const target = resolvePlanPath(builtinToolPath(operation.name, path, invocation.action.cwd), resolvePath);
      if (!target) return { ok: false, reason: "builtin path cannot be resolved" };
      return {
        ok: true, operation,
        targets: {
          read: operation.name === "write" ? [] : [target],
          write: operation.name === "write" || operation.name === "edit" ? [target] : [],
        },
      };
    }
    case "shell": {
      if (!nonempty(operation.command)) {
        return { ok: false, reason: "shell command is empty" };
      }
      if (operation.command.includes("\0")) {
        return { ok: false, reason: "shell command contains NUL" };
      }
      if (
        operation.timeoutMs !== undefined &&
        (!Number.isInteger(operation.timeoutMs) || operation.timeoutMs <= 0)
      ) {
        return { ok: false, reason: "shell timeout is invalid" };
      }
      if (
        operation.shell !== undefined &&
        approvedShell !== undefined &&
        !isSamePath(operation.shell, approvedShell)
      ) {
        return { ok: false, reason: "shell interpreter does not match the host approval" };
      }
      const shell = operation.shell ?? approvedShell ?? defaultExecutionShell();
      if (!nonempty(shell) || shell.includes("\0")) {
        return { ok: false, reason: "shell interpreter is invalid" };
      }
      const normalized = { ...operation, shell };
      return {
        ok: true,
        operation: normalized,
        targets: { read: [], write: [] },
      };
    }
    case "read-file": {
      const path = resolvePlanPath(operation.path, resolvePath);
      if (!path) return { ok: false, reason: "read path cannot be resolved" };
      return {
        ok: true,
        operation: { ...operation, path },
        targets: { read: [path], write: [] },
      };
    }
    case "access-file": {
      const path = resolvePlanPath(operation.path, resolvePath);
      if (!path) return { ok: false, reason: "access path cannot be resolved" };
      return {
        ok: true,
        operation: { ...operation, path },
        targets: {
          read: [path],
          write: operation.mode === "read-write" ? [path] : [],
        },
      };
    }
    case "write-file": {
      const path = resolvePlanPath(operation.path, resolvePath);
      if (!path) return { ok: false, reason: "write path cannot be resolved" };
      if (typeof operation.content !== "string") {
        return { ok: false, reason: "write content is not a string" };
      }
      if (
        Buffer.byteLength(operation.content, "utf8") > MAX_FILE_CONTENT_BYTES
      ) {
        return { ok: false, reason: "write content exceeds the size limit" };
      }
      return {
        ok: true,
        operation: { ...operation, path },
        targets: { read: [], write: [path] },
      };
    }
    case "mkdir": {
      const path = resolvePlanPath(operation.path, resolvePath);
      if (!path) return { ok: false, reason: "mkdir path cannot be resolved" };
      return {
        ok: true,
        operation: { ...operation, path },
        targets: { read: [], write: [path] },
      };
    }
    case "access-dir": {
      const path = resolvePlanPath(operation.path, resolvePath);
      const forFile = resolvePlanPath(operation.forFile, resolvePath);
      if (!path) return { ok: false, reason: "access-dir path cannot be resolved" };
      if (!forFile) return { ok: false, reason: "access-dir file cannot be resolved" };
      const parent = normalizeHostPath(dirname(forFile));
      if (!parent || !isSamePath(parent, path)) {
        return {
          ok: false,
          reason: "access-dir path must be the parent of its approved file",
        };
      }
      return {
        ok: true,
        operation: { ...operation, path, forFile },
        targets: { read: [], write: [], parentOfFile: forFile },
      };
    }
    default:
      return { ok: false, reason: "unknown operation kind" };
  }
}

function networkDestinationAllowed(
  invocation: ToolInvocationFacts,
  destination: NetworkDestination,
): boolean {
  const host = destination.host.toLowerCase();
  const target = destination.port === undefined ? host : `${host}:${destination.port}`;
  return invocation.action.scopes.some((scope) => {
    if (scope.state !== "allow" || scope.access !== "network") return false;
    const approvedTarget = scope.target.trim().toLowerCase();
    if (approvedTarget === "*") return true;
    return approvedTarget === host || approvedTarget === target;
  });
}

function normalizeNetworkDestinations(
  destinations: readonly NetworkDestination[],
  source: "baseline" | "approved-extension",
  invocation?: ToolInvocationFacts,
): { readonly ok: true; readonly destinations: readonly NetworkDestination[] } | { readonly ok: false; readonly reason: string } {
  const result: NetworkDestination[] = [];
  for (const destination of destinations) {
    if (!nonempty(destination.host) || destination.host.includes("\0")) {
      return { ok: false, reason: "network destination host is invalid" };
    }
    if (
      destination.port !== undefined &&
      (!Number.isInteger(destination.port) ||
        destination.port <= 0 ||
        destination.port > 65_535)
    ) {
      return { ok: false, reason: "network destination port is invalid" };
    }
    if (
      source === "approved-extension" &&
      invocation &&
      !networkDestinationAllowed(invocation, destination)
    ) {
      return {
        ok: false,
        reason: `network destination has no matching allow scope: ${destination.host}`,
      };
    }
    result.push(
      Object.freeze({
        host: destination.host.toLowerCase(),
        ...(destination.port === undefined
          ? {}
          : { port: destination.port }),
        source,
      }),
    );
  }
  return { ok: true, destinations: Object.freeze(result) };
}

function validateNetwork(
  invocation: ToolInvocationFacts,
  input: CompileExecutionPlanInput,
): { readonly ok: true; readonly network: NetworkScope } | { readonly ok: false; readonly reason: string } {
  const baseline = input.baseline.network;
  if (baseline.kind !== "destinations" && baseline.kind !== "none" && baseline.kind !== "all") {
    return { ok: false, reason: "baseline network scope is invalid" };
  }
  const baselineResult =
    baseline.kind === "destinations"
      ? normalizeNetworkDestinations(baseline.destinations, "baseline")
      : { ok: true as const, destinations: [] as readonly NetworkDestination[] };
  if (!baselineResult.ok) return baselineResult;

  const approvedResult = normalizeNetworkDestinations(
    input.approved.network ?? [],
    "approved-extension",
    invocation,
  );
  if (!approvedResult.ok) return approvedResult;

  // `all` is a host-wide allowance and cannot be narrowed by an extension.
  if (baseline.kind === "all") {
    return { ok: true, network: Object.freeze({ kind: "all" }) };
  }

  const combined = [...baselineResult.destinations, ...approvedResult.destinations];
  if (combined.length === 0) {
    return { ok: true, network: Object.freeze({ kind: "none" }) };
  }
  const hostOnly = new Set(
    combined
      .filter((destination) => destination.port === undefined)
      .map((destination) => destination.host),
  );
  const seen = new Set<string>();
  const destinations: NetworkDestination[] = [];
  for (const destination of combined) {
    if (destination.port !== undefined && hostOnly.has(destination.host)) {
      continue;
    }
    const key = `${destination.host}\0${destination.port ?? "*"}`;
    if (seen.has(key)) continue;
    seen.add(key);
    destinations.push(destination);
  }
  destinations.sort((left, right) => {
    const host = left.host.localeCompare(right.host);
    if (host !== 0) return host;
    return (left.port ?? 0) - (right.port ?? 0);
  });
  return {
    ok: true,
    network: Object.freeze({
      kind: "destinations",
      destinations: Object.freeze(destinations),
    }),
  };
}

/**
 * Compile the immutable plan the helper receives. Everything is derived from
 * the frozen invocation, the host baseline, and allow scopes of that same
 * action; the caller cannot inject a broader target by passing a different
 * operation.
 */
export function compileExecutionPlan(
  input: CompileExecutionPlanInput,
): PlanCompileResult {
  if (input.mode === "full-access") {
    return fail(
      "mode-not-sandboxed",
      "full-access has no module sandbox and must not use the controlled executor",
    );
  }
  if (!toolInvocationDigestMatches(input.invocation)) {
    return fail("action-mismatch", "invocation facts do not verify");
  }
  const binding = input.invocation.executionBinding;
  if (binding.status !== "bound") {
    return fail("action-mismatch", "action has no bound execution");
  }
  if (
    binding.owner !== input.owner ||
    binding.bindingId !== input.bindingId ||
    binding.toolName !== input.invocation.action.tool.name
  ) {
    return fail("action-mismatch", "execution binding does not match the plan");
  }
  if (
    input.expectedToolRevision !== undefined &&
    input.expectedToolRevision !== input.invocation.action.tool.revision
  ) {
    return fail("action-mismatch", "tool registration revision changed");
  }
  if (
    !nonempty(input.policyRevision) ||
    !nonempty(input.configRevision)
  ) {
    return fail("invalid-plan", "policy and config revisions are required");
  }
  if (
    !nonempty(input.invocation.action.cwd) ||
    !nonempty(input.invocation.requester.sessionId)
  ) {
    return fail("invalid-plan", "cwd and requester session are required");
  }
  const cwd = normalizeHostPath(input.invocation.action.cwd);
  if (!cwd) return fail("invalid-plan", "cwd is not absolute");

  const operation = validateOperation(
    input.operation,
    input.resolvePath,
    input.shell,
    input.invocation,
  );
  if (!operation.ok) {
    return fail("unsupported-operation", operation.reason);
  }

  const now = input.now ?? Date.now();
  if (
    !Number.isFinite(input.deadlineAt) ||
    !Number.isInteger(input.deadlineAt) ||
    input.deadlineAt <= now
  ) {
    return fail("deadline-invalid", "deadline must be a future epoch value");
  }
  if (input.deadlineAt - now > MAX_DEADLINE_HORIZON_MS) {
    return fail("deadline-invalid", "deadline exceeds the maximum horizon");
  }

  const environment = filterExecutionEnvironment(
    input.environment,
    input.environmentAllowlist ?? DEFAULT_HELPER_ENVIRONMENT_ALLOWLIST,
  );
  if (!environment.ok) {
    return fail("environment-not-allowed", environment.reason);
  }

  for (const grant of input.baseline.filesystem) {
    if (!resolvePlanPath(grant.path, input.resolvePath)) {
      return fail("invalid-plan", `baseline grant cannot be resolved: ${grant.path}`);
    }
  }
  const approvedCoverage = approvedGrantsAreCovered(
    input.invocation,
    input.approved.filesystem,
    input.resolvePath,
  );
  if (approvedCoverage) {
    return fail("scope-expansion", approvedCoverage);
  }

  const filesystem = Object.freeze([
    ...normalizeGrants(input.baseline.filesystem, "baseline", input.resolvePath),
    ...normalizeGrants(
      input.approved.filesystem,
      "approved-extension",
      input.resolvePath,
    ),
  ]);

  const network = validateNetwork(input.invocation, input);
  if (!network.ok) {
    return fail("scope-expansion", network.reason);
  }

  // A parent-directory check is only a metadata read of the directory that
  // holds this plan's own write target. Requiring the file itself to be
  // writable keeps it from becoming a probe for an unrelated directory.
  if (operation.targets.parentOfFile !== undefined) {
    const file = operation.targets.parentOfFile;
    if (targetGrants(filesystem, file, "write").length === 0) {
      return fail(
        "scope-expansion",
        `parent directory check has no write grant for its approved file: ${file}`,
      );
    }
  }

  const protectedNames =
    input.protectedControlNames ?? PROTECTED_CONTROL_DIRECTORY_NAMES;
  const protectedPaths = new Set<string>();
  for (const grant of filesystem) {
    if (grant.access !== "write") continue;
    if (grant.granularity === "directory") {
      for (const path of protectedPathsForGrant(grant.path, protectedNames)) {
        protectedPaths.add(path);
      }
    }
  }

  for (const { target, access } of [
    ...operation.targets.read.map((target) => ({
      target,
      access: "read" as const,
    })),
    ...operation.targets.write.map((target) => ({
      target,
      access: "write" as const,
    })),
  ]) {
    const protectedRoot = findProtectedControlRoot(target, protectedNames);
    if (!protectedRoot) continue;
    const exactApprovedFile = filesystem.some(
      (grant) =>
        grant.access === access &&
        grant.granularity === "file" &&
        grant.source === "approved-extension" &&
        isSamePath(grant.path, target),
    );
    if (!exactApprovedFile) {
      return fail(
        "protected-path",
        `protected control path requires an explicit ${access} approval: ${protectedRoot}`,
      );
    }
    if (access === "write") protectedPaths.add(protectedRoot);
  }

  // Directory grants must not sit inside a protected control directory: such a
  // grant would silently widen a protected child even without naming it.
  for (const grant of filesystem) {
    if (grant.access !== "write" || grant.granularity !== "directory") continue;
    const protectedRoot = findProtectedControlRoot(grant.path, protectedNames);
    if (protectedRoot) {
      return fail(
        "protected-path",
        `directory write grant is inside a protected control path: ${grant.path}`,
      );
    }
  }

  const missing: string[] = [];
  for (const target of operation.targets.read) {
    if (targetGrants(filesystem, target, "read").length === 0) {
      missing.push(`read ${target}`);
    }
  }
  for (const target of operation.targets.write) {
    if (targetGrants(filesystem, target, "write").length === 0) {
      missing.push(`write ${target}`);
    }
  }
  if (missing.length > 0) {
    return fail(
      "scope-expansion",
      `operation targets are outside the approved scope: ${missing.join(", ")}`,
    );
  }

  const facts = {
    version: EXECUTION_PLAN_VERSION,
    requestId: input.invocation.action.requestId,
    toolCallId: input.invocation.action.toolCallId,
    actionDigest: input.invocation.digest,
    sessionId: input.invocation.requester.sessionId,
    tool: {
      name: input.invocation.action.tool.name,
      owner: binding.owner,
      revision: input.invocation.action.tool.revision,
      bindingId: binding.bindingId,
    },
    mode: input.mode,
    policyRevision: input.policyRevision,
    configRevision: input.configRevision,
    cwd,
    operation: operation.operation,
    environment: environment.environment,
    filesystem,
    protectedPaths: Object.freeze([...protectedPaths].sort()),
    network: input.networkCeiling === undefined ? network.network : intersectNetworkScopes(network.network, input.networkCeiling),
    deadlineAt: input.deadlineAt,
    backend: { id: input.backendId },
  } as const;
  const digest = jsonDigest(facts);
  const plan: ExecutionPlan = deepFreeze({
    ...facts,
    digest,
  });
  return { ok: true, plan };
}

/** Recursively freeze a plan-shaped value; cycles are impossible after capture. */
function deepFreeze<T>(value: T, seen = new Set<object>()): T {
  if (value === null || typeof value !== "object") return value;
  const object = value as object;
  if (seen.has(object)) return value;
  seen.add(object);
  for (const key of Object.keys(object)) {
    deepFreeze((object as Record<string, unknown>)[key], seen);
  }
  return Object.freeze(value);
}

const MAX_CAPTURED_PLAN_NODES = 8192;
const MAX_CAPTURED_PLAN_DEPTH = 32;

/**
 * Capture a caller-supplied plan into a private deep-frozen copy. Accessors,
 * non-plain prototypes, cycles, symbols and oversized graphs are rejected
 * without invoking getters. The controller must use only this copy.
 */
export function captureExecutionPlan(value: unknown): ExecutionPlan | null {
  let nodes = 0;
  const seen = new Set<object>();
  const copy = (current: unknown, depth: number): unknown => {
    if (depth > MAX_CAPTURED_PLAN_DEPTH) throw new Error("plan depth");
    if (current === null) return null;
    const type = typeof current;
    if (type === "string" || type === "boolean") return current;
    if (type === "number") {
      if (!Number.isFinite(current)) throw new Error("non-finite number");
      return current;
    }
    if (type !== "object") throw new Error("non-data plan value");
    const object = current as object;
    if (seen.has(object)) throw new Error("plan cycle");
    seen.add(object);
    nodes += 1;
    if (nodes > MAX_CAPTURED_PLAN_NODES) throw new Error("plan node limit");
    if (Object.getOwnPropertySymbols(object).length > 0) {
      throw new Error("symbol keys");
    }
    if (Array.isArray(object)) {
      if (Object.getPrototypeOf(object) !== Array.prototype) {
        throw new Error("array prototype");
      }
      const result: unknown[] = [];
      for (let index = 0; index < object.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(object, String(index));
        if (!descriptor || !("value" in descriptor)) {
          throw new Error("array hole or accessor");
        }
        result.push(copy(descriptor.value, depth + 1));
      }
      for (const key of Object.keys(object)) {
        if (!/^\d+$/u.test(key)) throw new Error("array extra property");
      }
      return result;
    }
    const prototype = Object.getPrototypeOf(object);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error("object prototype");
    }
    const result: Record<string, unknown> = Object.create(null);
    for (const key of Object.keys(object)) {
      const descriptor = Object.getOwnPropertyDescriptor(object, key);
      if (!descriptor || !("value" in descriptor)) {
        throw new Error("accessor property");
      }
      result[key] = copy(descriptor.value, depth + 1);
    }
    return result;
  };
  try {
    return deepFreeze(copy(value, 0) as ExecutionPlan);
  } catch {
    return null;
  }
}

/** Recompute a plan digest so a stale or mutated plan cannot run. */
export function executionPlanVerifies(plan: ExecutionPlan): boolean {
  try {
    const { digest, ...facts } = plan;
    return jsonDigest(facts) === digest;
  } catch {
    return false;
  }
}
