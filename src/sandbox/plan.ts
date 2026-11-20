import { statSync } from "node:fs";
import type { PermissionScope } from "../action";
import {
  toolInvocationDigestMatches,
  type ToolInvocationFacts,
} from "../invocation";
import {
  DEFAULT_EXECUTION_ENVIRONMENT_ALLOWLIST,
  EXECUTION_PLAN_VERSION,
  MAX_ENVIRONMENT_ENTRIES,
  MAX_ENVIRONMENT_VALUE_BYTES,
  type ExecutionFilesystemRestriction,
  type ExecutionPlan,
  type ExecutionRequest,
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
import type { SensitivePath } from "./sensitive-paths";

export type PlanFailureCode =
  | "action-mismatch"
  | "invalid-plan"
  | "scope-expansion"
  | "protected-path";

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
  readonly baseline: PlanBaselineScope;
  readonly runtimeFilesystem?: readonly FilesystemGrantInput[];
  readonly networkCeiling?: NetworkScope;
  readonly approved: PlanApprovedScope;
  readonly metadataRead?: "none" | "all";
  readonly protectedPaths?: readonly string[];
  readonly protectedFilePaths?: readonly string[];
  readonly sensitivePaths?: readonly SensitivePath[];
  readonly protectedControlNames?: readonly string[];
  /**
   * Host-owned canonicalizer (for example realpath/reparse resolution). It must
   * return null when the host cannot prove the target identity.
   */
  readonly resolvePath?: (path: string) => string | null;
}

export interface CompilePermissionPlanInput {
  readonly baseline: PlanBaselineScope;
  readonly runtimeFilesystem?: readonly FilesystemGrantInput[];
  readonly approved: PlanApprovedScope;
  readonly network: NetworkScope;
  readonly metadataRead?: "none" | "all";
  readonly protectedPaths?: readonly string[];
  readonly protectedFilePaths?: readonly string[];
  readonly sensitivePaths?: readonly SensitivePath[];
  readonly protectedControlNames?: readonly string[];
  readonly resolvePath?: (path: string) => string | null;
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
 * Validate requested values against the host's explicit allowlist. A native
 * process never inherits the controller environment, so a credential name
 * that is not allowlisted fails the plan before any process starts.
 */
export function filterExecutionEnvironment(
  environment: Readonly<Record<string, string>> | undefined,
  allowlist: readonly string[] = DEFAULT_EXECUTION_ENVIRONMENT_ALLOWLIST,
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
 * derivation used when the host did not configure the execution environment
 * explicitly; it never widens what the plan records.
 */
export function selectExecutionEnvironment(
  environment: Readonly<Record<string, string>>,
  allowlist: readonly string[] = DEFAULT_EXECUTION_ENVIRONMENT_ALLOWLIST,
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
  source: "baseline" | "approved-extension" | "runtime",
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

/** Compile the final permission rules. Call and startup data stays in the host request. */
export function compileExecutionPlan(
  input: CompileExecutionPlanInput,
): PlanCompileResult {
  if (!toolInvocationDigestMatches(input.invocation)) {
    return fail("action-mismatch", "invocation facts do not verify");
  }
  const approvedCoverage = approvedGrantsAreCovered(
    input.invocation,
    input.approved.filesystem,
    input.resolvePath,
  );
  if (approvedCoverage) {
    return fail("scope-expansion", approvedCoverage);
  }
  const network = validateNetwork(input.invocation, input);
  if (!network.ok) return fail("scope-expansion", network.reason);
  const intersected = input.networkCeiling === undefined
    ? network.network
    : intersectNetworkScopes(network.network, input.networkCeiling);
  const networkScope = intersected.kind === "destinations" && network.network.kind === "destinations"
    ? Object.freeze({ kind: "destinations" as const, destinations: Object.freeze(intersected.destinations.map(destination => {
      const source = network.network.kind === "destinations"
        ? network.network.destinations.find(candidate => candidate.host === destination.host &&
          (candidate.port === undefined || destination.port === undefined || candidate.port === destination.port))?.source
        : undefined;
      return { ...destination, ...(source === undefined ? {} : { source }) };
    })) })
    : intersected;
  return compilePermissionPlan({
    baseline: input.baseline,
    runtimeFilesystem: input.runtimeFilesystem,
    approved: { filesystem: input.approved.filesystem },
    network: networkScope,
    metadataRead: input.metadataRead,
    protectedPaths: input.protectedPaths,
    protectedFilePaths: input.protectedFilePaths,
    sensitivePaths: input.sensitivePaths,
    protectedControlNames: input.protectedControlNames,
    resolvePath: input.resolvePath,
  });
}

/** Compile permission sources shared by Pi tools and the CodeMode runtime. */
export function compilePermissionPlan(
  input: CompilePermissionPlanInput,
): PlanCompileResult {
  for (const grant of [...input.baseline.filesystem, ...(input.runtimeFilesystem ?? []), ...input.approved.filesystem]) {
    if (!resolvePlanPath(grant.path, input.resolvePath)) {
      return fail("invalid-plan", `filesystem grant cannot be resolved: ${grant.path}`);
    }
    if ((grant.access !== "read" && grant.access !== "write") ||
        (grant.granularity !== "file" && grant.granularity !== "directory")) {
      return fail("invalid-plan", `filesystem grant is invalid: ${grant.path}`);
    }
  }
  const network = normalizeFinalNetworkScope(input.network);
  if (!network.ok) return fail("invalid-plan", network.reason);
  const filesystem = Object.freeze([
    ...normalizeGrants(input.baseline.filesystem, "baseline", input.resolvePath),
    ...normalizeGrants(input.runtimeFilesystem ?? [], "runtime", input.resolvePath),
    ...normalizeGrants(
      input.approved.filesystem,
      "approved-extension",
      input.resolvePath,
    ),
  ]);

  const protectedNames =
    input.protectedControlNames ?? PROTECTED_CONTROL_DIRECTORY_NAMES;
  const protectedPaths = new Set<string>();
  const protectedFiles = new Set<string>();
  const requiredProtectedPaths = new Set<string>();
  for (const path of [...(input.protectedPaths ?? []), ...(input.protectedFilePaths ?? [])]) {
    const resolved = resolvePlanPath(path, input.resolvePath);
    if (!resolved) return fail("invalid-plan", `required protected path cannot be resolved: ${path}`);
    protectedPaths.add(resolved);
    requiredProtectedPaths.add(resolved);
    if ((input.protectedFilePaths ?? []).includes(path)) protectedFiles.add(resolved);
  }
  for (const grant of filesystem) {
    if (grant.access !== "write") continue;
    if (grant.granularity === "directory") {
      for (const path of protectedPathsForGrant(grant.path, protectedNames)) {
        protectedPaths.add(path);
      }
    }
  }

  // Directory grants must not sit inside a protected control directory.
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

  const restrictions: ExecutionFilesystemRestriction[] = [];
  for (const path of [...protectedPaths].sort()) {
    let granularity: "file" | "directory" = protectedFiles.has(path) ? "file" : "directory";
    let identity: ExecutionFilesystemRestriction["identity"];
    try {
      const stats = statSync(path, { bigint: true });
      if (stats.isFile()) granularity = "file";
      else if (!stats.isDirectory()) return fail("invalid-plan", `protected path has an unsupported type: ${path}`);
      identity = { device: String(stats.dev), inode: String(stats.ino) };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT" && !requiredProtectedPaths.has(path)) {
        continue;
      }
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        return fail("invalid-plan", `protected path cannot be inspected: ${path}`);
      }
      return fail("invalid-plan", `required protected path does not exist: ${path}`);
    }
    restrictions.push({ path, access: "deny-write", granularity, source: "protection",
      ...(identity === undefined ? {} : { requestedPath: path, identity }) });
  }
  for (const sensitive of input.sensitivePaths ?? []) {
    const requestedPath = normalizeHostPath(sensitive.requestedPath);
    const path = normalizeHostPath(sensitive.path);
    const resolved = requestedPath ? resolvePlanPath(requestedPath, input.resolvePath) : null;
    if (!requestedPath || !path || !resolved || !isSamePath(resolved, path) ||
        (sensitive.granularity !== "file" && sensitive.granularity !== "directory") ||
        !/^\d+$/u.test(sensitive.identity.device) || !/^\d+$/u.test(sensitive.identity.inode)) {
      return fail("invalid-plan", `sensitive path identity is invalid: ${sensitive.requestedPath}`);
    }
    restrictions.push({ ...sensitive, access: "deny-access", source: "protection" });
  }

  const facts = {
    version: EXECUTION_PLAN_VERSION,
    filesystem: Object.freeze([...filesystem, ...restrictions]),
    network: network.scope,
    metadataRead: input.metadataRead ?? "none",
  } as const;
  const digest = jsonDigest(facts);
  const plan: ExecutionPlan = deepFreeze({
    ...facts,
    digest,
  });
  return { ok: true, plan };
}

function normalizeFinalNetworkScope(
  scope: NetworkScope,
): { readonly ok: true; readonly scope: NetworkScope } | { readonly ok: false; readonly reason: string } {
  if (scope.kind === "none" || scope.kind === "all") return { ok: true, scope: Object.freeze({ kind: scope.kind }) };
  if (scope.kind !== "destinations" || !Array.isArray(scope.destinations)) {
    return { ok: false, reason: "network scope is invalid" };
  }
  const normalized: NetworkDestination[] = [];
  for (const destination of scope.destinations) {
    const source = destination.source ?? "baseline";
    const result = normalizeNetworkDestinations([destination], source);
    if (!result.ok) return result;
    normalized.push(result.destinations[0]!);
  }
  const hostOnly = new Set(normalized.filter(destination => destination.port === undefined).map(destination => destination.host));
  const seen = new Set<string>();
  const destinations = normalized.filter(destination => {
    if (destination.port !== undefined && hostOnly.has(destination.host)) return false;
    const key = `${destination.host}\0${destination.port ?? "*"}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).sort((left, right) => left.host.localeCompare(right.host) || (left.port ?? 0) - (right.port ?? 0));
  return { ok: true, scope: Object.freeze({ kind: "destinations", destinations: Object.freeze(destinations) }) };
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

/** Capture bounded plain data without invoking accessors. */
function captureExecutionData(value: unknown): unknown | null {
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
    return copy(value, 0);
  } catch {
    return null;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function onlyKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).every(key => keys.includes(key));
}

function validNetworkScope(value: unknown): boolean {
  if (!isRecord(value)) return false;
  if (value.kind === "none" || value.kind === "all") return onlyKeys(value, ["kind"]);
  if (value.kind !== "destinations" || !onlyKeys(value, ["kind", "destinations"]) ||
      !Array.isArray(value.destinations)) return false;
  return value.destinations.every(destination => isRecord(destination) &&
    onlyKeys(destination, ["host", "port", "source"]) &&
    typeof destination.host === "string" && destination.host.length > 0 &&
    (destination.port === undefined || (Number.isInteger(destination.port) && Number(destination.port) > 0 && Number(destination.port) <= 65_535)) &&
    (destination.source === undefined || destination.source === "baseline" || destination.source === "approved-extension"));
}

function validExecutionPlan(value: unknown): value is ExecutionPlan {
  if (!isRecord(value) || !onlyKeys(value, ["version", "filesystem", "network", "metadataRead", "digest"]) ||
      value.version !== EXECUTION_PLAN_VERSION || !Array.isArray(value.filesystem) ||
      !validNetworkScope(value.network) || (value.metadataRead !== "none" && value.metadataRead !== "all") ||
      typeof value.digest !== "string" || !/^[0-9a-f]{64}$/u.test(value.digest)) return false;
  return value.filesystem.every(rule => {
    if (!isRecord(rule) || typeof rule.path !== "string" || !rule.path ||
        (rule.granularity !== "file" && rule.granularity !== "directory")) return false;
    if (rule.access === "read" || rule.access === "write") {
      return onlyKeys(rule, ["path", "access", "granularity", "source"]) &&
        (rule.source === "baseline" || rule.source === "approved-extension" || rule.source === "runtime");
    }
    return (rule.access === "deny-write" || rule.access === "deny-access") &&
      onlyKeys(rule, ["path", "access", "granularity", "source", "requestedPath", "identity"]) &&
      rule.source === "protection" &&
      (rule.requestedPath === undefined || typeof rule.requestedPath === "string") &&
      (rule.identity === undefined || (isRecord(rule.identity) && onlyKeys(rule.identity, ["device", "inode"]) &&
        typeof rule.identity.device === "string" && typeof rule.identity.inode === "string"));
  });
}

/** Capture a permission plan into a private copy; its digest is not a transport integrity check. */
export function captureExecutionPlan(value: unknown): ExecutionPlan | null {
  const captured = captureExecutionData(value);
  return validExecutionPlan(captured) ? deepFreeze(captured) : null;
}

/** Capture and validate the host request independently from its permission rules. */
export function captureExecutionRequest(value: unknown): ExecutionRequest | null {
  const captured = captureExecutionData(value);
  if (!isRecord(captured) || !onlyKeys(captured, ["plan", "requestId", "toolCallId", "actionDigest", "sessionId", "toolName",
    "mode", "policyRevision", "configRevision", "backendId", "start"])) return null;
  const plan = captureExecutionPlan(captured.plan);
  const start = captured.start;
  if (!plan || typeof captured.requestId !== "string" || !captured.requestId ||
      typeof captured.toolCallId !== "string" || !captured.toolCallId ||
      typeof captured.actionDigest !== "string" || !captured.actionDigest ||
      typeof captured.sessionId !== "string" || !captured.sessionId ||
      typeof captured.toolName !== "string" || !captured.toolName ||
      (captured.mode !== "default" && captured.mode !== "read-only" && captured.mode !== "auto-review" &&
        captured.mode !== "full-access") ||
      typeof captured.policyRevision !== "string" || !captured.policyRevision ||
      typeof captured.configRevision !== "string" || !captured.configRevision ||
      typeof captured.backendId !== "string" || !captured.backendId ||
      !isRecord(start) || !onlyKeys(start, ["cwd", "operation", "environment", "deadlineAt"]) ||
      typeof start.cwd !== "string" || !normalizeHostPath(start.cwd) || !isRecord(start.operation) ||
      !isRecord(start.environment) || !Number.isSafeInteger(start.deadlineAt) || Number(start.deadlineAt) <= 0 ||
      Object.values(start.environment).some(value => typeof value !== "string")) return null;
  return deepFreeze({ ...captured, plan } as unknown as ExecutionRequest);
}
