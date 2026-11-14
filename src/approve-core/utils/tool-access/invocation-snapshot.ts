/**
 * Tool invocation capture and shell capability re-validation
 * (specs/tool-access.md §1/§9).
 *
 * Capture keeps the public definition, the final JSON arguments and the cwd.
 * It never guesses a tool by name: an unresolved or ambiguous definition is an
 * incomplete capture, and an inherited call whose expected identity differs is
 * unbound. Shell capabilities are re-validated here because a binding may not
 * assert its own execution proof: the capability must be a strict frozen
 * object whose action digest, tool name and registration revision all match
 * the current call.
 */
import { canonicalJson, sha256Hex } from "#approve-core/policy/project-rules/types";
import {
  cloneFrozenJson,
  normalizeToolDefinition,
  type ToolDefinition,
  type ToolIdentity,
} from "./tool-definition";

/** Identity of one bound execution; every shell proof names these four facts. */
export interface ShellAssessmentIdentity {
  readonly owner: string;
  readonly toolName: string;
  readonly revision: string;
  readonly bindingId: string;
}

/** Facts captured for one invocation before extraction or assessment. */
export interface AssessmentInvocationCapture {
  readonly tool: ToolDefinition;
  readonly arguments: Readonly<Record<string, unknown>>;
  readonly argumentsDigest: string;
  readonly cwd: string;
}

/** The only context an extractor receives: the tool, its input and the cwd. */
export interface AssessmentInvocationContext {
  readonly tool: ToolDefinition;
  readonly input: Readonly<Record<string, unknown>>;
  readonly cwd: string;
}

export type AssessmentInvocationCaptureResult =
  | { readonly status: "captured"; readonly capture: AssessmentInvocationCapture }
  | { readonly status: "incomplete"; readonly reason: string }
  | { readonly status: "unbound"; readonly reason: string };

/** A shell capability that survived the action-bound re-validation. */
export interface ValidatedShellSandboxCapability {
  readonly available: boolean;
  readonly enforcesAllLimits: boolean;
  readonly boundary: string;
  readonly actionDigest: string;
  readonly executionBinding: ShellAssessmentIdentity & { readonly status?: "bound" };
  readonly reason?: string;
}

const CAPABILITY_KEYS = ["available", "enforcesAllLimits", "boundary", "actionDigest", "executionBinding", "reason"] as const;
const BINDING_KEYS = ["status", "owner", "toolName", "bindingId", "revision"] as const;
const EXPECTED_TOOL_KEYS = ["identity", "name", "origin", "revision"] as const;

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasOnlyKeys(record: Record<string, unknown>, allowed: readonly string[]): boolean {
  return Object.keys(record).every((key) => allowed.includes(key));
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function incomplete(reason: string): AssessmentInvocationCaptureResult {
  return { status: "incomplete", reason };
}

function resolveCwd(raw: Record<string, unknown>, cwd: string): string | undefined {
  if (typeof cwd === "string" && cwd.trim().length > 0) return cwd.trim();
  const fallback = raw.cwd;
  if (nonEmptyString(fallback)) return fallback.trim();
  return undefined;
}

/**
 * Resolve exactly one definition. A bare tool name is never turned into a
 * synthetic definition: the caller must either pass the captured definition or
 * a registry in which the name resolves uniquely.
 */
function resolveToolDefinition(raw: Record<string, unknown>): ToolDefinition | string {
  if (raw.tool !== undefined) {
    return normalizeToolDefinition(raw.tool) ?? "tool-definition-unavailable";
  }
  const toolName = raw.toolName;
  if (!nonEmptyString(toolName)) return "tool-definition-unavailable";
  const registry = raw.registeredTools ?? raw.tools;
  if (!Array.isArray(registry)) return "tool-definition-unavailable";
  const candidates = registry
    .map((entry) => normalizeToolDefinition(entry))
    .filter((entry): entry is ToolDefinition => entry !== undefined && entry.identity.name === toolName);
  if (candidates.length === 0) return "tool-definition-unavailable";
  if (candidates.length > 1) return "tool-definition-ambiguous";
  return candidates[0] as ToolDefinition;
}

function readExpectedIdentity(value: unknown): ToolIdentity | undefined {
  if (!isPlainRecord(value) || !hasOnlyKeys(value, EXPECTED_TOOL_KEYS)) return undefined;
  const candidate = isPlainRecord(value.identity) ? value.identity : value;
  if (!isPlainRecord(candidate)) return undefined;
  const name = candidate.name;
  const origin = candidate.origin;
  const revision = candidate.revision;
  if (!nonEmptyString(name) || !nonEmptyString(origin) || !nonEmptyString(revision)) return undefined;
  return Object.freeze({ name, origin, revision });
}

/**
 * Capture one invocation. `expectedTool` is the identity an inherited call
 * expects; a mismatch of any component makes the capture unbound.
 */
export function captureToolInvocation(
  raw: unknown,
  cwd: string,
  expectedTool?: unknown,
): AssessmentInvocationCaptureResult {
  try {
    return captureInvocation(raw, cwd, expectedTool);
  } catch {
    // Capture must fail closed on hostile values instead of throwing into the host.
    return incomplete("capture-unavailable");
  }
}

function captureInvocation(
  raw: unknown,
  cwd: string,
  expectedTool: unknown,
): AssessmentInvocationCaptureResult {
  if (!isPlainRecord(raw)) return incomplete("tool-definition-unavailable");

  const captureCwd = resolveCwd(raw, cwd);
  if (captureCwd === undefined) return incomplete("cwd-unavailable");

  const tool = resolveToolDefinition(raw);
  if (typeof tool === "string") return incomplete(tool);

  if (expectedTool !== undefined) {
    const expected = readExpectedIdentity(expectedTool);
    if (expected === undefined) return incomplete("expected-tool-unavailable");
    if (expected.name !== tool.identity.name || expected.origin !== tool.identity.origin ||
      expected.revision !== tool.identity.revision) {
      return { status: "unbound", reason: "expected-tool-mismatch" };
    }
  }

  const input = raw.input !== undefined ? raw.input : raw.arguments;
  const frozen = cloneFrozenJson(input);
  if (!frozen.ok || !isPlainRecord(frozen.value)) return incomplete("input-unavailable");

  const argumentsValue = frozen.value;
  return Object.freeze({
    status: "captured",
    capture: Object.freeze({
      tool,
      arguments: argumentsValue,
      argumentsDigest: sha256Hex(canonicalJson(argumentsValue)),
      cwd: captureCwd,
    }),
  });
}

/**
 * Re-validate the host's shell capability against the current call. Anything
 * unreadable, unfreezable, extra or bound to a different action/tool/revision
 * is treated as "no capability".
 */
export function validateShellSandboxCapability(
  sandbox: unknown,
  actionDigest: string,
  toolName: string,
  registrationRevision: string,
): ValidatedShellSandboxCapability | undefined {
  try {
    return validateCapability(sandbox, actionDigest, toolName, registrationRevision);
  } catch {
    // A capability that cannot even be read is not a capability.
    return undefined;
  }
}

function validateCapability(
  sandbox: unknown,
  actionDigest: string,
  toolName: string,
  registrationRevision: string,
): ValidatedShellSandboxCapability | undefined {
  if (!isPlainRecord(sandbox) || !hasOnlyKeys(sandbox, CAPABILITY_KEYS)) return undefined;

  const available = sandbox.available;
  const enforcesAllLimits = sandbox.enforcesAllLimits;
  const boundary = sandbox.boundary;
  const digest = sandbox.actionDigest;
  const reason = sandbox.reason;
  if (typeof available !== "boolean" || typeof enforcesAllLimits !== "boolean") return undefined;
  if (typeof boundary !== "string") return undefined;
  if (!nonEmptyString(digest)) return undefined;
  if (reason !== undefined && typeof reason !== "string") return undefined;
  if (digest !== actionDigest) return undefined;

  const binding = sandbox.executionBinding;
  if (!isPlainRecord(binding) || !hasOnlyKeys(binding, BINDING_KEYS)) return undefined;
  const status = binding.status;
  if (status !== undefined && status !== "bound") return undefined;
  const owner = binding.owner;
  const bindingToolName = binding.toolName;
  const bindingId = binding.bindingId;
  const revision = binding.revision;
  if (!nonEmptyString(owner) || !nonEmptyString(bindingToolName) || !nonEmptyString(bindingId) ||
    !nonEmptyString(revision)) {
    return undefined;
  }
  // The binding must cover exactly this call: a different tool or registration
  // revision is not a proof for it.
  if (bindingToolName !== toolName || revision !== registrationRevision) return undefined;

  const executionBinding = Object.freeze({
    ...(status === undefined ? {} : { status }),
    owner,
    toolName: bindingToolName,
    revision,
    bindingId,
  });
  return Object.freeze({
    available,
    enforcesAllLimits,
    boundary,
    actionDigest: digest,
    executionBinding,
    ...(reason === undefined ? {} : { reason }),
  });
}
