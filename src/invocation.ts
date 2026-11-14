import type { ToolAnnotations } from "@earendil-works/pi-coding-agent";
import { cloneFrozenJson } from "#approve-core/utils/tool-access/tool-definition";
import { canonicalJson, sha256Hex } from "#approve-core/policy/project-rules/types";
import type { PermissionScope, RegisteredToolFacts } from "./action";

type JsonObject = Readonly<Record<string, unknown>>;
const TYPEBOX_MARKERS = new Set(["~kind", "~optional", "~readonly"]);
const TOOL_NAMESPACE_KEYS = new Set(["name", "aliases", "description", "instructions"]);

export interface InvocationRequester {
  readonly sessionId: string;
  readonly agentName: string | null;
}

export type ToolExecutionBinding =
  | {
      readonly status: "bound";
      readonly owner: string;
      readonly toolName: string;
      readonly bindingId: string;
      readonly revision: string;
    }
  | { readonly status: "unavailable"; readonly reason: string }
  | { readonly status: "unbound"; readonly reason: string };

export interface ToolInvocationSeed {
  readonly tool: RegisteredToolFacts;
  readonly toolCallId: string;
  readonly parentToolCallId?: string;
  readonly effectiveArguments: JsonObject;
  readonly cwd: string;
  readonly requester: InvocationRequester;
  readonly environment: Readonly<Record<string, string>>;
}

export interface ToolInvocationAction {
  readonly requestId: string;
  readonly toolCallId: string;
  readonly parentToolCallId?: string;
  readonly tool: RegisteredToolFacts;
  readonly effectiveArguments: JsonObject;
  readonly cwd: string;
  readonly environment: Readonly<Record<string, string>>;
  readonly scopes: readonly PermissionScope[];
}

export interface ToolInvocationFacts {
  readonly action: ToolInvocationAction;
  readonly requester: InvocationRequester;
  readonly executionBinding: ToolExecutionBinding;
  readonly digest: string;
}

export interface CaptureToolInvocationSeedInput {
  readonly event: {
    readonly type: "tool_call";
    readonly toolName: string;
    readonly toolCallId: string;
    readonly parentToolCallId?: string;
    readonly input: unknown;
  };
  readonly registeredTools: readonly unknown[];
  readonly cwd: string;
  readonly requester: InvocationRequester;
  readonly environment: unknown;
}

export type CaptureToolInvocationSeedResult =
  | { readonly ok: true; readonly seed: ToolInvocationSeed }
  | { readonly ok: false; readonly reason: string };

export type FinalizeToolInvocationResult =
  | { readonly ok: true; readonly invocation: ToolInvocationFacts }
  | { readonly ok: false; readonly reason: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function freezeRecord(value: unknown): JsonObject | undefined {
  const copy = cloneFrozenJson(value);
  return copy.ok && isRecord(copy.value) ? copy.value : undefined;
}

function projectPiJsonObject(value: unknown): JsonObject | undefined {
  const ancestors = new Set<object>();

  function project(item: unknown): unknown {
    if (item === null || typeof item === "string" || typeof item === "boolean" ||
      (typeof item === "number" && Number.isFinite(item) && !Object.is(item, -0))) return item;
    if (typeof item !== "object" || ancestors.has(item)) throw new Error("invalid-schema-value");
    const array = Array.isArray(item);
    const prototype = Object.getPrototypeOf(item);
    if (array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) {
      throw new Error("invalid-schema-object");
    }
    if (Object.getOwnPropertySymbols(item).length > 0) throw new Error("symbol-schema-key");

    ancestors.add(item);
    try {
      const descriptors = Object.getOwnPropertyDescriptors(item);
      if (array) {
        if (Object.keys(descriptors).length !== item.length + 1) throw new Error("invalid-schema-array");
        const result: unknown[] = [];
        for (let index = 0; index < item.length; index += 1) {
          const descriptor = descriptors[String(index)];
          if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
            throw new Error("invalid-schema-array");
          }
          result.push(project(descriptor.value));
        }
        return result;
      }

      const result: Record<string, unknown> = Object.create(null);
      for (const key of Object.keys(descriptors).sort()) {
        const descriptor = descriptors[key]!;
        if (TYPEBOX_MARKERS.has(key)) {
          if (!("value" in descriptor) ||
            (key === "~kind" ? !nonEmpty(descriptor.value) : descriptor.value !== true)) {
            throw new Error("invalid-typebox-marker");
          }
          continue;
        }
        if (!descriptor.enumerable || !("value" in descriptor)) throw new Error("invalid-schema-property");
        result[key] = project(descriptor.value);
      }
      return result;
    } finally {
      ancestors.delete(item);
    }
  }

  try {
    const projected = project(value);
    const frozen = cloneFrozenJson(projected);
    return frozen.ok && isRecord(frozen.value) ? frozen.value : undefined;
  } catch {
    return undefined;
  }
}

function normalizeToolNamespace(value: unknown): RegisteredToolFacts["namespace"] | null {
  if (value === undefined) return undefined;
  const namespace = projectPiJsonObject(value);
  if (namespace === undefined || Object.keys(namespace).some((key) => !TOOL_NAMESPACE_KEYS.has(key))) return null;
  const name = namespace.name;
  const description = namespace.description;
  const instructions = namespace.instructions;
  if (!nonEmpty(name) || (description !== undefined && typeof description !== "string") ||
    (instructions !== undefined && typeof instructions !== "string")) return null;

  let aliases: readonly string[] | undefined;
  if (namespace.aliases !== undefined) {
    if (!Array.isArray(namespace.aliases)) return null;
    const normalized: string[] = [];
    for (const alias of namespace.aliases) {
      if (!nonEmpty(alias)) return null;
      normalized.push(alias);
    }
    aliases = Object.freeze(normalized);
  }

  return Object.freeze({
    name,
    ...(aliases === undefined ? {} : { aliases }),
    ...(description === undefined ? {} : { description }),
    ...(instructions === undefined ? {} : { instructions }),
  });
}

function invocationDigest(value: Omit<ToolInvocationFacts, "digest">): string {
  return sha256Hex(canonicalJson(value));
}

function registeredToolFacts(value: unknown): RegisteredToolFacts | undefined {
  if (!isRecord(value) || !nonEmpty(value.name) || typeof value.description !== "string") return undefined;
  if (!isRecord(value.sourceInfo)) return undefined;
  const sourceInfo = value.sourceInfo;
  if (
    !nonEmpty(sourceInfo.path) ||
    !nonEmpty(sourceInfo.source) ||
    !nonEmpty(sourceInfo.scope) ||
    !nonEmpty(sourceInfo.origin)
  ) return undefined;
  if (sourceInfo.baseDir !== undefined && !nonEmpty(sourceInfo.baseDir)) return undefined;

  const parameters = projectPiJsonObject(value.parameters);
  if (parameters === undefined) return undefined;
  let annotations: ToolAnnotations | undefined;
  if (value.annotations !== undefined) {
    const frozen = freezeRecord(value.annotations);
    if (frozen === undefined) return undefined;
    annotations = frozen as ToolAnnotations;
  }
  const namespaceDescriptor = Object.getOwnPropertyDescriptor(value, "namespace");
  if (namespaceDescriptor !== undefined && (!namespaceDescriptor.enumerable || !("value" in namespaceDescriptor))) return undefined;
  const namespace = normalizeToolNamespace(namespaceDescriptor?.value);
  if (namespace === null) return undefined;

  const origin = canonicalJson({
    path: sourceInfo.path,
    source: sourceInfo.source,
    scope: sourceInfo.scope,
    origin: sourceInfo.origin,
    ...(sourceInfo.baseDir === undefined ? {} : { baseDir: sourceInfo.baseDir }),
  });
  const definition = {
    name: value.name,
    description: value.description,
    parameters,
    ...(annotations === undefined ? {} : { annotations }),
    ...(namespace === undefined ? {} : { namespace }),
  };
  const revision = sha256Hex(canonicalJson(definition));
  return Object.freeze({ ...definition, origin, revision });
}

export function captureToolInvocationSeed(
  input: CaptureToolInvocationSeedInput,
): CaptureToolInvocationSeedResult {
  try {
    if (!isRecord(input) || !Array.isArray(input.registeredTools)) {
      return { ok: false, reason: "tool-registry-unavailable" };
    }
    const event = input.event;
    if (
      !isRecord(event) ||
      event.type !== "tool_call" ||
      !nonEmpty(event.toolName) ||
      !nonEmpty(event.toolCallId)
    ) return { ok: false, reason: "tool-call-invalid" };
    if (!nonEmpty(input.cwd)) return { ok: false, reason: "cwd-unavailable" };
    if (!isRecord(input.requester) || !nonEmpty(input.requester.sessionId) ||
      !(input.requester.agentName === null || typeof input.requester.agentName === "string")) {
      return { ok: false, reason: "requester-unavailable" };
    }

    const matching = input.registeredTools.filter((tool) => isRecord(tool) && tool.name === event.toolName);
    if (matching.length === 0) return { ok: false, reason: "tool-definition-unavailable" };
    if (matching.length !== 1) return { ok: false, reason: "tool-definition-ambiguous" };
    const tool = registeredToolFacts(matching[0]);
    if (tool === undefined) return { ok: false, reason: "tool-definition-invalid" };

    const effectiveArguments = freezeRecord(event.input);
    if (effectiveArguments === undefined) return { ok: false, reason: "tool-input-invalid" };
    if (event.parentToolCallId !== undefined && !nonEmpty(event.parentToolCallId)) {
      return { ok: false, reason: "parent-tool-call-invalid" };
    }
    if (!isRecord(input.environment)) return { ok: false, reason: "environment-invalid" };
    const environment: Record<string, string> = {};
    for (const [name, value] of Object.entries(input.environment)) {
      if (typeof value !== "string") return { ok: false, reason: "environment-invalid" };
      environment[name] = value;
    }

    return {
      ok: true,
      seed: Object.freeze({
        tool,
        toolCallId: event.toolCallId,
        ...(event.parentToolCallId === undefined ? {} : { parentToolCallId: event.parentToolCallId }),
        effectiveArguments,
        cwd: input.cwd,
        requester: Object.freeze({
          sessionId: input.requester.sessionId,
          agentName: input.requester.agentName,
        }),
        environment: Object.freeze(environment),
      }),
    };
  } catch {
    return { ok: false, reason: "invocation-capture-failed" };
  }
}

export function finalizeToolInvocation(
  seed: ToolInvocationSeed,
  input: {
    readonly requestId: string;
    readonly scopes: readonly PermissionScope[];
    readonly executionBinding: ToolExecutionBinding;
  },
): FinalizeToolInvocationResult {
  try {
    if (!isRecord(seed) || !isRecord(input) || !nonEmpty(input.requestId) || !Array.isArray(input.scopes)) {
      return { ok: false, reason: "invocation-finalization-invalid" };
    }
    const binding = input.executionBinding;
    if (!isRecord(binding)) return { ok: false, reason: "execution-binding-invalid" };
    if (binding.status === "bound") {
      if (!nonEmpty(binding.owner) || !nonEmpty(binding.toolName) || !nonEmpty(binding.bindingId) ||
        !nonEmpty(binding.revision) || binding.toolName !== seed.tool.name || binding.revision !== seed.tool.revision) {
        return { ok: false, reason: "execution-binding-mismatch" };
      }
    } else if (
      (binding.status === "unbound" || binding.status === "unavailable") &&
      nonEmpty(binding.reason)
    ) {
      if (binding.status === "unbound") {
        return { ok: false, reason: "execution-binding-unavailable" };
      }
    } else {
      return { ok: false, reason: "execution-binding-invalid" };
    }

    const scopes = input.scopes.map((scope) => {
      const frozen = freezeRecord(scope);
      if (frozen === undefined) throw new Error("invalid scope");
      return frozen as unknown as PermissionScope;
    });
    const frozenBinding = freezeRecord(binding);
    if (frozenBinding === undefined) return { ok: false, reason: "execution-binding-invalid" };
    const action: ToolInvocationAction = Object.freeze({
      requestId: input.requestId,
      toolCallId: seed.toolCallId,
      ...(seed.parentToolCallId === undefined ? {} : { parentToolCallId: seed.parentToolCallId }),
      tool: seed.tool,
      effectiveArguments: seed.effectiveArguments,
      cwd: seed.cwd,
      environment: seed.environment,
      scopes: Object.freeze(scopes),
    });
    const facts = {
      action,
      requester: seed.requester,
      executionBinding: frozenBinding as unknown as ToolExecutionBinding,
    };
    const invocation = Object.freeze({ ...facts, digest: invocationDigest(facts) });
    return { ok: true, invocation };
  } catch {
    return { ok: false, reason: "invocation-finalization-invalid" };
  }
}

export function toolInvocationDigestMatches(value: unknown): value is ToolInvocationFacts {
  try {
    if (!isRecord(value) || typeof value.digest !== "string" || !isRecord(value.action) ||
      !isRecord(value.requester) || !isRecord(value.executionBinding)) return false;
    const { digest, ...facts } = value;
    return invocationDigest(facts as Omit<ToolInvocationFacts, "digest">) === digest;
  } catch {
    return false;
  }
}
