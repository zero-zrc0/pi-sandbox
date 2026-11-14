import { freezeJson, jsonDigest, type JsonObject, type JsonValue } from "../json";
import {
  BUILTIN_FRONT_NODES,
  BUILTIN_FRONT_PREFIX_NODES,
  BUILTIN_DECISION_NODE,
  BUILTIN_MODEL_NODES,
  BUILTIN_OBSERVER_NODES,
  BUILTIN_OPTIONAL_FRONT_NODES,
  BUILTIN_TAIL_NODES,
} from "./node-ids";

const MAX_OPTIONS_BYTES = 64 * 1024;
export const MAX_NODE_ID_LENGTH = 200;

const BUILTIN_IDS: ReadonlySet<string> = new Set([
  ...BUILTIN_FRONT_NODES,
  ...BUILTIN_OPTIONAL_FRONT_NODES,
  ...BUILTIN_MODEL_NODES,
  ...BUILTIN_OBSERVER_NODES,
  ...BUILTIN_TAIL_NODES,
]);
const MODEL_IDS: ReadonlySet<string> = new Set(BUILTIN_MODEL_NODES);
const OPTIONAL_FRONT_IDS: ReadonlySet<string> = new Set(BUILTIN_OPTIONAL_FRONT_NODES);
const OBSERVER_IDS: ReadonlySet<string> = new Set(BUILTIN_OBSERVER_NODES);
const USER_NODE_KEYS = ["id", "path", "enabled", "priority", "kind", "options", "description"] as const;

export interface NodeConfigEntry {
  readonly id: string;
  readonly path?: string;
  readonly enabled?: boolean;
  readonly priority?: number;
  /** The link kind the user declared; absent means `restriction` (v4 §4). */
  readonly kind?: "restriction" | "grant";
  readonly options?: JsonObject;
  readonly description?: string;
}

export interface EffectiveNode {
  readonly id: string;
  readonly source: "builtin" | "global" | "project";
  readonly position: "front" | "user" | "post" | "observer";
  readonly order: number;
  readonly enabled: boolean;
  readonly path?: string;
  readonly priority: number | null;
  /** `null` for built-in nodes, which carry their kind in code. */
  readonly handlerKind?: "restriction" | "grant" | null;
  readonly options?: JsonObject;
  readonly description?: string;
}

export interface NodeConfigWarning {
  readonly code: "project-node-shadowed";
  readonly id: string;
}

export interface EffectiveNodeConfiguration {
  readonly nodes: readonly EffectiveNode[];
  readonly warnings: readonly NodeConfigWarning[];
  readonly digest: string;
}

export type DescribeNodesFailure =
  | "invalid-config"
  | "unknown-builtin-node"
  | "builtin-immutable"
  | "project-builtin-forbidden"
  | "invalid-user-node"
  | "duplicate-node-id";

export type DescribeEffectiveNodesResult =
  | { readonly ok: true; readonly configuration: EffectiveNodeConfiguration }
  | { readonly ok: false; readonly reason: DescribeNodesFailure };

interface ParsedUserNode {
  readonly kind: "user";
  readonly id: string;
  readonly path: string;
  readonly enabled: boolean;
  readonly priority: number;
  /** The declared link kind; `restriction` is the default (v4 §4). */
  readonly handlerKind: "restriction" | "grant";
  readonly options?: JsonObject;
  readonly description?: string;
  readonly declaredOrder: number;
}

interface ParsedBuiltinNode {
  readonly kind: "builtin";
  readonly id: string;
  readonly enabled: boolean;
}

type ParsedNode = ParsedUserNode | ParsedBuiltinNode;

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function nonEmptyString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value : undefined;
}

function isSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value);
}

function freezeTree<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freezeTree(child);
    Object.freeze(value);
  }
  return value;
}

function parseNodeEntry(
  value: unknown,
  source: "global" | "project",
  declaredOrder: number,
): { readonly ok: true; readonly node: ParsedNode } |
   { readonly ok: false; readonly reason: DescribeNodesFailure } {
  if (!isRecord(value)) return { ok: false, reason: "invalid-config" };
  const id = nonEmptyString(value.id);
  if (!id || id.length > MAX_NODE_ID_LENGTH) {
    return { ok: false, reason: "invalid-config" };
  }

  if (id.startsWith("builtin/")) {
    if (source === "project") return { ok: false, reason: "project-builtin-forbidden" };
    if (!BUILTIN_IDS.has(id)) return { ok: false, reason: "unknown-builtin-node" };
    if (!Object.keys(value).every((key) => key === "id" || key === "enabled")) {
      return { ok: false, reason: "builtin-immutable" };
    }
    if (value.enabled !== undefined && typeof value.enabled !== "boolean") {
      return { ok: false, reason: "builtin-immutable" };
    }
    const enabled = MODEL_IDS.has(id) || OPTIONAL_FRONT_IDS.has(id)
      ? value.enabled === true
      : value.enabled !== false;
    if (!MODEL_IDS.has(id) && !OPTIONAL_FRONT_IDS.has(id) && !OBSERVER_IDS.has(id) && !enabled) {
      return { ok: false, reason: "builtin-immutable" };
    }
    return { ok: true, node: { kind: "builtin", id, enabled } };
  }

  if (!Object.keys(value).every((key) =>
    (USER_NODE_KEYS as readonly string[]).includes(key))) {
    return { ok: false, reason: "invalid-user-node" };
  }
  const path = nonEmptyString(value.path);
  if (!path) return { ok: false, reason: "invalid-user-node" };
  const enabled = value.enabled === undefined ? true : value.enabled;
  if (typeof enabled !== "boolean") return { ok: false, reason: "invalid-user-node" };
  const priority = value.priority === undefined ? 0 : value.priority;
  if (!isSafeInteger(priority)) return { ok: false, reason: "invalid-user-node" };
  const declaredKind = value.kind;
  if (declaredKind !== undefined && declaredKind !== "restriction" && declaredKind !== "grant") {
    return { ok: false, reason: "invalid-user-node" };
  }
  const handlerKind = declaredKind === "grant" ? "grant" as const : "restriction" as const;
  let options: JsonObject | undefined;
  if (value.options !== undefined) {
    if (!isRecord(value.options)) return { ok: false, reason: "invalid-user-node" };
    try {
      if (new TextEncoder().encode(JSON.stringify(value.options)).byteLength > MAX_OPTIONS_BYTES) {
        return { ok: false, reason: "invalid-user-node" };
      }
    } catch {
      return { ok: false, reason: "invalid-user-node" };
    }
    options = value.options as JsonObject;
  }
  const description = value.description === undefined ? undefined : nonEmptyString(value.description);
  if (value.description !== undefined && description === undefined) {
    return { ok: false, reason: "invalid-user-node" };
  }
  return {
    ok: true,
    node: {
      kind: "user",
      id,
      path,
      enabled,
      priority,
      handlerKind,
      ...(options === undefined ? {} : { options }),
      ...(description === undefined ? {} : { description }),
      declaredOrder,
    },
  };
}

function composeEffectiveNodes(
  globalNodes: readonly unknown[],
  projectNodes: readonly unknown[],
): DescribeEffectiveNodesResult {
  const parsedGlobal: ParsedNode[] = [];
  const globalIds = new Set<string>();
  for (const [index, candidate] of globalNodes.entries()) {
    const parsed = parseNodeEntry(candidate, "global", index);
    if (!parsed.ok) return { ok: false, reason: parsed.reason };
    if (globalIds.has(parsed.node.id)) return { ok: false, reason: "duplicate-node-id" };
    globalIds.add(parsed.node.id);
    parsedGlobal.push(parsed.node);
  }

  const parsedProject: ParsedUserNode[] = [];
  const projectIds = new Set<string>();
  const warnings: NodeConfigWarning[] = [];
  for (const [index, candidate] of projectNodes.entries()) {
    if (isRecord(candidate)) {
      const id = nonEmptyString(candidate.id);
      if (id && !id.startsWith("builtin/") && globalIds.has(id)) {
        warnings.push({ code: "project-node-shadowed", id });
        continue;
      }
    }
    const parsed = parseNodeEntry(candidate, "project", index);
    if (!parsed.ok) return { ok: false, reason: parsed.reason };
    if (parsed.node.kind !== "user") {
      return { ok: false, reason: "project-builtin-forbidden" };
    }
    if (projectIds.has(parsed.node.id)) return { ok: false, reason: "duplicate-node-id" };
    projectIds.add(parsed.node.id);
    parsedProject.push(parsed.node);
  }

  const globalUsers = parsedGlobal.filter(
    (node): node is ParsedUserNode => node.kind === "user");
  const globalBuiltins = new Map(
    parsedGlobal
      .filter((node): node is ParsedBuiltinNode => node.kind === "builtin")
      .map((node) => [node.id, node.enabled]),
  );
  const users = [
    ...globalUsers.map((node) => ({ node, source: "global" as const })),
    ...parsedProject.map((node) => ({ node, source: "project" as const })),
  ].sort((left, right) => {
    if (left.node.priority !== right.node.priority) {
      return left.node.priority < right.node.priority ? -1 : 1;
    }
    if (left.source !== right.source) return left.source === "global" ? -1 : 1;
    return left.node.declaredOrder - right.node.declaredOrder;
  });

  const builtinNode = (
    id: string,
    position: "front" | "post" | "observer",
    enabled: boolean,
  ): EffectiveNode => freezeTree({
    id,
    source: "builtin" as const,
    position,
    order: 0,
    enabled,
    priority: null,
    handlerKind: null,
  });
  const ordered: EffectiveNode[] = [
    ...BUILTIN_FRONT_PREFIX_NODES.map((id) => builtinNode(id, "front", true)),
    ...BUILTIN_OPTIONAL_FRONT_NODES
      .filter((id) => globalBuiltins.has(id))
      .map((id) => builtinNode(id, "front", globalBuiltins.get(id) === true)),
    builtinNode(BUILTIN_DECISION_NODE, "front", true),
    ...users.map(({ node, source }) => freezeTree({
      id: node.id,
      source,
      position: "user" as const,
      order: 0,
      enabled: node.enabled,
      path: node.path,
      priority: node.priority,
      handlerKind: node.handlerKind,
      ...(node.options === undefined ? {} : { options: node.options }),
      ...(node.description === undefined ? {} : { description: node.description }),
    })),
    ...BUILTIN_MODEL_NODES.map((id) => builtinNode(
      id,
      "post",
      globalBuiltins.get(id) ?? (
        id === "builtin/llm-approver" && globalBuiltins.get("builtin/decision-approver") !== true
      ),
    )),
    ...BUILTIN_TAIL_NODES.map((id) => builtinNode(id, "post", true)),
    ...BUILTIN_OBSERVER_NODES
      .filter((id) => globalBuiltins.has(id))
      .map((id) => builtinNode(id, "observer", globalBuiltins.get(id) === true)),
  ];
  const nodes = ordered.map((node, order) => freezeTree({ ...node, order }));
  const facts = { nodes, warnings: freezeTree(warnings) };
  const configuration = freezeTree({
    ...facts,
    digest: jsonDigest(facts),
  });
  return { ok: true, configuration };
}

export function describeEffectiveNodes(
  globalNodes: readonly NodeConfigEntry[] = [],
  projectNodes: readonly NodeConfigEntry[] = [],
): DescribeEffectiveNodesResult {
  let data: JsonValue;
  try {
    data = freezeJson({ globalNodes, projectNodes });
  } catch {
    return { ok: false, reason: "invalid-config" };
  }
  if (!isRecord(data) ||
      Object.keys(data).length !== 2 ||
      !Object.prototype.hasOwnProperty.call(data, "globalNodes") ||
      !Object.prototype.hasOwnProperty.call(data, "projectNodes") ||
      !Array.isArray(data.globalNodes) ||
      !Array.isArray(data.projectNodes)) {
    return { ok: false, reason: "invalid-config" };
  }
  return composeEffectiveNodes(data.globalNodes, data.projectNodes);
}



