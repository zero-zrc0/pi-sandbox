/**
 * Same-process node loader.
 *
 * It loads only the node paths explicitly declared in the effective config,
 * resolves relative paths against the directory of the declaring config file,
 * checks the module/node API version, id and evaluate entry, and warns-and-skips
 * invalid declarations. It never scans a fixed nodes directory, never fetches
 * remotely and never installs anything. Node code runs in the same process:
 * this is not an isolation boundary.
 */
import { isAbsolute, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import type { EffectiveNode } from "#approve-core/contracts";
import type { ChainNode, NodeBinding } from "#approve-core/runtime";
import type {
  ApprovalNodeConfigView,
  ApprovalNodeContext,
  ApprovalNodeModule,
  ApprovalPermissionQuery,
} from "../../sdk";
import { freezeJson, type JsonObject } from "../../json";

export type NodeLoadWarningCode =
  | "module-load-failed"
  | "module-api-version"
  | "module-shape"
  | "node-factory-failed"
  | "node-api-version"
  | "node-id-mismatch"
  | "node-shape"
  | "invalid-options"
  | "duplicate-node-id"
  | "module-dispose-failed";

export interface NodeLoadWarning {
  readonly code: NodeLoadWarningCode;
  readonly id: string;
  readonly path?: string;
  readonly message: string;
}

export interface LoadedApprovalNode {
  readonly id: string;
  readonly source: "global" | "project";
  readonly priority: number;
  /** The declared path exactly as written in the config file. */
  readonly path: string;
  /** The resolved file path handed to the module importer. */
  readonly resolvedPath: string;
  readonly options: JsonObject;
  readonly node: ChainNode;
  readonly module: ApprovalNodeModule;
}

export interface LoadApprovalNodesInput {
  readonly effectiveNodes: readonly EffectiveNode[];
  readonly nodeConfig: ApprovalNodeConfigView;
  readonly configDigest: string;
  readonly globalConfigDir: string;
  readonly projectConfigDir: string;
  readonly projectTrusted: boolean;
  readonly permissions?: ApprovalPermissionQuery;
  readonly importModule?: (url: string) => Promise<unknown>;
  readonly warn?: (warning: NodeLoadWarning) => void;
}

export interface LoadApprovalNodesResult {
  readonly nodes: readonly LoadedApprovalNode[];
  readonly bindings: readonly NodeBinding[];
  readonly warnings: readonly NodeLoadWarning[];
  readonly skippedDisabledIds: readonly string[];
  readonly configDigest: string;
}

/**
 * Conservative query used when the host does not inject the existing
 * permission service. It never grants; nodes that need real facts are handed
 * the host query by the host.
 */
const UNAVAILABLE_PERMISSION_QUERY: ApprovalPermissionQuery = Object.freeze({
  checkPermission: () => Object.freeze({ state: "ask" as const, origin: "unavailable" }),
  getToolPermission: () => "ask" as const,
});

function defaultImportModule(url: string): Promise<unknown> {
  return import(url);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function freezeOptions(value: unknown): JsonObject | undefined {
  if (value === undefined) return freezeJson({}) as JsonObject;
  try {
    const frozen = freezeJson(value);
    return isRecord(frozen) ? (frozen as JsonObject) : undefined;
  } catch {
    return undefined;
  }
}

function unwrapModule(namespace: unknown): unknown {
  if (isRecord(namespace) && "default" in namespace) {
    const candidate = namespace.default;
    if (isRecord(candidate)) return candidate;
  }
  return namespace;
}

export async function loadApprovalNodes(
  input: LoadApprovalNodesInput,
): Promise<LoadApprovalNodesResult> {
  const warnings: NodeLoadWarning[] = [];
  const nodes: LoadedApprovalNode[] = [];
  const skippedDisabledIds: string[] = [];
  const declaredIds = new Set<string>();
  const importModule = input.importModule ?? defaultImportModule;
  const permissions = input.permissions ?? UNAVAILABLE_PERMISSION_QUERY;
  const effectiveNodes = Array.isArray(input.effectiveNodes) ? input.effectiveNodes : [];

  const report = (warning: NodeLoadWarning): void => {
    warnings.push(warning);
    input.warn?.(warning);
  };
  const skip = (
    node: EffectiveNode,
    code: NodeLoadWarningCode,
    resolvedPath: string | undefined,
    detail: string,
  ): void => {
    report({
      code,
      id: node.id,
      ...(node.path === undefined ? {} : { path: node.path }),
      message: `${code}: node '${node.id}' was skipped (${detail})${resolvedPath === undefined ? "" : ` [${resolvedPath}]`}`,
    });
  };

  for (const node of effectiveNodes) {
    if (node.position !== "user") continue;
    if (node.enabled === false) {
      skippedDisabledIds.push(node.id);
      continue;
    }
    if (node.source === "project" && !input.projectTrusted) continue;
    if (declaredIds.has(node.id)) {
      skip(node, "duplicate-node-id", undefined, "an earlier declaration with this id wins");
      continue;
    }
    declaredIds.add(node.id);
    if (typeof node.path !== "string" || node.path.length === 0) {
      skip(node, "node-shape", undefined, "a user node must declare a path");
      continue;
    }

    const baseDir = node.source === "global" ? input.globalConfigDir : input.projectConfigDir;
    const resolvedPath = isAbsolute(node.path) ? node.path : resolve(baseDir, node.path);
    const url = pathToFileURL(resolvedPath).href;

    let namespace: unknown;
    try {
      namespace = await importModule(url);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      skip(node, "module-load-failed", resolvedPath, detail);
      continue;
    }

    const rawModule = unwrapModule(namespace);
    if (!isRecord(rawModule)) {
      skip(node, "module-shape", resolvedPath, "the module has no object export");
      continue;
    }
    if (rawModule.apiVersion !== "1") {
      skip(node, "module-api-version", resolvedPath, "expected apiVersion '1'");
      continue;
    }
    const createNode = rawModule.createNode;
    if (typeof createNode !== "function") {
      skip(node, "module-shape", resolvedPath, "the module has no createNode function");
      continue;
    }

    const options = freezeOptions(node.options);
    if (options === undefined) {
      skip(node, "invalid-options", resolvedPath, "node options are not a JSON object");
      continue;
    }
    const context: ApprovalNodeContext = Object.freeze({
      id: node.id,
      options,
      config: input.nodeConfig,
      permissions,
    });

    let candidate: unknown;
    try {
      candidate = await (createNode as (this: unknown, value: ApprovalNodeContext) => unknown).call(
        rawModule,
        context,
      );
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      skip(node, "node-factory-failed", resolvedPath, detail);
      continue;
    }
    if (!isRecord(candidate)) {
      skip(node, "node-shape", resolvedPath, "createNode did not return a node object");
      continue;
    }
    if (candidate.apiVersion !== "1") {
      skip(node, "node-api-version", resolvedPath, "the node must report apiVersion '1'");
      continue;
    }
    if (typeof candidate.evaluate !== "function") {
      skip(node, "node-shape", resolvedPath, "the node has no evaluate function");
      continue;
    }
    if (candidate.id !== node.id) {
      skip(node, "node-id-mismatch", resolvedPath, `the node reports id '${String(candidate.id)}'`);
      continue;
    }

    const chainNode: ChainNode = Object.freeze({
      apiVersion: "1" as const,
      id: node.id,
      evaluate: (candidate.evaluate as ChainNode["evaluate"]).bind(candidate),
    });
    nodes.push(Object.freeze({
      id: node.id,
      source: node.source,
      priority: node.priority ?? 0,
      path: node.path,
      resolvedPath,
      options,
      node: chainNode,
      module: rawModule as unknown as ApprovalNodeModule,
    }));
  }

  const bindings = Object.freeze(nodes.map((loaded): NodeBinding => Object.freeze({
    node: loaded.node,
    position: "user" as const,
    priority: loaded.priority,
  })));

  return Object.freeze({
    nodes: Object.freeze(nodes),
    bindings,
    warnings: Object.freeze(warnings),
    skippedDisabledIds: Object.freeze(skippedDisabledIds),
    configDigest: input.configDigest,
  });
}
