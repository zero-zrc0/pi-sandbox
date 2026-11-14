/**
 * Approval node host.
 *
 * `publish` loads the declared nodes through the same-process loader and
 * publishes one frozen generation; a later publish is the formal reload. The
 * previous generation's modules are disposed after the new one is installed,
 * and `dispose` releases the current modules. Publishes are serialized so a
 * reload cannot interleave with startup. No file watcher and no hot reload
 * are installed here.
 */
import type { EffectiveNode } from "#approve-core/contracts";
import type { NodeBinding } from "#approve-core/runtime";
import type {
  ApprovalNodeConfigView,
  ApprovalNodeLoadPlan,
  ApprovalPermissionQuery,
} from "../../sdk";
import {
  loadApprovalNodes,
  type LoadedApprovalNode,
  type LoadApprovalNodesInput,
  type NodeLoadWarning,
} from "#approve-core/node-loader/loader";

export interface ApprovalNodePublication {
  readonly generation: number;
  readonly publishedAt: number;
  readonly loaded: readonly LoadedApprovalNode[];
  readonly bindings: readonly NodeBinding[];
  readonly warnings: readonly NodeLoadWarning[];
  readonly effectiveNodes: readonly EffectiveNode[];
  readonly nodeConfig: ApprovalNodeConfigView;
  readonly configDigest: string;
  readonly models: Readonly<{ llmApprover: boolean; decisionApprover: boolean }>;
}

export interface PublishApprovalNodesInput {
  readonly plan: ApprovalNodeLoadPlan;
  readonly permissions: ApprovalPermissionQuery;
}

export interface PreparedApprovalNodePublication {
  readonly publication: ApprovalNodePublication;
  commit(): boolean;
  dispose(): Promise<readonly NodeLoadWarning[]>;
}

export interface ApprovalNodeHost {
  prepare(input: PublishApprovalNodesInput): Promise<PreparedApprovalNodePublication>;
  publish(input: PublishApprovalNodesInput): Promise<ApprovalNodePublication>;
  current(): ApprovalNodePublication | undefined;
  isCurrent(generation: number): boolean;
  /**
   * Release a non-current generation once no approval step uses it anymore.
   * The current generation is never released by this call.
   */
  release(generation: number): Promise<readonly NodeLoadWarning[]>;
  /** Dispose every live generation; returns disposal failures. */
  dispose(): Promise<readonly NodeLoadWarning[]>;
}

export interface ApprovalNodeHostOptions {
  importModule?: (url: string) => Promise<unknown>;
  now?: () => number;
  onWarning?: (warning: NodeLoadWarning, generation: number) => void;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validatePlan(plan: unknown): ApprovalNodeLoadPlan {
  if (!isRecord(plan)) throw new Error("invalid approval node load plan");
  if (!Array.isArray(plan.effectiveNodes)) {
    throw new Error("invalid approval node load plan: effectiveNodes");
  }
  if (!isRecord(plan.nodeConfig)) {
    throw new Error("invalid approval node load plan: nodeConfig");
  }
  for (const key of ["configDigest", "globalConfigDir", "projectConfigDir"] as const) {
    if (typeof plan[key] !== "string" || plan[key] === "") {
      throw new Error(`invalid approval node load plan: ${key}`);
    }
  }
  if (typeof plan.projectTrusted !== "boolean") {
    throw new Error("invalid approval node load plan: projectTrusted");
  }
  return plan as unknown as ApprovalNodeLoadPlan;
}

async function disposeModules(
  loaded: readonly LoadedApprovalNode[],
): Promise<NodeLoadWarning[]> {
  const warnings: NodeLoadWarning[] = [];
  for (const entry of loaded) {
    const dispose = entry.module.dispose;
    if (typeof dispose !== "function") continue;
    try {
      await dispose.call(entry.module);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      warnings.push(Object.freeze({
        code: "module-dispose-failed" as const,
        id: entry.id,
        path: entry.path,
        message: `module-dispose-failed: node '${entry.id}' did not dispose cleanly (${detail}) [${entry.resolvedPath}]`,
      }));
    }
  }
  return warnings;
}

function modelStates(nodes: readonly EffectiveNode[]): {
  llmApprover: boolean;
  decisionApprover: boolean;
} {
  return {
    llmApprover: nodes.find((node) => node.id === "builtin/llm-approver")?.enabled === true,
    decisionApprover: nodes.find((node) => node.id === "builtin/decision-approver")?.enabled === true,
  };
}

export function createApprovalNodeHost(
  options: ApprovalNodeHostOptions = {},
): ApprovalNodeHost {
  const importModule = options.importModule ?? ((url: string) => import(url));
  const now = options.now ?? Date.now;
  let disposed = false;
  let generation = 0;
  let current: ApprovalNodePublication | undefined;
  const live = new Map<number, readonly LoadedApprovalNode[]>();
  type CandidateState = {
    readonly publication: ApprovalNodePublication;
    readonly loaded: readonly LoadedApprovalNode[];
    readonly baseGeneration: number;
    state: "prepared" | "committed" | "disposed";
  };
  const candidates = new Set<CandidateState>();
  let queue: Promise<unknown> = Promise.resolve();

  function enqueue<T>(task: () => Promise<T>): Promise<T> {
    const run = queue.then(task, task);
    queue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  async function load(input: PublishApprovalNodesInput, nextGeneration: number): Promise<{
    readonly loaded: Awaited<ReturnType<typeof loadApprovalNodes>>;
    readonly publication: ApprovalNodePublication;
  }> {
    const plan = validatePlan(input?.plan);
    if (!isRecord(input?.permissions)) {
      throw new Error("invalid approval node load plan: permissions");
    }
    const loadInput: LoadApprovalNodesInput = {
        effectiveNodes: plan.effectiveNodes,
        nodeConfig: plan.nodeConfig,
        configDigest: plan.configDigest,
        globalConfigDir: plan.globalConfigDir,
        projectConfigDir: plan.projectConfigDir,
        projectTrusted: plan.projectTrusted,
        permissions: input.permissions,
        importModule,
        warn: (warning) => {
          options.onWarning?.(warning, nextGeneration);
        },
    };
    const loaded = await loadApprovalNodes(loadInput);
    const publication: ApprovalNodePublication = Object.freeze({
      generation: nextGeneration,
      publishedAt: now(),
      loaded: loaded.nodes,
      bindings: loaded.bindings,
      warnings: Object.freeze([...loaded.warnings]),
      effectiveNodes: plan.effectiveNodes,
      nodeConfig: plan.nodeConfig,
      configDigest: plan.configDigest,
      models: Object.freeze(modelStates(plan.effectiveNodes)),
    });
    return { loaded, publication };
  }

  function install(
    publication: ApprovalNodePublication,
    loaded: readonly LoadedApprovalNode[],
  ): void {
    generation = publication.generation;
    live.set(generation, loaded);
    current = publication;
  }

  async function prepare(input: PublishApprovalNodesInput): Promise<PreparedApprovalNodePublication> {
    if (disposed) throw new Error("approval node host is disposed");
    return enqueue(async () => {
      if (disposed) throw new Error("approval node host is disposed");
      const baseGeneration = generation;
      const candidate = await load(input, baseGeneration + 1);
      if (disposed) {
        await disposeModules(candidate.loaded.nodes);
        throw new Error("approval node host is disposed");
      }
      const state: CandidateState = {
        publication: candidate.publication,
        loaded: candidate.loaded.nodes,
        baseGeneration,
        state: "prepared",
      };
      candidates.add(state);
      return {
        publication: state.publication,
        commit() {
          if (state.state !== "prepared" || disposed || generation !== baseGeneration) return false;
          state.state = "committed";
          candidates.delete(state);
          install(state.publication, state.loaded);
          return true;
        },
        async dispose() {
          if (state.state !== "prepared") return [];
          state.state = "disposed";
          candidates.delete(state);
          return disposeModules(state.loaded);
        },
      };
    });
  }

  async function publish(input: PublishApprovalNodesInput): Promise<ApprovalNodePublication> {
    if (disposed) throw new Error("approval node host is disposed");
    return enqueue(async () => {
      if (disposed) throw new Error("approval node host is disposed");
      const candidate = await load(input, generation + 1);
      if (disposed) {
        await disposeModules(candidate.loaded.nodes);
        throw new Error("approval node host is disposed");
      }
      install(candidate.publication, candidate.loaded.nodes);
      return candidate.publication;
    });
  }

  function release(generationToRelease: number): Promise<readonly NodeLoadWarning[]> {
    return enqueue(async () => {
      if (current?.generation === generationToRelease) return [];
      const loaded = live.get(generationToRelease);
      if (loaded === undefined) return [];
      live.delete(generationToRelease);
      return disposeModules(loaded);
    });
  }

  function dispose(): Promise<readonly NodeLoadWarning[]> {
    if (disposed) return Promise.resolve([]);
    disposed = true;
    return enqueue(async () => {
      current = undefined;
      const warnings: NodeLoadWarning[] = [];
      for (const candidate of candidates) {
        candidate.state = "disposed";
        warnings.push(...await disposeModules(candidate.loaded));
      }
      candidates.clear();
      for (const loaded of live.values()) {
        warnings.push(...await disposeModules(loaded));
      }
      live.clear();
      return warnings;
    });
  }

  return {
    prepare,
    publish,
    current: () => current,
    isCurrent: (candidate: number) =>
      !disposed && current !== undefined && current.generation === candidate,
    release,
    dispose,
  };
}
