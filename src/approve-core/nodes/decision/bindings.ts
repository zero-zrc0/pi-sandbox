/**
 * Front bindings of the responsibility chain: analysis, identity, decision.
 *
 * The three former decision nodes (`builtin/rules`, `builtin/assessment`,
 * `builtin/powershell`/`external-command`, `builtin/mode`) are now links inside
 * `builtin/decision`; their configured ids stay accepted by the config layer
 * until the cleanup stage so existing `approval.nodes` documents keep loading.
 *
 * The order is frozen here rather than derived from config: a user priority must
 * never move the chain behind a user node, and `orderChainNodes` keeps every
 * `front` binding ahead of the `user` section.
 */
import type { NodeBinding } from "#approve-core/runtime";
import { createStructureAnalysisNode } from "#approve-core/nodes/analysis";
import { createIdentityNode, type IdentityNodeOptions } from "#approve-core/nodes/identity";
import { createDecisionNode, type DecisionNodeOptions } from "#approve-core/nodes/decision";

/** Frozen front order of the responsibility chain. */
export const CHAIN_FRONT_NODE_IDS = [
  "builtin/structure-analysis",
  "builtin/identity",
  "builtin/decision",
] as const;

export interface ChainFrontNodeOptions {
  readonly identity?: IdentityNodeOptions;
  readonly decision: DecisionNodeOptions;
}

export function createChainFrontBindings(
  options: ChainFrontNodeOptions,
): readonly NodeBinding[] {
  const bindings: NodeBinding[] = [
    { node: createStructureAnalysisNode(), position: "front", priority: null },
    { node: createIdentityNode(options.identity), position: "front", priority: null },
    { node: createDecisionNode(options.decision), position: "front", priority: null },
  ];
  const actual = bindings.map((binding) => binding.node.id);
  if (
    actual.length !== CHAIN_FRONT_NODE_IDS.length ||
    actual.some((id, index) => id !== CHAIN_FRONT_NODE_IDS[index])
  ) {
    throw new Error("chain front node order does not match the frozen contract");
  }
  return Object.freeze(bindings);
}
