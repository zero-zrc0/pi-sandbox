import { BUILTIN_FRONT_NODES } from "#approve-core/contracts";
import type { ChainNode, NodeBinding } from "#approve-core/runtime";
import { BUILTIN_FRONT_PREFIX_NODES, BUILTIN_OPTIONAL_FRONT_NODES } from "#approve-core/node-ids";
import { createStructureAnalysisNode } from "#approve-core/nodes/analysis";
import { createIdentityNode, type IdentityNodeOptions } from "#approve-core/nodes/identity";
import { createRulesNode, type RulesNodeOptions } from "#approve-core/nodes/rules";
import { createAssessmentNode, type AssessmentNodeOptions } from "#approve-core/nodes/assessment";
import { createModeNode, type ModeNodeOptions } from "#approve-core/nodes/mode";

/**
 * The fixed front nodes and any enabled optional shell nodes, ready for the chain.
 *
 * Assembly lives beside the last front node so it can import the other four
 * without a cycle. The returned bindings are all `front` with `priority: null`;
 * `orderChainNodes` therefore keeps them ahead of every user node, including a
 * user node with a negative priority.
 */
export interface BuiltinFrontNodeOptions {
  readonly identity?: IdentityNodeOptions;
  readonly rules: RulesNodeOptions;
  readonly assessment: AssessmentNodeOptions;
  readonly mode: ModeNodeOptions;
  readonly powershell?: ChainNode;
  readonly externalCommand?: ChainNode;
}

export function createBuiltinFrontBindings(
  options: BuiltinFrontNodeOptions,
): readonly NodeBinding[] {
  if ((options.powershell !== undefined && options.powershell.id !== BUILTIN_OPTIONAL_FRONT_NODES[0]) ||
      (options.externalCommand !== undefined && options.externalCommand.id !== BUILTIN_OPTIONAL_FRONT_NODES[1])) {
    throw new Error("optional built-in front nodes do not match the frozen contract");
  }
  const optional = [options.powershell, options.externalCommand].filter(
    (node): node is ChainNode => node !== undefined,
  );
  const bindings: NodeBinding[] = [
    { node: createStructureAnalysisNode(), position: "front", priority: null },
    { node: createIdentityNode(options.identity), position: "front", priority: null },
    { node: createRulesNode(options.rules), position: "front", priority: null },
    { node: createAssessmentNode(options.assessment), position: "front", priority: null },
    ...optional.map((node) => ({ node, position: "front" as const, priority: null })),
    { node: createModeNode(options.mode), position: "front", priority: null },
  ];
  const optionalIds = optional.map((node) => node.id);
  let previousIndex = -1;
  for (const id of optionalIds) {
    const currentIndex = BUILTIN_OPTIONAL_FRONT_NODES.findIndex((candidate) => candidate === id);
    if (currentIndex <= previousIndex) {
      throw new Error("optional built-in front nodes do not match the frozen contract");
    }
    previousIndex = currentIndex;
  }
  const expected = [...BUILTIN_FRONT_PREFIX_NODES, ...optionalIds, "builtin/mode"];
  const actual = bindings.map((binding) => binding.node.id);
  if (actual.length !== expected.length || actual.some((id, index) => id !== expected[index])) {
    throw new Error("built-in front node order does not match the frozen contract");
  }
  return Object.freeze(bindings);
}
