import type { EffectiveNode } from "./effective-nodes";

/**
 * Display-only metadata for the built-in approval nodes, shown in the
 * permission settings dialog. Custom nodes carry their own `description`
 * from the configuration instead.
 *
 * The decision node is the only front link that decides; the two shell-policy
 * entries are config switches for the adapters the decision node consults, not
 * chain nodes.
 */
export const BUILTIN_NODE_DESCRIPTIONS: Readonly<Record<string, string>> = {
  "builtin/structure-analysis": "Analyzes tool calls to understand command structure and access intent.",
  "builtin/identity": "Resolves the acting agent identity for policy evaluation.",
  "builtin/decision": "Runs the responsibility chain: facts once, then one composed decision.",
  "builtin/powershell": "Enables the shell-policy adapter for PowerShell commands.",
  "builtin/external-command": "Enables the shell-policy adapter for external commands.",
  "builtin/llm-approver": "Reviews requests with a configured LLM model.",
  "builtin/decision-approver": "Reviews requests with a local decision classifier.",
  "builtin/human": "Asks the user to approve or deny the request.",
  "builtin/review-debug": "Records approval-chain diagnostics without affecting decisions.",
};

/** One-line description of a node for display; custom nodes may override it. */
export function describeNode(node: Pick<EffectiveNode, "id" | "description">): string {
  return node.description ?? BUILTIN_NODE_DESCRIPTIONS[node.id] ?? "Custom approval node.";
}
