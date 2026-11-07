import type { EffectiveNode } from "./effective-nodes";

/**
 * Display-only metadata for the built-in approval nodes, shown in the
 * permission settings dialog. Custom nodes carry their own `description`
 * from the configuration instead.
 */
export const BUILTIN_NODE_DESCRIPTIONS: Readonly<Record<string, string>> = {
  "builtin/structure-analysis": "Analyzes tool calls to understand command structure and access intent.",
  "builtin/identity": "Resolves the acting agent identity for policy evaluation.",
  "builtin/rules": "Matches configured permission rules against the request.",
  "builtin/assessment": "Assesses request risk and local side effects.",
  "builtin/powershell": "Reviews PowerShell commands against the shell policy.",
  "builtin/external-command": "Reviews external command execution against the shell policy.",
  "builtin/mode": "Enforces the active permission mode (read-only, default, auto-review, full-access).",
  "builtin/llm-approver": "Reviews requests with a configured LLM model.",
  "builtin/decision-approver": "Reviews requests with a local decision classifier.",
  "builtin/human": "Asks the user to approve or deny the request.",
};

/** One-line description of a node for display; custom nodes may override it. */
export function describeNode(node: Pick<EffectiveNode, "id" | "description">): string {
  return node.description ?? BUILTIN_NODE_DESCRIPTIONS[node.id] ?? "Custom approval node.";
}
