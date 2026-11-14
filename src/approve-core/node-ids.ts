export const BUILTIN_FRONT_PREFIX_NODES = [
  "builtin/structure-analysis",
  "builtin/identity",
] as const;

/**
 * Config-only switches for the two shell-policy adapters. They are not chain
 * nodes: they select which adapter the decision node may consult, so the config
 * keeps accepting the ids while the chain has no node by those names.
 */
export const BUILTIN_OPTIONAL_FRONT_NODES = [
  "builtin/powershell",
  "builtin/external-command",
] as const;

/** The single front decision node: facts once, one responsibility chain, one batch. */
export const BUILTIN_DECISION_NODE = "builtin/decision" as const;

export const BUILTIN_FRONT_NODES = [
  ...BUILTIN_FRONT_PREFIX_NODES,
  BUILTIN_DECISION_NODE,
] as const;

export const BUILTIN_MODEL_NODES = [
  "builtin/llm-approver",
  "builtin/decision-approver",
] as const;

export const BUILTIN_TAIL_NODES = ["builtin/human"] as const;

export const BUILTIN_REVIEW_DEBUG_NODE = "builtin/review-debug" as const;
export const BUILTIN_OBSERVER_NODES = [BUILTIN_REVIEW_DEBUG_NODE] as const;
