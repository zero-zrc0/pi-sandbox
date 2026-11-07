export const BUILTIN_FRONT_PREFIX_NODES = [
  "builtin/structure-analysis",
  "builtin/identity",
  "builtin/rules",
  "builtin/assessment",
] as const;

export const BUILTIN_OPTIONAL_FRONT_NODES = [
  "builtin/powershell",
  "builtin/external-command",
] as const;

export const BUILTIN_MODE_NODE = "builtin/mode" as const;

export const BUILTIN_FRONT_NODES = [
  ...BUILTIN_FRONT_PREFIX_NODES,
  BUILTIN_MODE_NODE,
] as const;

export const BUILTIN_MODEL_NODES = [
  "builtin/llm-approver",
  "builtin/decision-approver",
] as const;

export const BUILTIN_TAIL_NODES = ["builtin/human"] as const;
