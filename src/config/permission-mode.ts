export const PERMISSION_MODES = Object.freeze([
  "read-only",
  "default",
  "auto-review",
  "full-access",
] as const);

export type PermissionModeName = (typeof PERMISSION_MODES)[number];
