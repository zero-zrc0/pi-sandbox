/**
 * Normalize an error message for display. No prefix is added: a real
 * sandbox-policy error already identifies itself with its machine-readable
 * code (`permission:`, `sandbox-bypass:`, `sandbox-`), and a tool's own
 * failure must not be mislabeled as a sandbox error. The legacy
 * `[pi-sandbox-error] : ` marker is only stripped when present.
 */
const LEGACY_PI_SANDBOX_ERROR_PREFIX = "[pi-sandbox-error] : ";

export function formatPiSandboxError(message: unknown): string {
  const value = message instanceof Error ? message.message : String(message);
  const trimmed = value.trim();
  const detail = trimmed.startsWith(LEGACY_PI_SANDBOX_ERROR_PREFIX)
    ? trimmed.slice(LEGACY_PI_SANDBOX_ERROR_PREFIX.length).trimStart()
    : trimmed;
  return detail || "Unknown error";
}
