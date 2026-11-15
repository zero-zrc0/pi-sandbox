const PI_SANDBOX_ERROR_PREFIX = "[pi-sandbox-error] : ";

export function formatPiSandboxError(message: unknown): string {
  const value = message instanceof Error ? message.message : String(message);
  const trimmed = value.trim();
  const detail = trimmed.startsWith(PI_SANDBOX_ERROR_PREFIX)
    ? trimmed.slice(PI_SANDBOX_ERROR_PREFIX.length).trimStart()
    : trimmed;
  return `${PI_SANDBOX_ERROR_PREFIX}${detail || "Unknown error"}`;
}
