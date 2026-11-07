/**
 * Safe system devices.
 *
 * Four device paths are exempt from external-directory treatment, and
 * `/dev/null` is the only device whose writes are provably discarded.
 */

export const SAFE_DEVICES = [
  "/dev/null",
  "/dev/stdin",
  "/dev/stdout",
  "/dev/stderr",
] as const;

export const DISCARD_DEVICE = "/dev/null";

/** True when the path is one of the four safe devices (exact spelling). */
export function isSafeDevice(path: string): boolean {
  return (SAFE_DEVICES as readonly string[]).includes(path);
}

/**
 * True when writes to the path are provably discarded without touching a
 * file. Only the exact `/dev/null` spelling qualifies: stdout/stderr may be
 * reopened behind a redirect, so they get no write exemption.
 */
export function isDiscardDevice(path: string): boolean {
  return path === DISCARD_DEVICE;
}
