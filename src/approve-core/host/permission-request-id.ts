/**
 * Permission request identity (specs/host-integration.md §1).
 *
 * A permission request id is not the host tool call id: one tool call can
 * visit several gates and produce several permission requests, so every
 * request mints its own UUID. The source is injectable for tests and audits.
 */
import { randomUUID } from "node:crypto";

/** The prefix every permission request id carries. */
export const PERMISSION_REQUEST_ID_PREFIX = "perm-";

/** The UUID source the id generator draws from; production uses crypto.randomUUID. */
export interface PermissionRequestIdSource {
  readonly randomUUID: () => string;
}

/** One fresh id per call: `perm-<uuid>`. Throws when the source yields an empty string. */
export function createPermissionRequestId(
  source?: Partial<PermissionRequestIdSource>,
): string {
  const generate = source?.randomUUID ?? randomUUID;
  const value = generate();
  if (typeof value !== "string") {
    throw new Error("permission request id source must return a string");
  }
  const trimmed = value.trim();
  if (trimmed === "") {
    throw new Error("permission request id source returned an empty id");
  }
  return `${PERMISSION_REQUEST_ID_PREFIX}${trimmed}`;
}

/** True for `perm-` followed by at least one character. */
export function isPermissionRequestId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.startsWith(PERMISSION_REQUEST_ID_PREFIX) &&
    value.length > PERMISSION_REQUEST_ID_PREFIX.length
  );
}
