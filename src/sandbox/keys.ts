/**
 * One correlation key for a scoped id pair. Lifecycle task keys and captured
 * approval keys must use the same separator so they cannot drift apart.
 */
export function correlationKey(scope: string, id: string): string {
  return `${scope}\u0000${id}`;
}
