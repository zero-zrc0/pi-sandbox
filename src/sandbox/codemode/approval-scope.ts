import { AsyncLocalStorage } from "node:async_hooks";

interface ApprovedCodemodeScope {
  readonly sessionId: string;
  readonly isCurrent: () => boolean;
}

const approvedScope = new AsyncLocalStorage<ApprovedCodemodeScope>();

/** Run nested tools under the already-approved outer Codemode call. */
export function runWithApprovedCodemode<T>(
  sessionId: string,
  isCurrent: () => boolean,
  execute: () => Promise<T>,
): Promise<T> {
  return approvedScope.run({ sessionId, isCurrent }, execute);
}

/** True only while the outer approval belongs to this session and remains valid. */
export function hasApprovedCodemodeScope(sessionId: string): boolean {
  const scope = approvedScope.getStore();
  return scope?.sessionId === sessionId && scope.isCurrent();
}
