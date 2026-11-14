export interface BubblewrapCandidate {
  readonly path: string;
  readonly version: string;
}

export function findSystemBubblewrap(
  pathValue: string | undefined,
  workspaceRoot: string | undefined,
): string | undefined;

export function resolveSystemBubblewrap(
  candidatePath: string | undefined,
  workspaceRoot: string | undefined,
): string | undefined;

export function selectBubblewrapCandidate(
  systemPath: string | undefined,
  bundledPath: BubblewrapCandidate | undefined,
  probe: (path: string, expectedVersion?: string) => string | undefined,
): BubblewrapCandidate | undefined;
