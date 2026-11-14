export interface RuntimeCandidate {
  readonly version: string;
  readonly stable: boolean;
  readonly platform: string;
  readonly arch: string;
  readonly protocolVersion: number;
  readonly minPluginVersion: string;
  readonly maxPluginVersionExclusive: string;
  readonly source?: "manual" | "managed";
}

export type RuntimeSelection<TInstalled extends RuntimeCandidate = RuntimeCandidate, TRelease extends RuntimeCandidate = RuntimeCandidate> =
  | { readonly kind: "installed"; readonly runtime: TInstalled }
  | { readonly kind: "download"; readonly release: TRelease }
  | { readonly kind: "unavailable"; readonly reason: string };

interface RuntimeSelectionInput<TInstalled extends RuntimeCandidate, TRelease extends RuntimeCandidate> {
  readonly platform: string;
  readonly arch: string;
  readonly pluginVersion: string;
  readonly protocolVersion: number;
  readonly installed: readonly TInstalled[];
  readonly releases: readonly TRelease[];
}

function stableVersion(value: string): readonly [number, number, number] | undefined {
  const match = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u.exec(value);
  if (!match) return undefined;
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

export function compareRuntimeVersions(left: string, right: string): number | undefined {
  const leftParts = stableVersion(left);
  const rightParts = stableVersion(right);
  if (!leftParts || !rightParts) return undefined;
  for (let index = 0; index < leftParts.length; index += 1) {
    if (leftParts[index] !== rightParts[index]) return leftParts[index]! - rightParts[index]!;
  }
  return 0;
}

function compatible(candidate: RuntimeCandidate, input: RuntimeSelectionInput<RuntimeCandidate, RuntimeCandidate>): boolean {
  if (
    !candidate.stable ||
    candidate.platform !== input.platform ||
    candidate.arch !== input.arch ||
    candidate.protocolVersion !== input.protocolVersion
  ) return false;
  const pluginAtLeastMinimum = compareRuntimeVersions(input.pluginVersion, candidate.minPluginVersion);
  const pluginBeforeMaximum = compareRuntimeVersions(input.pluginVersion, candidate.maxPluginVersionExclusive);
  return pluginAtLeastMinimum !== undefined && pluginAtLeastMinimum >= 0 &&
    pluginBeforeMaximum !== undefined && pluginBeforeMaximum < 0 &&
    stableVersion(candidate.version) !== undefined;
}

function newest<T extends RuntimeCandidate>(candidates: readonly T[]): T | undefined {
  let selected: T | undefined;
  for (const candidate of candidates) {
    if (!selected) {
      selected = candidate;
      continue;
    }
    const order = compareRuntimeVersions(candidate.version, selected.version);
    if (order !== undefined && order > 0) selected = candidate;
  }
  return selected;
}

export function selectRuntime<TInstalled extends RuntimeCandidate, TRelease extends RuntimeCandidate>(
  input: RuntimeSelectionInput<TInstalled, TRelease>,
): RuntimeSelection<TInstalled, TRelease> {
  const local = newest(input.installed.filter(candidate => compatible(candidate, input)));
  if (local) return { kind: "installed", runtime: local };

  const release = newest(input.releases.filter(candidate => compatible(candidate, input)));
  if (release) return { kind: "download", release };

  return {
    kind: "unavailable",
    reason: `no stable runtime for ${input.platform}/${input.arch} matches plugin ${input.pluginVersion} and protocol ${input.protocolVersion}`,
  };
}
