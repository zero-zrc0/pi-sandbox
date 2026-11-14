import type { RuntimeCandidate } from "./runtime-selection";
import type { RuntimeFileEntry, RuntimeFileRole } from "./runtime-catalog";

export interface RuntimeManifest extends RuntimeCandidate {
  readonly schemaVersion: 1;
  readonly backendId: string;
  readonly files: readonly RuntimeFileEntry[];
  readonly components?: {
    readonly bubblewrapVersion: string;
    readonly bubblewrapSourceCommit: string;
  };
}

const HASH = /^[0-9a-f]{64}$/u;
const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u;
const REQUIRED_FILES: Readonly<Record<string, Readonly<Partial<Record<RuntimeFileRole, { path: string; executable: boolean }>>>>> = {
  win32: {
    windowsExecutable: { path: "pi-sandbox-windows-mxc.exe", executable: true },
    mxcManifest: { path: "mxc-runtime.json", executable: false },
  },
  linux: {
    linuxLauncher: { path: "linux-sandbox", executable: true },
    egressBridge: { path: "linux-egress-bridge", executable: true },
    bubblewrap: { path: "bwrap", executable: true },
    bubblewrapLicense: { path: "bwrap.LICENSE", executable: false },
  },
};

function object(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], label: string, optional: readonly string[] = []): void {
  const allowed = new Set([...expected, ...optional]);
  if (Object.keys(value).some(key => !allowed.has(key))) throw new Error(`${label} has an unknown field`);
  if (expected.some(key => !(key in value))) throw new Error(`${label} is missing a field`);
}

function nonEmptyString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${label} must be a non-empty string`);
  return value;
}

function version(value: unknown, label: string): string {
  const result = nonEmptyString(value, label);
  if (!VERSION.test(result)) throw new Error(`${label} must be a stable semantic version`);
  return result;
}

function compareVersions(left: string, right: string): number {
  const leftParts = left.split(".").map(Number);
  const rightParts = right.split(".").map(Number);
  for (let index = 0; index < 3; index += 1) {
    if (leftParts[index] !== rightParts[index]) return leftParts[index]! - rightParts[index]!;
  }
  return 0;
}

export function parseRuntimeManifest(value: unknown): RuntimeManifest {
  const input = object(value, "runtime manifest");
  exactKeys(input, [
    "schemaVersion", "version", "stable", "platform", "arch", "protocolVersion",
    "minPluginVersion", "maxPluginVersionExclusive", "backendId", "files",
  ], "runtime manifest", ["components"]);
  if (input.schemaVersion !== 1 || input.stable !== true) throw new Error("runtime manifest schema or release channel is unsupported");
  if (input.platform !== "win32" && input.platform !== "linux") throw new Error("runtime platform is unsupported");
  if (input.arch !== "x64" && input.arch !== "arm64") throw new Error("runtime architecture is unsupported");
  const targetPlatform = input.platform;
  const expectedFiles = REQUIRED_FILES[targetPlatform]!;
  if (!Array.isArray(input.files)) throw new Error("runtime manifest files must be an array");
  const files = input.files.map((value, index): RuntimeFileEntry => {
    const file = object(value, `runtime file ${index}`);
    exactKeys(file, ["role", "path", "sha256", "executable"], `runtime file ${index}`);
    const role = nonEmptyString(file.role, `runtime file ${index} role`) as RuntimeFileRole;
    const expected = expectedFiles[role];
    const sha256 = nonEmptyString(file.sha256, `runtime file ${index} sha256`);
    if (!expected || file.path !== expected.path || file.executable !== expected.executable || !HASH.test(sha256)) {
      throw new Error(`runtime file ${index} does not match the fixed ${targetPlatform} layout`);
    }
    return { role, path: expected.path, sha256, executable: expected.executable };
  });
  if (new Set(files.map(file => file.role)).size !== Object.keys(expectedFiles).length ||
      files.length !== Object.keys(expectedFiles).length) {
    throw new Error(`runtime manifest files are incomplete for ${targetPlatform}`);
  }
  const backendId = nonEmptyString(input.backendId, "runtime backendId");
  if ((targetPlatform === "linux" && backendId !== "linux-bwrap-landlock-seccomp") ||
      (targetPlatform === "win32" && backendId !== "windows-mxc")) {
    throw new Error("runtime backend does not match its platform");
  }
  let components: RuntimeManifest["components"];
  if (targetPlatform === "linux") {
    const value = object(input.components, "runtime components");
    exactKeys(value, ["bubblewrapVersion", "bubblewrapSourceCommit"], "runtime components");
    const bubblewrapVersion = version(value.bubblewrapVersion, "bubblewrapVersion");
    const bubblewrapSourceCommit = nonEmptyString(value.bubblewrapSourceCommit, "bubblewrapSourceCommit");
    if (!/^[0-9a-f]{40}$/u.test(bubblewrapSourceCommit)) throw new Error("bubblewrapSourceCommit is invalid");
    components = { bubblewrapVersion, bubblewrapSourceCommit };
  } else if (input.components !== undefined) {
    throw new Error("runtime components are unsupported for this platform");
  }
  const protocolVersion = input.protocolVersion;
  if (!Number.isSafeInteger(protocolVersion) || Number(protocolVersion) < 1) throw new Error("runtime protocolVersion is invalid");
  const minPluginVersion = version(input.minPluginVersion, "runtime minPluginVersion");
  const maxPluginVersionExclusive = version(input.maxPluginVersionExclusive, "runtime maxPluginVersionExclusive");
  if (compareVersions(minPluginVersion, maxPluginVersionExclusive) >= 0) {
    throw new Error("runtime plugin compatibility range is empty");
  }
  return {
    schemaVersion: 1,
    version: version(input.version, "runtime version"),
    stable: true,
    platform: targetPlatform,
    arch: input.arch,
    protocolVersion: Number(protocolVersion),
    minPluginVersion,
    maxPluginVersionExclusive,
    backendId,
    files,
    ...(components === undefined ? {} : { components }),
  };
}
