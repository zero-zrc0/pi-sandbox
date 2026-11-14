import type { RuntimeCandidate } from "./runtime-selection";

export type RuntimeFileRole =
  | "runtimeManifest"
  | "windowsExecutable"
  | "mxcManifest"
  | "linuxLauncher"
  | "egressBridge"
  | "bubblewrap"
  | "bubblewrapLicense";

export interface RuntimeFileEntry {
  readonly role: RuntimeFileRole;
  readonly path: string;
  readonly sha256: string;
  readonly executable: boolean;
}

export interface RuntimeResourceEntry extends RuntimeCandidate {
  readonly backendId: string;
  readonly url: string;
  readonly archiveFormat: "tar.gz";
  readonly archiveSizeBytes: number;
  readonly archiveSha256: string;
  readonly files: readonly RuntimeFileEntry[];
}

export interface RuntimeCatalog {
  readonly schemaVersion: 1;
  readonly runtimes: readonly RuntimeResourceEntry[];
}

const HASH = /^[0-9a-f]{64}$/u;
const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u;
const MAX_ARCHIVE_BYTES = 512 * 1024 * 1024;
const EXPECTED_FILES: Readonly<Record<string, Readonly<Partial<Record<RuntimeFileRole, { path: string; executable: boolean }>>>>> = {
  win32: {
    runtimeManifest: { path: "runtime.json", executable: false },
    windowsExecutable: { path: "pi-sandbox-windows-mxc.exe", executable: true },
    mxcManifest: { path: "mxc-runtime.json", executable: false },
  },
  linux: {
    runtimeManifest: { path: "runtime.json", executable: false },
    linuxLauncher: { path: "linux-sandbox", executable: true },
    egressBridge: { path: "linux-egress-bridge", executable: true },
    bubblewrap: { path: "bwrap", executable: true },
    bubblewrapLicense: { path: "bwrap.LICENSE", executable: false },
  },
};

function object(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  const allowed = new Set(expected);
  if (Object.keys(value).some(key => !allowed.has(key))) throw new Error(`${label} has an unknown field`);
  if (expected.some(key => !(key in value))) throw new Error(`${label} is missing a field`);
}

function text(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${label} must be a non-empty string`);
  return value;
}

function stableVersion(value: unknown, label: string): string {
  const version = text(value, label);
  if (!VERSION.test(version)) throw new Error(`${label} must be a stable semantic version`);
  return version;
}

function compareVersions(left: string, right: string): number {
  const leftParts = left.split(".").map(Number);
  const rightParts = right.split(".").map(Number);
  for (let index = 0; index < 3; index += 1) {
    if (leftParts[index] !== rightParts[index]) return leftParts[index]! - rightParts[index]!;
  }
  return 0;
}

function platform(value: unknown): "win32" | "linux" | "darwin" {
  if (value !== "win32" && value !== "linux" && value !== "darwin") {
    throw new Error("runtime platform is unsupported");
  }
  return value;
}

function arch(value: unknown): "x64" | "arm64" {
  if (value !== "x64" && value !== "arm64") throw new Error("runtime architecture is unsupported");
  return value;
}

export function trustedReleaseUrl(value: unknown): string {
  const input = text(value, "runtime URL");
  let parsed: URL;
  try { parsed = new URL(input); } catch { throw new Error("runtime URL is invalid"); }
  if (parsed.protocol !== "https:" || parsed.hostname !== "github.com" ||
      !/^\/[^/]+\/[^/]+\/releases\/download\/[^/]+\/[^/]+$/u.test(parsed.pathname) ||
      parsed.username !== "" || parsed.password !== "") {
    throw new Error("runtime URL must identify a GitHub Release asset over HTTPS");
  }
  return parsed.href;
}

export function trustedRuntimeRedirectUrl(value: unknown): string {
  const input = text(value, "runtime redirect URL");
  let parsed: URL;
  try { parsed = new URL(input); } catch { throw new Error("runtime redirect URL is invalid"); }
  const githubRelease = parsed.hostname === "github.com" &&
    /^\/[^/]+\/[^/]+\/releases\/download\/[^/]+\/[^/]+$/u.test(parsed.pathname);
  const githubAssetHost = parsed.hostname.endsWith(".githubusercontent.com");
  if (parsed.protocol !== "https:" || (!githubRelease && !githubAssetHost) || parsed.username !== "" || parsed.password !== "") {
    throw new Error("runtime redirect target is not a trusted GitHub release host");
  }
  return parsed.href;
}

function files(value: unknown, targetPlatform: string): readonly RuntimeFileEntry[] {
  if (!Array.isArray(value)) throw new Error("runtime files must be an array");
  const expected = EXPECTED_FILES[targetPlatform];
  if (!expected) throw new Error(`runtime files are unsupported for ${targetPlatform}`);
  const result = value.map((item, index): RuntimeFileEntry => {
    const entry = object(item, `runtime file ${index}`);
    exactKeys(entry, ["role", "path", "sha256", "executable"], `runtime file ${index}`);
    const role = text(entry.role, `runtime file ${index} role`) as RuntimeFileRole;
    const required = expected[role];
    if (!required || entry.path !== required.path || entry.executable !== required.executable) {
      throw new Error(`runtime file ${index} does not match the fixed ${targetPlatform} file layout`);
    }
    const sha256 = text(entry.sha256, `runtime file ${index} sha256`);
    if (!HASH.test(sha256)) throw new Error(`runtime file ${index} sha256 is invalid`);
    return { role, path: required.path, sha256, executable: required.executable };
  });
  const roles = new Set(result.map(item => item.role));
  if (roles.size !== result.length || roles.size !== Object.keys(expected).length) {
    throw new Error(`runtime files are incomplete for ${targetPlatform}`);
  }
  return result;
}

function resource(value: unknown, index: number): RuntimeResourceEntry {
  const label = `runtime ${index}`;
  const entry = object(value, label);
  exactKeys(entry, [
    "version", "stable", "platform", "arch", "protocolVersion", "minPluginVersion",
    "maxPluginVersionExclusive", "backendId", "url", "archiveFormat", "archiveSizeBytes",
    "archiveSha256", "files",
  ], label);
  const targetPlatform = platform(entry.platform);
  const version = stableVersion(entry.version, `${label} version`);
  const minPluginVersion = stableVersion(entry.minPluginVersion, `${label} minPluginVersion`);
  const maxPluginVersionExclusive = stableVersion(entry.maxPluginVersionExclusive, `${label} maxPluginVersionExclusive`);
  if (compareVersions(minPluginVersion, maxPluginVersionExclusive) >= 0) {
    throw new Error(`${label} plugin compatibility range is empty`);
  }
  if (entry.stable !== true) throw new Error(`${label} must be a stable release`);
  if (!Number.isSafeInteger(entry.protocolVersion) || Number(entry.protocolVersion) < 1) {
    throw new Error(`${label} protocolVersion is invalid`);
  }
  if (!Number.isSafeInteger(entry.archiveSizeBytes) || Number(entry.archiveSizeBytes) < 1 || Number(entry.archiveSizeBytes) > MAX_ARCHIVE_BYTES) {
    throw new Error(`${label} archiveSizeBytes is outside the allowed limit`);
  }
  if (entry.archiveFormat !== "tar.gz") throw new Error(`${label} archiveFormat is unsupported`);
  const archiveSha256 = text(entry.archiveSha256, `${label} archiveSha256`);
  if (!HASH.test(archiveSha256)) throw new Error(`${label} archiveSha256 is invalid`);
  const runtimeFiles = files(entry.files, targetPlatform);
  const backendId = text(entry.backendId, `${label} backendId`);
  if ((targetPlatform === "linux" && backendId !== "linux-bwrap-landlock-seccomp") ||
      (targetPlatform === "win32" && backendId !== "windows-mxc")) {
    throw new Error(`${label} backendId does not match its platform`);
  }
  return {
    version,
    stable: true,
    platform: targetPlatform,
    arch: arch(entry.arch),
    protocolVersion: Number(entry.protocolVersion),
    minPluginVersion,
    maxPluginVersionExclusive,
    backendId,
    url: trustedReleaseUrl(entry.url),
    archiveFormat: "tar.gz",
    archiveSizeBytes: Number(entry.archiveSizeBytes),
    archiveSha256,
    files: runtimeFiles,
  };
}

export function parseRuntimeCatalog(value: unknown): RuntimeCatalog {
  const input = object(value, "runtime catalog");
  exactKeys(input, ["schemaVersion", "runtimes"], "runtime catalog");
  if (input.schemaVersion !== 1 || !Array.isArray(input.runtimes)) {
    throw new Error("runtime catalog schema is unsupported");
  }
  const runtimes = input.runtimes.map(resource);
  const identities = new Set<string>();
  for (const entry of runtimes) {
    const identity = `${entry.platform}/${entry.arch}/${entry.version}`;
    if (identities.has(identity)) throw new Error(`runtime catalog repeats ${identity}`);
    identities.add(identity);
  }
  return { schemaVersion: 1, runtimes };
}
