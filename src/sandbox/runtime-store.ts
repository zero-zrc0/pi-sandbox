import { createReadStream, lstatSync, readFileSync, realpathSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, resolve } from "node:path";
import { isPathWithin } from "./path";
import type { RuntimeCatalog, RuntimeFileEntry, RuntimeFileRole, RuntimeResourceEntry } from "./runtime-catalog";
import { parseRuntimeManifest, type RuntimeManifest } from "./runtime-manifest";
import { prepareWindowsRuntimeExecutable } from "./runtime-windows-integrity";
import type { RuntimeCandidate } from "./runtime-selection";

const MANAGED_MARKER = ".runtime-install.json";

function pathExists(path: string): boolean {
  try { lstatSync(path); return true; }
  catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return false; throw error; }
}

export interface InstalledRuntimeCandidate extends RuntimeCandidate {
  readonly directory: string;
  readonly storageRoot: string;
  readonly source: "manual" | "managed";
  readonly archiveSha256?: string;
  readonly manifest: RuntimeManifest;
  readonly catalogEntry?: RuntimeResourceEntry;
}

export interface ResolvedRuntimeFiles {
  readonly directory: string;
  readonly storageRoot: string;
  readonly manifest: RuntimeManifest;
  readonly source: "manual" | "managed";
  readonly files: Readonly<Partial<Record<RuntimeFileRole, string>>>;
}

export interface InstalledRuntimeScan {
  readonly candidates: readonly InstalledRuntimeCandidate[];
  readonly problems: readonly { readonly directory: string; readonly reason: string }[];
}

function canonicalDirectory(root: string, path: string, label: string): string {
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) throw new Error(`${label} must be a real directory`);
  const actual = realpathSync(path);
  if (!isPathWithin(root, actual)) throw new Error(`${label} resolves outside the trusted runtime root`);
  return actual;
}

function candidateFor(
  pluginRoot: string,
  directory: string,
  catalog: RuntimeCatalog,
  platform: "linux" | "win32",
  arch: "x64" | "arm64",
): InstalledRuntimeCandidate {
  const root = realpathSync(pluginRoot);
  const runtimeRoot = canonicalDirectory(root, join(root, "runtimes"), "runtime root");
  const runtimeDirectory = canonicalDirectory(runtimeRoot, directory, "runtime directory");
  const expectedDirectory = resolve(runtimeRoot, `${platform}-${arch}`);
  const normalize = (path: string) => process.platform === "win32" ? resolve(path).toLowerCase() : resolve(path);
  if (normalize(runtimeDirectory) !== normalize(expectedDirectory)) {
    throw new Error("runtime directory does not match the fixed platform layout");
  }
  const manifestPath = join(runtimeDirectory, "runtime.json");
  const manifestStat = lstatSync(manifestPath);
  if (manifestStat.isSymbolicLink() || !manifestStat.isFile() || manifestStat.nlink > 1) {
    throw new Error("runtime manifest must be a regular file inside the runtime directory");
  }
  const manifest = parseRuntimeManifest(JSON.parse(readFileSync(manifestPath, "utf8")) as unknown);
  if (manifest.platform !== platform || manifest.arch !== arch) {
    throw new Error("runtime manifest does not match its fixed directory");
  }
  let catalogEntry: RuntimeResourceEntry | undefined;
  let source: "manual" | "managed" = "manual";
  let archiveSha256: string | undefined;
  const markerPath = join(runtimeDirectory, MANAGED_MARKER);
  if (pathExists(markerPath)) {
    const markerStat = lstatSync(markerPath);
    if (markerStat.isSymbolicLink() || !markerStat.isFile() || markerStat.nlink > 1) {
      throw new Error("managed runtime marker is not a regular file");
    }
    let marker: Record<string, unknown>;
    try { marker = JSON.parse(readFileSync(markerPath, "utf8")) as Record<string, unknown>; }
    catch { throw new Error("managed runtime marker is invalid"); }
    const markerKeys = ["schemaVersion", "platform", "arch", "version", "archiveSha256"];
    if (Object.keys(marker).some(key => !markerKeys.includes(key)) || markerKeys.some(key => !(key in marker)) ||
        marker.schemaVersion !== 1 || marker.platform !== platform || marker.arch !== arch || marker.version !== manifest.version ||
        typeof marker.archiveSha256 !== "string" || !/^[0-9a-f]{64}$/u.test(marker.archiveSha256)) {
      throw new Error("managed runtime marker does not match its runtime directory");
    }
    archiveSha256 = marker.archiveSha256;
    catalogEntry = catalog.runtimes.find(entry =>
      entry.platform === platform && entry.arch === arch && entry.version === manifest.version &&
      entry.archiveSha256 === marker.archiveSha256,
    );
    if (!catalogEntry) throw new Error("managed runtime is not present in the current trusted catalog");
    source = "managed";
  } else {
    const runtimeManifestHash = createHash("sha256").update(readFileSync(manifestPath)).digest("hex");
    catalogEntry = catalog.runtimes.find(entry => {
      if (entry.platform !== platform || entry.arch !== arch || entry.version !== manifest.version ||
          entry.files.find(file => file.role === "runtimeManifest")?.sha256 !== runtimeManifestHash ||
          entry.protocolVersion !== manifest.protocolVersion || entry.backendId !== manifest.backendId ||
          entry.minPluginVersion !== manifest.minPluginVersion ||
          entry.maxPluginVersionExclusive !== manifest.maxPluginVersionExclusive || !entry.stable ||
          manifest.stable !== entry.stable) return false;
      const catalogFiles = new Map(entry.files.filter(file => file.role !== "runtimeManifest").map(file => [file.role, file]));
      return catalogFiles.size === manifest.files.length && manifest.files.every(file => {
        const expected = catalogFiles.get(file.role);
        return expected?.path === file.path && expected.sha256 === file.sha256 && expected.executable === file.executable;
      });
    });
  }
  if (catalogEntry) {
    if (catalogEntry.protocolVersion !== manifest.protocolVersion || catalogEntry.backendId !== manifest.backendId ||
        catalogEntry.minPluginVersion !== manifest.minPluginVersion ||
        catalogEntry.maxPluginVersionExclusive !== manifest.maxPluginVersionExclusive ||
        catalogEntry.stable !== manifest.stable || !catalogEntry.stable) {
      throw new Error("runtime manifest metadata differs from its trusted resource entry");
    }
    const catalogFiles = new Map(catalogEntry.files.filter(file => file.role !== "runtimeManifest").map(file => [file.role, file]));
    if (catalogFiles.size !== manifest.files.length || manifest.files.some(file => {
      const expected = catalogFiles.get(file.role);
      return !expected || expected.path !== file.path || expected.sha256 !== file.sha256 || expected.executable !== file.executable;
    })) throw new Error("runtime manifest file list differs from its trusted resource entry");
  }
  return {
    version: manifest.version,
    stable: manifest.stable,
    platform: manifest.platform,
    arch: manifest.arch,
    protocolVersion: manifest.protocolVersion,
    minPluginVersion: manifest.minPluginVersion,
    maxPluginVersionExclusive: manifest.maxPluginVersionExclusive,
    directory: runtimeDirectory,
    storageRoot: root,
    source,
    manifest,
    ...(archiveSha256 === undefined ? {} : { archiveSha256 }),
    ...(catalogEntry === undefined ? {} : { catalogEntry }),
  };
}

export function scanInstalledRuntimes(input: {
  readonly pluginRoot: string;
  readonly platform: "linux" | "win32";
  readonly arch: "x64" | "arm64";
  readonly catalog: RuntimeCatalog;
}): InstalledRuntimeScan {
  const root = realpathSync(input.pluginRoot);
  const runtimeRootPath = join(root, "runtimes");
  if (!pathExists(runtimeRootPath)) return { candidates: [], problems: [] };
  const runtimeRoot = canonicalDirectory(root, runtimeRootPath, "runtime root");
  const directory = join(runtimeRoot, `${input.platform}-${input.arch}`);
  if (!pathExists(directory)) return { candidates: [], problems: [] };
  try {
    return {
      candidates: [candidateFor(root, directory, input.catalog, input.platform, input.arch)],
      problems: [],
    };
  } catch (error) {
    return {
      candidates: [],
      problems: [{ directory, reason: error instanceof Error ? error.message : String(error) }],
    };
  }
}

async function sha256File(path: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest("hex");
}

export function verifyMxcManifest(path: string, executableHash: string): void {
  let manifest: Record<string, unknown>;
  try { manifest = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>; }
  catch { throw new Error("Windows MXC manifest is invalid"); }
  if (manifest.schemaVersion !== 1 || manifest.backend !== "windows-mxc" || manifest.version !== "1.0.0" ||
      manifest.sdkRevision !== "b21120168d70befe12356411423266bfef168446" || manifest.sha256 !== executableHash) {
    throw new Error("Windows MXC manifest does not match the runtime executable");
  }
}

function expectedFileEntries(candidate: InstalledRuntimeCandidate): readonly RuntimeFileEntry[] {
  if (candidate.catalogEntry) return candidate.catalogEntry.files;
  return candidate.manifest.files;
}

export async function validateInstalledRuntime(candidate: InstalledRuntimeCandidate): Promise<ResolvedRuntimeFiles> {
  const root = realpathSync(candidate.storageRoot);
  const directory = canonicalDirectory(root, candidate.directory, "runtime directory");
  const manifestPath = join(directory, "runtime.json");
  const manifestStat = lstatSync(manifestPath);
  if (manifestStat.isSymbolicLink() || !manifestStat.isFile() || manifestStat.nlink > 1) {
    throw new Error("runtime manifest is not a regular file");
  }
  const currentManifest = parseRuntimeManifest(JSON.parse(readFileSync(manifestPath, "utf8")) as unknown);
  if (JSON.stringify(currentManifest) !== JSON.stringify(candidate.manifest)) {
    throw new Error("runtime manifest changed after version selection");
  }
  if (candidate.source === "managed") {
    const markerPath = join(directory, MANAGED_MARKER);
    const markerStat = lstatSync(markerPath);
    if (markerStat.isSymbolicLink() || !markerStat.isFile() || markerStat.nlink > 1) {
      throw new Error("managed runtime marker is not a regular file");
    }
    const marker = JSON.parse(readFileSync(markerPath, "utf8")) as Record<string, unknown>;
    if (marker.schemaVersion !== 1 || marker.platform !== candidate.platform || marker.arch !== candidate.arch ||
        marker.version !== candidate.version || marker.archiveSha256 !== candidate.archiveSha256) {
      throw new Error("managed runtime marker changed after version selection");
    }
  }
  const expectedEntries = expectedFileEntries(candidate);
  const resolved: Partial<Record<RuntimeFileRole, string>> = { runtimeManifest: manifestPath };
  const hashes = new Map<RuntimeFileRole, string>();
  hashes.set("runtimeManifest", await sha256File(manifestPath));
  for (const entry of candidate.manifest.files) {
    const path = join(directory, entry.path);
    const metadata = lstatSync(path);
    if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.nlink > 1) {
      throw new Error(`runtime file ${entry.path} must be a regular file`);
    }
    const actual = realpathSync(path);
    if (!isPathWithin(directory, actual)) throw new Error(`runtime file ${entry.path} resolves outside its directory`);
    if (entry.executable && candidate.platform === "linux" && (metadata.mode & 0o111) === 0) {
      throw new Error(`runtime file ${entry.path} is not executable`);
    }
    const hash = await sha256File(actual);
    if (hash !== entry.sha256) throw new Error(`runtime file ${entry.path} hash does not match runtime.json`);
    resolved[entry.role] = actual;
    hashes.set(entry.role, hash);
  }
  for (const entry of expectedEntries) {
    if (hashes.get(entry.role) !== entry.sha256) throw new Error(`runtime file ${entry.path} does not match its trusted resource entry`);
  }
  if (candidate.platform === "win32") {
    const executableHash = hashes.get("windowsExecutable");
    const manifest = resolved.mxcManifest;
    if (!executableHash || !manifest) throw new Error("Windows runtime files are incomplete");
    verifyMxcManifest(manifest, executableHash);
    prepareWindowsRuntimeExecutable(resolved.windowsExecutable!);
  }
  return {
    directory,
    storageRoot: root,
    manifest: currentManifest,
    source: candidate.source,
    files: Object.freeze(resolved),
  };
}
