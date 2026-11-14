import { closeSync, existsSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, realpathSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { isPathWithin } from "./path";
import type { RuntimeResourceEntry } from "./runtime-catalog";
import { downloadRuntimeArchive, type RuntimeDownloadProgress } from "./runtime-download";
import { extractRuntimeArchive } from "./runtime-archive";
import { scanInstalledRuntimes, validateInstalledRuntime, type ResolvedRuntimeFiles } from "./runtime-store";

const installing = new Map<string, Promise<ResolvedRuntimeFiles>>();

function ensureDirectory(root: string, path: string): string {
  if (!isPathWithin(root, resolve(path))) throw new Error("runtime installation path is outside the plugin root");
  if (!existsSync(path)) {
    try { mkdirSync(path); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
  }
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) throw new Error("runtime installation directory is not a real directory");
  const actual = realpathSync(path);
  if (!isPathWithin(root, actual)) throw new Error("runtime installation directory resolves outside the plugin root");
  return actual;
}

function safeRemoveDirectory(root: string, path: string): void {
  if (!existsSync(path)) return;
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) throw new Error("refusing to remove an unexpected runtime staging path");
  const actual = realpathSync(path);
  if (!isPathWithin(root, actual)) throw new Error("refusing to remove a runtime staging path outside the plugin root");
  rmSync(actual, { recursive: true, force: true });
}

function acquireLock(stageDirectory: string): () => void {
  const lockPath = join(stageDirectory, "install.lock");
  const openLock = () => {
    const descriptor = openSync(lockPath, "wx", 0o600);
    try { writeFileSync(descriptor, JSON.stringify({ pid: process.pid, startedAt: Date.now() })); }
    finally { closeSync(descriptor); }
  };
  try {
    openLock();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      const metadata = lstatSync(lockPath);
      if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.nlink > 1) throw new Error("runtime installation lock is not a regular file");
      let state: { pid?: unknown };
      try { state = JSON.parse(readFileSync(lockPath, "utf8")) as { pid?: unknown }; }
      catch { throw new Error("runtime installation lock is invalid"); }
      if (!Number.isSafeInteger(state.pid) || Number(state.pid) < 1) throw new Error("runtime installation lock is invalid");
      let ownerAlive = true;
      try { process.kill(Number(state.pid), 0); }
      catch (lockError) { ownerAlive = (lockError as NodeJS.ErrnoException).code !== "ESRCH"; }
      if (ownerAlive) throw new Error("runtime installation for this resource is already in progress");
      rmSync(lockPath);
      try { openLock(); }
      catch { throw new Error("runtime installation for this resource is already in progress"); }
    }
    else throw error;
  }
  return () => {
    const metadata = lstatSync(lockPath);
    if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.nlink > 1) throw new Error("runtime installation lock changed unexpectedly");
    const state = JSON.parse(readFileSync(lockPath, "utf8")) as { pid?: unknown };
    if (state.pid !== process.pid) throw new Error("runtime installation lock owner changed unexpectedly");
    rmSync(lockPath);
  };
}

async function reuseExisting(input: {
  readonly pluginRoot: string;
  readonly entry: RuntimeResourceEntry;
}): Promise<ResolvedRuntimeFiles | undefined> {
  const runtimeDirectory = join(input.pluginRoot, "runtimes", input.entry.version, `${input.entry.platform}-${input.entry.arch}`);
  if (!existsSync(runtimeDirectory)) return undefined;
  const scan = scanInstalledRuntimes({
    pluginRoot: input.pluginRoot,
    platform: input.entry.platform as "linux" | "win32",
    arch: input.entry.arch as "x64" | "arm64",
    catalog: { schemaVersion: 1, runtimes: [input.entry] },
  });
  const candidate = scan.candidates.find(item => item.version === input.entry.version);
  if (!candidate) throw new Error(scan.problems.find(problem => problem.directory === runtimeDirectory)?.reason ?? "runtime version directory conflicts with an existing installation");
  return validateInstalledRuntime(candidate);
}

async function installRuntimeEntryImpl(input: {
  readonly pluginRoot: string;
  readonly entry: RuntimeResourceEntry;
  readonly fetch?: typeof fetch;
  readonly signal?: AbortSignal;
  readonly onProgress?: (progress: RuntimeDownloadProgress) => void;
}): Promise<ResolvedRuntimeFiles> {
  const pluginRoot = realpathSync(input.pluginRoot);
  const reused = await reuseExisting({ pluginRoot, entry: input.entry });
  if (reused) return reused;

  const runtimesRoot = ensureDirectory(pluginRoot, join(pluginRoot, "runtimes"));
  const stagingRoot = ensureDirectory(pluginRoot, join(runtimesRoot, ".staging"));
  const stageDirectory = ensureDirectory(pluginRoot, join(stagingRoot, input.entry.archiveSha256));
  const releaseLock = acquireLock(stageDirectory);
  const extractionDirectory = join(stageDirectory, "extracted");
  let published = false;
  let keepPartialDownload = true;
  let result: ResolvedRuntimeFiles | undefined;
  try {
    const archivePath = await downloadRuntimeArchive({
      entry: input.entry,
      stagingDirectory: stageDirectory,
      ...(input.fetch === undefined ? {} : { fetch: input.fetch }),
      ...(input.signal === undefined ? {} : { signal: input.signal }),
      ...(input.onProgress === undefined ? {} : { onProgress: input.onProgress }),
    });
    keepPartialDownload = false;
    if (existsSync(extractionDirectory)) safeRemoveDirectory(pluginRoot, extractionDirectory);
    const manifest = await extractRuntimeArchive({ entry: input.entry, archivePath, destination: extractionDirectory });
    writeFileSync(join(extractionDirectory, ".runtime-install.json"), JSON.stringify({
      schemaVersion: 1,
      platform: input.entry.platform,
      arch: input.entry.arch,
      version: input.entry.version,
      archiveSha256: input.entry.archiveSha256,
    }), { flag: "wx", mode: 0o600 });
    const versionDirectory = ensureDirectory(pluginRoot, join(runtimesRoot, input.entry.version));
    const runtimeDirectory = join(versionDirectory, `${input.entry.platform}-${input.entry.arch}`);
    if (existsSync(runtimeDirectory)) {
      result = await reuseExisting({ pluginRoot, entry: input.entry });
      if (!result) throw new Error("runtime destination was created by a conflicting installation");
      published = true;
      return result;
    }
    renameSync(extractionDirectory, runtimeDirectory);
    published = true;
    const scan = scanInstalledRuntimes({
      pluginRoot,
      platform: input.entry.platform as "linux" | "win32",
      arch: input.entry.arch as "x64" | "arm64",
      catalog: { schemaVersion: 1, runtimes: [input.entry] },
    });
    const candidate = scan.candidates.find(item => item.version === manifest.version);
    if (!candidate) throw new Error(scan.problems.find(problem => problem.directory === runtimeDirectory)?.reason ?? "installed runtime could not be re-opened");
    result = await validateInstalledRuntime(candidate);
    return result;
  } catch (error) {
    if (!keepPartialDownload && !published) safeRemoveDirectory(pluginRoot, extractionDirectory);
    throw error;
  } finally {
    releaseLock();
    if (published || !keepPartialDownload) {
      safeRemoveDirectory(pluginRoot, stageDirectory);
    } else if (readdirSync(stageDirectory).every(name => name === "install.lock")) {
      safeRemoveDirectory(pluginRoot, stageDirectory);
    }
  }
}

export function installRuntimeEntry(input: {
  readonly pluginRoot: string;
  readonly entry: RuntimeResourceEntry;
  readonly fetch?: typeof fetch;
  readonly signal?: AbortSignal;
  readonly onProgress?: (progress: RuntimeDownloadProgress) => void;
}): Promise<ResolvedRuntimeFiles> {
  const key = `${resolve(input.pluginRoot)}:${input.entry.platform}/${input.entry.arch}/${input.entry.version}`;
  const current = installing.get(key);
  if (current) return current;
  const run = installRuntimeEntryImpl(input);
  installing.set(key, run);
  void run.finally(() => {
    if (installing.get(key) === run) installing.delete(key);
  }).catch(() => undefined);
  return run;
}
