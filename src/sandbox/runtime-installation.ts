import { closeSync, existsSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, realpathSync, renameSync, rmSync, rmdirSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { isPathWithin } from "./path";
import type { RuntimeResourceEntry } from "./runtime-catalog";
import { downloadRuntimeArchive, type RuntimeDownloadProgress } from "./runtime-download";
import { extractRuntimeArchive } from "./runtime-archive";
import { scanInstalledRuntimes, validateInstalledRuntime, type InstalledRuntimeCandidate, type ResolvedRuntimeFiles } from "./runtime-store";

const installing = new Map<string, Promise<void>>();

function pathExists(path: string): boolean {
  try { lstatSync(path); return true; }
  catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return false; throw error; }
}

function ensureDirectory(root: string, path: string): string {
  if (!isPathWithin(root, resolve(path))) throw new Error("runtime installation path is outside its storage root");
  if (!existsSync(path)) {
    try { mkdirSync(path); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
  }
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) throw new Error("runtime installation directory is not a real directory");
  const actual = realpathSync(path);
  if (!isPathWithin(root, actual)) throw new Error("runtime installation directory resolves outside its storage root");
  return actual;
}

function safeRemoveDirectory(root: string, path: string): void {
  if (!existsSync(path)) return;
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) throw new Error("refusing to remove an unexpected runtime staging path");
  const actual = realpathSync(path);
  if (!isPathWithin(root, actual)) throw new Error("refusing to remove a runtime staging path outside its storage root");
  rmSync(actual, { recursive: true, force: true });
}

function acquireLock(lockPath: string): () => void {
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

function targetName(entry: Pick<RuntimeResourceEntry, "platform" | "arch" | "version">): string {
  return `${entry.platform}-${entry.arch}-${entry.version}`;
}

function installLockPath(runtimesRoot: string, target: string): string {
  return join(runtimesRoot, `.${target}.install.lock`);
}

function commitLockPath(runtimesRoot: string, target: string): string {
  return join(runtimesRoot, `.${target}.commit.lock`);
}

function commitIsLocked(runtimesRoot: string, target: string): boolean {
  const path = commitLockPath(runtimesRoot, target);
  if (!pathExists(path)) return false;
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.nlink > 1) {
    throw new Error("runtime installation lock is not a regular file");
  }
  let state: { pid?: unknown };
  try { state = JSON.parse(readFileSync(path, "utf8")) as { pid?: unknown }; }
  catch { throw new Error("runtime installation lock is invalid"); }
  if (!Number.isSafeInteger(state.pid) || Number(state.pid) < 1) throw new Error("runtime installation lock is invalid");
  try {
    process.kill(Number(state.pid), 0);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ESRCH") return true;
    rmSync(path);
    return false;
  }
}

function leaseDirectory(runtimesRoot: string, target: string): string {
  return join(runtimesRoot, `.${target}.use`);
}

function releaseRuntimeLease(path: string): void {
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.nlink > 1) {
    throw new Error("runtime use lease changed unexpectedly");
  }
  const state = JSON.parse(readFileSync(path, "utf8")) as { pid?: unknown };
  if (state.pid !== process.pid) throw new Error("runtime use lease owner changed unexpectedly");
  rmSync(path);
  const parent = dirname(path);
  if (readdirSync(parent).length === 0) {
    try { rmdirSync(parent); } catch { /* Another process may have created a lease. */ }
  }
}

export async function acquireRuntimeUseLease(input: {
  readonly storageRoot: string;
  readonly platform: string;
  readonly arch: string;
  readonly version: string;
}): Promise<() => void> {
  const runtimesRoot = ensureDirectory(input.storageRoot, join(input.storageRoot, "runtimes"));
  const target = `${input.platform}-${input.arch}-${input.version}`;
  if (commitIsLocked(runtimesRoot, target)) throw new Error("runtime update is being committed");
  const directory = ensureDirectory(input.storageRoot, leaseDirectory(runtimesRoot, target));
  const path = join(directory, `${process.pid}-${randomUUID()}.json`);
  const descriptor = openSync(path, "wx", 0o600);
  try { writeFileSync(descriptor, JSON.stringify({ pid: process.pid, startedAt: Date.now() })); }
  finally { closeSync(descriptor); }
  if (commitIsLocked(runtimesRoot, target)) {
    releaseRuntimeLease(path);
    throw new Error("runtime update is being committed");
  }
  let released = false;
  return () => {
    if (released) return;
    released = true;
    releaseRuntimeLease(path);
  };
}

function runtimeLeasesActive(runtimesRoot: string, target: string): boolean {
  const directory = leaseDirectory(runtimesRoot, target);
  if (!pathExists(directory)) return false;
  const metadata = lstatSync(directory);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) throw new Error("runtime use lease directory is not a real directory");
  let active = false;
  for (const name of readdirSync(directory)) {
    const path = join(directory, name);
    const leaseStat = lstatSync(path);
    if (leaseStat.isSymbolicLink() || !leaseStat.isFile() || leaseStat.nlink > 1) {
      throw new Error("runtime use lease is not a regular file");
    }
    let state: { pid?: unknown };
    try { state = JSON.parse(readFileSync(path, "utf8")) as { pid?: unknown }; }
    catch { throw new Error("runtime use lease is invalid"); }
    if (!Number.isSafeInteger(state.pid) || Number(state.pid) < 1) throw new Error("runtime use lease is invalid");
    try {
      process.kill(Number(state.pid), 0);
      active = true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ESRCH") active = true;
      else rmSync(path);
    }
  }
  return active;
}

async function waitForRuntimeLeases(runtimesRoot: string, target: string, signal?: AbortSignal): Promise<void> {
  while (true) {
    signal?.throwIfAborted();
    if (!runtimeLeasesActive(runtimesRoot, target)) {
      signal?.throwIfAborted();
      return;
    }
    await new Promise<void>((resolve, reject) => {
      const finish = () => {
        signal?.removeEventListener("abort", onAbort);
        resolve();
      };
      const timer = setTimeout(finish, 100);
      const onAbort = () => {
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        reject(signal?.reason instanceof Error ? signal.reason : new Error("runtime installation was cancelled"));
      };
      signal?.addEventListener("abort", onAbort, { once: true });
      if (signal?.aborted) onAbort();
    });
  }
}

async function reuseExisting(input: {
  readonly pluginRoot: string;
  readonly entry: RuntimeResourceEntry;
}): Promise<ResolvedRuntimeFiles | undefined> {
  const runtimeDirectory = join(input.pluginRoot, "runtimes", targetName(input.entry));
  if (!pathExists(runtimeDirectory)) return undefined;
  const scan = scanInstalledRuntimes({
    pluginRoot: input.pluginRoot,
    platform: input.entry.platform as "linux" | "win32",
    arch: input.entry.arch as "x64" | "arm64",
    catalog: { schemaVersion: 1, runtimes: [input.entry] },
  });
  const candidate = scan.candidates.find(item => item.catalogEntry?.archiveSha256 === input.entry.archiveSha256);
  if (!candidate) return undefined;
  try { return await validateInstalledRuntime(candidate); }
  catch { return undefined; }
}

async function installRuntimeEntryImpl(input: {
  readonly pluginRoot: string;
  readonly entry: RuntimeResourceEntry;
  readonly fetch?: typeof fetch;
  readonly signal?: AbortSignal;
  readonly beforeCommit?: (runtime: ResolvedRuntimeFiles) => Promise<void>;
  readonly onProgress?: (progress: RuntimeDownloadProgress) => void;
}): Promise<ResolvedRuntimeFiles> {
  const pluginRoot = realpathSync(input.pluginRoot);
  const reused = await reuseExisting({ pluginRoot, entry: input.entry });
  if (reused) {
    await input.beforeCommit?.(reused);
    return reused;
  }

  const runtimesRoot = ensureDirectory(pluginRoot, join(pluginRoot, "runtimes"));
  const stagingRoot = ensureDirectory(pluginRoot, join(runtimesRoot, ".staging"));
  const target = targetName(input.entry);
  const releaseInstallLock = acquireLock(installLockPath(runtimesRoot, target));
  let stageDirectory: string;
  try { stageDirectory = ensureDirectory(pluginRoot, join(stagingRoot, input.entry.archiveSha256)); }
  catch (error) { releaseInstallLock(); throw error; }
  const extractionDirectory = join(stageDirectory, "extracted");
  let published = false;
  let keepPartialDownload = true;
  let result: ResolvedRuntimeFiles | undefined;
  try {
    result = await reuseExisting({ pluginRoot, entry: input.entry });
    if (result) {
      await input.beforeCommit?.(result);
      return result;
    }
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
    const stagedCandidate: InstalledRuntimeCandidate = {
      version: manifest.version,
      stable: manifest.stable,
      platform: manifest.platform,
      arch: manifest.arch,
      protocolVersion: manifest.protocolVersion,
      minPluginVersion: manifest.minPluginVersion,
      maxPluginVersionExclusive: manifest.maxPluginVersionExclusive,
      directory: extractionDirectory,
      storageRoot: pluginRoot,
      source: "managed",
      archiveSha256: input.entry.archiveSha256,
      manifest,
      catalogEntry: input.entry,
    };
    const stagedRuntime = await validateInstalledRuntime(stagedCandidate);
    await input.beforeCommit?.(stagedRuntime);

    const runtimeDirectory = join(runtimesRoot, target);
    const releaseCommitLock = acquireLock(commitLockPath(runtimesRoot, target));
    try {
      await waitForRuntimeLeases(runtimesRoot, target, input.signal);
      input.signal?.throwIfAborted();
      result = await reuseExisting({ pluginRoot, entry: input.entry });
      if (result) {
        keepPartialDownload = false;
        await input.beforeCommit?.(result);
        return result;
      }

      const backupDirectory = join(stagingRoot, `backup-${target}-${process.pid}-${randomUUID()}`);
      let movedOldRuntime = false;
      try {
        if (pathExists(runtimeDirectory)) {
          const metadata = lstatSync(runtimeDirectory);
          if (metadata.isSymbolicLink() || !metadata.isDirectory()) throw new Error("runtime destination is not a real directory");
          const actual = realpathSync(runtimeDirectory);
          if (!isPathWithin(runtimesRoot, actual)) throw new Error("runtime destination resolves outside the runtime root");
          renameSync(actual, backupDirectory);
          movedOldRuntime = true;
        }
        renameSync(extractionDirectory, runtimeDirectory);
        published = true;
        const scan = scanInstalledRuntimes({
          pluginRoot,
          platform: input.entry.platform as "linux" | "win32",
          arch: input.entry.arch as "x64" | "arm64",
          catalog: { schemaVersion: 1, runtimes: [input.entry] },
        });
        const candidate = scan.candidates.find(item => item.archiveSha256 === input.entry.archiveSha256);
        if (!candidate) throw new Error(scan.problems.find(problem => problem.directory === runtimeDirectory)?.reason ?? "promoted runtime could not be re-opened");
        result = await validateInstalledRuntime(candidate);
        input.signal?.throwIfAborted();
      } catch (error) {
        if (pathExists(runtimeDirectory)) safeRemoveDirectory(pluginRoot, runtimeDirectory);
        if (movedOldRuntime && pathExists(backupDirectory)) renameSync(backupDirectory, runtimeDirectory);
        throw error;
      }
      if (movedOldRuntime) safeRemoveDirectory(pluginRoot, backupDirectory);
      for (const name of readdirSync(stagingRoot)) {
        if (name.startsWith(`backup-${target}-`)) safeRemoveDirectory(pluginRoot, join(stagingRoot, name));
      }
      return result!;
    } finally {
      releaseCommitLock();
    }
  } catch (error) {
    if (!keepPartialDownload && !published) safeRemoveDirectory(pluginRoot, extractionDirectory);
    throw error;
  } finally {
    releaseInstallLock();
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
  readonly beforeCommit?: (runtime: ResolvedRuntimeFiles) => Promise<void>;
  readonly onProgress?: (progress: RuntimeDownloadProgress) => void;
}): Promise<ResolvedRuntimeFiles> {
  const key = `${resolve(input.pluginRoot)}:${targetName(input.entry)}`;
  const previous = installing.get(key);
  const run = (async () => {
    if (previous !== undefined) {
      await new Promise<void>((resolveWait, rejectWait) => {
        const stop = () => { cleanup(); rejectWait(input.signal?.reason ?? new Error("runtime installation was cancelled")); };
        const cleanup = () => input.signal?.removeEventListener("abort", stop);
        if (input.signal?.aborted) { stop(); return; }
        input.signal?.addEventListener("abort", stop, { once: true });
        void previous.then(() => { cleanup(); resolveWait(); }, () => { cleanup(); resolveWait(); });
      });
    }
    input.signal?.throwIfAborted();
    return installRuntimeEntryImpl(input);
  })();
  const settled = run.then(() => undefined, () => undefined);
  const tail = previous === undefined ? settled : Promise.all([previous, settled]).then(() => undefined);
  installing.set(key, tail);
  void tail.then(() => {
    if (installing.get(key) === tail) installing.delete(key);
  });
  return run;
}
