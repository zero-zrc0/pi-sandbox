/**
 * Project rule storage.
 *
 * One project owns one JSON file under the Pi root. Loading validates the file
 * against the project identity and caches frozen results by content hash;
 * committing acquires a directory lock, re-loads under it, runs one change,
 * validates the next file completely and publishes it with a same-directory
 * rename. Locks carry owner metadata and are only released or recovered when
 * ownership can be proven.
 *
 * The service layer depends only on {@link ProjectRulesStore}; tests inject an
 * in-memory store for it and use the real file store with an injectable
 * filesystem, clock, sleep, token generator and process-liveness probe.
 */
import { randomBytes } from "node:crypto";
import { promises as fsp } from "node:fs";
import nodePath from "node:path";
import {
  PROJECT_RULES_SCHEMA_VERSION,
  sha256Hex,
  type ProjectIdentity,
  type ProjectRulesFile,
  type RuleTombstone,
  type StoredProjectRule,
} from "./types";
import { validateProjectRulesFile } from "./schema";

/** Stable categories for a file the store cannot use. */
export type ProjectRulesUnavailableCategory =
  | "io"
  | "corrupt"
  | "schema-invalid"
  | "unknown-schema"
  | "identity-mismatch"
  | "duplicate-id"
  | "revocation-mismatch"
  | "limit-exceeded"
  | "sensitive-content";

export type ProjectRulesLoadResult =
  | {
      readonly kind: "available";
      readonly path: string;
      readonly contentHash: string;
      readonly file: ProjectRulesFile;
    }
  | { readonly kind: "missing"; readonly path: string; readonly revision: 0 }
  | {
      readonly kind: "unavailable";
      readonly path: string;
      readonly category: ProjectRulesUnavailableCategory;
      readonly diagnostic?: string;
    };

export interface ProjectRulesChangeInput {
  /** Revision of the file the change is based on; 0 when the file is missing. */
  readonly revision: number;
  readonly file: ProjectRulesFile;
}

export type ProjectRulesChangeOutcome =
  | {
      readonly kind: "apply";
      readonly rules: readonly StoredProjectRule[];
      readonly tombstones: readonly RuleTombstone[];
    }
  | { readonly kind: "no-change" }
  | { readonly kind: "reject"; readonly reason: string };

/** One atomic change; the store stamps revision, identity and schema version. */
export interface ProjectRulesChange {
  readonly apply: (input: ProjectRulesChangeInput) => ProjectRulesChangeOutcome | Promise<ProjectRulesChangeOutcome>;
}

/** A condition that must still hold right before the file is published. */
export interface ProjectRulesCommitGuard {
  readonly isCurrent: () => boolean | Promise<boolean>;
}

export type ProjectRulesCommitResult =
  | {
      readonly kind: "committed";
      readonly previousRevision: number;
      readonly revision: number;
      readonly ruleIds: readonly string[];
      readonly tombstoneIds: readonly string[];
    }
  | { readonly kind: "no-change"; readonly revision: number }
  | { readonly kind: "rejected"; readonly revision: number; readonly reason: string }
  | { readonly kind: "revision-conflict"; readonly expectedRevision: number; readonly revision: number }
  /** The guard threw or reported that the transaction is no longer current. */
  | { readonly kind: "stale-guard"; readonly revision: number }
  | {
      readonly kind: "unavailable";
      readonly category: ProjectRulesUnavailableCategory;
      readonly diagnostic?: string;
    }
  | { readonly kind: "failed"; readonly category: "lock" | "io"; readonly diagnostic?: string };

/** The seam the service layer consumes. */
export interface ProjectRulesStore {
  load(): Promise<ProjectRulesLoadResult>;
  commit(
    change: ProjectRulesChange,
    expectedRevision: number,
    guard?: ProjectRulesCommitGuard,
  ): Promise<ProjectRulesCommitResult>;
  /** Test seam: drop cached parses without touching the file. */
  clearCache(): void;
  /** Test seam: observe how many parsed files the cache holds. */
  cacheSize(): number;
}

export interface ProjectRulesFileStat {
  readonly isFile: boolean;
  readonly size: number;
}

/**
 * Filesystem port. Every method may throw; the store maps failures to stable
 * categories. `stat` answers `undefined` only for a missing path.
 */
export interface ProjectRulesFs {
  stat(path: string): Promise<ProjectRulesFileStat | undefined>;
  readFile(path: string): Promise<string>;
  /** Create one directory; throws when it already exists. */
  makeDirectory(path: string, mode: number): Promise<void>;
  makeDirectoryRecursive(path: string, mode: number): Promise<void>;
  readDirectory(path: string): Promise<readonly string[]>;
  /** Exclusive create (`wx`), write, fsync and close. */
  writeFileExclusive(path: string, content: string, mode: number): Promise<void>;
  writeFile(path: string, content: string, mode: number): Promise<void>;
  rename(from: string, to: string): Promise<void>;
  removeFile(path: string): Promise<void>;
  removeDirectory(path: string): Promise<void>;
  /** Best effort; a platform that cannot sync directories may throw. */
  fsyncDirectory(path: string): Promise<void>;
}

export interface ProjectRulesStoreDeps {
  readonly now: () => Date;
  readonly sleep: (milliseconds: number) => Promise<void>;
  readonly randomToken: () => string;
  readonly currentPid: () => number;
  readonly processAlive: (pid: number) => boolean;
  /** Wait before giving up on the lock. */
  readonly lockTimeoutMs: number;
  /** Retry interval while waiting for the lock. */
  readonly lockRetryMs: number;
  /** A recovered lock must be this old before it can be broken. */
  readonly staleLockAgeMs: number;
  /** Parsed-file cache capacity. */
  readonly cacheCapacity: number;
  readonly fs: ProjectRulesFs;
}

export interface FileProjectRulesStoreOptions {
  /** Project-specific directory under the Pi root. */
  readonly directory: string;
  readonly filePath: string;
  readonly lockPath: string;
  readonly identity: ProjectIdentity;
  readonly deps?: Partial<ProjectRulesStoreDeps>;
}

const DEFAULT_LOCK_TIMEOUT_MS = 5_000;
const DEFAULT_LOCK_RETRY_MS = 20;
const DEFAULT_STALE_LOCK_AGE_MS = 15_000;
const DEFAULT_CACHE_CAPACITY = 64;
const LOCK_OWNER_FILE = "owner.json";
const RECOVERY_MARKER_SUFFIX = ".recovery";
const CACHE_BYTE_LIMIT = 1024 * 1024;

/** Parsed files are shared per path+identity so every store reuses one parse. */
const parseCache = new Map<string, { readonly contentHash: string; readonly file: ProjectRulesFile }>();

function parseCacheKey(filePath: string, identityHash: string): string {
  return `${filePath}\0${identityHash}`;
}

/** Test seam: observe the size of the process-wide parsed-file LRU. */
export function projectRulesParseCacheSize(): number {
  return parseCache.size;
}

export function createDefaultProjectRulesFs(): ProjectRulesFs {
  return {
    async stat(path) {
      try {
        const stat = await fsp.stat(path);
        return { isFile: stat.isFile(), size: stat.size };
      } catch (error) {
        const code = errorCode(error);
        if (code === "ENOENT" || code === "ENOTDIR") return undefined;
        throw error;
      }
    },
    readFile: (path) => fsp.readFile(path, "utf8"),
    makeDirectory: (path, mode) => fsp.mkdir(path, { mode }).then(() => undefined),
    makeDirectoryRecursive: (path, mode) => fsp.mkdir(path, { recursive: true, mode }).then(() => undefined),
    readDirectory: (path) => fsp.readdir(path),
    async writeFileExclusive(path, content, mode) {
      const handle = await fsp.open(path, "wx", mode);
      try {
        await handle.writeFile(content, "utf8");
        await handle.sync();
      } finally {
        await handle.close();
      }
    },
    writeFile: (path, content, mode) => fsp.writeFile(path, content, { encoding: "utf8", mode }).then(() => undefined),
    rename: (from, to) => fsp.rename(from, to),
    removeFile: (path) => fsp.rm(path, { force: true }),
    removeDirectory: (path) => fsp.rmdir(path).then(() => undefined),
    async fsyncDirectory(path) {
      const handle = await fsp.open(path, "r");
      try {
        await handle.sync();
      } finally {
        await handle.close();
      }
    },
  };
}

function defaultProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // EPERM means the process exists but belongs to another user.
    return errorCode(error) === "EPERM";
  }
}

export function createDefaultProjectRulesStoreDeps(): ProjectRulesStoreDeps {
  return {
    now: () => new Date(),
    sleep: (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
    randomToken: () => randomBytes(16).toString("hex"),
    currentPid: () => process.pid,
    processAlive: defaultProcessAlive,
    lockTimeoutMs: DEFAULT_LOCK_TIMEOUT_MS,
    lockRetryMs: DEFAULT_LOCK_RETRY_MS,
    staleLockAgeMs: DEFAULT_STALE_LOCK_AGE_MS,
    cacheCapacity: DEFAULT_CACHE_CAPACITY,
    fs: createDefaultProjectRulesFs(),
  };
}

function errorCode(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  const code = (error as { code?: unknown }).code;
  return typeof code === "string" ? code : undefined;
}

interface LockOwner {
  readonly token: string;
  readonly pid: number;
  readonly createdAt: number;
}

interface HeldLock {
  readonly generation: number;
  readonly token: string;
  readonly pid: number;
  assertHeld: () => Promise<void>;
  release: () => Promise<void>;
}

const UNAVAILABLE_BY_PROBLEM: Readonly<Record<string, ProjectRulesUnavailableCategory>> = Object.freeze({
  "not-object": "corrupt",
  "unknown-version": "unknown-schema",
  "schema-invalid": "schema-invalid",
  "identity-mismatch": "identity-mismatch",
  "duplicate-rule-id": "duplicate-id",
  "duplicate-tombstone-id": "duplicate-id",
  "revocation-mismatch": "revocation-mismatch",
  "limit-exceeded": "limit-exceeded",
  "sensitive-content": "sensitive-content",
});

function emptyRulesFile(identity: ProjectIdentity): ProjectRulesFile {
  return Object.freeze({
    schemaVersion: PROJECT_RULES_SCHEMA_VERSION,
    revision: 0,
    identity,
    rules: Object.freeze([]) as readonly StoredProjectRule[],
    tombstones: Object.freeze([]) as readonly RuleTombstone[],
  });
}

/**
 * The real store: one file per project, a same-directory temporary file and
 * rename for publication, and a directory lock with owner metadata.
 */
export class FileProjectRulesStore implements ProjectRulesStore {
  private readonly deps: ProjectRulesStoreDeps;
  private activeGeneration = 0;
  private nextGeneration = 1;

  constructor(private readonly options: FileProjectRulesStoreOptions) {
    this.deps = { ...createDefaultProjectRulesStoreDeps(), ...options.deps };
  }

  private cacheKey(): string {
    return parseCacheKey(this.options.filePath, this.options.identity.identityHash);
  }

  async load(): Promise<ProjectRulesLoadResult> {
    return this.readCurrent();
  }

  clearCache(): void {
    parseCache.delete(this.cacheKey());
  }

  cacheSize(): number {
    return parseCache.has(this.cacheKey()) ? 1 : 0;
  }

  async commit(
    change: ProjectRulesChange,
    expectedRevision: number,
    guard?: ProjectRulesCommitGuard,
  ): Promise<ProjectRulesCommitResult> {
    const prepared = await this.ensureDirectory();
    if (!prepared) return { kind: "failed", category: "io", diagnostic: "directory" };
    const lock = await this.acquireLock();
    if (lock === undefined) return { kind: "failed", category: "lock" };

    try {
      if (guard !== undefined && !(await this.guardIsCurrent(guard))) {
        return { kind: "stale-guard", revision: 0 };
      }
      const loaded = await this.readCurrent();
      if (loaded.kind === "unavailable") {
        return { kind: "unavailable", category: loaded.category, ...(loaded.diagnostic === undefined ? {} : { diagnostic: loaded.diagnostic }) };
      }
      const currentFile = loaded.kind === "available" ? loaded.file : emptyRulesFile(this.options.identity);
      const currentRevision = currentFile.revision;
      if (currentRevision !== expectedRevision) {
        return { kind: "revision-conflict", expectedRevision, revision: currentRevision };
      }

      let outcome: ProjectRulesChangeOutcome;
      try {
        outcome = await change.apply({ revision: currentRevision, file: currentFile });
      } catch {
        return { kind: "failed", category: "io", diagnostic: "change" };
      }
      if (outcome.kind === "no-change") return { kind: "no-change", revision: currentRevision };
      if (outcome.kind === "reject") return { kind: "rejected", revision: currentRevision, reason: outcome.reason };

      const nextValue = {
        schemaVersion: PROJECT_RULES_SCHEMA_VERSION,
        revision: currentRevision + 1,
        identity: this.options.identity,
        rules: outcome.rules,
        tombstones: outcome.tombstones,
      };
      const validation = validateProjectRulesFile(nextValue, this.options.identity);
      if (!validation.ok) return { kind: "rejected", revision: currentRevision, reason: "next-file-invalid" };
      const nextFile = validation.file;
      const content = `${JSON.stringify(nextFile, null, 2)}\n`;
      if (Buffer.byteLength(content, "utf8") > CACHE_BYTE_LIMIT) {
        return { kind: "rejected", revision: currentRevision, reason: "next-file-too-large" };
      }

      const temporary = `${this.options.filePath}.${lock.token}.tmp`;
      let published = false;
      try {
        await this.deps.fs.writeFileExclusive(temporary, content, 0o600);
        // Publication is only allowed while this exact lock generation and the
        // caller's transaction are still current.
        await lock.assertHeld();
        if (guard !== undefined && !(await this.guardIsCurrent(guard))) {
          // The transaction stopped being current while the temporary file was
          // already written; never publish and never leave it behind.
          await this.deps.fs.removeFile(temporary).catch(() => undefined);
          return { kind: "stale-guard", revision: currentRevision };
        }
        await this.deps.fs.rename(temporary, this.options.filePath);
        published = true;
      } catch (error) {
        await this.deps.fs.removeFile(temporary).catch(() => undefined);
        const category = errorCode(error) === "stale-lock" ? "lock" : "io";
        return { kind: "failed", category, diagnostic: errorCode(error) };
      }
      if (published) {
        // Directory sync is best effort; the file sync above is mandatory.
        await this.deps.fs.fsyncDirectory(this.options.directory).catch(() => undefined);
        this.remember(this.options.filePath, sha256Hex(content), nextFile);
      }
      return {
        kind: "committed",
        previousRevision: currentRevision,
        revision: nextFile.revision,
        ruleIds: Object.freeze(nextFile.rules.map((rule) => rule.id)),
        tombstoneIds: Object.freeze(nextFile.tombstones.map((tombstone) => tombstone.ruleId)),
      };
    } finally {
      await lock.release();
    }
  }

  private async guardIsCurrent(guard: ProjectRulesCommitGuard): Promise<boolean> {
    try {
      return await guard.isCurrent();
    } catch {
      return false;
    }
  }

  private async ensureDirectory(): Promise<boolean> {
    try {
      await this.deps.fs.makeDirectoryRecursive(this.options.directory, 0o700);
      return true;
    } catch (error) {
      return errorCode(error) === "EEXIST";
    }
  }

  private remember(path: string, contentHash: string, file: ProjectRulesFile): void {
    const key = parseCacheKey(path, this.options.identity.identityHash);
    parseCache.delete(key);
    parseCache.set(key, { contentHash, file });
    while (parseCache.size > this.deps.cacheCapacity) {
      const oldest = parseCache.keys().next();
      if (oldest.done === true) break;
      parseCache.delete(oldest.value);
    }
  }

  private async readCurrent(): Promise<ProjectRulesLoadResult> {
    const path = this.options.filePath;
    let stat: ProjectRulesFileStat | undefined;
    try {
      stat = await this.deps.fs.stat(path);
    } catch (error) {
      return { kind: "unavailable", path, category: "io", ...maybeDiagnostic(errorCode(error)) };
    }
    if (stat === undefined) return { kind: "missing", path, revision: 0 };
    if (!stat.isFile) return { kind: "unavailable", path, category: "io", diagnostic: "not-a-file" };
    if (stat.size > CACHE_BYTE_LIMIT) return { kind: "unavailable", path, category: "limit-exceeded", diagnostic: "file-bytes" };

    let content: string;
    try {
      content = await this.deps.fs.readFile(path);
    } catch (error) {
      if (errorCode(error) === "ENOENT" || errorCode(error) === "ENOTDIR") return { kind: "missing", path, revision: 0 };
      return { kind: "unavailable", path, category: "io", ...maybeDiagnostic(errorCode(error)) };
    }
    if (Buffer.byteLength(content, "utf8") > CACHE_BYTE_LIMIT) {
      return { kind: "unavailable", path, category: "limit-exceeded", diagnostic: "file-bytes" };
    }

    const contentHash = sha256Hex(content);
    const key = parseCacheKey(path, this.options.identity.identityHash);
    const cached = parseCache.get(key);
    if (cached !== undefined && cached.contentHash === contentHash) {
      // Refresh LRU order without re-parsing.
      parseCache.delete(key);
      parseCache.set(key, cached);
      return { kind: "available", path, contentHash, file: cached.file };
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(content);
    } catch {
      return { kind: "unavailable", path, category: "corrupt", diagnostic: "json" };
    }
    const validation = validateProjectRulesFile(parsed, this.options.identity);
    if (!validation.ok) {
      const category = UNAVAILABLE_BY_PROBLEM[validation.problem.kind] ?? "schema-invalid";
      return {
        kind: "unavailable",
        path,
        category,
        ...(validation.problem.path === undefined ? {} : { diagnostic: `${validation.problem.kind}:${validation.problem.path}` }),
      };
    }
    this.remember(path, contentHash, validation.file);
    return { kind: "available", path, contentHash, file: validation.file };
  }

  private ownerPath(lockPath = this.options.lockPath): string {
    return nodePath.join(lockPath, LOCK_OWNER_FILE);
  }

  private async readOwner(lockPath = this.options.lockPath): Promise<LockOwner | undefined> {
    let raw: string;
    try {
      raw = await this.deps.fs.readFile(this.ownerPath(lockPath));
    } catch {
      return undefined;
    }
    let value: unknown;
    try {
      value = JSON.parse(raw);
    } catch {
      return undefined;
    }
    if (typeof value !== "object" || value === null) return undefined;
    const owner = value as Record<string, unknown>;
    if (typeof owner.token !== "string" || owner.token.length === 0) return undefined;
    if (typeof owner.pid !== "number" || !Number.isSafeInteger(owner.pid) || owner.pid <= 0) return undefined;
    if (typeof owner.createdAt !== "number" || !Number.isFinite(owner.createdAt)) return undefined;
    return { token: owner.token, pid: owner.pid, createdAt: owner.createdAt };
  }

  private async acquireLock(): Promise<HeldLock | undefined> {
    const deadline = this.deps.now().getTime() + this.deps.lockTimeoutMs;
    for (;;) {
      const held = await this.tryAcquire();
      if (held !== undefined) return held;
      if (this.deps.now().getTime() >= deadline) return undefined;
      await this.deps.sleep(this.deps.lockRetryMs);
    }
  }

  private async tryAcquire(): Promise<HeldLock | undefined> {
    if (await this.pathExists(`${this.options.lockPath}${RECOVERY_MARKER_SUFFIX}`)) return undefined;
    try {
      await this.deps.fs.makeDirectory(this.options.lockPath, 0o700);
    } catch (error) {
      if (errorCode(error) === "EEXIST") {
        await this.recoverStaleLock();
        return undefined;
      }
      return undefined;
    }
    const token = this.deps.randomToken();
    const pid = this.deps.currentPid();
    const owner: LockOwner = { token, pid, createdAt: this.deps.now().getTime() };
    try {
      await this.deps.fs.writeFile(this.ownerPath(), JSON.stringify(owner), 0o600);
      const confirmed = await this.readOwner();
      if (confirmed === undefined || confirmed.token !== token || confirmed.pid !== pid) {
        await this.cleanupOwnLock(token, pid);
        return undefined;
      }
    } catch {
      await this.cleanupOwnLock(token, pid);
      return undefined;
    }
    const generation = this.nextGeneration++;
    this.activeGeneration = generation;
    return {
      generation,
      token,
      pid,
      assertHeld: async () => {
        if (this.activeGeneration !== generation) throw Object.assign(new Error("stale lock generation"), { code: "stale-lock" });
        const current = await this.readOwner();
        if (current === undefined || current.token !== token || current.pid !== pid) {
          throw Object.assign(new Error("lock owner changed"), { code: "stale-lock" });
        }
      },
      release: async () => {
        if (this.activeGeneration !== generation) return;
        const current = await this.readOwner();
        if (current === undefined || current.token !== token || current.pid !== pid) return;
        this.activeGeneration = 0;
        await this.deps.fs.removeFile(this.ownerPath()).catch(() => undefined);
        await this.deps.fs.removeDirectory(this.options.lockPath).catch(() => undefined);
      },
    };
  }

  /** Remove a lock directory and owner file we just created but failed to own. */
  private async cleanupOwnLock(token: string, pid: number): Promise<void> {
    const current = await this.readOwner();
    if (current !== undefined && (current.token !== token || current.pid !== pid)) return;
    await this.deps.fs.removeFile(this.ownerPath()).catch(() => undefined);
    await this.deps.fs.removeDirectory(this.options.lockPath).catch(() => undefined);
  }

  private async pathExists(path: string): Promise<boolean> {
    try {
      return (await this.deps.fs.stat(path)) !== undefined;
    } catch {
      return true;
    }
  }

  /**
   * Break a stale lock only when ownership is complete, the process is gone and
   * the lock is old enough. A recovery marker serializes recoverers; the moved
   * lock is re-verified before it is deleted.
   */
  private async recoverStaleLock(): Promise<boolean> {
    const owner = await this.readOwner();
    if (owner === undefined) return false;
    if (this.deps.processAlive(owner.pid)) return false;
    if (this.deps.now().getTime() - owner.createdAt <= this.deps.staleLockAgeMs) return false;

    const marker = `${this.options.lockPath}${RECOVERY_MARKER_SUFFIX}`;
    const markerToken = this.deps.randomToken();
    try {
      await this.deps.fs.writeFileExclusive(marker, markerToken, 0o600);
    } catch {
      return false;
    }
    try {
      const again = await this.readOwner();
      if (again === undefined || again.token !== owner.token || again.pid !== owner.pid) return false;
      const aside = `${this.options.lockPath}.stale-${markerToken}`;
      try {
        await this.deps.fs.rename(this.options.lockPath, aside);
      } catch {
        return false;
      }
      const moved = await this.readOwner(aside);
      if (moved === undefined || moved.token !== owner.token || moved.pid !== owner.pid) {
        // Ownership changed while moving: put the live lock back.
        await this.deps.fs.rename(aside, this.options.lockPath).catch(() => undefined);
        return false;
      }
      await this.deps.fs.removeFile(this.ownerPath(aside)).catch(() => undefined);
      await this.deps.fs.removeDirectory(aside).catch(() => undefined);
      return true;
    } finally {
      await this.deps.fs.removeFile(marker).catch(() => undefined);
    }
  }
}

function maybeDiagnostic(diagnostic: string | undefined): { diagnostic?: string } {
  return diagnostic === undefined ? {} : { diagnostic };
}
