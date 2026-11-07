import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  FileProjectRulesStore,
  createDefaultProjectRulesFs,
  projectRulesParseCacheSize,
  type ProjectRulesChange,
  type ProjectRulesStoreDeps,
} from "#approve-core/policy/project-rules/storage";
import {
  PROJECT_RULES_SCHEMA_VERSION,
  canonicalJson,
  sha256Hex,
  type ExactAction,
  type ProjectIdentity,
  type ProjectRulesFile,
  type RuleTombstone,
  type StoredProjectRule,
} from "#approve-core/policy/project-rules/types";
import { buildExactMatch } from "#approve-core/policy/project-rules/match";
import { ProjectRulesService, type ProjectRulesIntentBarrier } from "#approve-core/policy/project-rules/service";

const identity: ProjectIdentity = {
  rootPath: "/work/project",
  displayName: "project",
  slug: "project",
  identityHash: "0123456789abcdef",
};

const argumentsValue = { command: "cat file.txt" };
const argumentsDigest = sha256Hex(canonicalJson(argumentsValue));

function rule(id: string, overrides: Partial<StoredProjectRule> = {}): StoredProjectRule {
  return {
    id,
    effect: "allow",
    status: "active",
    match: {
      contractVersion: 1,
      type: "exact_action",
      tool: { name: "bash", origin: "builtin", definitionRevision: "7" },
      definitionDigest: "definition-digest",
      arguments: argumentsValue,
      argumentsDigest,
      cwd: "/work/project",
      environmentDigest: "environment-digest",
      requiredScopes: [{ surface: "bash", target: "cat file.txt", access: "other" }],
    },
    provenance: {
      sessionId: "session-1",
      sourceEntryId: "entry-1",
      quote: "always allow this",
      confidence: 0.95,
      judge: "judge-1",
      actor: "user-1",
    },
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z",
    ...overrides,
  };
}

function rulesFile(revision: number, rules: readonly StoredProjectRule[] = [rule("rule-0123456789abcdef01234567")]): ProjectRulesFile {
  return {
    schemaVersion: PROJECT_RULES_SCHEMA_VERSION,
    revision,
    identity,
    rules,
    tombstones: [],
  };
}

function applyChange(rules: readonly StoredProjectRule[], tombstones: readonly RuleTombstone[] = []): ProjectRulesChange {
  return { apply: () => ({ kind: "apply", rules, tombstones }) };
}

const noChange: ProjectRulesChange = { apply: () => ({ kind: "no-change" }) };

let root: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "pi-project-rules-"));
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

interface StoreOptions {
  readonly identity?: ProjectIdentity;
  readonly directory?: string;
  readonly deps?: Partial<ProjectRulesStoreDeps>;
}

function makeStore(options: StoreOptions = {}) {
  const directory = options.directory ?? join(root, "project");
  return {
    directory,
    filePath: join(directory, "project-rules.json"),
    lockPath: join(directory, "project-rules.lock"),
    store: new FileProjectRulesStore({
      directory,
      filePath: join(directory, "project-rules.json"),
      lockPath: join(directory, "project-rules.lock"),
      identity: options.identity ?? identity,
      ...(options.deps === undefined ? {} : { deps: options.deps }),
    }),
  };
}

async function writeRules(path: string, value: unknown): Promise<void> {
  await mkdir(join(path, ".."), { recursive: true });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

describe("project rules file loading", () => {
  it("reports a missing file as revision 0 and creates nothing", async () => {
    const { store, directory } = makeStore();
    await expect(store.load()).resolves.toEqual({ kind: "missing", path: join(directory, "project-rules.json"), revision: 0 });
    expect(store.cacheSize()).toBe(0);
    await expect(readdir(directory)).rejects.toThrow();
  });

  it("loads and caches an available file", async () => {
    const { store, filePath } = makeStore();
    await writeRules(filePath, rulesFile(3));
    const first = await store.load();
    expect(first).toMatchObject({ kind: "available", path: filePath });
    if (first.kind !== "available") throw new Error("expected available");
    expect(first.file.revision).toBe(3);
    expect(first.contentHash).toMatch(/^[0-9a-f]{64}$/);
    expect(store.cacheSize()).toBe(1);

    const second = await store.load();
    if (second.kind !== "available") throw new Error("expected available");
    // A cache hit returns the same frozen parse.
    expect(second.file).toBe(first.file);
    expect(second.contentHash).toBe(first.contentHash);

    store.clearCache();
    expect(store.cacheSize()).toBe(0);
    const third = await store.load();
    if (third.kind !== "available") throw new Error("expected available");
    expect(third.file).not.toBe(first.file);
    expect(third.file.revision).toBe(3);
  });

  it("reparses when external content changes", async () => {
    const { store, filePath } = makeStore();
    await writeRules(filePath, rulesFile(3));
    const first = await store.load();
    await writeRules(filePath, rulesFile(4));
    const second = await store.load();
    if (first.kind !== "available" || second.kind !== "available") throw new Error("expected available");
    expect(second.file.revision).toBe(4);
    expect(second.contentHash).not.toBe(first.contentHash);
    // Writing identical content again reuses the cached parse.
    const third = await store.load();
    if (third.kind !== "available") throw new Error("expected available");
    expect(third.file).toBe(second.file);
  });

  it("keeps the parsed-file cache bounded and evicts the least recently used project", async () => {
    const stores = Array.from({ length: 65 }, (_, index) => makeStore({ directory: join(root, `project-${index}`) }));
    const references: unknown[] = [];
    for (let index = 0; index < 64; index += 1) {
      const { store, filePath } = stores[index]!;
      await writeRules(filePath, rulesFile(1));
      const loaded = await store.load();
      if (loaded.kind !== "available") throw new Error("expected available");
      references[index] = loaded.file;
    }
    expect(projectRulesParseCacheSize()).toBeLessThanOrEqual(64);
    // Touch the first project, so the second one is now the least recently used.
    const refreshed = await stores[0]!.store.load();
    if (refreshed.kind !== "available") throw new Error("expected available");
    expect(refreshed.file).toBe(references[0]);

    const last = stores[64]!;
    await writeRules(last.filePath, rulesFile(1));
    const loadedLast = await last.store.load();
    if (loadedLast.kind !== "available") throw new Error("expected available");
    expect(projectRulesParseCacheSize()).toBeLessThanOrEqual(64);

    // The touched project is still cached; the untouced second project was evicted.
    const againFirst = await stores[0]!.store.load();
    if (againFirst.kind !== "available") throw new Error("expected available");
    expect(againFirst.file).toBe(references[0]);
    const againSecond = await stores[1]!.store.load();
    if (againSecond.kind !== "available") throw new Error("expected available");
    expect(againSecond.file).not.toBe(references[1]);
  });

  it("maps corrupt JSON, unknown schema versions and identity mismatches separately", async () => {
    const { store, filePath } = makeStore();
    await writeRules(filePath, rulesFile(1));
    await writeFile(filePath, "{ not json", "utf8");
    expect(await store.load()).toMatchObject({ kind: "unavailable", category: "corrupt" });

    await writeRules(filePath, { ...rulesFile(1), schemaVersion: 7 });
    expect(await store.load()).toMatchObject({ kind: "unavailable", category: "unknown-schema" });

    await writeRules(filePath, { ...rulesFile(1), identity: { ...identity, identityHash: "ffffffffffffffff" } });
    expect(await store.load()).toMatchObject({ kind: "unavailable", category: "identity-mismatch" });

    await writeRules(filePath, rulesFile(1));
    const otherIdentity = makeStore({ identity: { ...identity, rootPath: "/work/other" }, directory: join(root, "project") });
    expect(await otherIdentity.store.load()).toMatchObject({ kind: "unavailable", category: "identity-mismatch" });
  });

  it("rejects a directory at the rules path and oversized files", async () => {
    const { store, filePath } = makeStore();
    await mkdir(filePath, { recursive: true });
    expect(await store.load()).toMatchObject({ kind: "unavailable", category: "io" });

    await rm(filePath, { recursive: true, force: true });
    await writeFile(filePath, "x".repeat(1024 * 1024 + 1), "utf8");
    expect(await store.load()).toMatchObject({ kind: "unavailable", category: "limit-exceeded" });
  });

  it("treats a disappeared file as missing and other read errors as unavailable", async () => {
    const fs = createDefaultProjectRulesFs();
    const deps = {
      fs: {
        ...fs,
        stat: async () => ({ isFile: true, size: 10 }),
        readFile: async () => {
          throw Object.assign(new Error("gone"), { code: "ENOENT" });
        },
      },
    };
    const missing = makeStore({ deps });
    await expect(missing.store.load()).resolves.toMatchObject({ kind: "missing" });

    const unavailable = makeStore({
      deps: {
        fs: {
          ...fs,
          stat: async () => ({ isFile: true, size: 10 }),
          readFile: async () => {
            throw Object.assign(new Error("denied"), { code: "EACCES" });
          },
        },
      },
    });
    await expect(unavailable.store.load()).resolves.toMatchObject({ kind: "unavailable", category: "io" });
  });
});

describe("project rules atomic commit", () => {
  it("creates the project directory and writes revision 1 from a missing file", async () => {
    const { store, filePath } = makeStore();
    const result = await store.commit(applyChange([rule("rule-0123456789abcdef01234567")]), 0);
    expect(result).toMatchObject({ kind: "committed", previousRevision: 0, revision: 1 });
    const loaded = await store.load();
    if (loaded.kind !== "available") throw new Error("expected available");
    expect(loaded.file.revision).toBe(1);
    await expect(readFile(filePath, "utf8")).resolves.toMatch(/\n$/);
  });

  it("bumps the revision on an existing file and updates the cache", async () => {
    const { store, filePath } = makeStore();
    await writeRules(filePath, rulesFile(3));
    const result = await store.commit(applyChange([rule("rule-0123456789abcdef01234567")]), 3);
    expect(result).toMatchObject({ kind: "committed", previousRevision: 3, revision: 4 });
    if (result.kind !== "committed") throw new Error("expected committed");
    expect(result.ruleIds).toEqual(["rule-0123456789abcdef01234567"]);
    const loaded = await store.load();
    if (loaded.kind !== "available") throw new Error("expected available");
    expect(loaded.file.revision).toBe(4);
  });

  it("hands a missing file to the change as an empty revision 0 file", async () => {
    const { store } = makeStore();
    let seenRevision: number | undefined;
    let seenRules: readonly StoredProjectRule[] | undefined;
    let seenIdentity = "";
    await store.commit({
      apply: (input) => {
        seenRevision = input.revision;
        seenRules = input.file.rules;
        seenIdentity = input.file.identity.identityHash;
        return { kind: "apply", rules: [], tombstones: [] };
      },
    }, 0);
    expect(seenRevision).toBe(0);
    expect(seenRules).toEqual([]);
    expect(seenIdentity).toBe(identity.identityHash);
  });

  it("does not create the rules file for a no-change on a missing file", async () => {
    const { store, filePath } = makeStore();
    expect(await store.commit(noChange, 0)).toEqual({ kind: "no-change", revision: 0 });
    expect((await store.load()).kind).toBe("missing");
    await expect(readFile(filePath, "utf8")).rejects.toThrow();
  });

  it("reports a revision conflict and leaves the file unchanged", async () => {
    const { store, filePath } = makeStore();
    await writeRules(filePath, rulesFile(3));
    const before = await readFile(filePath, "utf8");
    expect(await store.commit(applyChange([rule("rule-0123456789abcdef01234567")]), 1)).toEqual({
      kind: "revision-conflict",
      expectedRevision: 1,
      revision: 3,
    });
    await expect(readFile(filePath, "utf8")).resolves.toBe(before);
  });

  it("does not touch the file for no-change and rejected changes", async () => {
    const { store, filePath } = makeStore();
    await writeRules(filePath, rulesFile(3));
    const before = await readFile(filePath, "utf8");
    expect(await store.commit(noChange, 3)).toEqual({ kind: "no-change", revision: 3 });
    expect(await store.commit({ apply: () => ({ kind: "reject", reason: "capacity" }) }, 3)).toEqual({
      kind: "rejected",
      revision: 3,
      reason: "capacity",
    });
    await expect(readFile(filePath, "utf8")).resolves.toBe(before);
  });

  it("refuses to publish when the guard is no longer current", async () => {
    const { store, filePath } = makeStore();
    await writeRules(filePath, rulesFile(3));
    const before = await readFile(filePath, "utf8");
    const stale = await store.commit(applyChange([rule("rule-0123456789abcdef01234567")]), 0, { isCurrent: () => false });
    expect(stale).toEqual({ kind: "stale-guard", revision: 0 });
    let calls = 0;
    const flaky = await store.commit(applyChange([rule("rule-0123456789abcdef01234567")]), 3, {
      isCurrent: () => ++calls === 1,
    });
    expect(flaky).toEqual({ kind: "stale-guard", revision: 3 });
    await expect(readFile(filePath, "utf8")).resolves.toBe(before);
    expect((await readdir(join(root, "project"))).filter((entry) => entry.endsWith(".tmp"))).toEqual([]);
  });

  it("treats a throwing guard as stale", async () => {
    const { store } = makeStore();
    const result = await store.commit(applyChange([rule("rule-0123456789abcdef01234567")]), 0, {
      isCurrent: () => {
        throw new Error("owner gone");
      },
    });
    expect(result).toEqual({ kind: "stale-guard", revision: 0 });
  });

  it("reports a next file that fails validation as rejected", async () => {
    const { store, filePath } = makeStore();
    await writeRules(filePath, rulesFile(3));
    const missingProvenance = { ...rule("rule-0123456789abcdef01234567") } as unknown as StoredProjectRule;
    (missingProvenance as unknown as Record<string, unknown>).provenance = undefined;
    const result = await store.commit(applyChange([missingProvenance]), 3);
    expect(result).toMatchObject({ kind: "rejected", revision: 3 });
  });

  it("maps a throwing change to a failed commit and releases the lock", async () => {
    const { store, filePath } = makeStore();
    const result = await store.commit({ apply: () => { throw new Error("boom"); } }, 0);
    expect(result.kind).toBe("failed");
    // A later commit still acquires the lock.
    expect(await store.commit(applyChange([rule("rule-0123456789abcdef01234567")]), 0)).toMatchObject({ kind: "committed", revision: 1 });
    await expect(readFile(filePath, "utf8")).resolves.toContain("\"revision\": 1");
  });

  it("removes the temporary file when publication fails and leaves the original", async () => {
    const fs = createDefaultProjectRulesFs();
    let failRename = true;
    const { store, filePath, directory } = makeStore({
      deps: {
        fs: {
          ...fs,
          rename: async (from, to) => {
            if (failRename) {
              failRename = false;
              throw Object.assign(new Error("rename failed"), { code: "EIO" });
            }
            return fs.rename(from, to);
          },
        },
      },
    });
    await writeRules(filePath, rulesFile(3));
    const before = await readFile(filePath, "utf8");
    expect(await store.commit(applyChange([rule("rule-0123456789abcdef01234567")]), 3)).toMatchObject({ kind: "failed", category: "io" });
    await expect(readFile(filePath, "utf8")).resolves.toBe(before);
    expect((await readdir(directory)).filter((entry) => entry.endsWith(".tmp"))).toEqual([]);
    // The lock is released, so a retry can publish.
    expect(await store.commit(applyChange([rule("rule-0123456789abcdef01234567")]), 3)).toMatchObject({ kind: "committed", revision: 4 });
  });

  it("tolerates a directory fsync failure after a successful file sync", async () => {
    const fs = createDefaultProjectRulesFs();
    const { store } = makeStore({
      deps: {
        fs: {
          ...fs,
          fsyncDirectory: async () => {
            throw Object.assign(new Error("cannot sync directory"), { code: "EPERM" });
          },
        },
      },
    });
    expect(await store.commit(applyChange([rule("rule-0123456789abcdef01234567")]), 0)).toMatchObject({ kind: "committed", revision: 1 });
  });
});

describe("project rules lock ownership", () => {
  async function writeLock(lockPath: string, owner: unknown): Promise<void> {
    await mkdir(lockPath, { recursive: true });
    await writeFile(join(lockPath, "owner.json"), typeof owner === "string" ? owner : JSON.stringify(owner), "utf8");
  }

  it("recovers a stale lock whose process is gone and that is old enough", async () => {
    const { store, lockPath } = makeStore();
    await writeLock(lockPath, { token: "dead-token", pid: 999_999, createdAt: Date.now() - 60_000 });
    const result = await store.commit(applyChange([rule("rule-0123456789abcdef01234567")]), 0, undefined);
    expect(result).toMatchObject({ kind: "committed", revision: 1 });
    await expect(readdir(lockPath)).rejects.toThrow();
  });

  it("does not break a lock whose process is still alive", async () => {
    const { store, lockPath } = makeStore({ deps: { processAlive: () => true, lockTimeoutMs: 25, lockRetryMs: 5 } });
    await writeLock(lockPath, { token: "live-token", pid: 4_242, createdAt: Date.now() - 60_000 });
    expect(await store.commit(applyChange([rule("rule-0123456789abcdef01234567")]), 0)).toMatchObject({ kind: "failed", category: "lock" });
    await expect(readFile(join(lockPath, "owner.json"), "utf8")).resolves.toContain("live-token");
  });

  it("does not break a young lock", async () => {
    const { store, lockPath } = makeStore({ deps: { lockTimeoutMs: 25, lockRetryMs: 5 } });
    await writeLock(lockPath, { token: "young-token", pid: 999_999, createdAt: Date.now() });
    expect(await store.commit(applyChange([rule("rule-0123456789abcdef01234567")]), 0)).toMatchObject({ kind: "failed", category: "lock" });
  });

  it("does not treat corrupt owner metadata as stale", async () => {
    const { store, lockPath } = makeStore({ deps: { lockTimeoutMs: 25, lockRetryMs: 5 } });
    await writeLock(lockPath, "not json");
    expect(await store.commit(applyChange([rule("rule-0123456789abcdef01234567")]), 0)).toMatchObject({ kind: "failed", category: "lock" });
    await expect(readdir(lockPath)).resolves.toHaveLength(1);
  });

  it("waits for a live lock to be released and then commits", async () => {
    const { store } = makeStore({ deps: { lockTimeoutMs: 30, lockRetryMs: 5 } });
    let releaseChange: (() => void) | undefined;
    const slow: ProjectRulesChange = {
      apply: () => new Promise((resolve) => {
        releaseChange = () => resolve({ kind: "no-change" });
      }),
    };
    const holding = store.commit(slow, 0);
    // Wait until the lock directory exists.
    for (let attempt = 0; attempt < 200; attempt += 1) {
      try {
        await readdir(join(root, "project", "project-rules.lock"));
        break;
      } catch {
        await new Promise((resolve) => setTimeout(resolve, 2));
      }
    }
    const competitor = makeStore({ deps: { lockTimeoutMs: 30, lockRetryMs: 5 } }).store;
    expect(await competitor.commit(noChange, 0)).toMatchObject({ kind: "failed", category: "lock" });
    releaseChange!();
    await expect(holding).resolves.toMatchObject({ kind: "no-change" });
    expect(await competitor.commit(applyChange([rule("rule-0123456789abcdef01234567")]), 0)).toMatchObject({ kind: "committed" });
  });

  it("does not publish or delete a lock after ownership changes", async () => {
    const fs = createDefaultProjectRulesFs();
    const { store, lockPath, filePath } = makeStore({
      deps: {
        fs: {
          ...fs,
          writeFileExclusive: async (path, content, mode) => {
            await fs.writeFileExclusive(path, content, mode);
            // Another process steals the lock after we wrote our temporary file.
            await writeFile(join(lockPath, "owner.json"), JSON.stringify({ token: "thief", pid: 1, createdAt: Date.now() }), "utf8");
          },
        },
      },
    });
    await writeRules(filePath, rulesFile(3));
    const before = await readFile(filePath, "utf8");
    expect(await store.commit(applyChange([rule("rule-0123456789abcdef01234567")]), 3)).toMatchObject({ kind: "failed", category: "lock" });
    await expect(readFile(filePath, "utf8")).resolves.toBe(before);
    // The thief's lock is not deleted by our release.
    await expect(readFile(join(lockPath, "owner.json"), "utf8")).resolves.toContain("thief");
    expect((await readdir(join(root, "project"))).filter((entry) => entry.endsWith(".tmp"))).toEqual([]);
  });
});

describe("service over the real file store", () => {
  const action: ExactAction = {
    requestId: "req-1",
    tool: { name: "bash", origin: "builtin", definitionRevision: "7" },
    definitionDigest: "definition-digest",
    arguments: argumentsValue,
    argumentsDigest,
    cwd: "/work/project",
    environmentDigest: "environment-digest",
    scopes: [{ id: "s1", surface: "bash", target: "cat file.txt", access: "other" }],
  };

  function matchedRule(id: string): StoredProjectRule {
    const match = buildExactMatch(action);
    if (match === undefined) throw new Error("expected a built match");
    return rule(id, { match });
  }

  function openBarrier(): ProjectRulesIntentBarrier {
    return {
      revision: 1,
      needsReconciliation: () => false,
      currentTaskPaused: () => false,
      learningDisabled: () => false,
      holdsRevision: () => ({ isCurrent: () => true }),
    };
  }

  function service(store: FileProjectRulesStore): ProjectRulesService {
    return new ProjectRulesService({ store, identity, barrier: openBarrier(), now: () => new Date("2026-01-02T00:00:00.000Z") });
  }

  it("evaluates an allow, then revokes it through the store and records a tombstone", async () => {
    const { store } = makeStore();
    const ruleId = "rule-0123456789abcdef01234567";
    await store.commit(applyChange([matchedRule(ruleId)]), 0);
    const rules = service(store);

    const allowed = await rules.evaluate(action);
    expect(allowed).toMatchObject({ kind: "allow", revision: 1, ruleIds: [ruleId] });
    if (allowed.kind !== "allow") throw new Error("expected allow");
    expect(allowed.coveredScopeIds).toEqual(["s1"]);
    expect(allowed.remainingAskScopeIds).toEqual([]);

    expect(await rules.revoke({ ruleId, actor: "user-1", reason: "no longer needed" })).toMatchObject({
      kind: "revoked",
      revision: 2,
      ruleIds: [ruleId],
    });

    const loaded = await store.load();
    if (loaded.kind !== "available") throw new Error("expected available");
    expect(loaded.file.revision).toBe(2);
    const revoked = loaded.file.rules.find((item) => item.id === ruleId);
    expect(revoked).toMatchObject({ status: "revoked", revocation: { actor: "user-1", reason: "no longer needed" } });
    expect(loaded.file.tombstones).toEqual([
      { ruleId, effect: "allow", matchDigest: expect.any(String), revokedAt: "2026-01-02T00:00:00.000Z", revision: 2 },
    ]);
    // A revoked rule no longer evaluates as an allow.
    expect((await rules.evaluate(action)).kind).toBe("none");
    // The list reports the revoked status.
    const listed = await rules.list();
    expect(listed.kind).toBe("available");
    if (listed.kind !== "available") throw new Error("expected available");
    expect(listed.rules.map((item) => [item.id, item.status])).toEqual([[ruleId, "revoked"]]);
  });

  it("reports a definition change for review instead of reusing the old allow", async () => {
    const { store } = makeStore();
    const ruleId = "rule-0123456789abcdef01234567";
    await store.commit(applyChange([matchedRule(ruleId)]), 0);
    const rules = service(store);
    const evaluation = await rules.evaluate({ ...action, definitionDigest: "definition-digest-2" });
    expect(evaluation.kind).toBe("none");
    if (evaluation.kind !== "none") throw new Error("expected none");
    expect(evaluation.needsReviewRuleIds).toEqual([ruleId]);
  });

  it("marks a rule for review through the real store without adding a tombstone", async () => {
    const { store } = makeStore();
    const ruleId = "rule-0123456789abcdef01234567";
    await store.commit(applyChange([matchedRule(ruleId)]), 0);
    const rules = service(store);
    expect(await rules.markNeedsReview({ ruleId, reason: "definition changed" })).toMatchObject({ kind: "marked", revision: 2 });
    expect(await rules.markNeedsReview({ ruleId })).toMatchObject({ kind: "already-needs-review" });
    const loaded = await store.load();
    if (loaded.kind !== "available") throw new Error("expected available");
    expect(loaded.file.tombstones).toEqual([]);
    expect(loaded.file.rules[0]).toMatchObject({ status: "needs_review", updatedAt: "2026-01-02T00:00:00.000Z" });
  });
});
