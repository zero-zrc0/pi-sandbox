import { mkdirSync, mkdtempSync, realpathSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { collectSensitivePaths, sensitivePathIdentityMatches } from "#sandbox/sensitive-paths";
import { normalizeHostPath } from "#sandbox/path";

const directories: string[] = [];
afterEach(() => {
  for (const path of directories.splice(0)) rmSync(path, { recursive: true, force: true });
});

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "sensitive-paths-"));
  directories.push(root);
  const home = join(root, "home");
  const agentDirectory = join(root, "agent");
  mkdirSync(home);
  mkdirSync(agentDirectory);
  return { root, home, agentDirectory, cwd: root, environment: {}, systemPaths: [] };
}

function canonical(path: string): string {
  return normalizeHostPath(realpathSync.native(path))!;
}

describe("sensitive path collection", () => {
  it("collects existing built-in and configured files and directories once", () => {
    const input = fixture();
    mkdirSync(join(input.home, ".ssh"));
    writeFileSync(join(input.agentDirectory, "auth.json"), "fixture");
    writeFileSync(join(input.home, "private.txt"), "fixture");
    const github = join(input.root, "github-config");
    mkdirSync(github);
    const paths = collectSensitivePaths({ ...input, environment: { GH_CONFIG_DIR: github },
      denyPaths: ["~/private.txt", join(input.home, ".ssh")] });
    expect(paths.map(({ path, granularity }) => ({ path, granularity }))).toEqual(expect.arrayContaining([
      { path: canonical(join(input.agentDirectory, "auth.json")), granularity: "file" },
      { path: canonical(join(input.home, ".ssh")), granularity: "directory" },
      { path: canonical(join(input.home, "private.txt")), granularity: "file" },
      { path: canonical(github), granularity: "directory" },
    ]));
    expect(paths).toHaveLength(4);
    expect(paths.every(entry => /^\d+$/u.test(entry.identity.device) && /^\d+$/u.test(entry.identity.inode))).toBe(true);
  });

  it("uses the supplied macOS system path list", () => {
    const input = fixture();
    const systemFile = join(input.root, "system-auth.db");
    writeFileSync(systemFile, "fixture");
    const [entry] = collectSensitivePaths({ ...input, platform: "darwin",
      systemPaths: [systemFile] });
    expect(entry).toMatchObject({ path: canonical(systemFile), granularity: "file" });
  });

  it("omits absent built-ins and reports a missing explicitly configured path", () => {
    const input = fixture();
    expect(collectSensitivePaths(input)).toEqual([]);
    expect(() => collectSensitivePaths({ ...input, denyPaths: ["missing"] })).toThrow(/sensitive path missing:/u);
  });

  it("detects replacement of a protected object after collection", () => {
    const input = fixture();
    const target = join(input.root, "secret");
    const replacement = join(input.root, "replacement");
    writeFileSync(target, "first");
    writeFileSync(replacement, "replacement");
    const [entry] = collectSensitivePaths({ ...input, denyPaths: [target] });
    const [replacementEntry] = collectSensitivePaths({ ...input, denyPaths: [replacement] });
    expect(entry).toBeDefined();
    expect(replacementEntry?.identity).not.toEqual(entry?.identity);
    expect(sensitivePathIdentityMatches(entry!)).toBe(true);
    renameSync(target, join(input.root, "previous"));
    renameSync(replacement, target);
    expect(sensitivePathIdentityMatches(entry!)).toBe(false);
  });

  it.skipIf(process.platform === "win32")("fails when an optional path has a dangling link ancestor", () => {
    const input = fixture();
    symlinkSync(join(input.root, "missing"), join(input.home, ".config"));
    expect(() => collectSensitivePaths(input)).toThrow(/sensitive path/u);
  });
});
