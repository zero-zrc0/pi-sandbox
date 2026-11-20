import { lstatSync, realpathSync, statSync } from "node:fs";
import { dirname, isAbsolute, join, resolve, sep } from "node:path";
import { homedir } from "node:os";
import { normalizeHostPath, pathKey } from "./path";

export interface SensitivePath {
  readonly requestedPath: string;
  readonly path: string;
  readonly granularity: "file" | "directory";
  readonly identity: { readonly device: string; readonly inode: string };
}

export const MACOS_SYSTEM_PATHS = [
  { path: "/private/var/db/dslocal", granularity: "directory" },
  { path: "/private/var/db/DarwinDirectory", granularity: "directory" },
  { path: "/private/var/db/auth.db", granularity: "file" },
  { path: "/private/etc/master.passwd", granularity: "file" },
  { path: "/private/etc/sudoers", granularity: "file" },
  { path: "/private/etc/sudoers.d", granularity: "directory" },
  { path: "/private/var/db/sudo", granularity: "directory" },
  { path: "/private/var/db/SystemPolicyConfiguration", granularity: "directory" },
  { path: "/Library/Keychains/System.keychain", granularity: "file" },
  { path: "/Library/Application Support/com.apple.TCC/TCC.db", granularity: "file" },
] as const;

function confirmMissingPath(path: string): void {
  let parent = dirname(path);
  for (;;) {
    try {
      lstatSync(parent);
      realpathSync.native(parent);
      return;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      try {
        lstatSync(parent);
        throw new Error(`cannot resolve existing path: ${parent}`);
      } catch (parentError) {
        if ((parentError as NodeJS.ErrnoException).code !== "ENOENT") throw parentError;
      }
      const next = dirname(parent);
      if (next === parent) throw error;
      parent = next;
    }
  }
}

export function sensitivePathIdentityMatches(entry: SensitivePath): boolean {
  try {
    const canonical = normalizeHostPath(realpathSync.native(entry.requestedPath));
    if (!canonical || pathKey(canonical) !== pathKey(entry.path)) return false;
    const stats = statSync(canonical, { bigint: true });
    return (entry.granularity === "file" ? stats.isFile() : stats.isDirectory()) &&
      String(stats.dev) === entry.identity.device && String(stats.ino) === entry.identity.inode;
  } catch {
    return false;
  }
}

/** Resolve the paths present at plan creation; configured paths are required. */
export function collectSensitivePaths(input: {
  readonly agentDirectory: string;
  readonly cwd: string;
  readonly denyPaths?: readonly string[];
  readonly home?: string;
  readonly environment?: NodeJS.ProcessEnv;
  readonly platform?: NodeJS.Platform;
}): readonly SensitivePath[] {
  const home = input.home ?? homedir();
  const env = input.environment ?? process.env;
  const platform = input.platform ?? process.platform;
  const githubBase = env.GH_CONFIG_DIR || (env.XDG_CONFIG_HOME
    ? join(env.XDG_CONFIG_HOME, "gh")
    : platform === "win32" && env.AppData
      ? join(env.AppData, "GitHub CLI")
      : join(home, ".config", "gh"));
  const optional = [
    join(input.agentDirectory, "auth.json"),
    ...[".ssh", ".gnupg", ".aws", ".git-credentials", ".netrc"].map(name => join(home, name)),
    githubBase,
    ...(platform === "darwin" ? [
      ...[".azure", ".config", ".docker", ".kube", ".npmrc", ".pypirc", ".pi/agent/auth.json",
        "Library/Keychains", "Library/Application Support/com.apple.TCC/TCC.db"].map(name => join(home, name)),
      ...MACOS_SYSTEM_PATHS.map(entry => entry.path),
    ] : []),
  ];
  const records: SensitivePath[] = [];
  const seen = new Set<string>();
  for (const [path, required] of [
    ...optional.map(path => [path, false] as const),
    ...(input.denyPaths ?? []).map(path => [path, true] as const),
  ]) {
    const expanded = path === "~" ? home : path.startsWith(`~${sep}`) || path.startsWith("~/")
      ? join(home, path.slice(2)) : path;
    if (!expanded || expanded.includes("\0") || expanded.startsWith("~")) {
      throw new Error(`invalid sensitive path: ${path}`);
    }
    const absolute = normalizeHostPath(isAbsolute(expanded) ? expanded : resolve(input.cwd, expanded));
    if (!absolute) throw new Error(`invalid sensitive path: ${path}`);
    try {
      lstatSync(absolute);
    } catch (error) {
      if (!required && (error as NodeJS.ErrnoException).code === "ENOENT") {
        try {
          confirmMissingPath(absolute);
          continue;
        } catch (identityError) {
          throw new Error(`sensitive path ${path}: ${identityError instanceof Error ? identityError.message : String(identityError)}`);
        }
      }
      throw new Error(`sensitive path ${path}: ${error instanceof Error ? error.message : String(error)}`);
    }
    try {
      const canonical = normalizeHostPath(realpathSync.native(absolute));
      if (!canonical) throw new Error("canonical path is invalid");
      const stats = statSync(canonical, { bigint: true });
      const granularity = stats.isFile() ? "file" : stats.isDirectory() ? "directory" : undefined;
      if (!granularity) throw new Error("target is not a regular file or directory");
      const key = pathKey(absolute);
      if (!seen.has(key)) {
        seen.add(key);
        records.push({ requestedPath: absolute, path: canonical, granularity,
          identity: { device: String(stats.dev), inode: String(stats.ino) } });
      }
    } catch (error) {
      throw new Error(`sensitive path ${path}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  return records;
}
