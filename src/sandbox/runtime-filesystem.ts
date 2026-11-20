import { existsSync, realpathSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join, parse } from "node:path";
import type { ExecutionOperation, FilesystemGrantInput } from "./types";

export const MACOS_SYSTEM_READ_PATHS = [
  "/System/Library", "/System/Volumes/Preboot", "/bin", "/private/var/db/dyld", "/sbin",
  "/usr/bin", "/usr/lib", "/usr/libexec", "/usr/share",
] as const;
export const MACOS_SYSTEM_READ_FILES = [
  "/dev/null", "/dev/random", "/dev/urandom", "/etc/group", "/etc/hosts", "/etc/localtime", "/etc/passwd",
  "/private/etc/group", "/private/etc/hosts", "/private/etc/localtime", "/private/etc/passwd",
] as const;

export function macOSRuntimeFilesystem(installRoot: string): {
  readonly grants: readonly FilesystemGrantInput[];
  readonly protectedPaths: readonly string[];
} {
  const grants: FilesystemGrantInput[] = [];
  const protectedPaths: string[] = [];
  const add = (value: string, granularity: "file" | "directory", optional = false, protect = false) => {
    try {
      const path = realpathSync.native(value);
      const stats = statSync(path);
      if (granularity === "directory" ? !stats.isDirectory() : !stats.isFile() && !stats.isCharacterDevice()) {
        throw new Error(`unexpected runtime path type: ${value}`);
      }
      grants.push({ path, access: "read", granularity });
      if (protect) protectedPaths.push(path);
    } catch (error) {
      if (!optional || (error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  };
  for (const path of MACOS_SYSTEM_READ_PATHS) add(path, "directory", true);
  for (const path of MACOS_SYSTEM_READ_FILES) add(path, "file", true);
  const nullPath = realpathSync.native("/dev/null");
  grants.push({ path: nullPath, access: "write", granularity: "file" });
  add(process.execPath, "file", false, true);
  add(dirname(process.execPath), "directory");
  add(installRoot, "directory", false, true);
  add("/usr/bin/sandbox-exec", "file", false, true);
  return { grants, protectedPaths };
}

export function windowsRuntimeFilesystem(input: {
  readonly cwd: string;
  readonly installRoot: string;
  readonly agentDirectory: string;
  readonly operation: ExecutionOperation;
  readonly environment: Readonly<Record<string, string>>;
  readonly includeWorkingDirectoryVolumeRoot?: boolean;
}): { readonly grants: readonly FilesystemGrantInput[]; readonly protectedPaths: readonly string[] } {
  const systemRoot = process.env.SystemRoot;
  if (!systemRoot) throw new Error("Windows system root is unavailable");
  const grants: FilesystemGrantInput[] = [];
  const protectedPaths: string[] = [];
  const add = (value: string, granularity: "file" | "directory", protect = false) => {
    const path = realpathSync.native(value);
    const stats = statSync(path);
    if (granularity === "file" ? !stats.isFile() : !stats.isDirectory()) {
      throw new Error(`runtime path has an unexpected type: ${value}`);
    }
    grants.push({ path, access: "read", granularity });
    if (protect) protectedPaths.push(path);
  };
  add(systemRoot, "directory");
  if (input.includeWorkingDirectoryVolumeRoot !== false) add(parse(input.cwd).root, "directory");
  const operation = input.operation;
  if (operation.kind !== "builtin-tool" && operation.kind !== "sandbox-tool") return { grants, protectedPaths };
  add(input.installRoot, "directory", true);
  add(process.execPath, "file", true);
  if (operation.kind === "builtin-tool" && (operation.name === "grep" || operation.name === "find")) {
    const binary = operation.name === "grep" ? "rg.exe" : "fd.exe";
    const local = join(input.agentDirectory, "bin", binary);
    const tools: string[] = existsSync(local) ? [local] : [];
    if (tools.length === 0) {
      const where = join(systemRoot, "System32", "where.exe");
      for (const name of operation.name === "grep" ? ["rg.exe"] : ["fd.exe", "fdfind.exe"]) {
        const found = spawnSync(where, [name], { cwd: input.cwd,
          env: { ...process.env, PATH: input.environment.PATH ?? "" }, encoding: "utf8", windowsHide: true, timeout: 3_000 });
        const tool = found.status === 0 ? found.stdout.split(/\r?\n/u).find(Boolean) : undefined;
        if (tool) tools.push(tool);
      }
    }
    if (tools.length === 0) throw new Error(`required ${binary} runtime is unavailable`);
    for (const tool of new Set(tools)) add(tool, "file", true);
  }
  return { grants, protectedPaths };
}

export function linuxRuntimeFilesystem(input: {
  readonly installRoot: string;
  readonly operation: ExecutionOperation;
}): { readonly grants: readonly FilesystemGrantInput[]; readonly protectedPaths: readonly string[] } {
  const grants: FilesystemGrantInput[] = [];
  const protectedPaths: string[] = [];
  const add = (value: string, granularity: "file" | "directory", optional = false, protect = false) => {
    try {
      const path = realpathSync.native(value);
      const stats = statSync(path);
      if (granularity === "file" ? !stats.isFile() : !stats.isDirectory()) throw new Error(`unexpected runtime path type: ${value}`);
      grants.push({ path, access: "read", granularity });
      if (protect) protectedPaths.push(path);
    } catch (error) {
      if (!optional || (error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  };
  add("/usr", "directory");
  add("/etc/ld.so.cache", "file", true);
  add("/etc/ssl/openssl.cnf", "file", true);
  grants.push({ path: "/dev", access: "read", granularity: "directory" },
    { path: "/dev", access: "write", granularity: "directory" });
  if (input.operation.kind === "builtin-tool" || input.operation.kind === "sandbox-tool") {
    add(input.installRoot, "directory", false, true);
    add(process.execPath, "file", false, true);
  }
  return { grants, protectedPaths };
}
