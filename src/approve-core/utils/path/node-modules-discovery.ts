/**
 * Global node_modules discovery.
 *
 * Prefer an ancestor directory literally named `node_modules` starting from
 * the given module URL. Only when that fails, run `npm root -g`
 * synchronously with a five-second ceiling. Every failure mode returns no
 * result so callers can degrade.
 */
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";

export interface GlobalNodeModulesOptions {
  readonly exists?: (path: string) => boolean;
  readonly runNpmRoot?: () => { readonly status: number | null; readonly stdout: string };
  readonly timeoutMs?: number;
}

const DEFAULT_TIMEOUT_MS = 5_000;

function lastSegmentIndex(path: string): number {
  let last = -1;
  for (let i = 0; i < path.length; i += 1) {
    if (path[i] === "/" || path[i] === "\\") last = i;
  }
  return last;
}

function parentDir(path: string): string | undefined {
  const last = lastSegmentIndex(path);
  if (last <= 0) return undefined;
  return path.slice(0, last);
}

function baseName(path: string): string {
  const last = lastSeparatorOrRoot(path);
  return path.slice(last + 1);
}

function lastSeparatorOrRoot(path: string): number {
  const last = lastSegmentIndex(path);
  // A leading separator is part of the root, not a segment boundary.
  return last === 0 ? -1 : last;
}

function ancestorNodeModules(startDir: string, exists: (path: string) => boolean): string | undefined {
  let current: string | undefined = startDir;
  while (current !== undefined) {
    if (baseName(current) === "node_modules" && exists(current)) return current;
    current = parentDir(current);
  }
  return undefined;
}

/**
 * Locate the global node_modules directory for a module URL. Returns
 * undefined when nothing can be proven; the caller must degrade.
 */
export function findGlobalNodeModules(
  moduleUrl: string,
  options: GlobalNodeModulesOptions = {},
): string | undefined {
  const exists = options.exists ?? existsSync;

  let startDir: string;
  try {
    const url = new URL(moduleUrl);
    if (url.protocol !== "file:") return undefined;
    if (url.hostname !== "" && url.hostname !== "localhost") return undefined;
    const filePath = decodeURIComponent(url.pathname);
    const last = lastSegmentIndex(filePath);
    startDir = last === -1 ? filePath : filePath.slice(0, last);
  } catch {
    return undefined;
  }

  const local = ancestorNodeModules(startDir, exists);
  if (local !== undefined) return local;

  const run = options.runNpmRoot ?? (() =>
    spawnSync("npm", ["root", "-g"], {
      encoding: "utf8",
      timeout: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      shell: process.platform === "win32",
    }));
  let result: { readonly status: number | null; readonly stdout: string };
  try {
    result = run();
  } catch {
    return undefined;
  }
  if (result.status !== 0) return undefined;
  const candidate = result.stdout.trim();
  if (candidate.length === 0 || !exists(candidate)) return undefined;
  return candidate;
}
