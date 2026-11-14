import { accessSync, constants, readFileSync, realpathSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { isPathWithin } from "../../path";

export interface CgroupResourceSnapshot {
  readonly status: "available" | "unavailable";
  readonly reason?: string;
  readonly path?: string;
  readonly controllers?: readonly string[];
  readonly delegated?: boolean;
  readonly usage?: Readonly<Record<string, string>>;
  readonly ancestorLimits?: readonly { path: string; limits: Readonly<Record<string, string>> }[];
}

/** Report measured values and inherited ceilings; this function chooses no quotas. */
export function assessCgroupV2Resources(): CgroupResourceSnapshot {
  if (process.platform !== "linux") return { status: "unavailable", reason: "cgroup v2 requires native Linux" };
  try {
    const root = realpathSync("/sys/fs/cgroup");
    const membership = readFileSync("/proc/self/cgroup", "utf8").split("\n").find(line => line.startsWith("0::"));
    if (!membership) return { status: "unavailable", reason: "the process has no unified cgroup v2 membership" };
    const path = realpathSync(resolve(root, `.${membership.slice(3)}`));
    if (!isPathWithin(root, path)) return { status: "unavailable", reason: "cgroup membership is outside the visible mount" };
    const readValues = (directory: string, names: readonly string[]) => Object.fromEntries(names.flatMap(name => {
      try { return [[name, readFileSync(join(directory, name), "utf8").trim()]]; }
      catch (error) {
        // The root cgroup has no quota files; disabled controllers and older
        // kernels can also omit individual measurements.
        if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
        throw error;
      }
    }));
    const usage = readValues(path, ["cpu.stat", "memory.current", "memory.peak", "pids.current"]);
    const ancestorLimits = [];
    for (let current = path; ; current = dirname(current)) {
      ancestorLimits.push({ path: current, limits: readValues(current, ["cpu.max", "memory.max", "pids.max"]) });
      if (current === root) break;
    }
    let delegated = false;
    try { accessSync(join(path, "cgroup.procs"), constants.W_OK); accessSync(join(path, "cgroup.subtree_control"), constants.W_OK); delegated = true; } catch {}
    return { status: "available", path, controllers: readFileSync(join(path, "cgroup.controllers"), "utf8").trim().split(/\s+/).filter(Boolean), delegated, usage, ancestorLimits };
  } catch (error) {
    return { status: "unavailable", reason: error instanceof Error ? error.message : String(error) };
  }
}
