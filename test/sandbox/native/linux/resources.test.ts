import { beforeEach, describe, expect, it, vi } from "vitest";
import { assessCgroupV2Resources } from "#sandbox/backend/linux/resources";

const files = vi.hoisted(() => new Map<string, string | Error>());
vi.mock("node:fs", async importOriginal => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    realpathSync: (path: string) => path,
    accessSync: () => { throw Object.assign(new Error("not delegated"), { code: "EACCES" }); },
    readFileSync: (path: string) => {
      const value = files.get(path);
      if (value instanceof Error) throw value;
      if (value === undefined) throw Object.assign(new Error(`missing: ${path}`), { code: "ENOENT" });
      return value;
    },
  };
});

describe.skipIf(process.platform !== "linux")("cgroup v2 resource assessment", () => {
  beforeEach(() => {
    files.clear();
    for (const [path, value] of Object.entries({
      "/proc/self/cgroup": "0::/init.scope\n",
      "/sys/fs/cgroup/init.scope/cgroup.controllers": "cpu memory pids\n",
      "/sys/fs/cgroup/init.scope/cpu.stat": "usage_usec 123\n",
      "/sys/fs/cgroup/init.scope/memory.current": "4096\n",
      "/sys/fs/cgroup/init.scope/memory.peak": "8192\n",
      "/sys/fs/cgroup/init.scope/pids.current": "3\n",
      "/sys/fs/cgroup/init.scope/cpu.max": "max 100000\n",
      "/sys/fs/cgroup/init.scope/memory.max": "max\n",
      "/sys/fs/cgroup/init.scope/pids.max": "max\n",
    })) files.set(path, value);
  });

  it("retains measured usage when the root cgroup has no quota files", () => {
    expect(assessCgroupV2Resources()).toMatchObject({ status: "available", delegated: false,
      usage: { "cpu.stat": "usage_usec 123", "memory.current": "4096", "pids.current": "3" },
      ancestorLimits: [{ path: "/sys/fs/cgroup/init.scope", limits: { "cpu.max": "max 100000" } },
        { path: "/sys/fs/cgroup", limits: {} }],
    });
  });

  it("omits absent measurements without inventing a resource limit", () => {
    files.delete("/sys/fs/cgroup/init.scope/memory.peak");
    const snapshot = assessCgroupV2Resources();
    expect(snapshot.status).toBe("available");
    expect(snapshot.usage).not.toHaveProperty("memory.peak");
    expect(snapshot.ancestorLimits?.at(-1)?.limits).toEqual({});
  });

  it("reports permission failures instead of treating them as absent measurements", () => {
    files.set("/sys/fs/cgroup/init.scope/cpu.stat", Object.assign(new Error("permission denied"), { code: "EACCES" }));
    expect(assessCgroupV2Resources()).toMatchObject({ status: "unavailable", reason: "permission denied" });
  });
});
