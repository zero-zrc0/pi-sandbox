import { expect, it } from "vitest";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { createLinuxDirectBackend } from "#sandbox/backend/linux/direct";
import { probeBubblewrap } from "#sandbox/backend/linux/direct-launch.mjs";
import { linuxRuntimeFilesystem } from "#sandbox/runtime-filesystem";
import type { ResolvedRuntimeFiles } from "#sandbox/runtime-store";
import { createTestDirectBackend } from "./fixtures/direct-backend";
import { compileTestRequest, makeInvocation, runtimeEnvironment, waitFor, waitForProcessGone } from "./fixtures/harness";

it("reuses the Linux capability result and selected bundled bubblewrap from runtime preparation", async () => {
  const original = await createTestDirectBackend().probe();
  if (!original.ok) throw new Error("test backend probe failed");
  const runtime = {
    directory: "/runtime/final", storageRoot: "/runtime", files: {
      linuxLauncher: "/runtime/final/linux-sandbox", egressBridge: "/runtime/final/linux-egress-bridge",
      bubblewrap: "/runtime/final/bwrap",
    },
    manifest: { version: "1.0.0", components: { bubblewrapVersion: "0.10.0" } },
    linuxProbe: { bubblewrap: { kind: "bundled" }, capabilities: original.capabilities },
  } as unknown as ResolvedRuntimeFiles;
  const backend = createLinuxDirectBackend({ runtime, installRoot: "/install", hostCwd: "/tmp", hostEnvironment: {} });
  expect(await backend.probe()).toMatchObject({ ok: true, capabilities: original.capabilities });
});

it.skipIf(process.platform !== "linux")("cancels and reaps a running bubblewrap capability process", async () => {
  const root = mkdtempSync(join(tmpdir(), "linux-bwrap-probe-"));
  try {
    const executable = join(root, "bwrap");
    const pidFile = join(root, "probe.pid");
    writeFileSync(executable, `#!/bin/sh\ntrap '' TERM\nprintf '%s' "$$" > '${pidFile}'\nexec sleep 30\n`, { mode: 0o755 });
    const controller = new AbortController();
    const pending = probeBubblewrap(executable, undefined, controller.signal);
    expect(pending).toBeInstanceOf(Promise);
    await waitFor(() => existsSync(pidFile));
    const pid = Number(readFileSync(pidFile, "utf8"));
    controller.abort();
    const exited = await Promise.race([pending.then(() => true), new Promise<boolean>(resolve => setTimeout(() => resolve(false), 1_000))]);
    if (!exited) process.kill(pid, "SIGKILL");
    expect(exited).toBe(true);
    expect(await pending).toBeUndefined();
    await waitForProcessGone(pid);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

it.skipIf(process.platform !== "linux" || !existsSync("/usr/bin/bwrap")).for(["system", "bundled"] as const)(
  "selects the %s bubblewrap candidate in the actual backend probe", async kind => {
    const root = mkdtempSync(join(tmpdir(), "linux-bwrap-order-"));
    try {
      const bad = join(root, "bad-bwrap");
      const marker = join(root, "bad-probed");
      writeFileSync(bad, `#!/bin/sh\nprintf tried > '${marker}'\nexit 1\n`, { mode: 0o755 });
      const launcher = join(root, "launcher");
      writeFileSync(launcher, "#!/bin/sh\nprintf '%s' '{\"planVersion\":3,\"landlockAbi\":3,\"seccomp\":true}'\n", { mode: 0o755 });
      const version = /^bubblewrap (\d+\.\d+\.\d+)/u.exec(execFileSync("/usr/bin/bwrap", ["--version"], { encoding: "utf8" }))?.[1];
      if (!version) throw new Error("system bubblewrap version is unavailable");
      const runtime = {
        directory: root, storageRoot: root,
        files: { linuxLauncher: launcher, egressBridge: launcher, bubblewrap: kind === "system" ? bad : "/usr/bin/bwrap" },
        manifest: { version: "1.0.0", components: { bubblewrapVersion: version } },
      } as unknown as ResolvedRuntimeFiles;
      const backend = createLinuxDirectBackend({ runtime, installRoot: root, hostCwd: root, hostEnvironment: {},
        systemBubblewrapPath: kind === "system" ? "/usr/bin/bwrap" : bad });
      const result = await backend.probe();
      expect(result).toMatchObject({ ok: true, linuxBubblewrap: kind === "system" ? { kind, path: "/usr/bin/bwrap" } : { kind } });
      expect(existsSync(marker)).toBe(kind === "bundled");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  },
);

it.skipIf(process.platform !== "linux")("reuses the selected path without re-probing or hashing its changed contents", async () => {
  const root = mkdtempSync(join(tmpdir(), "linux-selected-bwrap-"));
  try {
    const workspace = join(root, "workspace");
    mkdirSync(workspace);
    const path = join(root, "bwrap");
    writeFileSync(path, "first", { mode: 0o755 });
    const initial = await createTestDirectBackend().probe();
    if (!initial.ok) throw new Error("test backend probe failed");
    const runtime = {
      directory: root, storageRoot: root,
      files: { linuxLauncher: join(root, "launcher"), bubblewrap: path },
      manifest: { version: "1.0.0" },
      linuxProbe: { bubblewrap: { kind: "bundled" }, capabilities: initial.capabilities },
    } as unknown as ResolvedRuntimeFiles;
    const backend = createLinuxDirectBackend({ runtime, installRoot: root, hostCwd: workspace, hostEnvironment: {} });
    const operation = { kind: "shell" as const, command: "true", shell: "/bin/sh" };
    const filesystem = linuxRuntimeFilesystem({ installRoot: root, operation });
    const request = compileTestRequest({
      invocation: makeInvocation({ cwd: workspace, toolName: "bash", args: { command: "true" } }),
      operation, workspace, environment: runtimeEnvironment(), backendId: "linux-bwrap-landlock-seccomp",
      runtimeFilesystem: filesystem.grants, protectedPaths: filesystem.protectedPaths,
    });
    expect(await backend.probe()).toMatchObject({ ok: true });
    const first = await backend.prepare(request);
    if ("ok" in first) throw new Error(first.reason);
    expect(first.environment.PI_SANDBOX_BWRAP_PATH).toBe(path);
    writeFileSync(path, "changed");
    const second = await backend.prepare(request);
    if ("ok" in second) throw new Error(second.reason);
    expect(second.environment.PI_SANDBOX_BWRAP_PATH).toBe(path);
    chmodSync(path, 0o644);
    expect(await backend.prepare(request)).toMatchObject({ ok: false, code: "setup" });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
