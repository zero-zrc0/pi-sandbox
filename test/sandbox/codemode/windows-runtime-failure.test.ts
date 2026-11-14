import { existsSync } from "node:fs";
import { spawnSync, type ChildProcessWithoutNullStreams } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { windowsRuntimeFiles } from "../fixtures/runtime";

const observed = vi.hoisted(() => ({ children: [] as object[] }));

vi.mock("node:child_process", async importOriginal => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return {
    ...actual,
    spawn: (...args: Parameters<typeof actual.spawn>) => {
      const child = actual.spawn(...args) as ChildProcessWithoutNullStreams;
      if (!child.spawnfile.toLowerCase().endsWith("pi-sandbox-windows-mxc.exe")) return child;
      let pending = "";
      let resolveReady!: () => void;
      const ready = new Promise<void>(resolve => { resolveReady = resolve; });
      child.stdout.on("data", chunk => {
        pending += Buffer.isBuffer(chunk) ? chunk.toString("utf8") : chunk;
        for (;;) {
          const newline = pending.indexOf("\n");
          if (newline < 0) return;
          const line = pending.slice(0, newline);
          pending = pending.slice(newline + 1);
          try {
            if (JSON.parse(line).type === "ready") resolveReady();
          } catch {
            // The production listener reports malformed protocol frames.
          }
        }
      });
      observed.children.push({ child, ready });
      return child;
    },
  };
});

const { createWindowsCodemodeSandbox } = await import("#sandbox/codemode/windows-runtime");

const executable = fileURLToPath(new URL("../../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url));

function runtimeChildPids(parentPid: number): number[] {
  const powershell = `${process.env.SystemRoot}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
  const query = `@(Get-CimInstance Win32_Process -Filter 'ParentProcessId = ${parentPid}' | Select-Object -ExpandProperty ProcessId) | ConvertTo-Json -Compress`;
  const result = spawnSync(powershell, ["-NoProfile", "-NonInteractive", "-Command", query], {
    encoding: "utf8",
    timeout: 5_000,
    windowsHide: true,
  });
  if (result.status !== 0) throw new Error(`Could not inspect Runtime child processes: ${result.stderr}`);
  const output = result.stdout.trim();
  if (!output || output === "null") return [];
  const pids: unknown = JSON.parse(output);
  return (Array.isArray(pids) ? pids : [pids]).map(Number);
}

function processInfo(pid: number): unknown | null {
  const powershell = `${process.env.SystemRoot}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
  const query = `Get-CimInstance Win32_Process -Filter 'ProcessId = ${pid}' | Select-Object ProcessId,ParentProcessId,Name,CommandLine | ConvertTo-Json -Compress`;
  const result = spawnSync(powershell, ["-NoProfile", "-NonInteractive", "-Command", query], {
    encoding: "utf8",
    timeout: 5_000,
    windowsHide: true,
  });
  if (result.status !== 0) throw new Error(`Could not inspect Runtime process: ${result.stderr}`);
  const output = result.stdout.trim();
  return output && output !== "null" ? JSON.parse(output) : null;
}

async function waitForRuntimePid(parentPid: number): Promise<number> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const [runtimePid] = runtimeChildPids(parentPid);
    if (runtimePid !== undefined) return runtimePid;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error(`MXC process ${parentPid} did not start a Runtime child`);
}

describe.skipIf(process.platform !== "win32" || !existsSync(executable))("Windows Codemode Runtime failure", () => {
  it("settles the Pi execution when MXC exits after Runtime readiness", async () => {
    observed.children.length = 0;
    const sandbox = createWindowsCodemodeSandbox({ timeoutMs: 15_000 }, undefined, windowsRuntimeFiles());
    const execution = sandbox.execute("while (true) {}");
    let child: ChildProcessWithoutNullStreams | undefined;

    try {
      const entry = observed.children[0] as { child: ChildProcessWithoutNullStreams; ready: Promise<void> } | undefined;
      expect(entry).toBeDefined();
      child = entry!.child;
      await entry!.ready;
      child.kill();

      const result = await Promise.race([
        execution,
        new Promise<null>(resolve => setTimeout(() => resolve(null), 2_000)),
      ]);

      expect(result).not.toBeNull();
      expect(result).toMatchObject({ ok: false, error: { kind: "sandbox" } });
    } finally {
      child?.kill();
      await sandbox.close();
    }
  }, 20_000);

  it("confirms the Runtime process has exited before hard cancellation settles", async () => {
    observed.children.length = 0;
    const sandbox = createWindowsCodemodeSandbox({ timeoutMs: Infinity }, undefined, windowsRuntimeFiles());
    const controller = new AbortController();
    const execution = sandbox.execute("while (true) {}", { signal: controller.signal });
    let child: ChildProcessWithoutNullStreams | undefined;

    try {
      const entry = observed.children[0] as { child: ChildProcessWithoutNullStreams; ready: Promise<void> } | undefined;
      expect(entry).toBeDefined();
      child = entry!.child;
      await entry!.ready;
      const runtimePid = await waitForRuntimePid(child.pid!);
      expect(processInfo(runtimePid)).toMatchObject({ ProcessId: runtimePid, ParentProcessId: child.pid });

      controller.abort();
      const result = await execution;

      expect(result).toMatchObject({ ok: false, error: { kind: "aborted" } });
      expect(processInfo(runtimePid), `Runtime process persisted after cancellation; MXC exit=${child.exitCode}`).toBeNull();
    } finally {
      child?.kill();
      await sandbox.close();
    }
  }, 20_000);
});
