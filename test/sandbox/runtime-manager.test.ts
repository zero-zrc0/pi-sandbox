import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { parseRuntimeCatalog } from "#sandbox/runtime-catalog";
import { SandboxRuntimeManager } from "#sandbox/runtime-manager";

const temporaryDirectories: string[] = [];
const sdkRevision = "b21120168d70befe12356411423266bfef168446";

function runtime(pluginRoot: string, version: string): void {
  const directory = join(pluginRoot, "runtimes", version, "win32-x64");
  mkdirSync(directory, { recursive: true });
  const executable = Buffer.from(`mxc-${version}`);
  const executableHash = createHash("sha256").update(executable).digest("hex");
  writeFileSync(join(directory, "pi-sandbox-windows-mxc.exe"), executable);
  const mxcManifest = JSON.stringify({
    schemaVersion: 1,
    backend: "windows-mxc",
    version: "1.0.0",
    sdkRevision,
    sha256: executableHash,
  });
  writeFileSync(join(directory, "mxc-runtime.json"), mxcManifest);
  const manifestFiles = [
    { role: "windowsExecutable", path: "pi-sandbox-windows-mxc.exe", sha256: executableHash, executable: true },
    { role: "mxcManifest", path: "mxc-runtime.json", sha256: createHash("sha256").update(mxcManifest).digest("hex"), executable: false },
  ];
  writeFileSync(join(directory, "runtime.json"), JSON.stringify({
    schemaVersion: 1,
    version,
    stable: true,
    platform: "win32",
    arch: "x64",
    protocolVersion: 2,
    minPluginVersion: "1.0.0",
    maxPluginVersionExclusive: "2.0.0",
    backendId: "windows-mxc",
    files: manifestFiles,
  }));
}

function root(): string {
  const path = mkdtempSync(join(tmpdir(), "runtime-manager-test-"));
  temporaryDirectories.push(path);
  return path;
}

function workspace(): string {
  const path = join(root(), "workspace");
  mkdirSync(path);
  return path;
}

afterEach(() => {
  for (const path of temporaryDirectories.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe("SandboxRuntimeManager", () => {
  it("starts disabled and prepares a user-trusted manual runtime without a release catalog", async () => {
    const pluginRoot = join(root(), "plugin");
    mkdirSync(pluginRoot);
    runtime(pluginRoot, "9.1.0");
    const probe = vi.fn(async () => ({ available: true }));
    const fetch = vi.fn(async () => { throw new Error("manual runtime must not download"); });
    const manager = new SandboxRuntimeManager({
      pluginRoot,
      catalog: { schemaVersion: 1, runtimes: [] },
      platform: "win32",
      arch: "x64",
      pluginVersion: "1.2.0",
      protocolVersion: 2,
      probe,
      fetch,
    });

    expect(manager.state()).toEqual({ status: "disabled" });
    const state = await manager.prepare({ workspaceRoot: workspace() });

    expect(state.status).toBe("ready");
    if (state.status === "ready") {
      expect(state.runtime.source).toBe("manual");
      expect(state.runtime.manifest.version).toBe("9.1.0");
    }
    expect(fetch).not.toHaveBeenCalled();
    expect(probe).toHaveBeenCalledTimes(1);
  });

  it("retries preparation after a manual runtime is added following an unavailable result", async () => {
    const pluginRoot = join(root(), "plugin");
    mkdirSync(pluginRoot);
    const workspaceRoot = workspace();
    const probe = vi.fn(async () => ({ available: true }));
    const manager = new SandboxRuntimeManager({
      pluginRoot,
      catalog: { schemaVersion: 1, runtimes: [] },
      platform: "win32",
      arch: "x64",
      pluginVersion: "1.2.0",
      protocolVersion: 2,
      probe,
    });

    expect((await manager.prepare({ workspaceRoot })).status).toBe("unavailable");
    expect(probe).not.toHaveBeenCalled();
    runtime(pluginRoot, "9.1.0");

    const state = await manager.prepare({ workspaceRoot });

    expect(state.status).toBe("ready");
    expect(probe).toHaveBeenCalledOnce();
  });

  it("treats a manually placed runtime as user-trusted even when its version is cataloged", async () => {
    const pluginRoot = join(root(), "plugin");
    mkdirSync(pluginRoot);
    runtime(pluginRoot, "1.0.0");
    const catalog = parseRuntimeCatalog({ schemaVersion: 1, runtimes: [{
      version: "1.0.0",
      stable: true,
      platform: "win32",
      arch: "x64",
      protocolVersion: 2,
      minPluginVersion: "1.0.0",
      maxPluginVersionExclusive: "2.0.0",
      backendId: "windows-mxc",
      url: "https://github.com/sirzero/pi-sandbox/releases/download/v1.0.0/windows-x64.tar.gz",
      archiveFormat: "tar.gz",
      archiveSizeBytes: 100,
      archiveSha256: "a".repeat(64),
      files: [
        { role: "runtimeManifest", path: "runtime.json", sha256: "a".repeat(64), executable: false },
        { role: "windowsExecutable", path: "pi-sandbox-windows-mxc.exe", sha256: "a".repeat(64), executable: true },
        { role: "mxcManifest", path: "mxc-runtime.json", sha256: "a".repeat(64), executable: false },
      ],
    }] });
    const manager = new SandboxRuntimeManager({
      pluginRoot,
      catalog,
      platform: "win32",
      arch: "x64",
      pluginVersion: "1.2.0",
      protocolVersion: 2,
      probe: async () => ({ available: true }),
    });

    const state = await manager.prepare({ workspaceRoot: workspace() });

    expect(state.status).toBe("ready");
    if (state.status === "ready") expect(state.runtime.source).toBe("manual");
  });

  it("reports a failed probe without silently selecting an older local version", async () => {
    const pluginRoot = join(root(), "plugin");
    mkdirSync(pluginRoot);
    runtime(pluginRoot, "9.1.0");
    runtime(pluginRoot, "9.2.0");
    let probedVersion = "";
    const manager = new SandboxRuntimeManager({
      pluginRoot,
      catalog: { schemaVersion: 1, runtimes: [] },
      platform: "win32",
      arch: "x64",
      pluginVersion: "1.2.0",
      protocolVersion: 2,
      probe: async candidate => {
        probedVersion = candidate.manifest.version;
        return { available: false, reason: "native probe failed" };
      },
    });

    const state = await manager.prepare({ workspaceRoot: workspace() });

    expect(state).toEqual({ status: "unavailable", reason: "native probe failed" });
    expect(probedVersion).toBe("9.2.0");
  });

  it("disable aborts an active preparation and clears its selected runtime", async () => {
    const pluginRoot = join(root(), "plugin");
    mkdirSync(pluginRoot);
    runtime(pluginRoot, "9.1.0");
    const manager = new SandboxRuntimeManager({
      pluginRoot,
      catalog: { schemaVersion: 1, runtimes: [] },
      platform: "win32",
      arch: "x64",
      pluginVersion: "1.2.0",
      protocolVersion: 2,
      probe: async (_candidate, input) => new Promise(resolve => {
        input.signal.addEventListener("abort", () => resolve({ available: false, reason: "aborted" }), { once: true });
      }),
    });
    const preparation = manager.prepare({ workspaceRoot: workspace() });

    expect(await manager.disable()).toEqual({ status: "disabled" });
    await preparation;
    expect(manager.state()).toEqual({ status: "disabled" });
  });
});
