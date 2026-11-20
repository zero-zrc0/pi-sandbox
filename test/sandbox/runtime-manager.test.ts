import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { parseRuntimeCatalog } from "#sandbox/runtime-catalog";
import { SandboxRuntimeManager, type SandboxRuntimeManagerOptions } from "#sandbox/runtime-manager";
import type { ResolvedRuntimeFiles } from "#sandbox/runtime-store";

const temporaryDirectories: string[] = [];
const sdkRevision = "b21120168d70befe12356411423266bfef168446";

function runtime(pluginRoot: string, version: string): void {
  // runtimes use the fixed `<platform>-<arch>` layout; the version lives in runtime.json.
  const directory = join(pluginRoot, "runtimes", "win32-x64");
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
    protocolVersion: 3,
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
      protocolVersion: 3,
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
      protocolVersion: 3,
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
    // The catalog must describe the exact bytes on disk, otherwise the manual
    // runtime is not recognized as the cataloged release.
    const directory = join(pluginRoot, "runtimes", "win32-x64");
    const sha256 = (path: string) => createHash("sha256").update(readFileSync(path)).digest("hex");
    const catalog = parseRuntimeCatalog({ schemaVersion: 1, runtimes: [{
      version: "1.0.0",
      stable: true,
      platform: "win32",
      arch: "x64",
      protocolVersion: 3,
      minPluginVersion: "1.0.0",
      maxPluginVersionExclusive: "2.0.0",
      backendId: "windows-mxc",
      url: "https://github.com/sirzero/pi-sandbox/releases/download/v1.0.0/windows-x64.tar.gz",
      archiveFormat: "tar.gz",
      archiveSizeBytes: 100,
      archiveSha256: "a".repeat(64),
      files: [
        { role: "runtimeManifest", path: "runtime.json", sha256: sha256(join(directory, "runtime.json")), executable: false },
        { role: "windowsExecutable", path: "pi-sandbox-windows-mxc.exe", sha256: sha256(join(directory, "pi-sandbox-windows-mxc.exe")), executable: true },
        { role: "mxcManifest", path: "mxc-runtime.json", sha256: sha256(join(directory, "mxc-runtime.json")), executable: false },
      ],
    }] });
    const manager = new SandboxRuntimeManager({
      pluginRoot,
      catalog,
      platform: "win32",
      arch: "x64",
      pluginVersion: "1.2.0",
      protocolVersion: 3,
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
      protocolVersion: 3,
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
      protocolVersion: 3,
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

describe("SandboxRuntimeManager macOS system runtime", () => {
  function macOSManager(pluginRoot: string, probe: SandboxRuntimeManagerOptions["probe"], arch = "arm64") {
    return new SandboxRuntimeManager({
      pluginRoot,
      catalog: { schemaVersion: 1, runtimes: [] },
      platform: "darwin",
      arch,
      pluginVersion: "1.2.0",
      protocolVersion: 3,
      probe,
    });
  }

  it("prepares a synthetic system runtime without a runtime directory or download", async () => {
    // The plugin root deliberately does not exist: the system runtime must not
    // touch storage, scan a catalog, or prompt for a download.
    const pluginRoot = join(root(), "plugin");
    let probedRuntime: ResolvedRuntimeFiles | undefined;
    const probe = vi.fn<SandboxRuntimeManagerOptions["probe"]>(async runtime => {
      probedRuntime = runtime;
      return { available: true };
    });
    const fetch = vi.fn(async () => { throw new Error("macOS must not download a runtime"); });
    const manager = new SandboxRuntimeManager({
      pluginRoot,
      catalog: { schemaVersion: 1, runtimes: [] },
      platform: "darwin",
      arch: "arm64",
      pluginVersion: "1.2.0",
      protocolVersion: 3,
      probe,
      fetch,
    });
    const confirmDownload = vi.fn(async () => true);

    const state = await manager.prepare({ workspaceRoot: workspace(), confirmDownload });

    expect(confirmDownload).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
    expect(probe).toHaveBeenCalledTimes(1);
    expect(state.status).toBe("ready");
    if (state.status === "ready") {
      expect(state.runtime.manifest).toEqual({
        schemaVersion: 1,
        version: "1.2.0",
        stable: true,
        platform: "darwin",
        arch: "arm64",
        protocolVersion: 3,
        minPluginVersion: "0.0.0",
        maxPluginVersionExclusive: "999999.999.999",
        backendId: "macos-seatbelt",
        files: [],
      });
      expect(state.runtime.directory).toBe(join(pluginRoot, "runtimes", "darwin-arm64"));
      expect(state.runtime.storageRoot).toBe(pluginRoot);
      expect(state.runtime.source).toBe("manual");
      expect(state.runtime.files).toEqual({});
      expect(probedRuntime).toBe(state.runtime);
    }
  });

  it("reports the probe reason when the system runtime is unusable", async () => {
    const manager = macOSManager(join(root(), "plugin"), async () => ({
      available: false,
      reason: "sandbox-exec did not pass the default-deny file probe",
    }));

    expect(await manager.prepare({ workspaceRoot: workspace() })).toEqual({
      status: "unavailable",
      reason: "sandbox-exec did not pass the default-deny file probe",
    });
  });

  it("keeps the unsupported-platform error for platforms without a system runtime", async () => {
    const probe = vi.fn(async () => ({ available: true }));
    const manager = new SandboxRuntimeManager({
      pluginRoot: join(root(), "plugin"),
      catalog: { schemaVersion: 1, runtimes: [] },
      platform: "freebsd",
      arch: "x64",
      pluginVersion: "1.2.0",
      protocolVersion: 3,
      probe,
    });

    expect(await manager.prepare({ workspaceRoot: workspace() })).toEqual({
      status: "unavailable",
      reason: "OS sandbox is unsupported on freebsd",
    });
    expect(probe).not.toHaveBeenCalled();
  });

  it("rejects an unsupported macOS architecture before probing", async () => {
    const probe = vi.fn(async () => ({ available: true }));
    const manager = macOSManager(join(root(), "plugin"), probe, "ia32");

    expect(await manager.prepare({ workspaceRoot: workspace() })).toEqual({
      status: "unavailable",
      reason: "OS sandbox is unsupported on darwin/ia32",
    });
    expect(probe).not.toHaveBeenCalled();
  });
});
