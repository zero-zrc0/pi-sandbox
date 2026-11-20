import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { ResolvedRuntimeFiles } from "#sandbox/runtime-store";
import { prepareWindowsRuntimeExecutable } from "#sandbox/runtime-windows-integrity";
import { afterAll } from "vitest";

const temporaryRuntimes: string[] = [];
afterAll(async () => {
  for (const directory of temporaryRuntimes.splice(0)) await rm(directory, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
});

export function windowsRuntimeFiles(): ResolvedRuntimeFiles {
  const storageRoot = fileURLToPath(new URL("../../../", import.meta.url));
  const override = process.env.PI_SANDBOX_TEST_MXC_EXECUTABLE;
  let executable = fileURLToPath(new URL("../../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url));
  let directory = dirname(executable);
  if (override) {
    const root = join(storageRoot, "runtimes");
    mkdirSync(root, { recursive: true });
    directory = mkdtempSync(join(root, "test-codemode-"));
    temporaryRuntimes.push(directory);
    executable = join(directory, "pi-sandbox-windows-mxc.exe");
    copyFileSync(override, executable);
    prepareWindowsRuntimeExecutable(executable);
    writeFileSync(join(directory, "mxc-runtime.json"), JSON.stringify({ schemaVersion: 1, backend: "windows-mxc", version: "1.0.0",
      sdkRevision: "b21120168d70befe12356411423266bfef168446",
      sha256: createHash("sha256").update(readFileSync(executable)).digest("hex") }));
  }
  const mxcManifest = join(directory, "mxc-runtime.json");
  const executableHash = createHash("sha256").update(readFileSync(executable)).digest("hex");
  const manifestHash = createHash("sha256").update(readFileSync(mxcManifest)).digest("hex");
  return {
    directory,
    storageRoot,
    source: "manual",
    manifest: {
      schemaVersion: 1,
      version: "1.0.0",
      stable: true,
      platform: "win32",
      arch: process.arch,
      protocolVersion: 3,
      minPluginVersion: "1.0.0",
      maxPluginVersionExclusive: "2.0.0",
      backendId: "windows-mxc",
      files: [
        { role: "windowsExecutable", path: "pi-sandbox-windows-mxc.exe", sha256: executableHash, executable: true },
        { role: "mxcManifest", path: "mxc-runtime.json", sha256: manifestHash, executable: false },
      ],
    },
    files: { windowsExecutable: executable, mxcManifest },
  };
}

export function installWindowsTestRuntime(): ResolvedRuntimeFiles {
  const source = windowsRuntimeFiles();
  const packageRoot = fileURLToPath(new URL("../../../", import.meta.url));
  const runtimeRoot = join(packageRoot, "runtimes");
  mkdirSync(runtimeRoot, { recursive: true });
  const directory = mkdtempSync(join(runtimeRoot, "test-native-"));
  const files = { ...source.files };
  for (const entry of source.manifest.files) {
    const destination = join(directory, entry.path);
    copyFileSync(source.files[entry.role]!, destination);
    files[entry.role] = destination;
  }
  const manifestPath = join(directory, "runtime.json");
  writeFileSync(manifestPath, JSON.stringify(source.manifest));
  files.runtimeManifest = manifestPath;
  prepareWindowsRuntimeExecutable(files.windowsExecutable!);
  const canonicalFiles = Object.fromEntries(Object.entries(files).map(([role, path]) => [role, path && realpathSync(path)])) as typeof files;
  return {
    ...source,
    directory: realpathSync(directory),
    storageRoot: realpathSync(packageRoot),
    files: canonicalFiles,
  };
}

export function installLinuxTestRuntime(directory: string): void {
  const source = fileURLToPath(new URL("../../../src/sandbox/backend/linux/", import.meta.url));
  const bubblewrap = join(directory, "bwrap");
  copyFileSync("/usr/bin/bwrap", bubblewrap);
  chmodSync(bubblewrap, 0o755);
  copyFileSync(join(source, "bwrap-selection.mjs"), join(directory, "bwrap-selection.mjs"));
  writeFileSync(join(directory, "bwrap.LICENSE"), "test license");
  const bubblewrapVersion = /^bubblewrap (\d+\.\d+\.\d+)/u.exec(
    execFileSync(bubblewrap, ["--version"], { encoding: "utf8" }),
  )?.[1];
  if (bubblewrapVersion === undefined) throw new Error("Linux test bubblewrap version is unavailable");

  const roles = [
    ["linuxLauncher", "linux-sandbox", true],
    ["egressBridge", "linux-egress-bridge", true],
    ["bubblewrap", "bwrap", true],
    ["bubblewrapLicense", "bwrap.LICENSE", false],
  ] as const;
  const files = roles.map(([role, path, executable]) => ({
    role,
    path,
    executable,
    sha256: createHash("sha256").update(readFileSync(join(directory, path))).digest("hex"),
  }));
  writeFileSync(join(directory, "runtime.json"), JSON.stringify({
    schemaVersion: 1,
    version: "1.0.0",
    stable: true,
    platform: "linux",
    arch: process.arch,
    protocolVersion: 3,
    minPluginVersion: "1.0.0",
    maxPluginVersionExclusive: "2.0.0",
    backendId: "linux-bwrap-landlock-seccomp",
    files,
    components: { bubblewrapVersion, bubblewrapSourceCommit: "a".repeat(40) },
  }));
}
