import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { ResolvedRuntimeFiles } from "#sandbox/runtime-store";
import { prepareWindowsRuntimeExecutable } from "#sandbox/runtime-windows-integrity";

export function windowsRuntimeFiles(): ResolvedRuntimeFiles {
  const executable = fileURLToPath(new URL("../../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url));
  const directory = dirname(executable);
  const mxcManifest = join(directory, "mxc-runtime.json");
  const executableHash = createHash("sha256").update(readFileSync(executable)).digest("hex");
  const manifestHash = createHash("sha256").update(readFileSync(mxcManifest)).digest("hex");
  return {
    directory,
    source: "manual",
    manifest: {
      schemaVersion: 1,
      version: "1.0.0",
      stable: true,
      platform: "win32",
      arch: process.arch,
      protocolVersion: 2,
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
  return { ...source, directory, files };
}
