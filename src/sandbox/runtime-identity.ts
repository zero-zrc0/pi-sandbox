import { createHash } from "node:crypto";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { jsonDigest } from "../json";
import { isPathWithin, isSamePath } from "./path";
import { parseRuntimeManifest } from "./runtime-manifest";
import type { ResolvedRuntimeFiles } from "./runtime-store";

function hash(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

export function captureRuntimeIdentity(runtime: ResolvedRuntimeFiles): () => string | undefined {
  if (runtime.manifest.platform === "darwin") {
    const executable = "/usr/bin/sandbox-exec";
    try {
      const info = lstatSync(executable, { bigint: true });
      if (!info.isFile() || !isSamePath(realpathSync.native(executable), executable)) throw new Error("launcher identity is invalid");
      const identity = `${info.dev}:${info.ino}:${info.size}:${info.mtimeNs}`;
      return () => {
        try {
          const current = lstatSync(executable, { bigint: true });
          return current.isFile() && isSamePath(realpathSync.native(executable), executable) &&
            `${current.dev}:${current.ino}:${current.size}:${current.mtimeNs}` === identity
            ? undefined : `runtime launcher changed: ${executable}`;
        } catch { return `runtime launcher is unavailable: ${executable}`; }
      };
    } catch { return () => `runtime launcher is unavailable: ${executable}`; }
  }
  const manifestPath = join(runtime.directory, "runtime.json");
  let manifestHash: string;
  try {
    const selected = parseRuntimeManifest(JSON.parse(readFileSync(manifestPath, "utf8")));
    if (jsonDigest(selected) !== jsonDigest(runtime.manifest)) throw new Error("manifest differs from selected runtime");
    manifestHash = hash(manifestPath);
  } catch { return () => `selected runtime manifest is unavailable or changed: ${manifestPath}`; }
  return () => {
    try {
      const directory = realpathSync.native(runtime.directory);
      const storageRoot = realpathSync.native(runtime.storageRoot);
      if (!isSamePath(directory, runtime.directory) || !isPathWithin(storageRoot, directory)) {
        return `runtime directory identity changed: ${runtime.directory}`;
      }
      const manifest = lstatSync(manifestPath);
      if (!manifest.isFile() || manifest.isSymbolicLink() || manifest.nlink > 1 || hash(manifestPath) !== manifestHash) {
        return `runtime manifest changed: ${manifestPath}`;
      }
      for (const entry of runtime.manifest.files) {
        const expected = join(directory, entry.path);
        const selected = runtime.files[entry.role];
        const info = lstatSync(expected);
        if (!selected || !info.isFile() || info.isSymbolicLink() || info.nlink > 1 ||
            !isSamePath(realpathSync.native(expected), selected) || !isPathWithin(directory, selected) ||
            (entry.executable && runtime.manifest.platform === "linux" && (info.mode & 0o111) === 0) || hash(expected) !== entry.sha256) {
          return `runtime file changed: ${expected}`;
        }
      }
      return undefined;
    } catch { return `selected runtime files are unavailable or changed: ${runtime.directory}`; }
  };
}
