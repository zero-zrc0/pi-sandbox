import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { captureRuntimeIdentity } from "#sandbox/runtime-identity";
import { parseRuntimeManifest } from "#sandbox/runtime-manifest";
import type { ResolvedRuntimeFiles } from "#sandbox/runtime-store";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

function fixture(): ResolvedRuntimeFiles {
  const root = realpathSync.native(mkdtempSync(join(tmpdir(), "runtime-identity-")));
  roots.push(root);
  const directory = join(root, "runtime");
  mkdirSync(directory);
  const executable = join(directory, "pi-sandbox-windows-mxc.exe");
  const mxcManifest = join(directory, "mxc-runtime.json");
  writeFileSync(executable, "fixture executable");
  writeFileSync(mxcManifest, "fixture manifest");
  const hash = (path: string) => createHash("sha256").update(readFileSync(path)).digest("hex");
  const manifest = parseRuntimeManifest({ schemaVersion: 1, version: "1.0.0", stable: true, platform: "win32", arch: "x64",
    protocolVersion: 3, minPluginVersion: "1.0.0", maxPluginVersionExclusive: "2.0.0", backendId: "windows-mxc",
    files: [
      { role: "windowsExecutable", path: "pi-sandbox-windows-mxc.exe", executable: true, sha256: hash(executable) },
      { role: "mxcManifest", path: "mxc-runtime.json", executable: false, sha256: hash(mxcManifest) },
    ] });
  writeFileSync(join(directory, "runtime.json"), JSON.stringify(manifest));
  return { directory, storageRoot: root, source: "manual", manifest,
    files: { windowsExecutable: executable, mxcManifest } };
}

describe("selected runtime identity", () => {
  it("rejects runtime file replacement after selection", () => {
    const runtime = fixture();
    const check = captureRuntimeIdentity(runtime);
    expect(check()).toBeUndefined();
    writeFileSync(runtime.files.windowsExecutable!, "modified");
    expect(check()).toContain("runtime file changed");
  });

  it("rejects a manifest changed after selection", () => {
    const runtime = fixture();
    const check = captureRuntimeIdentity(runtime);
    const manifestPath = join(runtime.directory, "runtime.json");
    writeFileSync(manifestPath, `${readFileSync(manifestPath, "utf8")} `);
    expect(check()).toContain("runtime manifest changed");
  });

  it("rejects a manifest that no longer matches the selected runtime", () => {
    const runtime = fixture();
    const manifestPath = join(runtime.directory, "runtime.json");
    writeFileSync(manifestPath, JSON.stringify({ ...runtime.manifest, version: "1.0.1" }));
    expect(captureRuntimeIdentity(runtime)()).toContain("selected runtime manifest");
  });
});
