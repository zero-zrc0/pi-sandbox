import { describe, expect, it } from "vitest";
import { parseRuntimeCatalog } from "#sandbox/runtime-catalog";

const hash = "a".repeat(64);

function linuxRelease(overrides: Record<string, unknown> = {}) {
  return {
    version: "1.0.0",
    stable: true,
    platform: "linux",
    arch: "x64",
    protocolVersion: 3,
    minPluginVersion: "1.0.0",
    maxPluginVersionExclusive: "2.0.0",
    backendId: "linux-bwrap-landlock-seccomp",
    url: "https://github.com/sirzero/pi-sandbox/releases/download/v1.0.0/linux-x64.tar.gz",
    archiveFormat: "tar.gz",
    archiveSizeBytes: 2048,
    archiveSha256: hash,
    files: [
      { role: "linuxLauncher", path: "linux-sandbox", sha256: hash, executable: true },
      { role: "egressBridge", path: "linux-egress-bridge", sha256: hash, executable: true },
      { role: "bubblewrap", path: "bwrap", sha256: hash, executable: true },
      { role: "bubblewrapLicense", path: "bwrap.LICENSE", sha256: hash, executable: false },
      { role: "runtimeManifest", path: "runtime.json", sha256: hash, executable: false },
    ],
    ...overrides,
  };
}

describe("parseRuntimeCatalog", () => {
  it("accepts an empty catalog while maintainers have not published runtime assets", () => {
    expect(parseRuntimeCatalog({ schemaVersion: 1, runtimes: [] })).toEqual({ schemaVersion: 1, runtimes: [] });
  });

  it("parses pinned GitHub release metadata and fixed Linux files", () => {
    const catalog = parseRuntimeCatalog({ schemaVersion: 1, runtimes: [linuxRelease()] });

    const entry = catalog.runtimes[0]!;
    expect(entry).toMatchObject({ version: "1.0.0", platform: "linux", arch: "x64", archiveSizeBytes: 2048 });
    expect(entry.files.some(file => file.role === "linuxLauncher" && file.path === "linux-sandbox")).toBe(true);
  });

  it("rejects non-GitHub URLs, missing files, and paths outside the fixed layout", () => {
    for (const release of [
      linuxRelease({ url: "https://example.org/runtime.tar.gz" }),
      linuxRelease({ files: [{ role: "linuxLauncher", path: "linux-sandbox", sha256: hash, executable: true }] }),
      linuxRelease({ files: [
        { role: "linuxLauncher", path: "../linux-sandbox", sha256: hash, executable: true },
        { role: "egressBridge", path: "linux-egress-bridge", sha256: hash, executable: true },
        { role: "bubblewrap", path: "bwrap", sha256: hash, executable: true },
        { role: "bubblewrapLicense", path: "bwrap.LICENSE", sha256: hash, executable: false },
        { role: "runtimeManifest", path: "runtime.json", sha256: hash, executable: false },
      ] }),
    ]) {
      expect(() => parseRuntimeCatalog({ schemaVersion: 1, runtimes: [release] })).toThrow();
    }
  });
});
