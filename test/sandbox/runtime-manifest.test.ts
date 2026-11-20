import { describe, expect, it } from "vitest";
import { parseRuntimeManifest } from "#sandbox/runtime-manifest";

const hash = "b".repeat(64);

function manifest(overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: 1,
    version: "9.1.0",
    stable: true,
    platform: "linux",
    arch: "arm64",
    protocolVersion: 3,
    minPluginVersion: "1.0.0",
    maxPluginVersionExclusive: "2.0.0",
    backendId: "linux-bwrap-landlock-seccomp",
    components: {
      bubblewrapVersion: "0.13.2",
      bubblewrapSourceCommit: "d".repeat(40),
    },
    files: [
      { role: "linuxLauncher", path: "linux-sandbox", sha256: hash, executable: true },
      { role: "egressBridge", path: "linux-egress-bridge", sha256: hash, executable: true },
      { role: "bubblewrap", path: "bwrap", sha256: hash, executable: true },
      { role: "bubblewrapLicense", path: "bwrap.LICENSE", sha256: hash, executable: false },
    ],
    ...overrides,
  };
}

describe("parseRuntimeManifest", () => {
  it("accepts a user-trusted manual runtime absent from the automatic release catalog", () => {
    expect(parseRuntimeManifest(manifest())).toMatchObject({
      version: "9.1.0",
      platform: "linux",
      arch: "arm64",
      protocolVersion: 3,
    });
  });

  it("rejects missing files, path traversal, and a mismatched backend", () => {
    const invalid = [
      manifest({ files: [] }),
      manifest({ files: [
        { role: "linuxLauncher", path: "../linux-sandbox", sha256: hash, executable: true },
        { role: "egressBridge", path: "linux-egress-bridge", sha256: hash, executable: true },
        { role: "bubblewrap", path: "bwrap", sha256: hash, executable: true },
      ] }),
      manifest({ backendId: "windows-mxc" }),
    ];

    for (const item of invalid) expect(() => parseRuntimeManifest(item)).toThrow();
  });
});
