import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parseRuntimeCatalog, type RuntimeResourceEntry } from "#sandbox/runtime-catalog";
import { extractRuntimeArchive } from "#sandbox/runtime-archive";
import { installRuntimeEntry } from "#sandbox/runtime-installation";

const temporaryDirectories: string[] = [];

function digest(value: Buffer | string): string {
  return createHash("sha256").update(value).digest("hex");
}

function octal(header: Buffer, offset: number, length: number, value: number): void {
  header.write(`${value.toString(8).padStart(length - 1, "0")}\0`, offset, length, "ascii");
}

function tar(entries: readonly { readonly name: string; readonly bytes: Buffer; readonly type?: string }[]): Buffer {
  const chunks: Buffer[] = [];
  for (const entry of entries) {
    const header = Buffer.alloc(512);
    header.write(entry.name, 0, 100, "utf8");
    octal(header, 100, 8, 0o644);
    octal(header, 108, 8, 0);
    octal(header, 116, 8, 0);
    octal(header, 124, 12, entry.bytes.byteLength);
    octal(header, 136, 12, 0);
    header.fill(32, 148, 156);
    header[156] = (entry.type ?? "0").charCodeAt(0);
    header.write("ustar\0", 257, 6, "ascii");
    header.write("00", 263, 2, "ascii");
    let checksum = 0;
    for (const byte of header) checksum += byte;
    header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
    chunks.push(header, entry.bytes);
    const padding = (512 - entry.bytes.byteLength % 512) % 512;
    if (padding) chunks.push(Buffer.alloc(padding));
  }
  chunks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(chunks));
}

function fixture(extra: readonly { readonly name: string; readonly bytes: Buffer; readonly type?: string }[] = []) {
  const nativeFiles = [
    { role: "linuxLauncher", path: "linux-sandbox", bytes: Buffer.from("native-launcher"), executable: true },
    { role: "egressBridge", path: "linux-egress-bridge", bytes: Buffer.from("egress-bridge"), executable: true },
    { role: "bubblewrap", path: "bwrap", bytes: Buffer.from("bubblewrap"), executable: true },
    { role: "bubblewrapLicense", path: "bwrap.LICENSE", bytes: Buffer.from("license text"), executable: false },
  ];
  const manifest = {
    schemaVersion: 1,
    version: "1.0.0",
    stable: true,
    platform: "linux",
    arch: "x64",
    protocolVersion: 2,
    minPluginVersion: "1.0.0",
    maxPluginVersionExclusive: "2.0.0",
    backendId: "linux-bwrap-landlock-seccomp",
    components: { bubblewrapVersion: "0.13.2", bubblewrapSourceCommit: "a".repeat(40) },
    files: nativeFiles.map(file => ({ role: file.role, path: file.path, sha256: digest(file.bytes), executable: file.executable })),
  };
  const manifestBytes = Buffer.from(JSON.stringify(manifest));
  const archive = tar([
    ...nativeFiles.map(file => ({ name: file.path, bytes: file.bytes })),
    { name: "runtime.json", bytes: manifestBytes },
    ...extra,
  ]);
  const entry = parseRuntimeCatalog({ schemaVersion: 1, runtimes: [{
    version: "1.0.0",
    stable: true,
    platform: "linux",
    arch: "x64",
    protocolVersion: 2,
    minPluginVersion: "1.0.0",
    maxPluginVersionExclusive: "2.0.0",
    backendId: "linux-bwrap-landlock-seccomp",
    url: "https://github.com/sirzero/pi-sandbox/releases/download/v1.0.0/linux-x64.tar.gz",
    archiveFormat: "tar.gz",
    archiveSizeBytes: archive.byteLength,
    archiveSha256: digest(archive),
    files: [
      ...nativeFiles.map(file => ({ role: file.role, path: file.path, sha256: digest(file.bytes), executable: file.executable })),
      { role: "runtimeManifest", path: "runtime.json", sha256: digest(manifestBytes), executable: false },
    ],
  }] }).runtimes[0]!;
  const parent = mkdtempSync(join(tmpdir(), "runtime-archive-test-"));
  temporaryDirectories.push(parent);
  const archivePath = join(parent, "runtime.tar.gz");
  const destination = join(parent, "extracted");
  writeFileSync(archivePath, archive);
  return { archivePath, destination, entry, manifest, parent };
}

function windowsFixture() {
  const executable = Buffer.from("windows-mxc");
  const executableHash = digest(executable);
  const nativeManifest = Buffer.from(JSON.stringify({
    schemaVersion: 1,
    backend: "windows-mxc",
    version: "1.0.0",
    sdkRevision: "b21120168d70befe12356411423266bfef168446",
    sha256: executableHash,
  }));
  const runtimeManifest = Buffer.from(JSON.stringify({
    schemaVersion: 1,
    version: "1.0.0",
    stable: true,
    platform: "win32",
    arch: "x64",
    protocolVersion: 2,
    minPluginVersion: "1.0.0",
    maxPluginVersionExclusive: "2.0.0",
    backendId: "windows-mxc",
    files: [
      { role: "windowsExecutable", path: "pi-sandbox-windows-mxc.exe", sha256: executableHash, executable: true },
      { role: "mxcManifest", path: "mxc-runtime.json", sha256: digest(nativeManifest), executable: false },
    ],
  }));
  const archive = tar([
    { name: "pi-sandbox-windows-mxc.exe", bytes: executable },
    { name: "mxc-runtime.json", bytes: nativeManifest },
    { name: "runtime.json", bytes: runtimeManifest },
  ]);
  const entry = parseRuntimeCatalog({ schemaVersion: 1, runtimes: [{
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
    archiveSizeBytes: archive.byteLength,
    archiveSha256: digest(archive),
    files: [
      { role: "windowsExecutable", path: "pi-sandbox-windows-mxc.exe", sha256: executableHash, executable: true },
      { role: "mxcManifest", path: "mxc-runtime.json", sha256: digest(nativeManifest), executable: false },
      { role: "runtimeManifest", path: "runtime.json", sha256: digest(runtimeManifest), executable: false },
    ],
  }] }).runtimes[0]!;
  const parent = mkdtempSync(join(tmpdir(), "runtime-install-test-"));
  temporaryDirectories.push(parent);
  const archivePath = join(parent, "windows.tar.gz");
  writeFileSync(archivePath, archive);
  return { parent, archivePath, entry };
}

afterEach(() => {
  for (const path of temporaryDirectories.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe("extractRuntimeArchive", () => {
  it("extracts only hashed regular files from the fixed root layout", async () => {
    const test = fixture();
    const manifest = await extractRuntimeArchive({ entry: test.entry, archivePath: test.archivePath, destination: test.destination });

    expect(manifest.components?.bubblewrapVersion).toBe("0.13.2");
    expect(readFileSync(join(test.destination, "bwrap"), "utf8")).toBe("bubblewrap");
    expect(readFileSync(join(test.destination, "runtime.json"), "utf8")).toBe(JSON.stringify(test.manifest));
  });

  it("rejects path traversal and archive links before publishing files", async () => {
    for (const extra of [
      { name: "../outside", bytes: Buffer.from("bad") },
      { name: "unexpected", bytes: Buffer.from("bad"), type: "2" },
    ]) {
      const test = fixture([extra]);
      await expect(extractRuntimeArchive({ entry: test.entry, archivePath: test.archivePath, destination: test.destination })).rejects.toThrow();
      expect(() => readFileSync(join(test.parent, "outside"))).toThrow();
    }
  });

  it("publishes a verified Windows runtime atomically and reuses it without another download", async () => {
    const test = windowsFixture();
    const pluginRoot = join(test.parent, "plugin");
    mkdirSync(pluginRoot);
    const archive = readFileSync(test.archivePath);
    let downloads = 0;
    const fetch = async () => {
      downloads += 1;
      return new Response(archive, { status: 200, headers: { etag: '"windows-v1"', "content-length": String(archive.byteLength) } });
    };
    const first = await installRuntimeEntry({ pluginRoot, entry: test.entry, fetch });
    const second = await installRuntimeEntry({ pluginRoot, entry: test.entry, fetch: async () => { throw new Error("should reuse"); } });

    expect(first.source).toBe("managed");
    expect(second.directory).toBe(first.directory);
    expect(downloads).toBe(1);
    expect(readFileSync(join(first.directory, "pi-sandbox-windows-mxc.exe"))).toEqual(Buffer.from("windows-mxc"));
  });
});
