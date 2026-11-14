import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parseRuntimeCatalog, type RuntimeResourceEntry } from "#sandbox/runtime-catalog";
import { downloadRuntimeArchive } from "#sandbox/runtime-download";

const temporaryDirectories: string[] = [];
const hash = "c".repeat(64);

function directory(): string {
  const path = mkdtempSync(join(tmpdir(), "runtime-download-test-"));
  temporaryDirectories.push(path);
  return path;
}

function release(bytes: Buffer): RuntimeResourceEntry {
  return parseRuntimeCatalog({
    schemaVersion: 1,
    runtimes: [{
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
      archiveSizeBytes: bytes.byteLength,
      archiveSha256: createHash("sha256").update(bytes).digest("hex"),
      files: [
        { role: "linuxLauncher", path: "linux-sandbox", sha256: hash, executable: true },
        { role: "egressBridge", path: "linux-egress-bridge", sha256: hash, executable: true },
        { role: "bubblewrap", path: "bwrap", sha256: hash, executable: true },
        { role: "bubblewrapLicense", path: "bwrap.LICENSE", sha256: hash, executable: false },
        { role: "runtimeManifest", path: "runtime.json", sha256: hash, executable: false },
      ],
    }],
  }).runtimes[0]!;
}

afterEach(() => {
  for (const path of temporaryDirectories.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe("downloadRuntimeArchive", () => {
  it("resumes a partial archive with Range and validates the completed digest", async () => {
    const bytes = Buffer.from("abcdef");
    const entry = release(bytes);
    const stagingDirectory = directory();
    let calls = 0;
    const fetch = async (_url: string | URL | Request, init?: RequestInit) => {
      calls += 1;
      const headers = new Headers(init?.headers);
      if (calls === 1) {
        expect(headers.has("range")).toBe(false);
        return new Response(bytes.subarray(0, 3), { status: 200, headers: { etag: '"v1"', "content-length": "6" } });
      }
      expect(headers.get("range")).toBe("bytes=3-");
      expect(headers.get("if-range")).toBe('"v1"');
      return new Response(bytes.subarray(3), {
        status: 206,
        headers: { etag: '"v1"', "content-range": "bytes 3-5/6", "content-length": "3" },
      });
    };

    await expect(downloadRuntimeArchive({ entry, stagingDirectory, fetch })).rejects.toThrow("can be resumed");
    const archivePath = await downloadRuntimeArchive({ entry, stagingDirectory, fetch });

    expect(calls).toBe(2);
    expect(readFileSync(archivePath)).toEqual(bytes);
  });

  it("rejects a redirect outside GitHub release hosts", async () => {
    const entry = release(Buffer.from("archive"));
    await expect(downloadRuntimeArchive({
      entry,
      stagingDirectory: directory(),
      fetch: async () => new Response(null, { status: 302, headers: { location: "https://evil.example/runtime.tar.gz" } }),
    })).rejects.toThrow("trusted GitHub release host");
  });

  it("stops an oversized response before reporting progress or retaining its partial file", async () => {
    const entry = release(Buffer.from("four"));
    const stagingDirectory = directory();
    const progress: { receivedBytes: number; totalBytes: number }[] = [];
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(1024 * 1024));
        controller.close();
      },
    });

    await expect(downloadRuntimeArchive({
      entry,
      stagingDirectory,
      fetch: async () => new Response(body, {
        status: 200,
        headers: { etag: '"v1"', "content-length": "4" },
      }),
      onProgress: value => progress.push(value),
    })).rejects.toThrow("runtime download exceeded the trusted archive size");

    expect(progress).toEqual([]);
    expect(existsSync(join(stagingDirectory, "runtime.tar.gz.part"))).toBe(false);
    expect(existsSync(join(stagingDirectory, "runtime-download.json"))).toBe(false);
  });
});
