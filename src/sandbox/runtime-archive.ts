import { createGunzip } from "node:zlib";
import { createReadStream, existsSync, mkdirSync, readFileSync } from "node:fs";
import { open, type FileHandle } from "node:fs/promises";
import { dirname, join } from "node:path";
import { createHash } from "node:crypto";
import { parseRuntimeManifest, type RuntimeManifest } from "./runtime-manifest";
import type { RuntimeResourceEntry } from "./runtime-catalog";
import { verifyMxcManifest } from "./runtime-store";

const TAR_BLOCK_BYTES = 512;
const MAX_UNPACKED_BYTES = 1024 * 1024 * 1024;

class TarReader {
  private readonly iterator: AsyncIterator<Buffer>;
  private pending: Buffer<ArrayBufferLike> = Buffer.alloc(0);
  private ended = false;

  constructor(stream: NodeJS.ReadableStream & AsyncIterable<Buffer | string>) {
    this.iterator = (async function* () {
      for await (const chunk of stream) yield Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    })()[Symbol.asyncIterator]();
  }

  private async fill(size: number): Promise<void> {
    while (this.pending.length < size && !this.ended) {
      const next = await this.iterator.next();
      if (next.done) this.ended = true;
      else this.pending = this.pending.length === 0 ? next.value : Buffer.concat([this.pending, next.value]);
    }
  }

  async readExact(size: number): Promise<Buffer | undefined> {
    await this.fill(size);
    if (this.pending.length === 0 && this.ended) return undefined;
    if (this.pending.length < size) throw new Error("runtime archive is truncated");
    const result = this.pending.subarray(0, size);
    this.pending = this.pending.subarray(size);
    return result;
  }

  async copyTo(handle: FileHandle, size: number, hash: ReturnType<typeof createHash>): Promise<void> {
    let remaining = size;
    while (remaining > 0) {
      await this.fill(1);
      if (this.pending.length === 0) throw new Error("runtime archive file content is truncated");
      const chunk = this.pending.subarray(0, Math.min(remaining, this.pending.length));
      hash.update(chunk);
      let written = 0;
      while (written < chunk.length) {
        const result = await handle.write(chunk, written, chunk.length - written);
        if (result.bytesWritten < 1) throw new Error("runtime archive extraction made no progress");
        written += result.bytesWritten;
      }
      this.pending = this.pending.subarray(chunk.length);
      remaining -= chunk.length;
    }
  }

  async discard(size: number): Promise<void> {
    let remaining = size;
    while (remaining > 0) {
      await this.fill(1);
      if (this.pending.length === 0) throw new Error("runtime archive padding is truncated");
      const chunk = this.pending.subarray(0, Math.min(remaining, this.pending.length));
      if (chunk.some(byte => byte !== 0)) throw new Error("runtime archive padding is invalid");
      this.pending = this.pending.subarray(chunk.length);
      remaining -= chunk.length;
    }
  }

  async requireZeroTail(): Promise<void> {
    while (true) {
      await this.fill(1);
      if (this.pending.length === 0) return;
      if (this.pending.some(byte => byte !== 0)) throw new Error("runtime archive contains data after its end marker");
      this.pending = Buffer.alloc(0);
    }
  }
}

function octal(field: Buffer, label: string): number {
  if ((field[0]! & 0x80) !== 0) throw new Error(`runtime archive ${label} uses an unsupported numeric encoding`);
  const value = field.toString("ascii").replace(/[\0 ]+$/u, "").trim();
  if (value === "") return 0;
  if (!/^[0-7]+$/u.test(value)) throw new Error(`runtime archive ${label} is invalid`);
  const parsed = Number.parseInt(value, 8);
  if (!Number.isSafeInteger(parsed)) throw new Error(`runtime archive ${label} is too large`);
  return parsed;
}

function fieldText(field: Buffer): string {
  const end = field.indexOf(0);
  return field.subarray(0, end < 0 ? field.length : end).toString("utf8");
}

function verifyHeader(header: Buffer): { readonly name: string; readonly size: number } | undefined {
  if (header.every(byte => byte === 0)) return undefined;
  const expectedChecksum = octal(header.subarray(148, 156), "header checksum");
  let actualChecksum = 0;
  for (let index = 0; index < header.length; index += 1) {
    actualChecksum += index >= 148 && index < 156 ? 32 : header[index]!;
  }
  if (actualChecksum !== expectedChecksum) throw new Error("runtime archive header checksum is invalid");
  if (header[156] !== 0 && header[156] !== 48) throw new Error("runtime archive contains a link, directory, or special file");
  if (fieldText(header.subarray(345, 500)) !== "") throw new Error("runtime archive path prefix is unsupported");
  const name = fieldText(header.subarray(0, 100));
  if (!name || name.includes("/") || name.includes("\\") || name === "." || name === "..") {
    throw new Error("runtime archive path is not a fixed file name");
  }
  return { name, size: octal(header.subarray(124, 136), "file size") };
}

function verifyManifest(entry: RuntimeResourceEntry, manifestPath: string): RuntimeManifest {
  const manifest = parseRuntimeManifest(JSON.parse(readFileSync(manifestPath, "utf8")) as unknown);
  if (manifest.version !== entry.version || manifest.stable !== entry.stable || manifest.platform !== entry.platform ||
      manifest.arch !== entry.arch || manifest.protocolVersion !== entry.protocolVersion ||
      manifest.minPluginVersion !== entry.minPluginVersion ||
      manifest.maxPluginVersionExclusive !== entry.maxPluginVersionExclusive || manifest.backendId !== entry.backendId) {
    throw new Error("runtime manifest does not match its trusted resource entry");
  }
  const catalogFiles = new Map(entry.files.filter(file => file.role !== "runtimeManifest").map(file => [file.role, file]));
  if (manifest.files.length !== catalogFiles.size) throw new Error("runtime manifest file list is incomplete");
  for (const file of manifest.files) {
    const expected = catalogFiles.get(file.role);
    if (!expected || expected.path !== file.path || expected.sha256 !== file.sha256 || expected.executable !== file.executable) {
      throw new Error(`runtime manifest entry for ${file.path} differs from the trusted resource entry`);
    }
  }
  if (entry.platform === "win32") {
    const executableHash = catalogFiles.get("windowsExecutable")?.sha256;
    const mxcManifest = catalogFiles.get("mxcManifest");
    if (!executableHash || !mxcManifest) throw new Error("Windows runtime resource is incomplete");
    verifyMxcManifest(join(dirname(manifestPath), mxcManifest.path), executableHash);
  }
  return manifest;
}

export async function extractRuntimeArchive(input: {
  readonly entry: RuntimeResourceEntry;
  readonly archivePath: string;
  readonly destination: string;
}): Promise<RuntimeManifest> {
  if (existsSync(input.destination)) throw new Error("runtime extraction destination already exists");
  mkdirSync(input.destination, { recursive: false });
  const expected = new Map(input.entry.files.map(file => [file.path, file]));
  const extracted = new Set<string>();
  let totalBytes = 0;
  let endMarkers = 0;
  const reader = new TarReader(createReadStream(input.archivePath).pipe(createGunzip()));
  while (true) {
    const header = await reader.readExact(TAR_BLOCK_BYTES);
    if (!header) throw new Error("runtime archive has no end marker");
    if (header.every(byte => byte === 0)) {
      endMarkers += 1;
      if (endMarkers === 2) break;
      continue;
    }
    if (endMarkers > 0) throw new Error("runtime archive has an incomplete end marker");
    const item = verifyHeader(header);
    if (!item) continue;
    const expectedFile = expected.get(item.name);
    if (!expectedFile) throw new Error(`runtime archive contains unexpected file ${item.name}`);
    if (extracted.has(item.name)) throw new Error(`runtime archive repeats file ${item.name}`);
    totalBytes += item.size;
    if (item.size < 1 || totalBytes > MAX_UNPACKED_BYTES) throw new Error("runtime archive exceeds its unpacked size limit");
    const outputPath = join(input.destination, expectedFile.path);
    const handle = await open(outputPath, "wx", expectedFile.executable ? 0o755 : 0o644);
    const hash = createHash("sha256");
    try {
      await reader.copyTo(handle, item.size, hash);
      await handle.sync();
    } finally {
      await handle.close();
    }
    if (hash.digest("hex") !== expectedFile.sha256) throw new Error(`runtime archive file ${item.name} has an invalid SHA-256`);
    extracted.add(item.name);
    const padding = (TAR_BLOCK_BYTES - item.size % TAR_BLOCK_BYTES) % TAR_BLOCK_BYTES;
    if (padding > 0) await reader.discard(padding);
  }
  await reader.requireZeroTail();
  if (extracted.size !== expected.size) throw new Error("runtime archive is missing required files");
  const manifestPath = join(input.destination, "runtime.json");
  const manifest = verifyManifest(input.entry, manifestPath);
  return manifest;
}
