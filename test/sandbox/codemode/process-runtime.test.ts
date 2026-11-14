import { existsSync } from "node:fs";
import { deflateSync } from "node:zlib";
import { fileURLToPath } from "node:url";
import { MAX_OUTPUT_CHARS, MAX_OUTPUT_ITEMS, MAX_STORE_TOTAL_CHARS, MAX_STORE_VALUE_CHARS } from "@earendil-works/pi-codemode/portable";
import { describe, expect, it } from "vitest";
import { createWindowsCodemodeSandbox as createWindowsRuntimeSandbox } from "#sandbox/codemode/windows-runtime";
import { windowsRuntimeFiles } from "../fixtures/runtime";

const executable = fileURLToPath(new URL("../../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url));
const createWindowsCodemodeSandbox = (options: Parameters<typeof createWindowsRuntimeSandbox>[0] = {}) =>
  createWindowsRuntimeSandbox(options, undefined, windowsRuntimeFiles());

function crc32(...buffers: Buffer[]): number {
  const table = new Uint32Array(256);
  for (let index = 0; index < table.length; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) value = (value & 1) !== 0 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    table[index] = value >>> 0;
  }
  let crc = 0xffffffff;
  for (const buffer of buffers) {
    for (const byte of buffer) crc = table[(crc ^ byte) & 0xff]! ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type: string, data: Buffer): Buffer {
  const typeBytes = Buffer.from(type, "ascii");
  const chunk = Buffer.alloc(12 + data.byteLength);
  chunk.writeUInt32BE(data.byteLength, 0);
  typeBytes.copy(chunk, 4);
  data.copy(chunk, 8);
  chunk.writeUInt32BE(crc32(typeBytes, data), 8 + data.byteLength);
  return chunk;
}

function nearLimitPngBase64(): string {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const header = Buffer.alloc(13);
  header.writeUInt32BE(1, 0);
  header.writeUInt32BE(1, 4);
  header[8] = 8;
  header[9] = 6;
  const imageData = deflateSync(Buffer.from([0, 0, 0, 0, 0]));
  const ihdr = pngChunk("IHDR", header);
  const textPrefix = Buffer.from("Comment\0", "ascii");
  const idat = pngChunk("IDAT", imageData);
  const iend = pngChunk("IEND", Buffer.alloc(0));
  const targetBytes = ((MAX_OUTPUT_CHARS - 4) / 4) * 3;
  const fixedBytes = signature.byteLength + ihdr.byteLength + 12 + textPrefix.byteLength + idat.byteLength + iend.byteLength;
  const text = Buffer.concat([textPrefix, Buffer.alloc(targetBytes - fixedBytes, 0x78)]);
  return Buffer.concat([signature, ihdr, pngChunk("tEXt", text), idat, iend]).toString("base64");
}

describe.skipIf(process.platform !== "win32" || !existsSync(executable))("Windows Codemode process Runtime", () => {
  it("runs the public Pi Codemode worker and returns host calls and script errors", async () => {
    const sandbox = createWindowsCodemodeSandbox({
      timeoutMs: 15_000,
      tools: [{
        name: "echo",
        execute: (args) => args,
      }],
    });

    const success = await sandbox.execute('const value = await tools.echo({ text: "round-trip" }); text(value.text); return value;');
    expect(success, JSON.stringify(success)).toMatchObject({
      ok: true,
      value: { text: "round-trip" },
      output: [{ type: "text", text: "round-trip" }],
      calls: [{ name: "echo", status: "ok" }],
    });

    const failure = await sandbox.execute('throw new Error("script-failure");');
    expect(failure).toMatchObject({ ok: false, error: { kind: "script", message: "script-failure" } });

    await sandbox.close();
  }, 30_000);

  it("transports a large Unicode host result and script output within Pi limits", async () => {
    const characters = 6 * 1024 * 1024;
    const text = "中".repeat(characters);
    const sandbox = createWindowsCodemodeSandbox({
      timeoutMs: 15_000,
      tools: [{ name: "echo", execute: () => ({ text }) }],
    });

    try {
      const largeSource = await sandbox.execute(`//${text}\nreturn 1;`);
      expect(largeSource).toMatchObject({ ok: true, value: 1 });

      const result = await sandbox.execute('const value = await tools.echo({}); text(value.text); return value;');

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value).toEqual({ text });
        expect(result.output).toEqual([{ type: "text", text }]);
      }
    } finally {
      await sandbox.close();
    }
  }, 30_000);

  it("preserves Pi's maximum text and store boundaries through the restricted Runtime", async () => {
    const sandbox = createWindowsCodemodeSandbox({ timeoutMs: 15_000 });

    try {
      const maximumOutput = await sandbox.execute(`text("x".repeat(${MAX_OUTPUT_CHARS}));`);
      expect(maximumOutput.ok).toBe(true);
      if (maximumOutput.ok) expect(maximumOutput.output[0]).toMatchObject({ type: "text", text: "x".repeat(MAX_OUTPUT_CHARS) });

      const maximumStore = await sandbox.execute(`store("k", "x".repeat(${MAX_STORE_VALUE_CHARS - 2})); return load("k").length;`);
      expect(maximumStore).toMatchObject({ ok: true, value: MAX_STORE_VALUE_CHARS - 2 });
      if (maximumStore.ok) expect(maximumStore.storeWrites.set.k).toHaveLength(MAX_STORE_VALUE_CHARS - 2);

      const totalStore = await sandbox.execute(`for (let i = 0; i < 4; i++) store("k" + i, "x".repeat(${MAX_STORE_TOTAL_CHARS / 4 - 4})); return load("k3").length;`);
      expect(totalStore).toMatchObject({ ok: true, value: MAX_STORE_TOTAL_CHARS / 4 - 4 });

      const oversizedTotalStore = await sandbox.execute(`for (let i = 0; i < 4; i++) store("k" + i, "x".repeat(${MAX_STORE_TOTAL_CHARS / 4 - 4})); store("x", "");`);
      expect(oversizedTotalStore).toMatchObject({
        ok: false,
        error: { kind: "script", message: expect.stringContaining("store is full") },
      });

      const oversizedStore = await sandbox.execute(`store("k", "x".repeat(${MAX_STORE_VALUE_CHARS - 1}));`);
      expect(oversizedStore).toMatchObject({
        ok: false,
        error: { kind: "script", message: expect.stringContaining("more than the limit") },
      });
    } finally {
      await sandbox.close();
    }
  }, 45_000);

  it("preserves Pi's maximum output item count through the restricted Runtime", async () => {
    const sandbox = createWindowsCodemodeSandbox({ timeoutMs: 30_000 });

    try {
      const maximumOutput = await sandbox.execute(`for (let i = 0; i < ${MAX_OUTPUT_ITEMS}; i++) text("");`);
      expect(maximumOutput.ok).toBe(true);
      if (maximumOutput.ok) expect(maximumOutput.output).toHaveLength(MAX_OUTPUT_ITEMS);

      const oversizedOutput = await sandbox.execute(`for (let i = 0; i <= ${MAX_OUTPUT_ITEMS}; i++) text("");`);
      expect(oversizedOutput).toMatchObject({
        ok: false,
        error: { kind: "script", message: expect.stringContaining("100000") },
      });
    } finally {
      await sandbox.close();
    }
  }, 75_000);

  it("transports a valid image at the Pi output limit in both directions", async () => {
    const data = nearLimitPngBase64();
    expect(data.length).toBe(MAX_OUTPUT_CHARS - 4);
    const sandbox = createWindowsCodemodeSandbox({
      timeoutMs: 15_000,
      tools: [{ name: "image", execute: () => ({ data }) }],
    });

    try {
      const result = await sandbox.execute('const value = await tools.image({}); image({ type: "image", data: value.data, mimeType: "image/png" });');

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.output[0]).toMatchObject({ type: "image", mimeType: "image/png" });
        if (result.output[0]?.type === "image") expect(result.output[0].data.length).toBe(data.length);
      }
    } finally {
      await sandbox.close();
    }
  }, 45_000);

  it("returns aborted when a non-cooperative Runtime is cancelled", async () => {
    const sandbox = createWindowsCodemodeSandbox({ timeoutMs: Infinity });
    const controller = new AbortController();
    const execution = sandbox.execute("while (true) {}", { signal: controller.signal });
    setTimeout(() => controller.abort(), 300);

    const result = await execution;
    expect(result, JSON.stringify(result)).toMatchObject({ ok: false, error: { kind: "aborted" } });
    await sandbox.close();
  }, 20_000);

  it("hard-stops a non-cooperative Runtime loop when the execution times out", async () => {
    const sandbox = createWindowsCodemodeSandbox({ timeoutMs: 500 });
    const result = await sandbox.execute("while (true) {}");

    expect(result, JSON.stringify(result)).toMatchObject({
      ok: false,
      error: { kind: "timeout", message: "Execution timed out after 500 ms" },
    });
    await sandbox.close();
  }, 20_000);
});
