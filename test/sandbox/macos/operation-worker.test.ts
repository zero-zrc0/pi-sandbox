import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const READY = "\x1ePI-MACOS-OPERATION-READY\x1f";
const worker = fileURLToPath(new URL("../../../src/sandbox/backend/macos/operation-worker.mjs", import.meta.url));
const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

function run(operation: Record<string, unknown>): Record<string, unknown> {
  const output = execFileSync(process.execPath, [worker], { input: `${JSON.stringify(operation)}\n`, encoding: "utf8" });
  expect(output.startsWith(READY)).toBe(true);
  return JSON.parse(output.slice(READY.length)) as Record<string, unknown>;
}

describe("macOS restricted file operation worker", () => {
  it("returns file contents from inside its process", () => {
    const root = mkdtempSync(join(tmpdir(), "pi-sandbox-macos-operation-"));
    roots.push(root);
    const path = join(root, "sample.txt");
    writeFileSync(path, "restricted-read");

    const result = run({ kind: "read-file", path });

    expect(result).toMatchObject({ exitCode: 0 });
    expect(Buffer.from(String(result.dataBase64), "base64").toString("utf8")).toBe("restricted-read");
  });

  it("writes files through the same worker entry", () => {
    const root = mkdtempSync(join(tmpdir(), "pi-sandbox-macos-operation-"));
    roots.push(root);
    const path = join(root, "nested", "sample.txt");
    mkdirSync(join(root, "nested"));

    const result = run({ kind: "write-file", path, content: "restricted-write" });

    expect(result).toEqual({ exitCode: 0 });
    expect(readFileSync(path, "utf8")).toBe("restricted-write");
  });
});
