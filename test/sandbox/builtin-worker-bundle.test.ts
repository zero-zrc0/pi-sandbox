import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const bundle = fileURLToPath(new URL("../../src/sandbox/builtin-worker.bundle.mjs", import.meta.url));

interface WorkerEnvelope {
  readonly result?: { readonly content?: readonly { readonly text?: string }[]; readonly isError?: boolean };
  readonly error?: string;
}

/*
 * Managed installs omit the pi peer packages, so the sandboxed worker ships as
 * this committed bundle. A missing or stale artifact breaks every builtin tool.
 */
function runBuiltin(cwd: string, name: string, args: Record<string, unknown>): Promise<WorkerEnvelope> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [bundle], { cwd, stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", chunk => { stdout += chunk; });
    child.stderr.on("data", chunk => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", code => {
      const line = stdout.trim().split("\n").at(-1) ?? "";
      if (code !== 0 || line === "") {
        reject(new Error(`bundled worker exited ${code}: ${stderr}`));
        return;
      }
      resolve(JSON.parse(line) as WorkerEnvelope);
    });
    child.stdin.end(JSON.stringify({ name, arguments: args, toolCallId: `bundle-${name}`, cwd }) + "\n");
  });
}

describe("bundled builtin worker", () => {
  /*
   * The worker imports only the tools subtree. A bundle near the old 4 MB size
   * means the build resolved the package barrel again and inlined the model
   * runtime plus every provider SDK.
   */
  it("stays within the tools-subtree size budget", () => {
    expect(statSync(bundle).size).toBeLessThan(1_000_000);
  });

  it("lists a directory without any installed dependency", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "bundle-worker-"));
    writeFileSync(join(cwd, "sample.txt"), "content");
    try {
      const envelope = await runBuiltin(cwd, "ls", { path: "." });
      expect(envelope.error).toBeUndefined();
      expect(envelope.result?.isError).not.toBe(true);
      expect(envelope.result?.content?.[0]?.text).toContain("sample.txt");
    } finally { rmSync(cwd, { recursive: true, force: true }); }
  }, 60_000);

  it("reads a file without any installed dependency", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "bundle-worker-"));
    writeFileSync(join(cwd, "sample.txt"), "bundled-read");
    try {
      const envelope = await runBuiltin(cwd, "read", { path: "sample.txt" });
      expect(envelope.error).toBeUndefined();
      expect(envelope.result?.content?.[0]?.text).toBe("bundled-read");
    } finally { rmSync(cwd, { recursive: true, force: true }); }
  }, 60_000);
});
