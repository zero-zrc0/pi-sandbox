import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const bundle = fileURLToPath(new URL("../src/sandbox/builtin-worker.bundle.mjs", import.meta.url));
const cwd = mkdtempSync(join(tmpdir(), "worker-smoke-"));
mkdirSync(join(cwd, "sub"));
writeFileSync(join(cwd, "a.txt"), "needle\nsecond line\n");
writeFileSync(join(cwd, "sub", "b.txt"), "sub\n");

const cases = [
  ["ls", { path: "." }],
  ["read", { path: "a.txt" }],
  ["write", { path: "written.txt", content: "written" }],
  ["edit", { path: "a.txt", edits: [{ oldText: "second", newText: "edited" }] }],
  ["grep", { pattern: "needle", path: "." }],
  ["find", { pattern: "*.txt", path: "." }],
  ["bash", { command: "echo bash-ok" }],
  ...(process.platform === "win32" ? [["powershell", { command: "Write-Output powershell-ok" }]] : []),
];

let failed = 0;
for (const [name, args] of cases) {
  const started = Date.now();
  const child = spawnSync(process.execPath, [bundle], {
    cwd,
    input: JSON.stringify({ name, arguments: args, toolCallId: `smoke-${name}`, cwd }) + "\n",
    encoding: "utf8",
    timeout: 120_000,
    env: process.env,
  });
  const lines = (child.stdout ?? "").trim().split("\n").filter(Boolean);
  const last = lines.at(-1);
  let packet;
  try { packet = JSON.parse(last); } catch { packet = undefined; }
  const ok = child.status === 0 && packet?.type === "result" && !packet.error && packet.result?.isError !== true;
  if (!ok) failed += 1;
  const text = JSON.stringify(packet?.result ?? packet ?? child.stderr?.slice(0, 400)).slice(0, 160);
  console.log(`${ok ? "PASS" : "FAIL"} ${name} (${Date.now() - started}ms) ${text}`);
  if (!ok) console.log("  stderr:", (child.stderr ?? "").slice(0, 500));
}
console.log("---");
console.log("written:", readFileSync(join(cwd, "written.txt"), "utf8"));
console.log("edited:", readFileSync(join(cwd, "a.txt"), "utf8").trim().split("\n")[1]);
rmSync(cwd, { recursive: true, force: true });
process.exitCode = failed === 0 ? 0 : 1;
