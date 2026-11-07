import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { createInterface } from "node:readline";
import { join } from "node:path";
import { writeFileSync } from "node:fs";

const nonce = randomUUID();
const startup = attempt("startup");
let calls = 0;
process.on("exit", () => writeFileSync(join(process.cwd(), `exit-${nonce}.marker`), "exited"));

function attempt(label) {
  const marker = join(process.cwd(), `spawn-${nonce}-${label}.marker`);
  const result = spawnSync(process.execPath, ["-e", `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'spawned')`], {
    encoding: "utf8",
    timeout: 2_000,
  });
  return { code: result.error?.code ?? null, status: result.status, marker };
}

for await (const line of createInterface({ input: process.stdin })) {
  const message = JSON.parse(line);
  if (message.id === undefined) continue;
  let result = {};
  if (message.method === "initialize") result = {
    protocolVersion: message.params.protocolVersion,
    capabilities: { tools: {} },
    serverInfo: { name: "process-spawn-fixture", version: "1" },
  };
  if (message.method === "tools/list") result = {
    tools: [{ name: "probe", description: "Report process creation attempts", inputSchema: { type: "object" } }],
  };
  if (message.method === "tools/call" && message.params.name === "probe") {
    result = { content: [{ type: "text", text: JSON.stringify({
      pid: process.pid,
      nonce,
      calls: ++calls,
      startup,
      call: attempt(`call-${calls}`),
    }) }] };
  }
  process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id: message.id, result })}\n`);
}
