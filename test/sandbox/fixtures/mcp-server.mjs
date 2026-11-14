import { createInterface } from "node:readline";
import { spawn } from "node:child_process";
const descendant = process.argv.includes("--spawn-descendant")
  ? spawn(process.execPath, ["-e", "setTimeout(() => {}, 30000)"], { stdio: "ignore" })
  : undefined;
let calls = 0;
let expanded = false;
const send = message => process.stdout.write(`${JSON.stringify(message)}\n`);
for await (const line of createInterface({ input: process.stdin })) {
  const message = JSON.parse(line);
  if (message.id === undefined) continue;
  let result = {};
  if (message.method === "initialize") result = { protocolVersion: message.params.protocolVersion,
    capabilities: { tools: { listChanged: true } }, serverInfo: { name: "controlled-fixture", version: "1" } };
  if (message.method === "tools/list") result = { tools: ["ping", "toggle", ...(expanded ? ["extra"] : [])].map(name => ({ name, description: "Return process identity", inputSchema: { type: "object" } })) };
  if (message.method === "tools/call") {
    if (message.params.name === "toggle") { expanded = !expanded; send({ jsonrpc: "2.0", method: "notifications/tools/list_changed" }); }
    result = { content: [{ type: "text", text: JSON.stringify({ pid: process.pid, calls: ++calls, secretPresent: process.env.UNAPPROVED_SECRET !== undefined,
      ...(descendant?.pid === undefined ? {} : { descendantPid: descendant.pid }) }) }] };
  }
  send({ jsonrpc: "2.0", id: message.id, result });
}
