import net from "node:net";
import { lookup } from "node:dns/promises";
import os from "node:os";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { fileURLToPath } from "node:url";

const privateAddress = Object.values(os.networkInterfaces()).flat().find(entry =>
  entry && entry.family === "IPv4" && !entry.internal && /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(entry.address))?.address;
const hosts = ["127.0.0.1", "127.0.0.1", "::1", ...(privateAddress ? [privateAddress] : [])];
const listeners = [];
try {
  for (const host of hosts) {
    const server = net.createServer(socket => {
      socket.on("data", data => socket.end(data.toString().startsWith("GET http://example.com/ HTTP/1.0")
        ? "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n" : ""));
    });
    server.listen(0, host);
    await once(server, "listening");
    listeners.push(server);
  }
  const targets = listeners.map((server, index) => [hosts[index], server.address().port]);
  targets.push([(await lookup("example.com", { family: 4 })).address, 443]);
  for (const [host, port] of targets) {
    const socket = net.connect(port, host);
    socket.setTimeout(3000, () => socket.destroy(new Error("host control timeout")));
    await once(socket, "connect");
    socket.destroy();
  }
  console.log(`host controls: ${targets.length} listeners reachable; private=${Boolean(privateAddress)}`);
  const executable = fileURLToPath(new URL("../target/debug/examples/proxy_probe.exe", import.meta.url));
  for (const mode of ["all", "none", "proxy"]) {
    const env = { ...process.env };
    env.MXC_PROBE_MODE = mode;
    const child = spawn(executable, targets.flat().map(String), { env });
    let output = "";
    let error = "";
    child.stdout.on("data", chunk => output += chunk);
    child.stderr.on("data", chunk => error += chunk);
    const [code] = await once(child, "exit");
    console.log(`${mode}: exit=${code} ${JSON.stringify(output.trim())} ${error.trim()}`);
    const lines = output.trim().split(/\r?\n/);
    const expected = targets.map((_, index) => `${index}=${mode === "all" || (mode === "proxy" && index === 0) ? "connected" : "blocked"}`);
    if (mode === "proxy") expected.push("proxy_http=ok");
    if (code !== 0 || JSON.stringify(lines) !== JSON.stringify(expected)) process.exitCode = 1;
  }
  if (!privateAddress) process.exitCode = 1;
} finally {
  for (const server of listeners) server.close();
}
