import { createConnection, createServer, type Server, type Socket } from "node:net";
import type { EgressGrant } from "./types";

export interface EgressForwarder {
  readonly host: "127.0.0.1";
  readonly port: number;
  close(): void;
}

export async function createEgressForwarder(grant: EgressGrant): Promise<EgressForwarder> {
  const sockets = new Set<Socket>();
  const server: Server = createServer(client => {
    if (sockets.size >= 256) { client.destroy(); return; }
    const upstream = createConnection({ host: grant.proxyHost, port: grant.proxyPort });
    sockets.add(client);
    sockets.add(upstream);
    client.on("error", () => upstream.destroy());
    upstream.on("error", () => client.destroy());
    client.on("close", () => { sockets.delete(client); upstream.destroy(); });
    upstream.on("close", () => { sockets.delete(upstream); client.destroy(); });
    upstream.write(`PIEGRESS1 ${grant.leaseId} ${grant.credential}\n`);
    client.pipe(upstream);
    upstream.pipe(client);
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => { server.off("error", reject); resolve(); });
  });
  server.on("error", () => { for (const socket of sockets) socket.destroy(); });
  server.unref();
  const address = server.address();
  if (address === null || typeof address === "string") { server.close(); throw new Error("forwarder has no TCP address"); }
  let closed = false;
  return {
    host: "127.0.0.1", port: address.port,
    close() {
      if (closed) return;
      closed = true;
      for (const socket of sockets) socket.destroy();
      server.close();
    },
  };
}
