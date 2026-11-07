import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, spawnSync } from "node:child_process";
import { discoverAndLoadExtensions } from "@earendil-works/pi-coding-agent";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const npmCli = process.env.npm_execpath;
if (!npmCli) throw new Error("Run this script with npm run verify:public-types.");
const verifyWindowsMxc = process.argv.includes("--windows-mxc");
if (verifyWindowsMxc && process.platform !== "win32") throw new Error("Windows MXC package verification requires Windows.");
if (verifyWindowsMxc && !existsSync(path.join(root, "src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe"))) {
  throw new Error("Build the Windows MXC runtime before package verification.");
}
const cache = path.join(root, ".cache");
mkdirSync(cache, { recursive: true });
const work = mkdtempSync(path.join(cache, "public-types-"));
const previousAgentDir = process.env.PI_CODING_AGENT_DIR;

function run(args, cwd = root, capture = false) {
  const result = spawnSync(process.execPath, args, {
    cwd,
    encoding: "utf8",
    stdio: capture ? "pipe" : "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`Command failed (${result.status}): ${args.join(" ")}\n${result.stderr ?? ""}`);
  return result.stdout;
}

try {
  run([npmCli, "run", "build"]);
  const declarations = readFileSync(path.join(root, "dist/public.d.ts"), "utf8");
  if (/#(?:engine|classifier|permissions)\b/.test(declarations)) {
    throw new Error("Public declarations still contain internal aliases.");
  }
  for (const symbol of [
    "getPermissionsService", "publishPermissionsService", "unpublishPermissionsService",
    "PermissionsService", "PermissionQuery", "PermissionCheckResult", "PermissionState",
    "ToolInputFormatter", "ToolBindingDeclaration",
  ]) {
    if (!declarations.includes(symbol)) throw new Error(`Missing public export: ${symbol}`);
  }
  for (const removed of ["registerAuthorizer", "AuthorizerVerdict", "PERMISSIONS_UI_PROMPT_CHANNEL"]) {
    if (declarations.includes(removed)) throw new Error(`Removed public export reappeared: ${removed}`);
  }
  if (declarations.includes("RootPermissionsService")) throw new Error("Removed process-root accessor reappeared.");
  const [packed] = JSON.parse(run([npmCli, "pack", "--ignore-scripts", "--json", "--cache", path.join(cache, "npm"), "--pack-destination", work], root, true));
  const consumer = path.join(work, "consumer");
  mkdirSync(consumer);
  writeFileSync(path.join(consumer, "package.json"), JSON.stringify({ name: "type-consumer", private: true, type: "module" }));
  writeFileSync(path.join(consumer, "tsconfig.json"), JSON.stringify({
    compilerOptions: { target: "ESNext", module: "ESNext", moduleResolution: "Bundler", strict: true, noEmit: true, skipLibCheck: true, types: ["node"] },
    include: ["probe.ts"],
  }));
  writeFileSync(path.join(consumer, "probe.ts"), `
import {
  getPermissionsService,
  type PermissionsService, type PermissionCheckResult,
} from "@sirzero/pi-sandbox";
import {
  defineApprovalNode,
} from "@sirzero/pi-sandbox/sdk";
// @ts-expect-error Ordinary plugin execution contracts were removed.
import type { PluginFactory, PluginToolDefinition, PluginStartupSnapshot } from "@sirzero/pi-sandbox/sdk";
// @ts-expect-error Ordinary plugin startup RPC was removed.
import { parsePluginStartupSnapshot } from "@sirzero/pi-sandbox/sdk";
const node = defineApprovalNode({ apiVersion: "1", createNode: () => ({ apiVersion: "1", id: "user:probe", evaluate: () => ({ decisions: [] }) }) });
void node;
const service: PermissionsService | undefined = getPermissionsService("session-id");
const result: PermissionCheckResult | undefined = service?.checkPermission("bash", "ls");
void [service, result];
// @ts-expect-error A session id is mandatory.
getPermissionsService();
`);
  // Install the locked Pi SDK so the isolated consumer checks native callback types.
  run([npmCli, "install", "--ignore-scripts", "--legacy-peer-deps", "--no-audit", "--no-fund",
    "--cache", path.join(cache, "npm"), path.join(work, packed.filename),
    "@earendil-works/pi-coding-agent@1.4.0", "@earendil-works/pi-ai@1.4.0", "@earendil-works/pi-tui@1.4.0", "@types/node@22"], consumer);
  run([path.join(root, "node_modules/typescript/bin/tsc"), "-p", path.join(consumer, "tsconfig.json")]);
  process.env.PI_CODING_AGENT_DIR = path.join(work, "agent");
  const loaded = await discoverAndLoadExtensions(
    [path.join(consumer, "node_modules/@sirzero/pi-sandbox/src/index.ts")],
    consumer,
    process.env.PI_CODING_AGENT_DIR,
  );
  if (loaded.errors.length || loaded.extensions.length !== 1) {
    throw new Error(`Packaged extension could not load: ${JSON.stringify(loaded.errors)}`);
  }
  for (const command of ["permission"]) {
    if (!loaded.extensions[0].commands.has(command)) throw new Error(`Missing packaged command: ${command}`);
  }
  for (const alias of ["permission-model", "permission-system"]) {
    if (loaded.extensions[0].commands.has(alias)) throw new Error(`Removed command alias reappeared: ${alias}`);
  }
  if (verifyWindowsMxc) {
    const installed = path.join(consumer, "node_modules/@sirzero/pi-sandbox");
    const helper = path.join(installed, "src/sandbox/backend/windows/helper.mjs");
    if (!existsSync(path.join(installed, "src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe")) ||
        !existsSync(path.join(installed, "src/sandbox/backend/windows/mxc/mxc-runtime.json"))) throw new Error("Packaged Windows runtime is missing.");
    const workspace = path.join(work, "native-workspace");
    mkdirSync(workspace);
    writeFileSync(path.join(workspace, "sample.txt"), "packaged-native-read");
    const child = spawn(process.execPath, [helper], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    try {
      const message = await new Promise((resolve, reject) => {
        let buffer = "";
        const timer = setTimeout(() => reject(new Error("Packaged Windows helper timed out.")), 15_000);
        child.stdout.setEncoding("utf8");
        child.stdout.on("data", chunk => {
          buffer += chunk;
          for (;;) {
            const end = buffer.indexOf("\n");
            if (end < 0) break;
            const packet = JSON.parse(buffer.slice(0, end));
            buffer = buffer.slice(end + 1);
            if (packet.type === "ready") child.stdin.write(JSON.stringify({ type: "start", requestId: "packaged", generation: 1,
              plan: { backend: { id: "windows-mxc" }, cwd: workspace, toolCallId: "packaged",
                filesystem: [{ path: workspace, access: "read", granularity: "directory" }], protectedPaths: [],
                network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot, PATH: process.env.PATH },
                operation: { kind: "builtin-tool", name: "read", arguments: { path: "sample.txt" } } } }) + "\n");
            if (["result", "rejected", "error"].includes(packet.type)) { clearTimeout(timer); resolve(packet); }
          }
        });
        child.on("error", reject);
        child.on("exit", code => reject(new Error(`Packaged Windows helper exited: ${code}`)));
        child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "packaged", generation: 1 }) + "\n");
      });
      if (message.type !== "result" || message.exitCode !== 0 ||
          !Buffer.from(message.dataBase64 ?? "", "base64").toString("utf8").includes("packaged-native-read")) {
        throw new Error(`Packaged Windows builtin failed: ${JSON.stringify(message)}`);
      }
    } finally { child.kill(); }
    console.log("Packaged Windows MXC runtime executed a builtin in the isolated consumer.");
  }
  console.log("Packaged public types compile in an isolated consumer; Pi loads the single permission extension.");
} finally {
  if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
  else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
  const resolved = path.resolve(work);
  if (path.dirname(resolved) !== cache || !path.basename(resolved).startsWith("public-types-")) {
    throw new Error("Refusing to remove a directory outside the verification workspace.");
  }
  rmSync(resolved, { recursive: true, force: true });
}
