import { copyFileSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { discoverAndLoadExtensions } from "@earendil-works/pi-coding-agent";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const npmCli = process.env.npm_execpath;
if (!npmCli) throw new Error("Run this script with npm run verify:public-types.");
const verifyWindowsMxc = process.argv.includes("--windows-mxc");
const windowsMxcSource = process.env.PI_SANDBOX_TEST_MXC_EXECUTABLE ??
  path.join(root, "src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe");
if (verifyWindowsMxc && process.platform !== "win32") throw new Error("Windows MXC package verification requires Windows.");
if (verifyWindowsMxc && !existsSync(windowsMxcSource)) {
  throw new Error("Build the Windows MXC runtime or set PI_SANDBOX_TEST_MXC_EXECUTABLE before package verification.");
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
  const packedPaths = new Set(packed.files.map(file => file.path));
  if (!packedPaths.has("src/sandbox/runtime-catalog.json")) throw new Error("Packaged runtime catalog is missing.");
  for (const forbidden of [
    "src/sandbox/backend/linux/linux-sandbox",
    "src/sandbox/backend/linux/linux-egress-bridge",
    "src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe",
    "src/sandbox/backend/windows/mxc/mxc-runtime.json",
  ]) {
    if (packedPaths.has(forbidden)) throw new Error(`Packaged npm tarball contains a local native runtime: ${forbidden}`);
  }
  if ([...packedPaths].some(item => item.startsWith("runtimes/") || item.includes("/.staging/"))) {
    throw new Error("Packaged npm tarball contains installed runtime files.");
  }
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
    const runtimeDirectory = path.join(installed, "runtimes/1.0.0/win32-x64");
    mkdirSync(runtimeDirectory, { recursive: true });
    const nativeSource = windowsMxcSource;
    const mxcManifestSource = path.join(root, "src/sandbox/backend/windows/mxc/mxc-runtime.json");
    const nativePath = path.join(runtimeDirectory, "pi-sandbox-windows-mxc.exe");
    const mxcManifestPath = path.join(runtimeDirectory, "mxc-runtime.json");
    copyFileSync(nativeSource, nativePath);
    const sha256 = file => createHash("sha256").update(readFileSync(file)).digest("hex");
    if (process.env.PI_SANDBOX_TEST_MXC_EXECUTABLE) {
      writeFileSync(mxcManifestPath, JSON.stringify({ schemaVersion: 1, backend: "windows-mxc", version: "1.0.0",
        sdkRevision: "b21120168d70befe12356411423266bfef168446", sha256: sha256(nativePath) }));
    } else {
      copyFileSync(mxcManifestSource, mxcManifestPath);
    }
    writeFileSync(path.join(runtimeDirectory, "runtime.json"), JSON.stringify({
      schemaVersion: 1,
      version: "1.0.0",
      stable: true,
      platform: "win32",
      arch: process.arch,
      protocolVersion: 3,
      minPluginVersion: "1.0.0",
      maxPluginVersionExclusive: "2.0.0",
      backendId: "windows-mxc",
      files: [
        { role: "windowsExecutable", path: "pi-sandbox-windows-mxc.exe", sha256: sha256(nativePath), executable: true },
        { role: "mxcManifest", path: "mxc-runtime.json", sha256: sha256(mxcManifestPath), executable: false },
      ],
    }));
    const workspace = path.join(work, "native-workspace");
    mkdirSync(workspace);
    const agentDirectory = path.join(work, "agent");
    mkdirSync(agentDirectory);
    const probe = spawnSync(nativePath, ["probe"], {
      encoding: "utf8",
      timeout: 15_000,
      env: {
        ...process.env,
        PI_MXC_AGENT_DIR: agentDirectory,
        PI_SANDBOX_RUNTIME_DIR: runtimeDirectory,
        PI_SANDBOX_RUNTIME_ROOT: path.join(installed, "runtimes"),
        PI_SANDBOX_WORKSPACE_ROOT: workspace,
      },
    });
    if (probe.error || probe.status !== 0) throw new Error(`Packaged Windows MXC probe failed: ${probe.stderr ?? probe.error}`);
    let capabilities;
    try { capabilities = JSON.parse(probe.stdout); }
    catch { throw new Error(`Packaged Windows MXC probe returned invalid data: ${probe.stdout}`); }
    if (capabilities.available !== true || capabilities.planVersion !== 3) {
      throw new Error(`Packaged Windows MXC runtime is incompatible: ${probe.stdout}`);
    }
    console.log("Packaged Windows MXC runtime passed its host-native probe.");
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
