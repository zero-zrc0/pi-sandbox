import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, realpathSync, statSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { StringDecoder } from "node:string_decoder";

const native = join(dirname(fileURLToPath(import.meta.url)), "mxc", "pi-sandbox-windows-mxc.exe");
let buffer = "";
let checked;
let denyAvailable = false;
let active;

function probe() {
  if (checked !== undefined) return checked;
  try {
    const manifest = JSON.parse(readFileSync(join(dirname(native), "mxc-runtime.json"), "utf8"));
    if (manifest.schemaVersion !== 1 || manifest.backend !== "windows-mxc" || manifest.version !== "1.0.0" ||
      manifest.sdkRevision !== "b21120168d70befe12356411423266bfef168446" ||
      !/^[0-9a-f]{64}$/u.test(manifest.sha256) ||
      createHash("sha256").update(readFileSync(native)).digest("hex") !== manifest.sha256) return checked = false;
    const result = spawnSync(native, ["probe"], { encoding: "utf8", timeout: 6_000, windowsHide: true });
    const capabilities = JSON.parse(result.stdout);
    denyAvailable = capabilities.deny === true;
    checked = result.status === 0 && capabilities.available === true;
  } catch { checked = false; }
  return checked;
}

function reply(message) {
  process.stdout.write(JSON.stringify(message) + "\n");
}

function reject(message, code, reason) {
  reply({ type: "rejected", requestId: message.requestId, generation: message.generation, started: false, code, reason });
}

function pathIdentity(path) {
  if (typeof path !== "string" || !isAbsolute(path) || path.split(/[\\/]/u).some(part => part === "." || part === "..")) throw new Error("invalid filesystem path");
  let current = path;
  const missing = [];
  for (;;) {
    try { return join(realpathSync(current), ...missing.reverse()); }
    catch (error) {
      if (error?.code !== "ENOENT") throw error;
      try {
        lstatSync(current);
        throw new Error("unresolved filesystem identity");
      } catch (check) { if (check?.code !== "ENOENT") throw check; }
      const parent = dirname(current);
      if (parent === current) throw error;
      missing.push(basename(current));
      current = parent;
    }
  }
}

function start(message) {
  if (active) return reject(message, "setup", "helper already has an active request");
  if (!probe()) return reject(message, "unavailable", "native sandbox is unavailable");
  let plan = message.plan;
  if (plan?.backend?.id !== "windows-mxc") return reject(message, "setup", "execution plan backend mismatch");
  const proxyPort = plan.network?.kind === "destinations" && message.egress?.proxyHost === "127.0.0.1" &&
    Number.isInteger(message.egress.proxyPort) && message.egress.proxyPort > 0 && message.egress.proxyPort <= 65535 ? message.egress.proxyPort : undefined;
  if (plan.network?.kind === "destinations" ? proxyPort === undefined :
      (plan.network?.kind !== "none" && plan.network?.kind !== "all") || message.egress !== undefined) return reject(message, "unsupported", "network policy is unsupported");
  if (plan.operation?.kind === "builtin-tool" && plan.operation.name === "bash") {
    return reject(message, "unsupported", "the bash builtin is unsupported by the Windows MXC backend");
  }
  if (plan.operation?.kind === "builtin-tool" && Object.keys(plan.environment ?? {}).some(name => ["NODE_OPTIONS", "NODE_PATH"].includes(name.toUpperCase()))) {
    return reject(message, "unsupported", "builtin runtime injection environment is unsupported");
  }
  if (plan.operation?.kind === "builtin-tool" && ["read", "ls", "grep", "find"].includes(plan.operation.name) &&
      Array.isArray(plan.filesystem) && Array.isArray(plan.protectedPaths)) {
    plan = { ...plan, filesystem: plan.filesystem.filter(grant => grant?.access !== "write"), protectedPaths: [] };
  }
  if (Array.isArray(plan.filesystem)) {
    const writeDirectories = plan.filesystem.filter(grant => grant?.access === "write" && grant.granularity === "directory" && typeof grant.path === "string");
    const missingFile = plan.filesystem.some(grant => grant?.access === "write" && grant.granularity === "file" &&
      typeof grant.path === "string" && !existsSync(grant.path) && !writeDirectories.some(directory => {
        const path = relative(directory.path, grant.path);
        return path === "" || (!isAbsolute(path) && path !== ".." && !path.startsWith(`..${sep}`));
      }));
    if (missingFile) return reject(message, "unsupported", "permission denied");
  }
  const operation = plan.operation;
  const arbitraryProcess = operation?.kind === "shell" ||
    operation?.kind === "builtin-tool" && ["bash", "powershell", "grep", "find"].includes(operation.name);
  if (arbitraryProcess && (!Array.isArray(plan.protectedPaths) || plan.protectedPaths.some(path => typeof path !== "string"))) {
    return reject(message, "unsupported", "a required protected path is invalid");
  }
  let args;
  let input = "";
  let nativePlan = plan;
  let agentDir;
  const builtin = operation?.kind === "builtin-tool";
  if (builtin) {
    try {
      const root = realpathSync(fileURLToPath(new URL("../../../../", import.meta.url)));
      const sdk = realpathSync(fileURLToPath(import.meta.resolve("@earendil-works/pi-coding-agent")));
      let modules = dirname(sdk);
      while (basename(modules).toLowerCase() !== "node_modules") {
        const parent = dirname(modules);
        if (parent === modules) throw new Error("SDK dependency directory is unavailable");
        modules = parent;
      }
      const runner = realpathSync(fileURLToPath(new URL("../../builtin-worker.mjs", import.meta.url)));
      const executable = realpathSync(process.execPath);
      const runtimeGrants = [
        { path: root, access: "read", granularity: "directory" },
        { path: modules, access: "read", granularity: "directory" },
        { path: executable, access: "read", granularity: "file" },
      ];
      const localModules = join(root, "node_modules");
      if (existsSync(localModules) && realpathSync(localModules).toLowerCase() !== modules.toLowerCase()) {
        runtimeGrants.push({ path: realpathSync(localModules), access: "read", granularity: "directory" });
      }
      if (operation.name === "grep" || operation.name === "find") {
        const binary = operation.name === "grep" ? "rg.exe" : "fd.exe";
        agentDir = process.env.PI_MXC_AGENT_DIR;
        if (agentDir && !isAbsolute(agentDir)) return reject(message, "setup", "agent directory must be absolute");
        const local = agentDir ? join(agentDir, "bin", binary)
          : join(plan.environment?.USERPROFILE ?? process.env.USERPROFILE ?? "", ".pi", "agent", "bin", binary);
        const tools = existsSync(local) ? [local] : [];
        if (tools.length === 0) {
          const where = join(process.env.SystemRoot ?? "", "System32", "where.exe");
          for (const name of operation.name === "grep" ? ["rg.exe"] : ["fd.exe", "fdfind.exe"]) {
            const found = spawnSync(where, [name], { cwd: plan.cwd, env: { ...process.env, PATH: plan.environment?.PATH ?? "" },
              encoding: "utf8", windowsHide: true, timeout: 3000 });
            const tool = found.status === 0 ? found.stdout.split(/\r?\n/u).find(Boolean) : undefined;
            if (tool) tools.push(tool);
          }
        }
        if (tools.length === 0) return reject(message, "unavailable", `required ${binary} runtime is unavailable`);
        for (const tool of new Set(tools.map(path => realpathSync(path)))) {
          runtimeGrants.push({ path: tool, access: "read", granularity: "file" });
        }
      }
      args = [executable, "--preserve-symlinks", "--preserve-symlinks-main", runner];
      const mutationQueuePath = operation.context?.mutationQueuePath;
      input = JSON.stringify({ ...operation, toolCallId: plan.toolCallId, cwd: plan.cwd,
        ...(operation.name === "powershell" && proxyPort !== undefined ? { useDefaultProxy: true } : {}),
        ...(mutationQueuePath ? { mutationQueuePath } : {}) }) + "\n";
      nativePlan = { ...plan, ...(agentDir ? { environment: { ...plan.environment, PI_CODING_AGENT_DIR: agentDir } } : {}),
        filesystem: [...plan.filesystem, ...runtimeGrants],
        protectedPaths: [...plan.protectedPaths, ...runtimeGrants.map(grant => grant.path)] };
    } catch { return reject(message, "setup", "builtin runtime is unavailable"); }
  } else if (operation?.kind === "shell" && typeof operation.command === "string" && !operation.command.includes("\0")) {
    const shell = operation.shell;
    if (typeof shell !== "string" || !isAbsolute(shell)) return reject(message, "setup", "shell path must be absolute");
    const name = basename(shell).toLowerCase();
    args = name === "cmd.exe" ? [shell, "/d", "/s", "/c", operation.command]
      : name === "powershell.exe" || name === "pwsh.exe" ? [shell, "-NoProfile", "-NonInteractive", "-Command", operation.command]
        : null;
    if (!args) return reject(message, "unsupported", "shell interpreter is unsupported");
  } else return reject(message, "unsupported", "execution operation is unsupported");
  if (Array.isArray(nativePlan.protectedPaths) && Array.isArray(nativePlan.filesystem)) {
    try {
      const protectedPaths = nativePlan.protectedPaths.map(pathIdentity);
      const filesystem = nativePlan.filesystem.map(grant => {
        const path = pathIdentity(grant.path);
        try {
          const directory = statSync(path).isDirectory();
          if (grant.granularity !== (directory ? "directory" : "file")) throw new Error("grant type mismatch");
        } catch (error) { if (error?.code !== "ENOENT") throw error; }
        return { ...grant, path };
      });
      const writes = filesystem.filter(grant => grant?.access === "write").map(grant => grant.path);
      if (protectedPaths.some(parent => writes.some(target => {
        const path = relative(parent, target);
        return path === "" || (!isAbsolute(path) && path !== ".." && !path.startsWith(`..${sep}`));
      }))) return reject(message, "denied", "write grant conflicts with protected path");
      nativePlan = { ...nativePlan, protectedPaths, filesystem };
    } catch { return reject(message, "unsupported", "filesystem path identity is unavailable"); }
  }
  const child = spawn(native, [], { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
  const state = { child, requestId: message.requestId, generation: message.generation, started: false, cancelled: false };
  active = state;
  let sequence = 0;
  let prefix = Buffer.alloc(0);
  const marker = Buffer.from("\x1ePI-MXC-READY\x1f");
  const stdout = new StringDecoder("utf8");
  const stderr = new StringDecoder("utf8");
  let diagnostics = "";
  let builtinBuffer = "";
  let builtinResult;
  const emit = (stream, data) => {
    let part = "";
    for (const character of data) {
      if (part.length + character.length > 16_000) {
        reply({ type: "output", requestId: state.requestId, generation: state.generation, sequence: sequence++, stream, data: part });
        part = "";
      }
      part += character;
    }
    if (part) reply({ type: "output", requestId: state.requestId, generation: state.generation, sequence: sequence++, stream, data: part });
  };
  child.stdin.on("error", () => {});
  child.stdin.end(JSON.stringify({ plan: nativePlan, argv: args, input, ...(proxyPort === undefined ? {} : { proxyPort }) }));
  child.stdout.on("data", chunk => {
    if (!state.started) {
      prefix = Buffer.concat([prefix, chunk]);
      if (prefix.length < marker.length) return;
      if (!prefix.subarray(0, marker.length).equals(marker)) { child.kill(); return; }
      state.started = true;
      reply({ type: "started", requestId: state.requestId, generation: state.generation, pid: null, startedAt: new Date().toISOString() });
      chunk = prefix.subarray(marker.length);
      prefix = Buffer.alloc(0);
    }
    const data = stdout.write(chunk);
    if (!builtin) { emit("stdout", data); return; }
    builtinBuffer += data;
    if (Buffer.byteLength(builtinBuffer) > 4 * 1024 * 1024) { diagnostics = "builtin result is too large"; child.kill(); return; }
    for (;;) {
      const end = builtinBuffer.indexOf("\n");
      if (end < 0) break;
      const line = builtinBuffer.slice(0, end);
      builtinBuffer = builtinBuffer.slice(end + 1);
      try {
        const packet = JSON.parse(line);
        if (packet.type === "update" && !builtinResult) emit("stdout", JSON.stringify(packet.result) + "\n");
        else if (packet.type === "result" && !builtinResult) builtinResult = packet;
        else throw new Error("unexpected builtin packet");
      } catch { diagnostics = "invalid builtin result"; child.kill(); return; }
    }
  });
  child.stderr.on("data", chunk => {
    const data = stderr.write(chunk);
    if (state.started && !builtin) emit("stderr", data);
    else if (diagnostics.length < 4096) diagnostics += data;
  });
  child.on("error", () => { diagnostics = "native sandbox process could not start"; });
  child.on("close", (code, signal) => {
    if (state.cancelled) reply({ type: "cancelled", requestId: state.requestId, generation: state.generation, started: state.started ? true : "unknown" });
    else if (!state.started) reply({ type: "error", requestId: state.requestId, generation: state.generation,
      code: "setup", message: diagnostics.trim() || "native sandbox exited before start notification" });
    else {
      emit("stdout", stdout.end()); emit("stderr", stderr.end());
      const failure = builtin && (!builtinResult || builtinBuffer.trim() || builtinResult.error || builtinResult.result?.isError === true);
      reply({ type: "result", requestId: state.requestId, generation: state.generation, started: true,
        exitCode: failure ? 1 : code, impact: code === null || signal !== null ? "unknown" : "known",
        ...(failure ? { errorCode: "tool", error: diagnostics || builtinResult?.error || "builtin returned an error" } : {}),
        ...(builtinResult ? { dataBase64: Buffer.from(JSON.stringify(builtinResult)).toString("base64") } : {}) });
    }
    active = undefined;
  });
}

function handle(message) {
  if (message?.type === "hello" && typeof message.requestId === "string" && Number.isInteger(message.generation)) {
    const available = probe();
    if (!available) {
      reply({ type: "error", requestId: message.requestId, generation: message.generation,
        code: "unavailable", message: "native sandbox is unavailable" });
      return;
    }
    reply({ type: "ready", protocolVersion: 2, requestId: message.requestId, generation: message.generation,
      backend: { id: "windows-mxc", version: "1.0.0" },
      capabilities: { filesystem: { read: available, write: available, granularity: "file", protectedPaths: available && denyAvailable, environment: available },
        network: "domains", cancel: available, streamOutput: available, startedNotification: available, processTree: available } });
  } else if (message?.type === "start" && typeof message.requestId === "string" && Number.isInteger(message.generation)) {
    start(message);
  } else if (message?.type === "cancel" && active && message.requestId === active.requestId && message.generation === active.generation) {
    active.cancelled = true;
    active.child.kill();
  } else if (message?.type === "shutdown") {
    if (active) active.child.kill();
    process.exit(0);
  }
}

process.stdin.setEncoding("utf8");
process.stdin.on("data", chunk => {
  buffer += chunk;
  if (Buffer.byteLength(buffer) > 8 * 1024 * 1024) { process.exit(2); return; }
  for (;;) {
    const end = buffer.indexOf("\n");
    if (end < 0) break;
    const line = buffer.slice(0, end);
    buffer = buffer.slice(end + 1);
    try { handle(JSON.parse(line)); } catch { reply({ type: "error", code: "protocol", message: "invalid helper message" }); }
  }
});
process.stdin.on("end", () => { if (active) active.child.kill(); process.exitCode = 0; });
