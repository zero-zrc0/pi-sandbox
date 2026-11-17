import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, realpathSync, statSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { StringDecoder } from "node:string_decoder";
import {
  findSystemBubblewrap as findSystemBubblewrapOnPath,
  resolveSystemBubblewrap,
  selectBubblewrapCandidate,
} from "./bwrap-selection.mjs";

const protocolVersion = 2;
const backendId = "linux-bwrap-landlock-seccomp";
const backendVersion = "1.1.0";
let runtimeLoadFailure = "";
const runtimeFiles = loadRuntimeFiles();
const nativeHelper = runtimeFiles?.linuxLauncher ?? "";
let selectedBubblewrapPath = "";
const MAX_INPUT_BYTES = 8 * 1024 * 1024;
const MAX_OUTPUT_CHUNK_BYTES = 48 * 1024;
const MAX_FILE_CONTENT_BYTES = 4 * 1024 * 1024;
const MAX_CAPTURED_OPERATION_ERROR_BYTES = 64 * 1024;
const ENVIRONMENT_ALLOWLIST = new Set([
  "PATH",
  "TEMP",
  "TMP",
  "TMPDIR",
  "PI_SANDBOX_WORK_DIR",
  "HOME",
  "LANG",
  "LC_ALL",
  "TERM",
]);

let inputBuffer = "";
let requestId = "";
let generation = 0;
let sequence = 0;
let active;
let shuttingDown = false;
let cachedProbe;

function pathWithin(parent, child) {
  const path = relative(parent, child);
  return path === "" || (path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path));
}

function loadRuntimeFiles() {
  try {
    const configured = process.env.PI_SANDBOX_RUNTIME_DIR;
    if (!configured || !isAbsolute(configured)) throw new Error("runtime directory was not supplied by the host");
    const configuredRoot = process.env.PI_SANDBOX_RUNTIME_ROOT;
    if (configuredRoot && !isAbsolute(configuredRoot)) throw new Error("runtime storage root is not absolute");
    const runtimeStorageRoot = realpathSync(configuredRoot ?? fileURLToPath(new URL("../../../../", import.meta.url)));
    if (configuredRoot && runtimeStorageRoot !== configuredRoot) throw new Error("runtime storage root is not canonical");
    const runtimeDirectory = realpathSync(configured);
    if (runtimeDirectory !== configured || !pathWithin(runtimeStorageRoot, runtimeDirectory)) {
      throw new Error("runtime directory is not canonical or is outside the trusted runtime root");
    }
    const manifestPath = join(runtimeDirectory, "runtime.json");
    const manifestStat = lstatSync(manifestPath);
    if (manifestStat.isSymbolicLink() || !manifestStat.isFile() || manifestStat.nlink > 1) {
      throw new Error("runtime manifest is not a regular file");
    }
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    if (manifest.schemaVersion !== 1 || manifest.stable !== true || manifest.platform !== "linux" ||
        manifest.arch !== process.arch || manifest.backendId !== backendId || manifest.protocolVersion !== protocolVersion ||
        !Array.isArray(manifest.files) || !manifest.components ||
        !/^\d+\.\d+\.\d+$/u.test(manifest.components.bubblewrapVersion) ||
        !/^[0-9a-f]{40}$/u.test(manifest.components.bubblewrapSourceCommit)) throw new Error("runtime manifest does not match this helper");
    const expected = new Map([
      ["linuxLauncher", ["linux-sandbox", true]],
      ["egressBridge", ["linux-egress-bridge", true]],
      ["bubblewrap", ["bwrap", true]],
      ["bubblewrapLicense", ["bwrap.LICENSE", false]],
    ]);
    const files = Object.create(null);
    for (const item of manifest.files) {
      const fixed = expected.get(item.role);
      if (!fixed || item.path !== fixed[0] || item.executable !== fixed[1] || !/^[0-9a-f]{64}$/u.test(item.sha256)) {
        throw new Error("runtime manifest contains an invalid Linux file entry");
      }
      if (files[item.role]) throw new Error("runtime manifest repeats a Linux file entry");
      const path = join(runtimeDirectory, fixed[0]);
      const stat = lstatSync(path);
      if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink > 1 || (fixed[1] && (stat.mode & 0o111) === 0)) {
        throw new Error(`runtime file ${fixed[0]} is not a regular file with the required permissions`);
      }
      const actual = realpathSync(path);
      if (actual !== path || !pathWithin(runtimeDirectory, actual) ||
          createHash("sha256").update(readFileSync(actual)).digest("hex") !== item.sha256) {
        throw new Error(`runtime file ${fixed[0]} failed path or hash validation`);
      }
      files[item.role] = actual;
    }
    if (manifest.files.length !== expected.size || expected.size !== Object.keys(files).length) {
      throw new Error("runtime manifest is missing required Linux files");
    }
    return {
      runtimeDirectory,
      linuxLauncher: files.linuxLauncher,
      egressBridge: files.egressBridge,
      bubblewrap: files.bubblewrap,
      bubblewrapVersion: manifest.components.bubblewrapVersion,
    };
  } catch (error) {
    runtimeLoadFailure = error instanceof Error ? error.message : String(error);
    return undefined;
  }
}

function send(message, callback) {
  if (shuttingDown) return;
  process.stdout.write(`${JSON.stringify(message)}\n`, callback);
}

function sendExit(message, code = 0) {
  if (shuttingDown) return;
  shuttingDown = true;
  process.stdout.write(`${JSON.stringify(message)}\n`, () => process.exit(code));
}

function failure(code, reason) {
  return Object.assign(new Error(reason), { code });
}

function versionAtLeast(actual, minimum) {
  const left = actual.split(".").map(Number);
  const right = minimum.split(".").map(Number);
  for (let index = 0; index < right.length; index += 1) {
    if ((left[index] ?? 0) > right[index]) return true;
    if ((left[index] ?? 0) < right[index]) return false;
  }
  return true;
}

const REQUIRED_BWRAP_FLAGS = [
  "--die-with-parent", "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-net",
  "--disable-userns", "--assert-userns-disabled", "--ro-bind", "--dev", "--proc", "--bind-fd", "--ro-bind-fd",
  "--tmpfs", "--dir", "--file", "--clearenv", "--setenv", "--chdir",
];

function findSystemBubblewrap() {
  const workspaceRoot = process.env.PI_SANDBOX_WORKSPACE_ROOT;
  const configuredPath = process.env.PI_SANDBOX_SYSTEM_BWRAP_PATH;
  return configuredPath === undefined
    ? findSystemBubblewrapOnPath(process.env.PATH, workspaceRoot)
    : resolveSystemBubblewrap(configuredPath, workspaceRoot);
}

function probeBubblewrap(path, expectedVersion) {
  try {
    const help = spawnSync(path, ["--help"], { encoding: "utf8", timeout: 3_000, stdio: ["ignore", "pipe", "pipe"] });
    const helpText = `${help.stdout ?? ""}\n${help.stderr ?? ""}`;
    if (help.status !== 0 || REQUIRED_BWRAP_FLAGS.some(flag => !helpText.includes(flag))) return undefined;
    const versionResult = spawnSync(path, ["--version"], { encoding: "utf8", timeout: 3_000, stdio: ["ignore", "pipe", "ignore"] });
    const match = /^bubblewrap (\d+\.\d+\.\d+)/u.exec(versionResult.stdout ?? "");
    if (versionResult.status !== 0 || !match || (expectedVersion !== undefined && match[1] !== expectedVersion) ||
        !versionAtLeast(match[1], "0.9.0")) return undefined;
    const smoke = spawnSync(path, [
      "--die-with-parent", "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-net",
      "--disable-userns", "--assert-userns-disabled", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
      "--clearenv", "--setenv", "PATH", "/usr/bin:/bin", "--chdir", "/", "--", "/bin/true",
    ], { stdio: "ignore", timeout: 3_000 });
    return smoke.status === 0 ? match[1] : undefined;
  } catch { return undefined; }
}

function selectBubblewrap() {
  const system = findSystemBubblewrap();
  const selected = selectBubblewrapCandidate(
    system,
    runtimeFiles?.bubblewrap === undefined ? undefined : {
      path: runtimeFiles.bubblewrap,
      version: runtimeFiles.bubblewrapVersion,
    },
    probeBubblewrap,
  );
  if (!selected) return "";
  selectedBubblewrapPath = selected.path;
  return selected.version;
}

function probeBackend() {
  if (cachedProbe) return cachedProbe;
  let native = { landlockAbi: -1, seccomp: false };
  try {
    if (!runtimeFiles) throw new Error(runtimeLoadFailure || "runtime files are unavailable");
    native = JSON.parse(spawnSync(nativeHelper, ["probe"], {
      encoding: "utf8",
      timeout: 3_000,
      stdio: ["ignore", "pipe", "ignore"],
    }).stdout);
  } catch {}

  const bwrapVersion = runtimeFiles === undefined ? "" : selectBubblewrap();
  const bwrapReady = bwrapVersion !== "";
  const bwrapReason = bwrapReady ? undefined
    : runtimeFiles === undefined ? runtimeLoadFailure || "runtime files are unavailable"
      : "no compatible system or bundled bubblewrap passed the required-option and user-namespace probes";

  /* The standalone egress bridge is what makes destination enforcement real. */
  let bridgeReady = false;
  try {
    const bridgePath = runtimeFiles?.egressBridge ?? "";
    const stat = statSync(bridgePath);
    bridgeReady = stat.isFile() && (stat.mode & 0o111) !== 0;
  } catch {}

  const supported = runtimeFiles !== undefined && native.landlockAbi >= 3 && native.seccomp === true && bwrapReady;
  cachedProbe = {
    supported,
    runtimeLoadFailure,
    bwrapReason,
    landlockAbi: native.landlockAbi,
    seccomp: native.seccomp === true,
    bwrapVersion,
    bwrapReady,
    bridgeReady,
  };
  return cachedProbe;
}

function capabilities(probe) {
  return {
    filesystem: {
      read: probe.supported,
      write: probe.supported,
      granularity: probe.supported ? "file" : "directory",
      protectedPaths: probe.supported,
      environment: probe.bwrapReady,
    },
    /*
     * `domains` is a superset capability: with the bridge installed the
     * backend both enforces destination allowlists and can still run
     * unrestricted plans.
     */
    network: probe.supported && probe.bridgeReady ? "domains" : probe.bwrapReady ? "all" : "none",
    cancel: true,
    streamOutput: true,
    startedNotification: probe.bwrapReady,
    processTree: probe.bwrapReady,
  };
}

function isWithin(parent, child) {
  const path = relative(parent, child);
  return path === "" || (path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path));
}

function canonicalPath(path, kind) {
  if (typeof path !== "string" || !isAbsolute(path) || path.includes("\0")) {
    throw failure("setup", "sandbox path must be an absolute Linux path");
  }
  let resolved;
  let info;
  try {
    resolved = realpathSync.native(path);
    info = statSync(path);
  } catch {
    throw failure("missing", `sandbox path does not exist: ${path}`);
  }
  if (resolved !== path) {
    throw failure("setup", `sandbox path is not canonical: ${path}`);
  }
  if (kind === "directory" && !info.isDirectory()) {
    throw failure("setup", `directory grant is not a directory: ${path}`);
  }
  if (kind === "file" && !info.isFile()) {
    throw failure("setup", `file grant is not a regular file: ${path}`);
  }
  return { path, directory: info.isDirectory() };
}

/*
 * Write targets and protected control paths may not exist yet: resolve the
 * identity of the deepest existing component and rejoin the missing tail.
 */
function pathIdentity(path) {
  if (typeof path !== "string" || !isAbsolute(path) || path.includes("\0")) {
    throw failure("setup", "sandbox path must be an absolute Linux path");
  }
  const missing = [];
  let current = path;
  for (;;) {
    try {
      const resolved = realpathSync.native(current);
      return missing.length === 0 ? resolved : join(resolved, ...missing.reverse());
    } catch (error) {
      if (error?.code !== "ENOENT") {
        throw failure("setup", `sandbox path identity is unavailable: ${path}`);
      }
      const parent = dirname(current);
      if (parent === current) throw failure("missing", `sandbox path does not exist: ${path}`);
      missing.push(basename(current));
      current = parent;
    }
  }
}

function validateEgressGrant(egress) {
  if (typeof egress !== "object" || egress === null) {
    throw failure("setup", "egress grant is missing");
  }
  const { proxyHost, proxyPort, leaseId, credential } = egress;
  if (
    typeof proxyHost !== "string" ||
    !/^[A-Za-z0-9._-]+$/u.test(proxyHost)
  ) {
    throw failure("setup", "egress proxy host is invalid");
  }
  if (!Number.isInteger(proxyPort) || proxyPort <= 0 || proxyPort > 65_535) {
    throw failure("setup", "egress proxy port is invalid");
  }
  for (const [name, value] of [["leaseId", leaseId], ["credential", credential]]) {
    if (
      typeof value !== "string" ||
      value.length === 0 ||
      value.length > 255 ||
      /[\r\n\0]/u.test(value)
    ) {
      throw failure("setup", `egress ${name} is invalid`);
    }
  }
}

function buildLaunchArgs(plan, egress) {
  /*
   * A sandbox tool runs the same one-shot node worker as a builtin tool, so
   * both kinds need the same runner resolution, execute grants and read-only
   * runtime mount. Decide it once: repeating the condition per site is how the
   * sandbox-tool execute grant went missing before.
   */
  const isWorker = plan.operation.kind === "builtin-tool" || plan.operation.kind === "sandbox-tool";
  let egressEnv;
  if (plan.network.kind === "destinations") {
    /*
     * Destinations run through the isolated network, the standalone bridge
     * and the host policy proxy. Without a host-issued grant there is no
     * second path: the launch is refused before anything starts.
     */
    if (egress === undefined) {
      throw failure("unsupported", "destination allowlists require a host egress grant");
    }
    validateEgressGrant(egress);
    egressEnv = {
      PI_EGRESS_PROXY: `${egress.proxyHost}:${egress.proxyPort}`,
      PI_EGRESS_LEASE: egress.leaseId,
      PI_EGRESS_CREDENTIAL: egress.credential,
    };
  } else if (plan.network.kind !== "none" && plan.network.kind !== "all") {
    throw failure("unsupported", "Linux backend received an unknown network profile");
  }
  let operationArgs;
  let operationInput;
  if (isWorker) {
    let runner;
    try {
      runner = realpathSync(fileURLToPath(new URL(
        plan.operation.kind === "sandbox-tool"
          ? "../../sandbox-tool-worker.mjs"
          : "../../builtin-worker.bundle.mjs",
        import.meta.url,
      )));
    } catch {
      throw failure("setup", "sandbox tool runtime is unavailable");
    }
    operationArgs = ["--", realpathSync(process.execPath), runner];
    operationInput = JSON.stringify({ ...plan.operation, toolCallId: plan.toolCallId, cwd: plan.cwd }) + "\n";
  } else if (plan.operation.kind === "shell") {
    const shell = plan.operation.shell ?? "/bin/sh";
    if (!new Set(["/bin/sh", "/bin/bash", "/usr/bin/bash"]).has(shell) || !existsSync(shell)) {
      throw failure("unsupported", "Linux backend received an unsupported shell interpreter");
    }
    if (plan.operation.command.includes("\0")) {
      throw failure("setup", "shell command contains a NUL byte");
    }
    operationArgs = ["--", shell, "-c", plan.operation.command];
  } else if (plan.operation.kind === "read-file") {
    operationArgs = ["--", "read-file", canonicalPath(plan.operation.path, "file").path];
  } else if (plan.operation.kind === "access-file") {
    operationArgs = ["--", "access-file", canonicalPath(plan.operation.path, "file").path, plan.operation.mode];
  } else if (plan.operation.kind === "write-file") {
    if (Buffer.byteLength(plan.operation.content, "utf8") > MAX_FILE_CONTENT_BYTES) {
      throw failure("unsupported", "file content exceeds the helper input limit");
    }
    operationArgs = ["--", "write-file", plan.operation.path];
    operationInput = plan.operation.content;
  } else if (plan.operation.kind === "mkdir") {
    operationArgs = ["--", "mkdir", plan.operation.path];
  } else if (plan.operation.kind === "access-dir") {
    operationArgs = ["--", "access-dir", canonicalPath(plan.operation.path, "directory").path];
  } else {
    throw failure("unsupported", `Linux backend does not support ${plan.operation.kind} operations yet`);
  }
  const cwd = canonicalPath(plan.cwd, "directory").path;
  const grants = [];
  if (isWorker) {
    grants.push({ path: realpathSync(fileURLToPath(new URL("../../../../", import.meta.url))), access: "read", granularity: "directory" });
    grants.push({ path: realpathSync(process.execPath), access: "read", granularity: "file" });
  }
  /*
   * The native launcher can only bind paths that exist. A write target that is
   * still missing is covered by its write directory grant, exactly as on the
   * Windows backend; a protected path that does not exist denies nothing yet.
   */
  const writeDirectories = plan.filesystem
    .filter((grant) => grant.access === "write" && grant.granularity === "directory")
    .map((grant) => pathIdentity(grant.path));
  for (const grant of plan.filesystem) {
    const kind = grant.granularity === "directory" ? "directory" : "file";
    const path = pathIdentity(grant.path);
    let info;
    try {
      info = statSync(path);
    } catch (error) {
      if (error?.code !== "ENOENT") {
        throw failure("missing", `sandbox path does not exist: ${grant.path}`);
      }
    }
    if (info === undefined) {
      if (grant.access === "write" && !writeDirectories.some((directory) => isWithin(directory, path))) {
        throw failure("unsupported", `write target does not exist and no write directory covers it: ${grant.path}`);
      }
      continue;
    }
    if (kind === "directory" && !info.isDirectory()) {
      throw failure("setup", `directory grant is not a directory: ${grant.path}`);
    }
    if (kind === "file" && !info.isFile()) {
      throw failure("setup", `file grant is not a regular file: ${grant.path}`);
    }
    grants.push({ ...grant, path });
  }
  if (!grants.some((grant) => grant.granularity === "directory" && isWithin(grant.path, cwd))) {
    throw failure("unsupported", "execution cwd is outside every directory grant");
  }
  const protectedPaths = plan.protectedPaths.map(pathIdentity).filter((path) => existsSync(path));
  const environment = Object.entries(plan.environment);
  for (const [name, value] of environment) {
    if (!ENVIRONMENT_ALLOWLIST.has(name) || typeof value !== "string" || value.includes("\0")) {
      throw failure("unsupported", `environment variable is not allowed: ${name}`);
    }
  }

  const args = ["run", "--network", plan.network.kind, "--cwd", cwd];
  // A sandbox-hosted tool also execs node and loads its module from the package
  // root, exactly like a builtin worker, so it needs the same execute grants.
  if (isWorker) {
    const runtime = realpathSync(fileURLToPath(new URL("../../../../", import.meta.url)));
    args.push("--execute-file", realpathSync(process.execPath), "--execute-dir", runtime);
  }
  for (const grant of grants) {
    if (grant.access === "read") {
      args.push(grant.granularity === "directory" ? "--read-dir" : "--read-file", grant.path);
    } else if (grant.access === "write") {
      args.push(grant.granularity === "directory" ? "--write-dir" : "--write-file", grant.path);
    }
  }
  for (const path of protectedPaths) args.push("--protected", path);
  // The host-owned runtime is read-only for both worker kinds.
  if (isWorker) {
    const runtimeRoot = realpathSync(fileURLToPath(new URL("../../../../", import.meta.url)));
    if (!protectedPaths.includes(runtimeRoot)) args.push("--protected", runtimeRoot);
  }
  for (const [name, value] of environment) args.push("--env", name, value);
  args.push(...operationArgs);
  return { args, operationInput, ...(egressEnv === undefined ? {} : { egressEnv }) };
}

function sendRejected(message, code, reason) {
  sendExit({
    type: "rejected",
    requestId: message.requestId,
    generation: message.generation,
    started: false,
    code,
    reason,
  });
}

function run(message) {
  const probe = probeBackend();
  if (!probe.supported) {
    sendRejected(message, "unsupported", "required bwrap, Landlock ABI 3, or seccomp capability is unavailable");
    return;
  }
  let launch;
  try {
    if (!message.plan || message.plan.backend?.id !== backendId) {
      throw failure("setup", "execution plan backend does not match the installed Linux helper");
    }
    launch = buildLaunchArgs(message.plan, message.egress);
  } catch (error) {
    sendRejected(message, error.code ?? "setup", error.message);
    return;
  }

  requestId = message.requestId;
  generation = message.generation;
  sequence = 0;
  let started = false;
  let settled = false;
  let diagnostics = "";
  let pendingOutputBytes = 0;
  const pendingOutput = [];
  const operation = message.plan.operation;
  const isInternalOperation = operation.kind !== "shell";
  /*
   * Both worker kinds relay their result through the same stdout protocol and
   * share the read-only runtime mount, so a sandbox tool is never a plain
   * internal operation here either.
   */
  const isWorker = operation.kind === "builtin-tool" || operation.kind === "sandbox-tool";
  const isReadFile = operation.kind === "read-file" || isWorker;
  let builtinLines = "";
  let builtinResult;
  function captureOperation(chunk) {
    if (!isWorker) {
      if (operationOutput.length + chunk.length > MAX_FILE_CONTENT_BYTES) { operationOutputTooLarge = true; child.kill("SIGKILL"); return; }
      operationOutput = Buffer.concat([operationOutput, chunk]);
      return;
    }
    builtinLines += stdoutDecoder.write(chunk);
    if (Buffer.byteLength(builtinLines) > MAX_INPUT_BYTES) { operationOutputTooLarge = true; child.kill("SIGKILL"); return; }
    let end;
    while ((end = builtinLines.indexOf("\n")) >= 0) {
      const line = builtinLines.slice(0, end); builtinLines = builtinLines.slice(end + 1);
      try {
        const packet = JSON.parse(line);
        if (packet.type === "update" && !builtinResult) emitOutput("stdout", JSON.stringify(packet.result) + "\n");
        else if (packet.type === "result" && !builtinResult) builtinResult = packet;
        else throw new Error("invalid builtin packet");
      } catch { diagnostics = "invalid builtin result protocol"; child.kill("SIGKILL"); }
    }
  }
  let operationOutput = Buffer.alloc(0);
  let operationOutputTooLarge = false;
  const stdoutDecoder = new StringDecoder("utf8");
  const stderrDecoder = new StringDecoder("utf8");
  const startupMarker = Buffer.from("\x1ePI-LINUX-SANDBOX-READY\x1f");
  let startupBuffer = Buffer.alloc(0);
  const child = spawn(nativeHelper, launch.args, {
    cwd: process.cwd(),
    env: { ...process.env, PI_SANDBOX_BWRAP_PATH: selectedBubblewrapPath, ...launch.egressEnv },
    stdio: [launch.operationInput === undefined ? "ignore" : "pipe", "pipe", "pipe"],
    shell: false,
  });
  if (launch.operationInput !== undefined) {
    child.stdin.on("error", () => {});
    child.stdin.end(launch.operationInput, "utf8");
  }
  const state = { child, requestId, generation, started: false, cancelled: false };
  active = state;

  const sendStarted = () => {
    if (started || settled) return;
    started = true;
    state.started = true;
    send({
      type: "started",
      requestId,
      generation,
      pid: child.pid ?? null,
      startedAt: new Date().toISOString(),
    });
    for (const item of pendingOutput.splice(0)) emitOutput(item.stream, item.data);
    pendingOutputBytes = 0;
  };

  const queueOrEmit = (stream, data) => {
    if (!data) return;
    if (started) {
      emitOutput(stream, data);
      return;
    }
    const bytes = Buffer.byteLength(data, "utf8");
    if (pendingOutputBytes + bytes > 64 * 1024) {
      diagnostics = "output arrived before sandbox readiness";
      child.kill("SIGKILL");
      return;
    }
    pendingOutput.push({ stream, data });
    pendingOutputBytes += bytes;
  };

  child.stdout.on("data", (chunk) => {
    if (started) {
      if (isReadFile) {
        captureOperation(chunk);
      } else if (!isInternalOperation) queueOrEmit("stdout", stdoutDecoder.write(chunk));
      return;
    }
    startupBuffer = Buffer.concat([startupBuffer, chunk]);
    const markerPrefix = startupMarker.subarray(0, startupBuffer.length);
    if (startupBuffer.length < startupMarker.length && markerPrefix.equals(startupBuffer)) return;
    if (!startupBuffer.subarray(0, startupMarker.length).equals(startupMarker)) {
      diagnostics = "sandbox readiness marker was missing or invalid";
      child.kill("SIGKILL");
      return;
    }
    const output = startupBuffer.subarray(startupMarker.length);
    startupBuffer = Buffer.alloc(0);
    sendStarted();
    if (output.length) {
      if (isReadFile) {
        captureOperation(output);
      }
      else if (!isInternalOperation) queueOrEmit("stdout", stdoutDecoder.write(output));
    }
  });
  child.stderr.on("data", (chunk) => {
    const value = stderrDecoder.write(chunk);
    if (isInternalOperation) {
      if (Buffer.byteLength(diagnostics, "utf8") < MAX_CAPTURED_OPERATION_ERROR_BYTES) diagnostics += value;
    } else if (started) queueOrEmit("stderr", value);
    else if (Buffer.byteLength(diagnostics, "utf8") < 64 * 1024) diagnostics += value;
  });
  child.on("error", (error) => {
    if (settled) return;
    settled = true;
    if (!started) sendRejected(message, "setup", error.message);
    else sendExit({
      type: "result", requestId, generation, started: true,
      exitCode: null, impact: "unknown", errorCode: "spawn", error: error.message,
    });
  });
  child.on("close", (code, signal) => {
    if (settled) return;
    settled = true;
    if (state.cancelled) {
      sendExit({ type: "cancelled", requestId, generation, started: started ? true : false });
      return;
    }
    if (!started) {
      sendRejected(message, "setup", diagnostics.trim() || `sandbox setup exited before readiness (code=${String(code)})`);
      return;
    }
    if (isWorker) {
      if (!builtinResult || builtinLines.trim()) {
        sendExit({ type: "result", requestId, generation, started: true, exitCode: null, impact: "unknown", errorCode: "protocol", error: diagnostics || "builtin exited without a complete result" });
        return;
      }
      operationOutput = Buffer.from(JSON.stringify(builtinResult));
      if (operationOutput.length > MAX_FILE_CONTENT_BYTES) operationOutputTooLarge = true;
    }
    const stdoutEnd = stdoutDecoder.end();
    const stderrEnd = stderrDecoder.end();
    if (!isInternalOperation && stdoutEnd) emitOutput("stdout", stdoutEnd);
    if (!isInternalOperation && stderrEnd) emitOutput("stderr", stderrEnd);
    if (isInternalOperation && stderrEnd && Buffer.byteLength(diagnostics, "utf8") < MAX_CAPTURED_OPERATION_ERROR_BYTES) {
      diagnostics += stderrEnd;
    }
    const operationError = /^PI-LINUX-OP-ERROR:(missing|denied|io|unsupported):(.+)$/mu.exec(diagnostics);
    if (operationOutputTooLarge) {
      sendExit({
        type: "result", requestId, generation, started: true,
        exitCode: 1, impact: "known", errorCode: "unsupported",
        error: "file content exceeds the helper result limit",
      });
      return;
    }
    sendExit({
      type: "result",
      requestId,
      generation,
      started: true,
      exitCode: operationError ? 1 : code ?? null,
      impact: code === null || signal !== null ? "unknown" : "known",
      ...(operationError ? { errorCode: operationError[1], error: operationError[2] } : {}),
      ...(isReadFile && !operationError ? { dataBase64: operationOutput.toString("base64") } : {}),
      ...(isWorker && (typeof builtinResult.error === "string" || builtinResult.result?.isError === true)
        ? { exitCode: 1, errorCode: "tool", error: builtinResult.error ?? "builtin returned an error result" } : {}),
      ...(signal ? { errorCode: "signal", error: `sandboxed process exited on ${signal}` } : {}),
    });
  });

  function emitOutput(stream, value) {
    let part = "";
    for (const character of value) {
      if (Buffer.byteLength(part + character, "utf8") > MAX_OUTPUT_CHUNK_BYTES) {
        send({ type: "output", requestId, generation, sequence: sequence++, stream, data: part });
        part = "";
      }
      part += character;
    }
    if (part) send({ type: "output", requestId, generation, sequence: sequence++, stream, data: part });
  }
}

function onHostMessage(message) {
  if (!message || typeof message !== "object") return;
  if (message.type === "hello") {
    if (!Number.isInteger(message.generation) || typeof message.requestId !== "string") return;
    const probe = probeBackend();
    if (!probe.supported) {
      send({
        type: "error",
        requestId: message.requestId,
        generation: message.generation,
        code: "unavailable",
      message: `linux sandbox is unavailable: ${probe.runtimeLoadFailure || probe.bwrapReason || `Landlock ABI ${probe.landlockAbi ?? 0} (need >= 3), seccomp ${probe.seccomp ? "ready" : "missing"}`}`,
      });
      return;
    }
    send({
      type: "ready",
      protocolVersion,
      requestId: message.requestId,
      generation: message.generation,
      backend: { id: backendId, version: backendVersion },
      capabilities: capabilities(probe),
    });
    return;
  }
  if (message.type === "start") {
    if (active || !Number.isInteger(message.generation) || typeof message.requestId !== "string") {
      sendRejected(message, "setup", "helper already has an active request or correlation is invalid");
      return;
    }
    run(message);
    return;
  }
  if (message.type === "cancel") {
    if (active && message.requestId === active.requestId && message.generation === active.generation) {
      active.cancelled = true;
      active.child.kill("SIGTERM");
      const child = active.child;
      const timer = setTimeout(() => child.kill("SIGKILL"), 200);
      timer.unref?.();
    }
    return;
  }
  if (message.type === "shutdown") {
    shuttingDown = true;
    if (active) active.child.kill("SIGTERM");
    process.exit(0);
  }
}

process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  inputBuffer += chunk;
  if (Buffer.byteLength(inputBuffer, "utf8") > MAX_INPUT_BYTES) {
    process.exit(2);
    return;
  }
  for (;;) {
    const newline = inputBuffer.indexOf("\n");
    if (newline < 0) break;
    const line = inputBuffer.slice(0, newline);
    inputBuffer = inputBuffer.slice(newline + 1);
    if (!line.trim()) continue;
    try {
      onHostMessage(JSON.parse(line));
    } catch {
      send({ type: "error", code: "protocol", message: "helper received invalid JSON" });
    }
  }
});
process.stdin.on("end", () => {
  if (active) active.child.kill("SIGTERM");
  process.exitCode = 0;
});
