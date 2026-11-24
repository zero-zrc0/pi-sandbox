import { spawn } from "node:child_process";
import { existsSync, realpathSync, statSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const MAX_FILE_CONTENT_BYTES = 4 * 1024 * 1024;
const ENVIRONMENT_ALLOWLIST = new Set(["PATH", "TEMP", "TMP", "TMPDIR", "PI_SANDBOX_WORK_DIR", "HOME", "LANG", "LC_ALL", "TERM"]);
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
  "--tmpfs", "--remount-ro", "--ro-bind-data", "--perms", "--dir", "--file", "--clearenv", "--setenv", "--chdir",
];

function runBubblewrapProbe(path, args, signal) {
  return new Promise(resolve => {
    if (signal?.aborted) { resolve(undefined); return; }
    let child;
    try { child = spawn(path, args, { stdio: ["ignore", "pipe", "pipe"] }); }
    catch { resolve(undefined); return; }
    let stdout = "";
    let stderr = "";
    let failed = false;
    const stop = () => { failed = true; child.kill("SIGKILL"); };
    const timer = setTimeout(stop, 3_000);
    timer.unref?.();
    signal?.addEventListener("abort", stop, { once: true });
    if (signal?.aborted) stop();
    const collect = (part, chunk) => {
      if (part === "stdout") stdout += chunk.toString("utf8");
      else stderr += chunk.toString("utf8");
      if (stdout.length + stderr.length > 1_048_576) stop();
    };
    child.stdout.on("data", chunk => collect("stdout", chunk));
    child.stderr.on("data", chunk => collect("stderr", chunk));
    child.once("error", () => { failed = true; });
    child.once("close", code => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", stop);
      resolve(failed || code !== 0 ? undefined : { stdout, stderr });
    });
  });
}

async function probeBubblewrap(path, expectedVersion, signal) {
  try {
    const help = await runBubblewrapProbe(path, ["--help"], signal);
    if (!help || REQUIRED_BWRAP_FLAGS.some(flag => !`${help.stdout}\n${help.stderr}`.includes(flag))) return undefined;
    const versionResult = await runBubblewrapProbe(path, ["--version"], signal);
    const match = /^bubblewrap (\d+\.\d+\.\d+)/u.exec(versionResult?.stdout ?? "");
    if (!versionResult || !match || (expectedVersion !== undefined && match[1] !== expectedVersion) ||
        !versionAtLeast(match[1], "0.9.0")) return undefined;
    const smoke = await runBubblewrapProbe(path, [
      "--die-with-parent", "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-net",
      "--disable-userns", "--assert-userns-disabled", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
      "--clearenv", "--setenv", "PATH", "/usr/bin:/bin", "--chdir", "/", "--", "/bin/true",
    ], signal);
    return smoke ? match[1] : undefined;
  } catch { return undefined; }
}

export { probeBubblewrap };

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

export function buildLaunchArgs(plan, start, toolCallId, egress, context = {}) {
  if (plan.version !== 3 || !Array.isArray(plan.filesystem) || plan.filesystem.some(grant =>
      !grant || !["read", "write", "deny-write", "deny-access"].includes(grant.access) ||
      !["file", "directory"].includes(grant.granularity)) || plan.metadataRead !== "none") {
    throw failure("unsupported", "execution plan filesystem version is unsupported");
  }
  const operation = start?.operation;
  if (!operation || typeof start.cwd !== "string" || !start.environment || typeof start.environment !== "object") {
    throw failure("setup", "execution start parameters are invalid");
  }
  /*
   * A sandbox tool runs the same one-shot node worker as a builtin tool, so
   * both kinds need the same runner resolution, execute grants and read-only
   * runtime mount. Decide it once: repeating the condition per site is how the
   * sandbox-tool execute grant went missing before.
   */
  const isWorker = operation.kind === "builtin-tool" || operation.kind === "sandbox-tool";
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
      const runnerName = operation.kind === "sandbox-tool"
        ? "sandbox-tool-worker.mjs"
        : "builtin-worker.bundle.mjs";
      runner = context.installRoot === undefined
        ? realpathSync(fileURLToPath(new URL(`../../${runnerName}`, import.meta.url)))
        : realpathSync(join(context.installRoot, "src", "sandbox", runnerName));
    } catch {
      throw failure("setup", "sandbox tool runtime is unavailable");
    }
    operationArgs = ["--", realpathSync(process.execPath), runner];
    operationInput = JSON.stringify({ ...operation, toolCallId, cwd: start.cwd }) + "\n";
  } else if (operation.kind === "shell") {
    const shell = operation.shell ?? "/bin/sh";
    if (!new Set(["/bin/sh", "/bin/bash", "/usr/bin/bash"]).has(shell) || !existsSync(shell)) {
      throw failure("unsupported", "Linux backend received an unsupported shell interpreter");
    }
    if (operation.command.includes("\0")) {
      throw failure("setup", "shell command contains a NUL byte");
    }
    operationArgs = ["--", shell, "-c", operation.command];
  } else if (operation.kind === "read-file") {
    operationArgs = ["--", "read-file", canonicalPath(operation.path, "file").path];
  } else if (operation.kind === "access-file") {
    operationArgs = ["--", "access-file", canonicalPath(operation.path, "file").path, operation.mode];
  } else if (operation.kind === "write-file") {
    if (Buffer.byteLength(operation.content, "utf8") > MAX_FILE_CONTENT_BYTES) {
      throw failure("unsupported", "file content exceeds the native input limit");
    }
    operationArgs = ["--", "write-file", operation.path];
    operationInput = operation.content;
  } else if (operation.kind === "mkdir") {
    operationArgs = ["--", "mkdir", operation.path];
  } else if (operation.kind === "access-dir") {
    operationArgs = ["--", "access-dir", canonicalPath(operation.path, "directory").path];
  } else {
    throw failure("unsupported", `Linux backend does not support ${operation.kind} operations yet`);
  }
  const cwd = canonicalPath(start.cwd, "directory").path;
  const grants = [];
  const masks = [];
  const denyWrites = new Map();
  const virtualDevice = new Set();
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
    if (grant.source === "runtime" && path === "/dev" && grant.granularity === "directory" &&
        (grant.access === "read" || grant.access === "write")) {
      virtualDevice.add(grant.access);
      continue;
    }
    if (grant.access === "deny-access") {
      try {
        if (typeof grant.requestedPath !== "string" || realpathSync(grant.requestedPath) !== path ||
            !grant.identity || typeof grant.identity.device !== "string" || typeof grant.identity.inode !== "string") {
          throw new Error("invalid sensitive path identity");
        }
        const info = statSync(path, { bigint: true });
        if ((kind === "directory" ? !info.isDirectory() : !info.isFile()) ||
            String(info.dev) !== grant.identity.device || String(info.ino) !== grant.identity.inode) {
          throw new Error("sensitive path identity changed");
        }
        masks.push({ path, kind, identity: grant.identity });
      } catch {
        throw failure("setup", `sensitive path identity is unavailable: ${grant.path}`);
      }
      continue;
    }
    if (grant.access === "deny-write") {
      try {
        if (!grant.identity || typeof grant.identity.device !== "string" || typeof grant.identity.inode !== "string") {
          throw new Error("protected path identity is missing");
        }
        const info = statSync(path, { bigint: true });
        if ((kind === "directory" ? !info.isDirectory() : !info.isFile()) ||
            String(info.dev) !== grant.identity.device || String(info.ino) !== grant.identity.inode ||
            realpathSync(grant.requestedPath ?? grant.path) !== path) throw new Error("protected path changed");
      } catch { throw failure("missing", `protected path identity changed: ${grant.path}`); }
      const existing = denyWrites.get(path);
      if (existing && (existing.granularity !== grant.granularity ||
          existing.identity.device !== grant.identity.device || existing.identity.inode !== grant.identity.inode)) {
        throw failure("setup", `protected path identity conflicts: ${grant.path}`);
      }
      denyWrites.set(path, { path, granularity: grant.granularity, identity: grant.identity });
      continue;
    }
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
  const protectedPaths = [...denyWrites.values()];
  const environment = Object.entries(start.environment);
  for (const [name, value] of environment) {
    if (!ENVIRONMENT_ALLOWLIST.has(name) || typeof value !== "string" || value.includes("\0")) {
      throw failure("unsupported", `environment variable is not allowed: ${name}`);
    }
  }

  const args = ["run", "--network", plan.network.kind, "--cwd", cwd];
  if (!virtualDevice.has("read") || !virtualDevice.has("write")) {
    throw failure("unsupported", "virtual device runtime permissions are missing");
  }
  args.push("--virtual-dev", "yes");
  // A sandbox-hosted tool also execs node and loads its module from the package
  // root, exactly like a builtin worker, so it needs the same execute grants.
  if (isWorker) {
    const runtime = context.installRoot === undefined
      ? realpathSync(fileURLToPath(new URL("../../../../", import.meta.url)))
      : realpathSync(context.installRoot);
    const node = realpathSync(process.execPath);
    if (!grants.some(grant => grant.source === "runtime" && grant.access === "read" && grant.path === runtime && grant.granularity === "directory") ||
        !grants.some(grant => grant.source === "runtime" && grant.access === "read" && grant.path === node && grant.granularity === "file")) {
      throw failure("unsupported", "worker runtime permissions are missing");
    }
    args.push("--execute-file", node, "--execute-dir", runtime);
  }
  for (const grant of grants) {
    if (grant.access === "read") {
      args.push(grant.source === "runtime" && grant.path === "/usr" ? "--execute-dir" :
        grant.granularity === "directory" ? "--read-dir" : "--read-file", grant.path);
    } else if (grant.access === "write") {
      args.push(grant.granularity === "directory" ? "--write-dir" : "--write-file", grant.path);
    }
  }
  for (const protectedPath of protectedPaths) {
    args.push("--protected", protectedPath.path, protectedPath.granularity,
      protectedPath.identity.device, protectedPath.identity.inode);
  }
  for (const mask of masks) {
    args.push(mask.kind === "directory" ? "--mask-dir" : "--mask-file", mask.path,
      mask.identity.device, mask.identity.inode);
  }
  for (const [name, value] of environment) args.push("--env", name, value);
  args.push(...operationArgs);
  return { args, operationInput, ...(egressEnv === undefined ? {} : { egressEnv }) };
}
