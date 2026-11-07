import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { basename, delimiter, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { ShellExecutionPermissions } from "../config/execution-source-schema";

export type ControlledMcpPermissions = ShellExecutionPermissions & {
  readonly process: { readonly spawn: "allow" | "deny" };
};
import type { HelperProcessSpec } from "./transport";
import { isPathWithin, protectedPathsForGrant } from "./path";
import type { EgressGrant } from "./egress/types";
import { toRuntimeNetworkScope } from "./network-scope";

export const EXECUTION_INSTALL_ROOT = realpathSync(fileURLToPath(new URL("../../", import.meta.url)));
export const LINUX_NATIVE_EXECUTABLE = fileURLToPath(new URL("./backend/linux/linux-sandbox", import.meta.url));
export const WINDOWS_NATIVE_EXECUTABLE = fileURLToPath(new URL("./backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url));

function canonical(path: string): string {
  if (!isAbsolute(path)) throw new Error("sandbox-capability-unsupported: executable and grants must use absolute paths");
  const resolved = realpathSync(path);
  if (process.platform === "win32" ? resolved.toLowerCase() !== path.toLowerCase() : resolved !== path) throw new Error("sandbox-capability-unsupported: launch paths must be canonical");
  return resolved;
}

function prepareWindowsStdio(input: {
  command: string; args: readonly string[]; cwd: string;
  environment: Readonly<Record<string, string>>; permissions: ControlledMcpPermissions;
  egress?: EgressGrant;
}): HelperProcessSpec {
  const network = toRuntimeNetworkScope(input.permissions.network);
  if (network.kind === "destinations" ? input.egress?.proxyHost !== "127.0.0.1" ||
    !Number.isInteger(input.egress.proxyPort) || input.egress.proxyPort < 1 || input.egress.proxyPort > 65535 : input.egress !== undefined) {
    throw new Error("sandbox-capability-unsupported: Windows MCP requires a trusted proxy endpoint");
  }
  if (input.permissions.process.spawn !== "allow") throw new Error("sandbox-capability-unsupported: Windows MCP process denial is unsupported");
  if (isPathWithin(input.cwd, EXECUTION_INSTALL_ROOT)) throw new Error("sandbox-setup-failed: execution installation is inside the workspace");
  if (!existsSync(WINDOWS_NATIVE_EXECUTABLE)) throw new Error("sandbox-unavailable: Windows runtime is missing");
  const native = canonical(WINDOWS_NATIVE_EXECUTABLE);
  try {
    const manifest = JSON.parse(readFileSync(join(dirname(native), "mxc-runtime.json"), "utf8"));
    if (manifest.schemaVersion !== 1 || manifest.backend !== "windows-mxc" || manifest.version !== "1.0.0" ||
      manifest.sdkRevision !== "b21120168d70befe12356411423266bfef168446" || !/^[0-9a-f]{64}$/u.test(manifest.sha256) ||
      createHash("sha256").update(readFileSync(native)).digest("hex") !== manifest.sha256) throw new Error();
  } catch { throw new Error("sandbox-unavailable: Windows runtime manifest is missing or invalid"); }
  const command = executablePath(input.command, input.cwd, input.environment);
  const cwd = canonical(input.cwd);
  const grants = [
    ...input.permissions.filesystem.read.map(grant => ({ ...grant, access: "read" as const })),
    ...input.permissions.filesystem.write.map(grant => ({ ...grant, access: "write" as const })),
    { path: EXECUTION_INSTALL_ROOT, access: "read" as const, granularity: "directory" as const },
    { path: dirname(command), access: "read" as const, granularity: "directory" as const },
  ];
  const filesystem = grants.map(grant => {
    const path = canonical(grant.path);
    if ((grant.granularity === "directory") !== statSync(path).isDirectory()) throw new Error("sandbox-setup-failed: grant granularity differs from the actual path");
    return { ...grant, path };
  });
  const protectedPaths = [EXECUTION_INSTALL_ROOT, command];
  for (const grant of filesystem) if (grant.access === "write" && grant.granularity === "directory") protectedPaths.push(...protectedPathsForGrant(grant.path));
  for (const [name, value] of Object.entries(input.environment)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || name.toUpperCase() === "PI_MXC_REQUEST" || value.includes("\0")) throw new Error("sandbox-setup-failed: invalid environment binding");
  }
  const argv = basename(command).toLowerCase() === "node.exe"
    ? [command, "--preserve-symlinks", "--preserve-symlinks-main", ...input.args] : [command, ...input.args];
  const payload = JSON.stringify({ plan: { cwd, filesystem, protectedPaths, network, environment: input.environment }, argv,
    ...(input.egress ? { proxyPort: input.egress.proxyPort } : {}) });
  if (Buffer.byteLength(payload) > 24_000) throw new Error("sandbox-capability-unsupported: Windows MCP launch request is too large");
  const systemRoot = process.env.SystemRoot, systemDrive = process.env.SystemDrive, localAppData = process.env.LOCALAPPDATA;
  if (!systemRoot || !systemDrive || !localAppData) throw new Error("sandbox-unavailable: required Windows environment is unavailable");
  return { executable: native, args: ["stdio"], cwd, environment: { SystemRoot: systemRoot, SystemDrive: systemDrive,
    LOCALAPPDATA: localAppData, PI_MXC_REQUEST: payload } };
}

function executablePath(command: string, cwd: string, environment: Readonly<Record<string, string>>): string {
  if (isAbsolute(command)) return process.platform === "win32" ? realpathSync(command) : canonical(command);
  if (command.includes("/") || (process.platform === "win32" && command.includes("\\"))) return canonical(resolve(cwd, command));
  // The host PATH only resolves the trusted configured command; this fallback is not forwarded.
  for (const directory of (environment.PATH ?? process.env.PATH ?? "").split(delimiter)) {
    if (!isAbsolute(directory)) continue;
    const candidates = process.platform === "win32" && !/\.exe$/iu.test(command) ? [command, `${command}.exe`] : [command];
    for (const name of candidates) {
      const candidate = resolve(directory, name);
      if (existsSync(candidate) && statSync(candidate).isFile()) return realpathSync(candidate);
    }
  }
  throw new Error("sandbox-unavailable: configured MCP executable could not be resolved");
}

/** The server command is Pi's declaration; this function adds only the OS boundary. */
export function prepareStdioLaunch(input: {
  command: string; args: readonly string[]; cwd: string;
  environment: Readonly<Record<string, string>>;
  permissions: ControlledMcpPermissions;
  egress?: EgressGrant;
}): HelperProcessSpec {
  if (process.platform === "win32") return prepareWindowsStdio(input);
  if (process.platform !== "linux") throw new Error(`sandbox-unavailable: controlled stdio launch is not available on ${process.platform}`);
  const network = toRuntimeNetworkScope(input.permissions.network);
  if ((network.kind === "destinations") !== (input.egress !== undefined)) throw new Error("sandbox-capability-unsupported: domain egress requires an enforced proxy boundary");
  if (isPathWithin(input.cwd, EXECUTION_INSTALL_ROOT)) throw new Error("sandbox-setup-failed: execution installation is inside the workspace");
  canonical(LINUX_NATIVE_EXECUTABLE);
  const command = executablePath(input.command, input.cwd, input.environment);
  const cwd = canonical(input.cwd);
  const args = ["run", "--ready", "none", "--network", network.kind,
    "--process-spawn", input.permissions.process.spawn, "--cwd", cwd, "--execute-file", command];
  const grants = [
    ...input.permissions.filesystem.read.map(grant => ({ ...grant, access: "read" as const })),
    ...input.permissions.filesystem.write.map(grant => ({ ...grant, access: "write" as const })),
    { path: EXECUTION_INSTALL_ROOT, access: "read" as const, granularity: "directory" as const },
    { path: dirname(command), access: "read" as const, granularity: "directory" as const },
  ];
  for (const grant of grants) {
    const path = canonical(grant.path);
    if ((grant.granularity === "directory") !== statSync(path).isDirectory()) throw new Error("sandbox-setup-failed: grant granularity differs from the actual path");
    args.push(`--${grant.access}-${grant.granularity === "directory" ? "dir" : "file"}`, path);
    if (grant.access === "write") {
      for (const protectedPath of protectedPathsForGrant(path)) args.push("--protected", protectedPath);
    }
  }
  args.push("--protected", EXECUTION_INSTALL_ROOT);
  for (const [name, value] of Object.entries(input.environment)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || /^(LD_|DYLD_|GLIBC_|GCONV_)/.test(name) || value.includes("\0")) throw new Error("sandbox-setup-failed: invalid environment binding");
    args.push("--env", name, value);
  }
  args.push("--", command, ...input.args);
  return { executable: LINUX_NATIVE_EXECUTABLE, args, cwd: resolve("/"), environment: input.egress ? {
    PI_EGRESS_PROXY: `${input.egress.proxyHost}:${input.egress.proxyPort}`,
    PI_EGRESS_LEASE: input.egress.leaseId, PI_EGRESS_CREDENTIAL: input.egress.credential,
  } : {} };
}
