import { spawn, spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { networkInterfaces, tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { createConnection, createServer } from "node:net";
import { createSocket } from "node:dgram";
import { createHash, randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { prepareWindowsRuntimeExecutable } from "#sandbox/runtime-windows-integrity";

const helper = fileURLToPath(new URL("../../../../src/sandbox/backend/windows/helper.mjs", import.meta.url));
const executable = fileURLToPath(new URL("../../../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url));
const localAddress = Object.values(networkInterfaces()).flat().find(address => address && address.family === "IPv4" && !address.internal)?.address;
const packageRoot = fileURLToPath(new URL("../../../../", import.meta.url));
let sharedRuntimeDirectory = "";
let previousRuntimeDirectory: string | undefined;

function installTestRuntime(root: string, corruptManifest = false): string {
  const directory = join(root, "runtimes", "1.0.0", `win32-${process.arch}`);
  mkdirSync(directory, { recursive: true });
  const nativePath = join(directory, "pi-sandbox-windows-mxc.exe");
  const manifestPath = join(directory, "mxc-runtime.json");
  copyFileSync(executable, nativePath);
  prepareWindowsRuntimeExecutable(nativePath);
  if (corruptManifest) {
    writeFileSync(manifestPath, JSON.stringify({ schemaVersion: 1, backend: "windows-mxc", version: "1.0.0",
      sdkRevision: "b21120168d70befe12356411423266bfef168446", sha256: "0".repeat(64) }));
  } else {
    copyFileSync(join(dirname(executable), "mxc-runtime.json"), manifestPath);
  }
  const hash = (path: string) => createHash("sha256").update(readFileSync(path)).digest("hex");
  writeFileSync(join(directory, "runtime.json"), JSON.stringify({
    schemaVersion: 1,
    version: "1.0.0",
    stable: true,
    platform: "win32",
    arch: process.arch,
    protocolVersion: 2,
    minPluginVersion: "1.0.0",
    maxPluginVersionExclusive: "2.0.0",
    backendId: "windows-mxc",
    files: [
      { role: "windowsExecutable", path: "pi-sandbox-windows-mxc.exe", sha256: hash(nativePath), executable: true },
      { role: "mxcManifest", path: "mxc-runtime.json", sha256: hash(manifestPath), executable: false },
    ],
  }));
  return directory;
}

describe.skipIf(process.platform !== "win32" || !existsSync(executable))("Windows native helper", () => {
  beforeAll(() => {
    previousRuntimeDirectory = process.env.PI_SANDBOX_RUNTIME_DIR;
    sharedRuntimeDirectory = installTestRuntime(packageRoot);
    process.env.PI_SANDBOX_RUNTIME_DIR = sharedRuntimeDirectory;
  });
  afterAll(() => {
    if (previousRuntimeDirectory === undefined) delete process.env.PI_SANDBOX_RUNTIME_DIR;
    else process.env.PI_SANDBOX_RUNTIME_DIR = previousRuntimeDirectory;
    if (sharedRuntimeDirectory) rmSync(sharedRuntimeDirectory, { recursive: true, force: true });
  });

  it("rejects a runtime with a mismatched manifest before launch", async () => {
    const root = mkdtempSync(join(tmpdir(), "mxc-manifest-"));
    const badRuntime = installTestRuntime(root, true);
    copyFileSync(helper, join(root, "helper.mjs"));
    const child = spawn(process.execPath, [join(root, "helper.mjs")], {
      stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, PI_SANDBOX_RUNTIME_DIR: badRuntime },
    });
    const response = new Promise<Record<string, unknown>>((resolve, reject) => {
      let buffer = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", chunk => { buffer += chunk; const end = buffer.indexOf("\n"); if (end >= 0) resolve(JSON.parse(buffer.slice(0, end))); });
      child.on("error", reject);
      child.on("exit", code => reject(new Error(`helper exited before response: ${code}`)));
    });
    child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "bad-manifest", generation: 1 }) + "\n");
    try { expect(await response).toMatchObject({ type: "error", code: "unavailable" }); }
    finally { child.stdin.end(); await new Promise(resolve => child.once("exit", resolve)); rmSync(root, { recursive: true, force: true }); }
  }, 15_000);
  it("probes the native backend before reporting readiness", async () => {
    const child = spawn(process.execPath, [helper], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    const result = new Promise<Record<string, unknown>>((resolve, reject) => {
      let buffer = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", chunk => {
        buffer += chunk;
        const end = buffer.indexOf("\n");
        if (end < 0) return;
        try { resolve(JSON.parse(buffer.slice(0, end))); } catch (error) { reject(error); }
      });
      child.on("error", reject);
      child.on("exit", code => reject(new Error(`helper exited before readiness: ${code}`)));
    });
    child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "probe", generation: 1 }) + "\n");
    try {
      expect(await result).toMatchObject({ type: "ready", requestId: "probe", generation: 1,
        backend: { id: "windows-mxc" }, capabilities: { filesystem: { read: true, write: true }, network: "domains" } });
    } finally { child.stdin.end(JSON.stringify({ type: "shutdown" }) + "\n"); }
  }, 15_000);

  it("starts a sandboxed shell and reports its output and exit status", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "mxc-helper-"));
    const child = spawn(process.execPath, [helper], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    const messages: Record<string, unknown>[] = [];
    const result = new Promise<void>((resolve, reject) => {
      let buffer = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", chunk => {
        buffer += chunk;
        for (;;) {
          const end = buffer.indexOf("\n");
          if (end < 0) break;
          const message = JSON.parse(buffer.slice(0, end));
          buffer = buffer.slice(end + 1);
          messages.push(message);
          if (message.type === "ready") {
            child.stdin.write(JSON.stringify({ type: "start", requestId: "exec", generation: 1,
              plan: { backend: { id: "windows-mxc" }, cwd, filesystem: [{ path: cwd, access: "read", granularity: "directory" }],
                protectedPaths: [], network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot },
                operation: { kind: "shell", shell: join(process.env.SystemRoot!, "System32", "cmd.exe"), command: "echo mxc-test-output" } } }) + "\n");
          }
          if (message.type === "result" || message.type === "rejected") resolve();
        }
      });
      child.on("error", reject);
      child.on("exit", code => reject(new Error(`helper exited before result: ${code}`)));
    });
    child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "exec", generation: 1 }) + "\n");
    try {
      await result;
      expect(messages).toEqual(expect.arrayContaining([
        expect.objectContaining({ type: "started", requestId: "exec" }),
        expect.objectContaining({ type: "output", stream: "stdout", data: expect.stringContaining("mxc-test-output") }),
        expect.objectContaining({ type: "result", started: true, exitCode: 0 }),
      ]));
    } finally {
      child.kill();
      rmSync(cwd, { recursive: true, force: true });
    }
  }, 15_000);

  it("terminates the sandbox process tree when the helper crashes", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "mxc-helper-crash-"));
    const child = spawn(process.execPath, [helper], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    let rootPid = 0;
    let childPid = 0;
    let output = "";
    const started = new Promise<void>((resolve, reject) => {
      let buffer = "";
      const timer = setTimeout(() => reject(new Error(`sandbox did not report process IDs: ${output}`)), 10_000);
      timer.unref();
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", chunk => {
        buffer += chunk;
        for (;;) {
          const end = buffer.indexOf("\n");
          if (end < 0) break;
          const message = JSON.parse(buffer.slice(0, end));
          buffer = buffer.slice(end + 1);
          if (message.type === "ready") child.stdin.write(JSON.stringify({ type: "start", requestId: "crash", generation: 1,
            plan: { backend: { id: "windows-mxc" }, cwd, filesystem: [{ path: cwd, access: "read", granularity: "directory" }],
              protectedPaths: [], network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot },
              operation: { kind: "shell", shell: join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
                command: "$exe=$env:SystemRoot + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'; $p=[Diagnostics.Process]::Start($exe, '-NoProfile -Command Start-Sleep -Seconds 30'); Write-Output ('rootpid=' + $PID); Write-Output ('childpid=' + $p.Id); Start-Sleep -Seconds 30" } } }) + "\n");
          if (message.type === "output") {
            output += String(message.data);
            rootPid = Number(/rootpid=(\d+)/u.exec(output)?.[1] ?? 0);
            childPid = Number(/childpid=(\d+)/u.exec(output)?.[1] ?? 0);
            if (rootPid && childPid) { clearTimeout(timer); resolve(); }
          }
          if (message.type === "result" || message.type === "rejected" || message.type === "error") reject(new Error(JSON.stringify(message)));
        }
      });
      child.on("error", reject);
    });
    child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "crash", generation: 1 }) + "\n");
    try {
      await started;
      const alive = (pid: number) => { try { process.kill(pid, 0); return true; } catch { return false; } };
      expect([alive(rootPid), alive(childPid)]).toEqual([true, true]);
      child.kill();
      for (let attempt = 0; attempt < 40 && (alive(rootPid) || alive(childPid)); attempt++) await new Promise(resolve => setTimeout(resolve, 100));
      expect([alive(rootPid), alive(childPid)]).toEqual([false, false]);
    } finally {
      child.kill();
      for (const pid of [childPid, rootPid]) if (pid) { try { process.kill(pid); } catch { /* The process already exited. */ } }
      rmSync(cwd, { recursive: true, force: true });
    }
  }, 20_000);

  it.each(["direct", "junction", "junction-new", "dangling"])("rejects a %s write grant beneath a protected directory before workload start", async form => {
    const cwd = mkdtempSync(join(tmpdir(), "mxc-protected-child-"));
    const protectedDir = join(cwd, ".git");
    mkdirSync(protectedDir);
    const target = form === "dangling" ? join(protectedDir, "missing", "config")
      : join(protectedDir, form === "junction-new" ? "new.txt" : "config");
    if (form !== "junction-new" && form !== "dangling") writeFileSync(target, "original");
    const junction = join(cwd, "alias");
    if (form !== "direct") symlinkSync(form === "dangling" ? dirname(target) : protectedDir, junction, "junction");
    const grantTarget = form === "direct" ? target : join(junction, basename(target));
    const child = spawn(process.execPath, [helper], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    const messages: Record<string, unknown>[] = [];
    const result = new Promise<void>((resolve, reject) => {
      let buffer = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", chunk => {
        buffer += chunk;
        for (;;) {
          const end = buffer.indexOf("\n");
          if (end < 0) break;
          const message = JSON.parse(buffer.slice(0, end));
          buffer = buffer.slice(end + 1);
          messages.push(message);
          if (message.type === "ready") child.stdin.write(JSON.stringify({ type: "start", requestId: "protected-child", generation: 1,
            plan: { backend: { id: "windows-mxc" }, cwd, filesystem: [
              { path: cwd, access: "read", granularity: "directory" },
              ...(form === "junction-new" || form === "dangling" ? [{ path: cwd, access: "write", granularity: "directory" }] : []),
              { path: grantTarget, access: "write", granularity: "file" },
            ], protectedPaths: [protectedDir], network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot },
              operation: { kind: "shell", shell: join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
                command: `[IO.File]::WriteAllText('${grantTarget.replaceAll("'", "''")}','changed')` } } }) + "\n");
          if (message.type === "result" || message.type === "rejected" || message.type === "error") resolve();
        }
      });
      child.on("error", reject);
      child.on("exit", code => reject(new Error(`helper exited before result: ${code}`)));
    });
    child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "protected-child", generation: 1 }) + "\n");
    try {
      await result;
      if (form === "junction-new" || form === "dangling") expect(existsSync(target)).toBe(false);
      else expect(readFileSync(target, "utf8")).toBe("original");
      expect(messages, JSON.stringify(messages)).toEqual(expect.arrayContaining([expect.objectContaining({ type: "rejected", code: form === "dangling" ? "unsupported" : "denied", started: false })]));
      expect(messages.some(message => message.type === "started")).toBe(false);
    } finally { child.kill(); if (form !== "direct") rmdirSync(junction); rmSync(cwd, { recursive: true, force: true }); }
  }, 20_000);

  it.each([false, true])("keeps protected files safe when a granted junction is retargeted: %s", async retarget => {
    const cwd = mkdtempSync(join(tmpdir(), "mxc-retarget-"));
    const protectedDir = join(cwd, ".git");
    const allowedDir = join(cwd, "allowed");
    const junction = join(cwd, "alias");
    mkdirSync(protectedDir);
    mkdirSync(allowedDir);
    writeFileSync(join(protectedDir, "config"), "protected");
    writeFileSync(join(allowedDir, "config"), "allowed");
    symlinkSync(allowedDir, junction, "junction");
    const signal = join(cwd, "signal");
    const target = join(junction, "config");
    const child = spawn(process.execPath, [helper], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    const messages: Record<string, unknown>[] = [];
    const result = new Promise<void>((resolve, reject) => {
      let buffer = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", chunk => {
        buffer += chunk;
        for (;;) {
          const end = buffer.indexOf("\n");
          if (end < 0) break;
          const message = JSON.parse(buffer.slice(0, end));
          buffer = buffer.slice(end + 1);
          messages.push(message);
          if (message.type === "ready") child.stdin.write(JSON.stringify({ type: "start", requestId: "retarget", generation: 1,
            plan: { backend: { id: "windows-mxc" }, cwd, filesystem: [
              { path: cwd, access: "read", granularity: "directory" },
              { path: cwd, access: "write", granularity: "directory" },
              { path: target, access: "write", granularity: "file" },
            ], protectedPaths: [protectedDir], network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot },
              operation: { kind: "shell", shell: join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
                command: `while(-not [IO.File]::Exists('${signal.replaceAll("'", "''")}')) { Start-Sleep -Milliseconds 50 }; try { [IO.File]::WriteAllText('${target.replaceAll("'", "''")}','changed') } catch { exit 2 }` } } }) + "\n");
          if (message.type === "started") {
            if (retarget) { rmdirSync(junction); symlinkSync(protectedDir, junction, "junction"); }
            writeFileSync(signal, "go");
          }
          if (message.type === "result" || message.type === "rejected" || message.type === "error") resolve();
        }
      });
      child.on("error", reject);
      child.on("exit", code => reject(new Error(`helper exited before result: ${code}`)));
    });
    child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "retarget", generation: 1 }) + "\n");
    try {
      await result;
      expect(messages, JSON.stringify(messages)).toEqual(expect.arrayContaining([expect.objectContaining({ type: "started" }), expect.objectContaining({ type: "result", exitCode: retarget ? 2 : 0 })]));
      expect(readFileSync(join(protectedDir, "config"), "utf8")).toBe("protected");
      expect(readFileSync(join(allowedDir, "config"), "utf8")).toBe(retarget ? "allowed" : "changed");
    } finally { child.kill(); rmdirSync(junction); rmSync(cwd, { recursive: true, force: true }); }
  }, 20_000);

  it.each(["junction", "ancestor"])("protects files when a %s changes between validation and native launch", async form => {
    const cwd = mkdtempSync(join(tmpdir(), "mxc-launch-retarget-"));
    const protectedDir = join(cwd, ".git");
    const allowedDir = join(cwd, "allowed");
    const junction = join(cwd, "alias");
    mkdirSync(protectedDir);
    mkdirSync(allowedDir);
    writeFileSync(join(protectedDir, "config"), "protected");
    writeFileSync(join(allowedDir, "config"), "allowed");
    if (form === "junction") symlinkSync(allowedDir, junction, "junction");
    else { mkdirSync(junction); writeFileSync(join(junction, "config"), "allowed"); }
    const preload = join(cwd, "retarget.cjs");
    writeFileSync(preload, `const cp = require('node:child_process'); const fs = require('node:fs'); const original = cp.spawn;
      cp.spawn = function(file, args, options) { if (file.endsWith('pi-sandbox-windows-mxc.exe') && args.length === 0) { ${form === "junction" ? `fs.rmdirSync(${JSON.stringify(junction)});` : `fs.renameSync(${JSON.stringify(junction)}, ${JSON.stringify(join(cwd, "saved"))});`} fs.symlinkSync(${JSON.stringify(protectedDir)}, ${JSON.stringify(junction)}, 'junction'); } return original.apply(this, arguments); }; require('node:module').syncBuiltinESMExports();`);
    const child = spawn(process.execPath, ["--require", preload, helper], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    const messages: Record<string, unknown>[] = [];
    const target = join(junction, "config");
    const result = new Promise<void>((resolve, reject) => {
      let buffer = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", chunk => {
        buffer += chunk;
        for (;;) {
          const end = buffer.indexOf("\n");
          if (end < 0) break;
          const message = JSON.parse(buffer.slice(0, end));
          buffer = buffer.slice(end + 1);
          messages.push(message);
          if (message.type === "ready") child.stdin.write(JSON.stringify({ type: "start", requestId: "launch-retarget", generation: 1,
            plan: { backend: { id: "windows-mxc" }, cwd, filesystem: [
              { path: cwd, access: "read", granularity: "directory" },
              { path: cwd, access: "write", granularity: "directory" },
              { path: target, access: "write", granularity: "file" },
            ], protectedPaths: [protectedDir], network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot },
              operation: { kind: "shell", shell: join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
                command: `try { [IO.File]::WriteAllText('${target.replaceAll("'", "''")}','changed') } catch { exit 2 }` } } }) + "\n");
          if (message.type === "result" || message.type === "rejected" || message.type === "error") resolve();
        }
      });
      child.on("error", reject);
      child.on("exit", code => reject(new Error(`helper exited before result: ${code}`)));
    });
    child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "launch-retarget", generation: 1 }) + "\n");
    try {
      await result;
      expect(readFileSync(target, "utf8")).toBe("protected");
      expect(readFileSync(join(protectedDir, "config"), "utf8"), JSON.stringify(messages)).toBe("protected");
      if (form === "ancestor") {
        expect(messages, JSON.stringify(messages)).toEqual(expect.arrayContaining([expect.objectContaining({ type: "error", code: "setup" })]));
        expect(messages.some(message => message.type === "started")).toBe(false);
      } else {
        expect(messages, JSON.stringify(messages)).toEqual(expect.arrayContaining([expect.objectContaining({ type: "result", exitCode: 2 })]));
      }
    } finally { child.kill(); rmdirSync(junction); rmSync(cwd, { recursive: true, force: true }); }
  }, 20_000);

  it("does not pass a junction write grant to the read builtin runtime", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "mxc-runtime-alias-"));
    const root = fileURLToPath(new URL("../../../../", import.meta.url));
    const junction = join(cwd, "runtime-alias");
    symlinkSync(root, junction, "junction");
    const target = join(junction, "package.json");
    const original = readFileSync(target, "utf8");
    writeFileSync(join(cwd, "sample.txt"), "sample");
    const child = spawn(process.execPath, [helper], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    const result = new Promise<Record<string, unknown>>((resolve, reject) => {
      let buffer = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", chunk => {
        buffer += chunk;
        for (;;) {
          const end = buffer.indexOf("\n");
          if (end < 0) break;
          const message = JSON.parse(buffer.slice(0, end));
          buffer = buffer.slice(end + 1);
          if (message.type === "ready") child.stdin.write(JSON.stringify({ type: "start", requestId: "runtime-alias", generation: 1,
            plan: { backend: { id: "windows-mxc" }, cwd, toolCallId: "runtime-alias", filesystem: [
              { path: cwd, access: "read", granularity: "directory" },
              { path: target, access: "read", granularity: "file" },
              { path: target, access: "write", granularity: "file" },
            ], protectedPaths: [], network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot },
              operation: { kind: "builtin-tool", name: "read", arguments: { path: "sample.txt" } } } }) + "\n");
          if (message.type === "result" || message.type === "rejected" || message.type === "error") resolve(message);
        }
      });
      child.on("error", reject);
      child.on("exit", code => reject(new Error(`helper exited before result: ${code}`)));
    });
    child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "runtime-alias", generation: 1 }) + "\n");
    try {
      expect(await result).toMatchObject({ type: "result", started: true, exitCode: 0 });
      expect(readFileSync(target, "utf8")).toBe(original);
    }
    finally { child.kill(); rmdirSync(junction); rmSync(cwd, { recursive: true, force: true }); }
  }, 20_000);

  it("does not execute a Node preload supplied to a builtin tool", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "mxc-node-preload-"));
    const target = join(cwd, ".git");
    const sample = join(cwd, "sample.txt");
    const preload = join(cwd, "preload.cjs");
    writeFileSync(sample, "original");
    writeFileSync(preload, `const fs = require('node:fs'); fs.mkdirSync(${JSON.stringify(target)}); fs.writeFileSync(${JSON.stringify(sample)}, 'changed');`);
    const options = `--require ${JSON.stringify(preload)}`;
    const control = spawnSync(process.execPath, ["-e", ""], { cwd, env: { ...process.env, NODE_OPTIONS: options }, encoding: "utf8" });
    expect(control.status, control.stderr).toBe(0);
    expect(readFileSync(sample, "utf8")).toBe("changed");
    expect(existsSync(target)).toBe(true);
    rmdirSync(target);
    writeFileSync(sample, "original");
    const child = spawn(process.execPath, [helper], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    const result = new Promise<Record<string, unknown>>((resolve, reject) => {
      let buffer = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", chunk => {
        buffer += chunk;
        for (;;) {
          const end = buffer.indexOf("\n");
          if (end < 0) break;
          const message = JSON.parse(buffer.slice(0, end));
          buffer = buffer.slice(end + 1);
          if (message.type === "ready") child.stdin.write(JSON.stringify({ type: "start", requestId: "preload", generation: 1,
            plan: { backend: { id: "windows-mxc" }, cwd, toolCallId: "preload", filesystem: [
              { path: cwd, access: "read", granularity: "directory" },
              { path: cwd, access: "write", granularity: "directory" },
            ], protectedPaths: [target], network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot, NODE_OPTIONS: options },
              operation: { kind: "builtin-tool", name: "read", arguments: { path: "sample.txt" } } } }) + "\n");
          if (message.type === "result" || message.type === "rejected" || message.type === "error") resolve(message);
        }
      });
      child.on("error", reject);
      child.on("exit", code => reject(new Error(`helper exited before result: ${code}`)));
    });
    child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "preload", generation: 1 }) + "\n");
    try {
      expect(await result).toMatchObject({ type: "rejected", code: "unsupported", started: false });
      expect(readFileSync(sample, "utf8")).toBe("original");
      expect(existsSync(target)).toBe(false);
    } finally { child.kill(); rmSync(cwd, { recursive: true, force: true }); }
  }, 20_000);

  it.each(["node_options", "NODE_PATH"])("rejects %s for native builtin launch", name => {
    const cwd = mkdtempSync(join(tmpdir(), "mxc-native-node-env-"));
    const shell = join(process.env.SystemRoot!, "System32", "cmd.exe");
    const request = { plan: { cwd, filesystem: [{ path: cwd, access: "read", granularity: "directory" }],
      protectedPaths: [], network: { kind: "none" }, environment: { [name]: "test" },
      operation: { kind: "builtin-tool", name: "read" } }, argv: [shell, "/d", "/c", "echo started"] };
    try {
      const result = spawnSync(executable, [], { input: JSON.stringify(request), env: process.env, encoding: "utf8", timeout: 10_000 });
      expect(result.status, result.stderr).toBe(125);
      expect(result.stderr).toContain("builtin runtime injection environment is unsupported");
      expect(result.stdout).not.toContain("started");
    } finally { rmSync(cwd, { recursive: true, force: true }); }
  }, 15_000);

  it.each(["redirection", "quoted executable"])("preserves cmd quoting for %s", async mode => {
    const cwd = mkdtempSync(join(tmpdir(), "mxc-cmd-"));
    const target = join(cwd, "file with spaces.txt");
    const shell = join(process.env.SystemRoot!, "System32", "cmd.exe");
    const command = mode === "redirection" ? `echo cmd-content > "${target}"`
      : `"${shell}" /d /c echo cmd-content > "${target}"`;
    const child = spawn(process.execPath, [helper], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    const messages: Record<string, unknown>[] = [];
    const result = new Promise<void>((resolve, reject) => {
      let buffer = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", chunk => {
        buffer += chunk;
        for (;;) {
          const end = buffer.indexOf("\n");
          if (end < 0) break;
          const message = JSON.parse(buffer.slice(0, end));
          buffer = buffer.slice(end + 1);
          messages.push(message);
          if (message.type === "ready") child.stdin.write(JSON.stringify({ type: "start", requestId: "cmd-quotes", generation: 1,
            plan: { backend: { id: "windows-mxc" }, cwd, filesystem: [
              { path: cwd, access: "read", granularity: "directory" },
              { path: cwd, access: "write", granularity: "directory" },
            ], protectedPaths: [], network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot },
              operation: { kind: "shell", shell, command } } }) + "\n");
          if (message.type === "result" || message.type === "rejected" || message.type === "error") resolve();
        }
      });
      child.on("error", reject);
      child.on("exit", code => reject(new Error(`helper exited before result: ${code}`)));
    });
    child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "cmd-quotes", generation: 1 }) + "\n");
    try {
      await result;
      expect(messages, JSON.stringify(messages)).toEqual(expect.arrayContaining([expect.objectContaining({ type: "result", exitCode: 0 })]));
      expect(readFileSync(target, "utf8")).toContain("cmd-content");
    } finally { child.kill(); rmSync(cwd, { recursive: true, force: true }); }
  }, 20_000);

  it.each([false, true])("handles missing exact-file grants with parent write=%s", async parentWrite => {
    const cwd = mkdtempSync(join(tmpdir(), "mxc-missing-file-"));
    const missing = join(cwd, "missing.txt");
    const sibling = join(cwd, "sibling.txt");
    const child = spawn(process.execPath, [helper], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    let output = "";
    const result = new Promise<Record<string, unknown>>((resolve, reject) => {
      let buffer = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", chunk => {
        buffer += chunk;
        for (;;) {
          const end = buffer.indexOf("\n");
          if (end < 0) break;
          const message = JSON.parse(buffer.slice(0, end));
          buffer = buffer.slice(end + 1);
          if (message.type === "output") output += String(message.data);
          if (message.type === "ready") child.stdin.write(JSON.stringify({ type: "start", requestId: "missing-file", generation: 1,
            plan: { backend: { id: "windows-mxc" }, cwd, filesystem: [
              { path: cwd, access: "read", granularity: "directory" },
              ...(parentWrite ? [{ path: cwd, access: "write", granularity: "directory" }] : []),
              { path: missing, access: "read", granularity: "file" },
              { path: missing, access: "write", granularity: "file" },
            ], protectedPaths: [], network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot },
              operation: { kind: "shell", shell: join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
                command: `[IO.File]::WriteAllText('${missing.replaceAll("'", "''")}','created'); [IO.File]::WriteAllText('${sibling.replaceAll("'", "''")}','sibling-created')` } } }) + "\n");
          if (message.type === "result" || message.type === "rejected" || message.type === "error") resolve(message);
        }
      });
      child.on("error", reject);
      child.on("exit", code => reject(new Error(`helper exited before result: ${code}`)));
    });
    child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "missing-file", generation: 1 }) + "\n");
    try {
      const message = await result;
      if (parentWrite) {
        expect(message, output).toMatchObject({ type: "result", started: true, exitCode: 0 });
        expect(readFileSync(missing, "utf8")).toContain("created");
        expect(readFileSync(sibling, "utf8")).toBe("sibling-created");
      } else {
        expect(message).toMatchObject({ type: "rejected", code: "unsupported", started: false });
        expect(existsSync(missing)).toBe(false);
        expect(existsSync(sibling)).toBe(false);
      }
    } finally { child.kill(); rmSync(cwd, { recursive: true, force: true }); }
  }, 20_000);

  it("rejects a directory disguised as a file grant before workload start", async () => {
    const root = mkdtempSync(join(tmpdir(), "mxc-grant-type-"));
    const cwd = join(root, "workspace");
    const outside = join(root, "outside");
    mkdirSync(cwd);
    mkdirSync(outside);
    const target = join(outside, "secret.txt");
    writeFileSync(target, "original");
    const child = spawn(process.execPath, [helper], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    const messages: Record<string, unknown>[] = [];
    const result = new Promise<void>((resolve, reject) => {
      let buffer = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", chunk => {
        buffer += chunk;
        for (;;) {
          const end = buffer.indexOf("\n");
          if (end < 0) break;
          const message = JSON.parse(buffer.slice(0, end));
          buffer = buffer.slice(end + 1);
          messages.push(message);
          if (message.type === "ready") child.stdin.write(JSON.stringify({ type: "start", requestId: "grant-type", generation: 1,
            plan: { backend: { id: "windows-mxc" }, cwd, filesystem: [
              { path: cwd, access: "read", granularity: "directory" },
              { path: outside, access: "read", granularity: "file" },
              { path: outside, access: "write", granularity: "file" },
            ], protectedPaths: [], network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot },
              operation: { kind: "shell", shell: join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
                command: `[IO.File]::WriteAllText('${target.replaceAll("'", "''")}','changed')` } } }) + "\n");
          if (message.type === "result" || message.type === "rejected" || message.type === "error") resolve();
        }
      });
      child.on("error", reject);
      child.on("exit", code => reject(new Error(`helper exited before result: ${code}`)));
    });
    child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "grant-type", generation: 1 }) + "\n");
    try {
      await result;
      expect(readFileSync(target, "utf8"), JSON.stringify(messages)).toBe("original");
      expect(messages, JSON.stringify(messages)).toEqual(expect.arrayContaining([expect.objectContaining({ type: "rejected", started: false })]));
    } finally { child.kill(); rmSync(root, { recursive: true, force: true }); }
  }, 20_000);

  it("rejects a disguised directory in the native stdio entry", () => {
    const root = mkdtempSync(join(tmpdir(), "mxc-stdio-grant-type-"));
    const target = join(root, "target.txt");
    writeFileSync(target, "original");
    const command = join(process.env.SystemRoot!, "System32", "cmd.exe");
    const request = { plan: { cwd: root, filesystem: [
      { path: root, access: "read", granularity: "file" },
      { path: root, access: "write", granularity: "file" },
    ], protectedPaths: [], network: { kind: "none" }, environment: {} }, argv: [command, "/d", "/c", `echo changed > "${target}"`] };
    try {
      const result = spawnSync(executable, ["stdio"], { env: { ...process.env, PI_MXC_REQUEST: JSON.stringify(request) }, encoding: "utf8", timeout: 10_000 });
      expect(result.status, result.stderr).toBe(125);
      expect(result.stderr).toContain("grant type mismatch");
      expect(readFileSync(target, "utf8")).toBe("original");
    } finally { rmSync(root, { recursive: true, force: true }); }
  }, 15_000);

  it("rejects a protected junction alias in the native stdio entry", () => {
    const root = mkdtempSync(join(tmpdir(), "mxc-stdio-alias-"));
    const protectedDir = join(root, ".git");
    const junction = join(root, "alias");
    mkdirSync(protectedDir);
    const target = join(protectedDir, "config");
    writeFileSync(target, "original");
    symlinkSync(protectedDir, junction, "junction");
    const alias = join(junction, "config");
    const command = join(process.env.SystemRoot!, "System32", "cmd.exe");
    const request = { plan: { cwd: root, filesystem: [
      { path: root, access: "read", granularity: "directory" },
      { path: alias, access: "write", granularity: "file" },
    ], protectedPaths: [protectedDir], network: { kind: "none" }, environment: {} }, argv: [command, "/d", "/c", `echo changed > "${alias}"`] };
    try {
      const result = spawnSync(executable, ["stdio"], { env: { ...process.env, PI_MXC_REQUEST: JSON.stringify(request) }, encoding: "utf8", timeout: 10_000 });
      expect(result.status, result.stderr).toBe(125);
      expect(result.stderr).toContain("grant path identity changed");
      expect(readFileSync(target, "utf8")).toBe("original");
    } finally { rmdirSync(junction); rmSync(root, { recursive: true, force: true }); }
  }, 15_000);

  it("rejects a noncanonical protected path in the native stdio entry", () => {
    const root = mkdtempSync(join(tmpdir(), "mxc-stdio-protected-alias-"));
    const protectedDir = join(root, "protected");
    const junction = join(root, "alias");
    mkdirSync(protectedDir);
    symlinkSync(protectedDir, junction, "junction");
    const command = join(process.env.SystemRoot!, "System32", "cmd.exe");
    const request = { plan: { cwd: root, filesystem: [
      { path: root, access: "read", granularity: "directory" },
    ], protectedPaths: [junction], network: { kind: "none" }, environment: {} }, argv: [command, "/d", "/c", "echo started"] };
    try {
      const result = spawnSync(executable, ["stdio"], { env: { ...process.env, PI_MXC_REQUEST: JSON.stringify(request) }, encoding: "utf8", timeout: 10_000 });
      expect(result.status, result.stderr).toBe(125);
      expect(result.stderr).toContain("protected path identity changed");
      expect(result.stdout).not.toContain("started");
    } finally { rmdirSync(junction); rmSync(root, { recursive: true, force: true }); }
  }, 15_000);

  it("rejects a missing protected path beneath a junction in the native stdio entry", () => {
    const root = mkdtempSync(join(tmpdir(), "mxc-stdio-missing-protected-alias-"));
    const target = join(root, "target");
    const junction = join(root, "alias");
    mkdirSync(target);
    symlinkSync(target, junction, "junction");
    const protectedDir = join(junction, ".git");
    const actualProtectedDir = join(target, ".git");
    const shell = join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
    const command = `[IO.Directory]::CreateDirectory('${actualProtectedDir.replaceAll("'", "''")}') | Out-Null; 'started'`;
    const request = { plan: { cwd: root, filesystem: [
      { path: root, access: "read", granularity: "directory" },
      { path: root, access: "write", granularity: "directory" },
    ], protectedPaths: [protectedDir], network: { kind: "none" }, environment: {} }, argv: [shell, "-NoProfile", "-NonInteractive", "-Command", command] };
    try {
      const result = spawnSync(executable, ["stdio"], { env: { ...process.env, PI_MXC_REQUEST: JSON.stringify(request) }, encoding: "utf8", timeout: 15_000 });
      expect(result.status, result.stderr).toBe(125);
      expect(result.stderr).toContain("protected path identity changed");
      expect(result.stdout).not.toContain("started");
      expect(existsSync(actualProtectedDir)).toBe(false);
    } finally { rmdirSync(junction); rmSync(root, { recursive: true, force: true }); }
  }, 20_000);

  it("allows workspace writes while denying a missing protected directory in the native stdio entry", () => {
    const root = mkdtempSync(join(tmpdir(), "mxc-stdio-missing-protected-"));
    const protectedDir = join(root, ".git");
    const allowed = join(root, "allowed.txt");
    const shell = join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
    const command = `[IO.File]::WriteAllText('${allowed.replaceAll("'", "''")}','allowed'); try { [IO.Directory]::CreateDirectory('${protectedDir.replaceAll("'", "''")}') | Out-Null; 'created' } catch { 'denied' }`;
    const request = { plan: { cwd: root, filesystem: [
      { path: root, access: "read", granularity: "directory" },
      { path: root, access: "write", granularity: "directory" },
    ], protectedPaths: [protectedDir], network: { kind: "none" }, environment: {} }, argv: [shell, "-NoProfile", "-NonInteractive", "-Command", command] };
    try {
      const result = spawnSync(executable, ["stdio"], { env: { ...process.env, PI_MXC_REQUEST: JSON.stringify(request) }, encoding: "utf8", timeout: 15_000 });
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toContain("denied");
      expect(readFileSync(allowed, "utf8")).toBe("allowed");
      expect(existsSync(protectedDir)).toBe(false);
    } finally { rmSync(root, { recursive: true, force: true }); }
  }, 20_000);

  it.each(["grep", "find"])("allows the native %s process while denying missing protected paths", name => {
    const root = mkdtempSync(join(tmpdir(), "mxc-tool-missing-protected-"));
    const protectedDir = join(root, ".git");
    const marker = join(root, "started.txt");
    const shell = join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
    const command = `[IO.File]::WriteAllText('${marker.replaceAll("'", "''")}','started'); try { [IO.Directory]::CreateDirectory('${protectedDir.replaceAll("'", "''")}') | Out-Null; 'created' } catch { 'denied' }`;
    const request = { plan: { cwd: root, filesystem: [
      { path: root, access: "read", granularity: "directory" },
      { path: root, access: "write", granularity: "directory" },
    ], protectedPaths: [protectedDir], network: { kind: "none" }, environment: {}, operation: { kind: "builtin-tool", name } },
      argv: [shell, "-NoProfile", "-NonInteractive", "-Command", command] };
    try {
      const result = spawnSync(executable, [], { input: JSON.stringify(request), env: process.env, encoding: "utf8", timeout: 15_000 });
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toContain("denied");
      expect(readFileSync(marker, "utf8")).toBe("started");
      expect(existsSync(protectedDir)).toBe(false);
    } finally { rmSync(root, { recursive: true, force: true }); }
  }, 20_000);

  it.each([
    { writable: false, interpreter: "powershell" }, { writable: true, interpreter: "powershell" },
    { writable: false, interpreter: "cmd" }, { writable: true, interpreter: "cmd" },
  ])("changes to an authorized directory with $interpreter and write=$writable", ({ writable, interpreter }) => {
    const root = mkdtempSync(join(tmpdir(), "mxc-cwd-access-"));
    const shell = interpreter === "cmd" ? join(process.env.SystemRoot!, "System32", "cmd.exe") : join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
    const argv = interpreter === "cmd" ? [shell, "/d", "/c", `cd /d ${root.replaceAll(" ", "^ ")} && echo location-ok`]
      : [shell, "-NoProfile", "-NonInteractive", "-Command", `$ErrorActionPreference='Stop'; Set-Location -LiteralPath '${root.replaceAll("'", "''")}'; 'location-ok'`];
    const request = { plan: { cwd: root, filesystem: [
      { path: root, access: "read", granularity: "directory" },
      ...(writable ? [{ path: root, access: "write", granularity: "directory" }] : []),
    ], protectedPaths: [], network: { kind: "none" }, environment: {} }, argv };
    try {
      const result = spawnSync(executable, ["stdio"], { env: { ...process.env, PI_MXC_REQUEST: JSON.stringify(request) }, encoding: "utf8", timeout: 15_000 });
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toContain("location-ok");
    } finally { rmSync(root, { recursive: true, force: true }); }
  }, 20_000);

  it.each([false, true])("starts a child PowerShell in the authorized directory with write=$writable", writable => {
    const root = mkdtempSync(join(tmpdir(), "mxc-child-cwd-"));
    const shell = join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
    const childCommand = Buffer.from("[Console]::WriteLine((Get-Location).Path)", "utf16le").toString("base64");
    const command = `$ErrorActionPreference='Stop'; $i=[Diagnostics.ProcessStartInfo]::new(); $i.FileName='${shell.replaceAll("'", "''")}'; $i.Arguments='-NoProfile -NonInteractive -EncodedCommand ${childCommand}'; $i.WorkingDirectory='${root.replaceAll("'", "''")}'; $i.UseShellExecute=$false; $i.RedirectStandardOutput=$true; $p=[Diagnostics.Process]::Start($i); $out=$p.StandardOutput.ReadToEnd(); $p.WaitForExit(); 'child-location=' + $out.Trim(); 'child-exit=' + $p.ExitCode`;
    const request = { plan: { cwd: root, filesystem: [
      { path: root, access: "read", granularity: "directory" },
      ...(writable ? [{ path: root, access: "write", granularity: "directory" }] : []),
    ], protectedPaths: [], network: { kind: "none" }, environment: {} }, argv: [shell, "-NoProfile", "-NonInteractive", "-Command", command] };
    try {
      const result = spawnSync(executable, ["stdio"], { env: { ...process.env, PI_MXC_REQUEST: JSON.stringify(request) }, encoding: "utf8", timeout: 15_000 });
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toContain("child-exit=0");
      expect(result.stdout).toContain(`child-location=${root}`);
    } finally { rmSync(root, { recursive: true, force: true }); }
  }, 20_000);

  it("rejects a file grant replaced by a directory before native launch", async () => {
    const root = mkdtempSync(join(tmpdir(), "mxc-grant-replace-"));
    const cwd = join(root, "workspace");
    const grant = join(root, "grant");
    const target = join(grant, "secret.txt");
    mkdirSync(cwd);
    writeFileSync(grant, "file");
    const preload = join(root, "replace.cjs");
    writeFileSync(preload, `const cp = require('node:child_process'); const fs = require('node:fs'); const original = cp.spawn;
      cp.spawn = function(file, args, options) { if (file.endsWith('pi-sandbox-windows-mxc.exe') && args.length === 0) { fs.unlinkSync(${JSON.stringify(grant)}); fs.mkdirSync(${JSON.stringify(grant)}); fs.writeFileSync(${JSON.stringify(target)}, 'original'); } return original.apply(this, arguments); }; require('node:module').syncBuiltinESMExports();`);
    const child = spawn(process.execPath, ["--require", preload, helper], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    const messages: Record<string, unknown>[] = [];
    const result = new Promise<void>((resolve, reject) => {
      let buffer = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", chunk => {
        buffer += chunk;
        for (;;) {
          const end = buffer.indexOf("\n");
          if (end < 0) break;
          const message = JSON.parse(buffer.slice(0, end));
          buffer = buffer.slice(end + 1);
          messages.push(message);
          if (message.type === "ready") child.stdin.write(JSON.stringify({ type: "start", requestId: "grant-replace", generation: 1,
            plan: { backend: { id: "windows-mxc" }, cwd, filesystem: [
              { path: cwd, access: "read", granularity: "directory" },
              { path: grant, access: "read", granularity: "file" },
              { path: grant, access: "write", granularity: "file" },
            ], protectedPaths: [], network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot },
              operation: { kind: "shell", shell: join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
                command: `[IO.File]::WriteAllText('${target.replaceAll("'", "''")}','changed')` } } }) + "\n");
          if (message.type === "result" || message.type === "rejected" || message.type === "error") resolve();
        }
      });
      child.on("error", reject);
      child.on("exit", code => reject(new Error(`helper exited before result: ${code}`)));
    });
    child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "grant-replace", generation: 1 }) + "\n");
    try {
      await result;
      expect(readFileSync(target, "utf8"), JSON.stringify(messages)).toBe("original");
      expect(messages, JSON.stringify(messages)).toEqual(expect.arrayContaining([expect.objectContaining({ type: "error", code: "setup" })]));
      expect(messages.some(message => message.type === "started")).toBe(false);
    } finally { child.kill(); rmSync(root, { recursive: true, force: true }); }
  }, 20_000);

  it.each(["read", "read-write", "new"])("handles a %s file grant outside the workspace with implicit volume reads", async access => {
    const root = mkdtempSync(join(tmpdir(), "mxc-file-grant-"));
    const cwd = join(root, "workspace");
    const external = join(root, "external");
    mkdirSync(cwd);
    mkdirSync(external);
    const allowed = join(external, "allowed.txt");
    const sibling = join(external, "sibling.txt");
    if (access !== "new") writeFileSync(allowed, "allowed-original");
    writeFileSync(sibling, "sibling-original");
    expect(readFileSync(sibling, "utf8")).toBe("sibling-original");
    const command = `try { [IO.File]::ReadAllText('${allowed.replaceAll("'", "''")}') } catch { 'allowed-read-failed' }; try { [IO.File]::WriteAllText('${allowed.replaceAll("'", "''")}','allowed-updated'); 'allowed-write' } catch { 'allowed-write-denied' }; try { [IO.File]::ReadAllText('${sibling.replaceAll("'", "''")}') } catch { 'sibling-read-denied' }; try { [IO.File]::WriteAllText('${sibling.replaceAll("'", "''")}','changed'); 'sibling-writable' } catch { 'sibling-write-denied' }`;
    const child = spawn(process.execPath, [helper], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    const messages: Record<string, unknown>[] = [];
    const result = new Promise<void>((resolve, reject) => {
      let buffer = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", chunk => {
        buffer += chunk;
        for (;;) {
          const end = buffer.indexOf("\n");
          if (end < 0) break;
          const message = JSON.parse(buffer.slice(0, end));
          buffer = buffer.slice(end + 1);
          messages.push(message);
          if (message.type === "ready") child.stdin.write(JSON.stringify({ type: "start", requestId: "file-grant", generation: 1,
            plan: { backend: { id: "windows-mxc" }, cwd, filesystem: [
              { path: cwd, access: "read", granularity: "directory" },
              { path: allowed, access: "read", granularity: "file" },
              ...(access !== "read" ? [{ path: allowed, access: "write", granularity: "file" }] : []),
            ], protectedPaths: [], network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot },
              operation: { kind: "shell", shell: join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), command } } }) + "\n");
          if (message.type === "result" || message.type === "rejected" || message.type === "error") resolve();
        }
      });
      child.on("error", reject);
      child.on("exit", code => reject(new Error(`helper exited before result: ${code}`)));
    });
    child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "file-grant", generation: 1 }) + "\n");
    try {
      await result;
      if (access === "new") {
        expect(messages, JSON.stringify(messages)).toEqual(expect.arrayContaining([expect.objectContaining({ type: "rejected", code: "unsupported", started: false })]));
        expect(existsSync(allowed)).toBe(false);
        expect(readFileSync(sibling, "utf8")).toBe("sibling-original");
        return;
      }
      expect(messages, JSON.stringify(messages)).toEqual(expect.arrayContaining([expect.objectContaining({ type: "result", exitCode: 0 })]));
      const output = messages.filter(message => message.type === "output").map(message => String(message.data)).join("");
      expect(output).toContain("allowed-original");
      expect(output).toContain(access === "read" ? "allowed-write-denied" : "allowed-write");
      if (access !== "read") expect(output).not.toContain("allowed-write-denied");
      expect(output).toContain("sibling-original");
      expect(output).toContain("sibling-write-denied");
      expect(readFileSync(allowed, "utf8")).toBe(access === "read" ? "allowed-original" : "allowed-updated");
      expect(readFileSync(sibling, "utf8")).toBe("sibling-original");
    } finally { child.kill(); rmSync(root, { recursive: true, force: true }); }
  }, 20_000);

  it.each([
    { access: "read", target: "outside" },
    { access: "write", target: "outside" },
    { access: "write", target: "protected" },
  ])("handles $access of a $target file through a workspace junction", async ({ access, target }) => {
    const root = mkdtempSync(join(tmpdir(), "mxc-junction-"));
    const cwd = join(root, "workspace");
    const outside = target === "protected" ? join(cwd, ".git") : join(root, "outside");
    const junction = join(cwd, "alias");
    mkdirSync(cwd);
    mkdirSync(outside);
    writeFileSync(join(outside, "secret.txt"), "junction-secret");
    symlinkSync(outside, junction, "junction");
    const alias = join(junction, "secret.txt");
    expect(readFileSync(alias, "utf8")).toBe("junction-secret");
    writeFileSync(alias, "junction-secret");
    const child = spawn(process.execPath, [helper], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    const messages: Record<string, unknown>[] = [];
    const result = new Promise<void>((resolve, reject) => {
      let buffer = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", chunk => {
        buffer += chunk;
        for (;;) {
          const end = buffer.indexOf("\n");
          if (end < 0) break;
          const message = JSON.parse(buffer.slice(0, end));
          buffer = buffer.slice(end + 1);
          messages.push(message);
          if (message.type === "ready") child.stdin.write(JSON.stringify({ type: "start", requestId: "junction", generation: 1,
            plan: { backend: { id: "windows-mxc" }, cwd, filesystem: [{ path: cwd, access: "read", granularity: "directory" },
              ...(access === "write" ? [{ path: cwd, access: "write", granularity: "directory" }] : [])],
              protectedPaths: target === "protected" ? [outside] : [], network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot },
              operation: { kind: "shell", shell: join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
                command: access === "read"
                  ? `try { [IO.File]::ReadAllText('${alias.replaceAll("'", "''")}') } catch { 'blocked' }`
                  : `try { [IO.File]::WriteAllText('${alias.replaceAll("'", "''")}','modified'); 'wrote' } catch { 'blocked' }` } } }) + "\n");
          if (message.type === "result" || message.type === "rejected" || message.type === "error") resolve();
        }
      });
      child.on("error", reject);
      child.on("exit", code => reject(new Error(`helper exited before result: ${code}`)));
    });
    child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "junction", generation: 1 }) + "\n");
    try {
      await result;
      const readable = access === "read" && target === "outside";
      expect(messages).toEqual(expect.arrayContaining([
        expect.objectContaining({ type: "output", data: expect.stringContaining(readable ? "junction-secret" : "blocked") }),
        expect.objectContaining({ type: "result", exitCode: 0 }),
      ]));
      if (!readable) expect(JSON.stringify(messages)).not.toContain("junction-secret");
      expect(readFileSync(join(outside, "secret.txt"), "utf8")).toBe("junction-secret");
    } finally { child.kill(); rmdirSync(junction); rmSync(root, { recursive: true, force: true }); }
  }, 20_000);

  it.each(["read", "ls"])("does not grant workspace writes to the %s worker", async name => {
    const workspace = mkdtempSync(join(tmpdir(), "mxc-worker-readonly-"));
    const modules = fileURLToPath(new URL("../../../../node_modules/", import.meta.url));
    const packageRoot = realpathSync(mkdtempSync(join(modules, ".mxc-readonly-")));
    const helperDir = join(packageRoot, "src", "sandbox", "backend", "windows");
    mkdirSync(helperDir, { recursive: true });
    const runtimeDirectory = installTestRuntime(packageRoot);
    copyFileSync(helper, join(helperDir, "helper.mjs"));
    writeFileSync(join(packageRoot, "package.json"), JSON.stringify({ type: "module" }));
    const file = join(workspace, "sample.txt");
    const protectedDir = join(workspace, ".git");
    writeFileSync(file, "original");
    const worker = join(packageRoot, "src", "sandbox", "builtin-worker.bundle.mjs");
    writeFileSync(worker, `import { writeFileSync, mkdirSync } from 'node:fs';\nlet a=false,b=false; try { writeFileSync(${JSON.stringify(file)}, 'changed'); a=true; } catch {} try { mkdirSync(${JSON.stringify(protectedDir)}); b=true; } catch {} console.log(JSON.stringify({ type: 'result', result: { content: [{ type: 'text', text: a || b ? 'probe-allowed' : 'probe-denied' }] } }));\n`);
    const control = spawnSync(process.execPath, [worker], { cwd: workspace, encoding: "utf8", timeout: 10_000 });
    expect(control.status, control.stderr).toBe(0);
    expect(control.stdout).toContain("probe-allowed");
    expect(readFileSync(file, "utf8")).toBe("changed");
    expect(existsSync(protectedDir)).toBe(true);
    writeFileSync(file, "original");
    rmdirSync(protectedDir);
    const child = spawn(process.execPath, [join(helperDir, "helper.mjs")], {
      stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, PI_SANDBOX_RUNTIME_DIR: runtimeDirectory },
    });
    const result = new Promise<Record<string, unknown>>((resolve, reject) => {
      let buffer = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", chunk => {
        buffer += chunk;
        for (;;) {
          const end = buffer.indexOf("\n");
          if (end < 0) break;
          const message = JSON.parse(buffer.slice(0, end));
          buffer = buffer.slice(end + 1);
          if (message.type === "ready") child.stdin.write(JSON.stringify({ type: "start", requestId: "worker-readonly", generation: 1,
            plan: { backend: { id: "windows-mxc" }, cwd: workspace, toolCallId: "worker-readonly", filesystem: [
              { path: workspace, access: "read", granularity: "directory" },
              { path: workspace, access: "write", granularity: "directory" },
            ], protectedPaths: [protectedDir], network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot },
              operation: { kind: "builtin-tool", name, arguments: { path: name === "read" ? "sample.txt" : "." } } } }) + "\n");
          if (message.type === "result" || message.type === "rejected" || message.type === "error") resolve(message);
        }
      });
      child.on("error", reject);
      child.on("exit", code => reject(new Error(`helper exited before result: ${code}`)));
    });
    child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "worker-readonly", generation: 1 }) + "\n");
    try {
      const message = await result;
      expect(message, JSON.stringify(message)).toMatchObject({ type: "result", started: true, exitCode: 0 });
      expect(Buffer.from(String(message.dataBase64), "base64").toString("utf8")).toContain("probe-denied");
      expect(readFileSync(file, "utf8")).toBe("original");
      expect(existsSync(protectedDir)).toBe(false);
    } finally { child.kill(); rmSync(workspace, { recursive: true, force: true }); rmSync(packageRoot, { recursive: true, force: true }); }
  }, 25_000);

  it.each([{ name: "grep", binary: "rg.exe", args: { path: ".", pattern: "needle" } },
    { name: "find", binary: "fd.exe", args: { path: ".", pattern: "*.txt" } }])(
    "prevents the external $name process from writing through a writable plan", async ({ name, binary, args }) => {
      const root = mkdtempSync(join(tmpdir(), "mxc-search-readonly-"));
      const cwd = join(root, "workspace");
      const agent = join(root, "agent");
      const bin = join(agent, "bin");
      mkdirSync(cwd);
      mkdirSync(bin, { recursive: true });
      const file = join(cwd, "sample.txt");
      const protectedDir = join(cwd, ".git");
      writeFileSync(file, "original");
      const source = join(root, "probe.rs");
      const executablePath = join(bin, binary);
      const deniedOutput = name === "grep"
        ? '{"type":"match","data":{"path":{"text":"sample.txt"},"line_number":1,"lines":{"text":"probe-denied"}}}'
        : "probe-denied";
      const allowedOutput = deniedOutput.replace("probe-denied", "probe-allowed");
      writeFileSync(source, `fn main() { let a = std::fs::write("sample.txt", "changed").is_ok(); let b = std::fs::create_dir(".git").is_ok(); if a || b { println!("{}", ${JSON.stringify(allowedOutput)}); } else { println!("{}", ${JSON.stringify(deniedOutput)}); } }`);
      const compiled = spawnSync("rustc", ["--edition=2021", source, "-o", executablePath], { encoding: "utf8", timeout: 30_000 });
      expect(compiled.status, compiled.stderr).toBe(0);
      const control = spawnSync(executablePath, [], { cwd, encoding: "utf8", timeout: 10_000 });
      expect(control.status, control.stderr).toBe(0);
      expect(control.stdout).toContain("probe-allowed");
      expect(readFileSync(file, "utf8")).toBe("changed");
      expect(existsSync(protectedDir)).toBe(true);
      writeFileSync(file, "original");
      rmdirSync(protectedDir);
      const child = spawn(process.execPath, [helper], { stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, PI_MXC_AGENT_DIR: agent } });
      const result = new Promise<Record<string, unknown>>((resolve, reject) => {
        let buffer = "";
        child.stdout.setEncoding("utf8");
        child.stdout.on("data", chunk => {
          buffer += chunk;
          for (;;) {
            const end = buffer.indexOf("\n");
            if (end < 0) break;
            const message = JSON.parse(buffer.slice(0, end));
            buffer = buffer.slice(end + 1);
            if (message.type === "ready") child.stdin.write(JSON.stringify({ type: "start", requestId: "search-readonly", generation: 1,
              plan: { backend: { id: "windows-mxc" }, cwd, toolCallId: "search-readonly", filesystem: [
                { path: cwd, access: "read", granularity: "directory" },
                { path: cwd, access: "write", granularity: "directory" },
              ], protectedPaths: [protectedDir], network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot, PATH: "" },
                operation: { kind: "builtin-tool", name, arguments: args } } }) + "\n");
            if (message.type === "result" || message.type === "rejected" || message.type === "error") resolve(message);
          }
        });
        child.on("error", reject);
        child.on("exit", code => reject(new Error(`helper exited before result: ${code}`)));
      });
      child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "search-readonly", generation: 1 }) + "\n");
      try {
        const message = await result;
        expect(message, JSON.stringify(message)).toMatchObject({ type: "result", started: true, exitCode: 0 });
        expect(Buffer.from(String(message.dataBase64), "base64").toString("utf8")).toContain("probe-denied");
        expect(readFileSync(file, "utf8")).toBe("original");
        expect(existsSync(protectedDir)).toBe(false);
      } finally { child.kill(); rmSync(root, { recursive: true, force: true }); }
    }, 45_000,
  );

  it.each([{ name: "grep", binary: "rg.exe", pathBinary: "rg.exe", custom: false, fallback: false, invalidFd: false, args: { path: ".", pattern: "needle" } },
    { name: "find", binary: "fd.exe", pathBinary: "fd.exe", custom: false, fallback: false, invalidFd: false, args: { path: ".", pattern: "*.txt" } },
    { name: "find", binary: "fd.exe", pathBinary: "fdfind.exe", custom: false, fallback: false, invalidFd: false, args: { path: ".", pattern: "*.txt" } },
    { name: "grep", binary: "rg.exe", pathBinary: "rg.exe", custom: true, fallback: false, invalidFd: false, args: { path: ".", pattern: "needle" } },
    { name: "find", binary: "fd.exe", pathBinary: "fd.exe", custom: true, fallback: false, invalidFd: false, args: { path: ".", pattern: "*.txt" } },
    { name: "find", binary: "fd.exe", pathBinary: "fdfind.exe", custom: true, fallback: true, invalidFd: false, args: { path: ".", pattern: "*.txt" } },
    { name: "find", binary: "fd.exe", pathBinary: "fdfind.exe", custom: true, fallback: true, invalidFd: true, args: { path: ".", pattern: "*.txt" } }])(
    "runs $name using $pathBinary in the selected runtime location (invalid fd: $invalidFd)", async ({ name, binary, pathBinary, args, custom, fallback, invalidFd }) => {
      const source = join(process.env.USERPROFILE!, ".pi", "agent", "bin", binary);
      expect(existsSync(source)).toBe(true);
      const root = mkdtempSync(join(tmpdir(), "mxc-path-tool-"));
      const cwd = join(root, "workspace");
      const agent = join(root, "custom-agent");
      const bin = custom && !fallback ? join(agent, "bin") : join(root, "bin");
      mkdirSync(cwd);
      mkdirSync(bin, { recursive: true });
      writeFileSync(join(cwd, "sample.txt"), "needle");
      copyFileSync(source, join(bin, pathBinary));
      if (invalidFd) writeFileSync(join(bin, "fd.exe"), "invalid executable");
      const child = spawn(process.execPath, [helper], { stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, USERPROFILE: root, PI_MXC_AGENT_DIR: custom ? agent : undefined } });
      const result = new Promise<Record<string, unknown>>((resolve, reject) => {
        let buffer = "";
        child.stdout.setEncoding("utf8");
        child.stdout.on("data", chunk => {
          buffer += chunk;
          for (;;) {
            const end = buffer.indexOf("\n");
            if (end < 0) break;
            const message = JSON.parse(buffer.slice(0, end));
            buffer = buffer.slice(end + 1);
            if (message.type === "ready") child.stdin.write(JSON.stringify({ type: "start", requestId: "path-tool", generation: 1,
              plan: { backend: { id: "windows-mxc" }, cwd, toolCallId: "path-tool",
                filesystem: [{ path: cwd, access: "read", granularity: "directory" }], protectedPaths: [],
                network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot, USERPROFILE: root, PATH: custom && !fallback ? "" : bin },
                operation: { kind: "builtin-tool", name, arguments: args } } }) + "\n");
            if (message.type === "result" || message.type === "rejected" || message.type === "error") resolve(message);
          }
        });
        child.on("error", reject);
        child.on("exit", code => reject(new Error(`helper exited before result: ${code}`)));
      });
      child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "path-tool", generation: 1 }) + "\n");
      try {
        const message = await result;
        expect(message, JSON.stringify(message)).toMatchObject({ type: "result", started: true, exitCode: 0 });
        expect(Buffer.from(String(message.dataBase64), "base64").toString("utf8")).toContain(name === "grep" ? "needle" : "sample.txt");
      } finally { child.kill(); rmSync(root, { recursive: true, force: true }); }
    }, 20_000,
  );

  it("executes a bundled builtin without the pi SDK on disk", async () => {
    const workspace = mkdtempSync(join(tmpdir(), "mxc-hoisted-workspace-"));
    const packageRoot = mkdtempSync(join(tmpdir(), "mxc-hoisted-package-"));
    const copiedHelperDir = join(packageRoot, "src", "sandbox", "backend", "windows");
    mkdirSync(copiedHelperDir, { recursive: true });
    const runtimeDirectory = installTestRuntime(packageRoot);
    copyFileSync(helper, join(copiedHelperDir, "helper.mjs"));
    copyFileSync(fileURLToPath(new URL("../../../../src/sandbox/builtin-worker.bundle.mjs", import.meta.url)), join(packageRoot, "src", "sandbox", "builtin-worker.bundle.mjs"));
    writeFileSync(join(packageRoot, "package.json"), JSON.stringify({ type: "module" }));
    writeFileSync(join(workspace, "approved.txt"), "hoisted-read");
    const child = spawn(process.execPath, [join(copiedHelperDir, "helper.mjs")], {
      stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, PI_SANDBOX_RUNTIME_DIR: runtimeDirectory },
    });
    const result = new Promise<Record<string, unknown>>((resolve, reject) => {
      let buffer = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", chunk => {
        buffer += chunk;
        for (;;) {
          const end = buffer.indexOf("\n");
          if (end < 0) break;
          const message = JSON.parse(buffer.slice(0, end));
          buffer = buffer.slice(end + 1);
          if (message.type === "ready") child.stdin.write(JSON.stringify({ type: "start", requestId: "hoisted", generation: 1,
            plan: { backend: { id: "windows-mxc" }, cwd: workspace, toolCallId: "hoisted",
              filesystem: [{ path: workspace, access: "read", granularity: "directory" }], protectedPaths: [],
              network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot, PATH: process.env.PATH },
              operation: { kind: "builtin-tool", name: "read", arguments: { path: "approved.txt" } } } }) + "\n");
          if (message.type === "result" || message.type === "rejected" || message.type === "error") resolve(message);
        }
      });
      child.on("error", reject);
      child.on("exit", code => reject(new Error(`helper exited before result: ${code}`)));
    });
    child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "hoisted", generation: 1 }) + "\n");
    try {
      const message = await result;
      expect(message, JSON.stringify(message)).toMatchObject({ type: "result", started: true, exitCode: 0 });
      expect(Buffer.from(String(message.dataBase64), "base64").toString("utf8")).toContain("hoisted-read");
    } finally { child.kill(); rmSync(workspace, { recursive: true, force: true }); rmSync(packageRoot, { recursive: true, force: true }); }
  }, 20_000);

  it("executes the read builtin inside the native boundary", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "mxc-builtin-"));
    writeFileSync(join(cwd, "approved.txt"), "contained-read");
    const child = spawn(process.execPath, [helper], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    const result = new Promise<Record<string, unknown>>((resolve, reject) => {
      let buffer = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", chunk => {
        buffer += chunk;
        for (;;) {
          const end = buffer.indexOf("\n");
          if (end < 0) break;
          const message = JSON.parse(buffer.slice(0, end));
          buffer = buffer.slice(end + 1);
          if (message.type === "ready") child.stdin.write(JSON.stringify({ type: "start", requestId: "builtin", generation: 1,
            plan: { backend: { id: "windows-mxc" }, cwd, toolCallId: "builtin",
              filesystem: [{ path: cwd, access: "read", granularity: "directory" }], protectedPaths: [],
              network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot, PATH: process.env.PATH },
              operation: { kind: "builtin-tool", name: "read", arguments: { path: "approved.txt" } } } }) + "\n");
          if (message.type === "result" || message.type === "rejected") resolve(message);
        }
      });
      child.on("error", reject);
      child.on("exit", code => reject(new Error(`helper exited before result: ${code}`)));
    });
    child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "builtin", generation: 1 }) + "\n");
    try {
      const message = await result;
      expect(message, JSON.stringify(message)).toMatchObject({ type: "result", started: true, exitCode: 0 });
      const packet = JSON.parse(Buffer.from(String(message.dataBase64), "base64").toString("utf8"));
      expect(JSON.stringify(packet)).toContain("contained-read");
    } finally { child.kill(); rmSync(cwd, { recursive: true, force: true }); }
  }, 20_000);

  it("prevents a nested native launcher from expanding filesystem access", async () => {
    const root = mkdtempSync(join(tmpdir(), "mxc-nested-"));
    const cwd = join(root, "workspace");
    const outside = join(root, "outside");
    mkdirSync(cwd);
    mkdirSync(outside);
    const secret = join(outside, "secret.txt");
    writeFileSync(secret, "nested-secret-canary");
    const shell = join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
    const inner = { plan: { cwd, filesystem: [
      { path: cwd, access: "read", granularity: "directory" },
      { path: outside, access: "read", granularity: "directory" },
    ], protectedPaths: [], network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot } },
      argv: [shell, "-NoProfile", "-NonInteractive", "-Command", `[IO.File]::ReadAllText('${secret.replaceAll("'", "''")}')`], input: "" };
    const payload = JSON.stringify(inner);
    const control = spawnSync(executable, [], { input: payload, encoding: "utf8", env: process.env, timeout: 10_000 });
    expect(control.status, control.stderr).toBe(0);
    expect(control.stdout).toContain("nested-secret-canary");
    const command = `$i=[Diagnostics.ProcessStartInfo]::new(); $i.FileName='${executable.replaceAll("'", "''")}'; $i.WorkingDirectory='${cwd.replaceAll("'", "''")}'; $i.UseShellExecute=$false; $i.RedirectStandardInput=$true; $i.RedirectStandardOutput=$true; $i.RedirectStandardError=$true; $p=[Diagnostics.Process]::Start($i); $p.StandardInput.Write('${payload.replaceAll("'", "''")}'); $p.StandardInput.Close(); $out=$p.StandardOutput.ReadToEnd(); $err=$p.StandardError.ReadToEnd(); $p.WaitForExit(); Write-Output $out; Write-Output $err; Write-Output ('native-exit=' + $p.ExitCode)`;
    const child = spawn(process.execPath, [helper], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    const messages: Record<string, unknown>[] = [];
    const result = new Promise<void>((resolve, reject) => {
      let buffer = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", chunk => {
        buffer += chunk;
        for (;;) {
          const end = buffer.indexOf("\n");
          if (end < 0) break;
          const message = JSON.parse(buffer.slice(0, end));
          buffer = buffer.slice(end + 1);
          messages.push(message);
          if (message.type === "ready") child.stdin.write(JSON.stringify({ type: "start", requestId: "nested", generation: 1,
            plan: { backend: { id: "windows-mxc" }, cwd, filesystem: [
              { path: cwd, access: "read", granularity: "directory" },
              { path: executable, access: "read", granularity: "file" },
            ], protectedPaths: [], network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot },
              operation: { kind: "shell", shell, command } } }) + "\n");
          if (message.type === "result" || message.type === "rejected" || message.type === "error") resolve();
        }
      });
      child.on("error", reject);
      child.on("exit", code => reject(new Error(`helper exited before result: ${code}`)));
    });
    child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "nested", generation: 1 }) + "\n");
    try {
      await result;
      expect(messages).toEqual(expect.arrayContaining([expect.objectContaining({ type: "result", started: true })]));
      expect(JSON.stringify(messages)).toMatch(/native-exit=\d+/u);
      expect(JSON.stringify(messages)).not.toContain("nested-secret-canary");
    } finally { child.kill(); rmSync(root, { recursive: true, force: true }); }
  }, 25_000);

  it("blocks access to a host named pipe", async () => {
    const name = `mxc-test-${randomUUID()}`;
    const pipe = `\\\\.\\pipe\\${name}`;
    let connections = 0;
    const server = createServer(socket => { connections++; socket.destroy(); });
    await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(pipe, resolve); });
    await new Promise<void>((resolve, reject) => {
      server.once("connection", () => resolve());
      const control = createConnection(pipe);
      control.once("error", reject);
      control.once("connect", () => control.end());
    });
    expect(connections).toBe(1);
    const shell = join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
    const command = `try { $p=[IO.Pipes.NamedPipeClientStream]::new('.','${name}',[IO.Pipes.PipeDirection]::InOut); $p.Connect(1500); 'connected'; $p.Dispose() } catch { 'blocked' }`;
    const hostConnection = new Promise<void>(resolve => server.once("connection", () => resolve()));
    const control = spawnSync(shell, ["-NoProfile", "-NonInteractive", "-Command", command], { encoding: "utf8" });
    expect(control.status).toBe(0);
    expect(control.stdout).toContain("connected");
    await hostConnection;
    expect(connections).toBe(2);
    const cwd = mkdtempSync(join(tmpdir(), "mxc-pipe-"));
    const child = spawn(process.execPath, [helper], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    const messages: Record<string, unknown>[] = [];
    const result = new Promise<void>((resolve, reject) => {
      let buffer = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", chunk => {
        buffer += chunk;
        for (;;) {
          const end = buffer.indexOf("\n");
          if (end < 0) break;
          const message = JSON.parse(buffer.slice(0, end));
          buffer = buffer.slice(end + 1);
          messages.push(message);
          if (message.type === "ready") child.stdin.write(JSON.stringify({ type: "start", requestId: "pipe", generation: 1,
            plan: { backend: { id: "windows-mxc" }, cwd, filesystem: [{ path: cwd, access: "read", granularity: "directory" }],
              protectedPaths: [], network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot },
              operation: { kind: "shell", shell, command } } }) + "\n");
          if (message.type === "result" || message.type === "rejected" || message.type === "error") resolve();
        }
      });
      child.on("error", reject);
      child.on("exit", code => reject(new Error(`helper exited before result: ${code}`)));
    });
    child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "pipe", generation: 1 }) + "\n");
    try {
      await result;
      expect(messages).toEqual(expect.arrayContaining([
        expect.objectContaining({ type: "output", data: expect.stringContaining("blocked") }),
        expect.objectContaining({ type: "result", exitCode: 0 }),
      ]));
      expect(connections).toBe(2);
    } finally { child.kill(); server.close(); rmSync(cwd, { recursive: true, force: true }); }
  }, 20_000);

  it.each([{ host: "127.0.0.1", family: "InterNetwork", label: "loopback 127.0.0.1" }, { host: "::1", family: "InterNetworkV6", label: "loopback ::1" },
    ...(localAddress ? [{ host: localAddress, family: "InterNetwork", label: "local interface IPv4" }] : [])]
    .flatMap(address => (["none", "all"] as const).map(kind => ({ ...address, kind }))))(
    "enforces TCP $label when network is $kind", async ({ host, family, kind }) => {
    const server = createServer(socket => { connected = true; socket.destroy(); });
    let connected = false;
    await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, host, resolve); });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("listener has no port");
    await new Promise<void>((resolve, reject) => {
      server.once("connection", () => resolve());
      const control = createConnection({ host, port: address.port });
      control.once("error", reject);
      control.once("connect", () => control.end());
    });
    expect(connected).toBe(true);
    connected = false;
    const cwd = mkdtempSync(join(tmpdir(), "mxc-network-"));
    const child = spawn(process.execPath, [helper], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    const messages: Record<string, unknown>[] = [];
    const result = new Promise<void>((resolve, reject) => {
      let buffer = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", chunk => {
        buffer += chunk;
        for (;;) {
          const end = buffer.indexOf("\n");
          if (end < 0) break;
          const message = JSON.parse(buffer.slice(0, end));
          buffer = buffer.slice(end + 1);
          messages.push(message);
          if (message.type === "ready") child.stdin.write(JSON.stringify({ type: "start", requestId: "network", generation: 1,
            plan: { backend: { id: "windows-mxc" }, cwd, filesystem: [{ path: cwd, access: "read", granularity: "directory" }],
              protectedPaths: [], network: { kind }, environment: { SystemRoot: process.env.SystemRoot },
              operation: { kind: "shell", shell: join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
                command: `try { $c = [Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::${family}); $a = $c.BeginConnect('${host}', ${address.port}, $null, $null); if ($a.AsyncWaitHandle.WaitOne(1500) -and $c.Connected) { 'connected' } else { 'blocked' }; $c.Close() } catch { 'blocked' }` } } }) + "\n");
          if (message.type === "result" || message.type === "rejected") resolve();
        }
      });
      child.on("error", reject);
      child.on("exit", code => reject(new Error(`helper exited before result: ${code}`)));
    });
    child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "network", generation: 1 }) + "\n");
    try {
      await result;
      expect(messages).toEqual(expect.arrayContaining([
        expect.objectContaining({ type: "output", stream: "stdout", data: expect.stringContaining(kind === "all" ? "connected" : "blocked") }),
        expect.objectContaining({ type: "result", exitCode: 0 }),
      ]));
      expect(connected).toBe(kind === "all");
    } finally { child.kill(); server.close(); rmSync(cwd, { recursive: true, force: true }); }
  }, 20_000);

  it.each([{ host: "127.0.0.1", socket: "udp4", family: "InterNetwork", label: "loopback 127.0.0.1" }, { host: "::1", socket: "udp6", family: "InterNetworkV6", label: "loopback ::1" },
    ...(localAddress ? [{ host: localAddress, socket: "udp4", family: "InterNetwork", label: "local interface IPv4" }] as const : [])] as const)(
    "blocks UDP $label when network is none", async ({ host, socket, family }) => {
      const server = createSocket(socket);
      let received = 0;
      server.on("message", () => { received++; });
      await new Promise<void>((resolve, reject) => { server.once("error", reject); server.bind(0, host, resolve); });
      const port = server.address().port;
      const sender = createSocket(socket);
      await new Promise<void>((resolve, reject) => {
        server.once("message", () => resolve());
        sender.send(Buffer.from("control"), port, host, error => { if (error) reject(error); });
      });
      sender.close();
      expect(received).toBe(1);
      const shell = join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
      const command = `try { $u=[Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::${family}); $bytes=[Text.Encoding]::UTF8.GetBytes('sandbox'); $null=$u.Send($bytes,$bytes.Length,'${host}',${port}); $u.Close(); 'attempted' } catch { 'blocked' }`;
      const hostMessage = new Promise<void>(resolve => server.once("message", () => resolve()));
      const control = spawnSync(shell, ["-NoProfile", "-NonInteractive", "-Command", command], { encoding: "utf8" });
      expect(control.status).toBe(0);
      expect(control.stdout).toContain("attempted");
      await hostMessage;
      expect(received).toBe(2);
      const cwd = mkdtempSync(join(tmpdir(), "mxc-udp-"));
      const child = spawn(process.execPath, [helper], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
      const messages: Record<string, unknown>[] = [];
      const result = new Promise<void>((resolve, reject) => {
        let buffer = "";
        child.stdout.setEncoding("utf8");
        child.stdout.on("data", chunk => {
          buffer += chunk;
          for (;;) {
            const end = buffer.indexOf("\n");
            if (end < 0) break;
            const message = JSON.parse(buffer.slice(0, end));
            buffer = buffer.slice(end + 1);
            messages.push(message);
            if (message.type === "ready") child.stdin.write(JSON.stringify({ type: "start", requestId: "udp", generation: 1,
              plan: { backend: { id: "windows-mxc" }, cwd, filesystem: [{ path: cwd, access: "read", granularity: "directory" }],
                protectedPaths: [], network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot },
                operation: { kind: "shell", shell, command } } }) + "\n");
            if (message.type === "result" || message.type === "rejected" || message.type === "error") resolve();
          }
        });
        child.on("error", reject);
        child.on("exit", code => reject(new Error(`helper exited before result: ${code}`)));
      });
      child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "udp", generation: 1 }) + "\n");
      try {
        await result;
        expect(messages).toEqual(expect.arrayContaining([expect.objectContaining({ type: "result", exitCode: 0 })]));
        await new Promise(resolve => setTimeout(resolve, 500));
        expect(received).toBe(2);
      } finally { child.kill(); server.close(); rmSync(cwd, { recursive: true, force: true }); }
    }, 20_000,
  );

  it.each([
    { family: "InterNetwork", address: "127.0.0.1", kind: "Stream", protocol: "Tcp" },
    { family: "InterNetworkV6", address: "::1", kind: "Stream", protocol: "Tcp" },
    { family: "InterNetwork", address: "127.0.0.1", kind: "Dgram", protocol: "Udp" },
    { family: "InterNetworkV6", address: "::1", kind: "Dgram", protocol: "Udp" },
  ])("allows $protocol $family loopback binding when network is none", async ({ family, address, kind, protocol }) => {
    const shell = join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
    const command = `try { $s=[Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::${family},[Net.Sockets.SocketType]::${kind},[Net.Sockets.ProtocolType]::${protocol}); $s.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Parse('${address}'),0)); ${protocol === "Tcp" ? "$s.Listen(1);" : ""} 'allowed'; $s.Close() } catch { 'blocked' }`;
    const control = spawnSync(shell, ["-NoProfile", "-NonInteractive", "-Command", command], { encoding: "utf8" });
    expect(control.status).toBe(0);
    expect(control.stdout).toContain("allowed");
    const cwd = mkdtempSync(join(tmpdir(), "mxc-bind-"));
    const child = spawn(process.execPath, [helper], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    const messages: Record<string, unknown>[] = [];
    const result = new Promise<void>((resolve, reject) => {
      let buffer = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", chunk => {
        buffer += chunk;
        for (;;) {
          const end = buffer.indexOf("\n");
          if (end < 0) break;
          const message = JSON.parse(buffer.slice(0, end));
          buffer = buffer.slice(end + 1);
          messages.push(message);
          if (message.type === "ready") child.stdin.write(JSON.stringify({ type: "start", requestId: "bind", generation: 1,
            plan: { backend: { id: "windows-mxc" }, cwd, filesystem: [{ path: cwd, access: "read", granularity: "directory" }],
              protectedPaths: [], network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot },
              operation: { kind: "shell", shell, command } } }) + "\n");
          if (message.type === "result" || message.type === "rejected" || message.type === "error") resolve();
        }
      });
      child.on("error", reject);
      child.on("exit", code => reject(new Error(`helper exited before result: ${code}`)));
    });
    child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "bind", generation: 1 }) + "\n");
    try {
      await result;
      expect(messages).toEqual(expect.arrayContaining([
        expect.objectContaining({ type: "output", stream: "stdout", data: expect.stringContaining("allowed") }),
        expect.objectContaining({ type: "result", exitCode: 0 }),
      ]));
    } finally { child.kill(); rmSync(cwd, { recursive: true, force: true }); }
  }, 20_000);

  it.each(["127.0.0.1", "::1"])("blocks host connections to a sandbox TCP listener on %s", async host => {
    const cwd = mkdtempSync(join(tmpdir(), "mxc-ingress-"));
    const child = spawn(process.execPath, [helper], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    let connected = false;
    let attempted = false;
    let hostBind: Promise<string> | undefined;
    const messages: Record<string, unknown>[] = [];
    const result = new Promise<void>((resolve, reject) => {
      let buffer = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", chunk => {
        buffer += chunk;
        for (;;) {
          const end = buffer.indexOf("\n");
          if (end < 0) break;
          const message = JSON.parse(buffer.slice(0, end));
          buffer = buffer.slice(end + 1);
          messages.push(message);
          if (message.type === "ready") child.stdin.write(JSON.stringify({ type: "start", requestId: "ingress", generation: 1,
            plan: { backend: { id: "windows-mxc" }, cwd, filesystem: [{ path: cwd, access: "read", granularity: "directory" }],
              protectedPaths: [], network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot },
              operation: { kind: "shell", shell: join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
                command: `$l=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse('${host}'),0); $l.Start(); Write-Output ('port=' + $l.LocalEndpoint.Port); $a=$l.BeginAcceptTcpClient($null,$null); if ($a.AsyncWaitHandle.WaitOne(3000)) { $c=$l.EndAcceptTcpClient($a); 'accepted'; $c.Close() } else { 'no-client' }; $l.Stop()` } } }) + "\n");
          if (message.type === "output") {
            const match = /port=(\d+)/u.exec(String(message.data));
            if (match && !attempted) {
              attempted = true;
              const socket = createConnection({ host, port: Number(match[1]) });
              socket.once("connect", () => { connected = true; socket.destroy(); });
              socket.once("error", () => {});
              socket.setTimeout(2000, () => socket.destroy());
              hostBind = new Promise(resolve => {
                const probe = createServer();
                probe.once("error", error => resolve((error as NodeJS.ErrnoException).code ?? "error"));
                probe.listen(Number(match[1]), host, () => probe.close(() => resolve("available")));
              });
            }
          }
          if (message.type === "result" || message.type === "rejected" || message.type === "error") resolve();
        }
      });
      child.on("error", reject);
      child.on("exit", code => reject(new Error(`helper exited before result: ${code}`)));
    });
    child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "ingress", generation: 1 }) + "\n");
    try {
      await result;
      expect(attempted).toBe(true);
      expect(connected).toBe(false);
      expect(await hostBind).toBe("EADDRINUSE");
      expect(messages).toEqual(expect.arrayContaining([
        expect.objectContaining({ type: "output", data: expect.stringContaining("no-client") }),
        expect.objectContaining({ type: "result", exitCode: 0 }),
      ]));
    } finally { child.kill(); rmSync(cwd, { recursive: true, force: true }); }
  }, 20_000);

  it.each([{ host: "127.0.0.1", socket: "udp4" }, { host: "::1", socket: "udp6" }] as const)(
    "blocks host datagrams to a sandbox UDP listener on $host", async ({ host, socket }) => {
    const cwd = mkdtempSync(join(tmpdir(), "mxc-udp-ingress-"));
    const child = spawn(process.execPath, [helper], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    const sender = createSocket(socket);
    let attempted = false;
    let hostBind: Promise<string> | undefined;
    const messages: Record<string, unknown>[] = [];
    const result = new Promise<void>((resolve, reject) => {
      let buffer = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", chunk => {
        buffer += chunk;
        for (;;) {
          const end = buffer.indexOf("\n");
          if (end < 0) break;
          const message = JSON.parse(buffer.slice(0, end));
          buffer = buffer.slice(end + 1);
          messages.push(message);
          if (message.type === "ready") child.stdin.write(JSON.stringify({ type: "start", requestId: "udp-ingress", generation: 1,
            plan: { backend: { id: "windows-mxc" }, cwd, filesystem: [{ path: cwd, access: "read", granularity: "directory" }],
              protectedPaths: [], network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot },
              operation: { kind: "shell", shell: join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
                command: `$u=[Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new([Net.IPAddress]::Parse('${host}'),0)); Write-Output ('port=' + $u.Client.LocalEndPoint.Port); $a=$u.ReceiveAsync(); if ($a.Wait(3000)) { 'received' } else { 'no-datagram' }; $u.Close()` } } }) + "\n");
          if (message.type === "output") {
            const match = /port=(\d+)/u.exec(String(message.data));
            if (match && !attempted) {
              attempted = true;
              sender.send(Buffer.from("host-datagram"), Number(match[1]), host, error => { if (error) reject(error); });
              hostBind = new Promise(resolve => {
                const probe = createSocket(socket);
                probe.once("error", error => { probe.close(); resolve((error as NodeJS.ErrnoException).code ?? "error"); });
                probe.bind({ port: Number(match[1]), address: host, exclusive: true }, () => probe.close(() => resolve("available")));
              });
            }
          }
          if (message.type === "result" || message.type === "rejected" || message.type === "error") resolve();
        }
      });
      child.on("error", reject);
      child.on("exit", code => reject(new Error(`helper exited before result: ${code}`)));
    });
    child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "udp-ingress", generation: 1 }) + "\n");
    try {
      await result;
      expect(attempted).toBe(true);
      expect(await hostBind).toBe("EADDRINUSE");
      expect(messages).toEqual(expect.arrayContaining([
        expect.objectContaining({ type: "output", data: expect.stringContaining("no-datagram") }),
        expect.objectContaining({ type: "result", exitCode: 0 }),
      ]));
    } finally { child.kill(); sender.close(); rmSync(cwd, { recursive: true, force: true }); }
  }, 20_000);

  it("prevents WMI from creating a host process outside the sandbox", async () => {
    const root = mkdtempSync(join(tmpdir(), "mxc-wmi-"));
    const cwd = join(root, "workspace");
    mkdirSync(cwd);
    const marker = join(root, "marker.txt");
    const shell = join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
    const command = `$r=Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='cmd.exe /d /c echo probe > "${marker}"'} -ErrorAction Stop; Write-Output ('return=' + $r.ReturnValue)`;
    const control = spawnSync(shell, ["-NoProfile", "-NonInteractive", "-Command", command], { encoding: "utf8", timeout: 10_000 });
    expect(control.status, control.stderr).toBe(0);
    expect(control.stdout).toContain("return=0");
    for (let attempt = 0; attempt < 50 && !existsSync(marker); attempt++) await new Promise(resolve => setTimeout(resolve, 100));
    expect(existsSync(marker)).toBe(true);
    rmSync(marker);
    const child = spawn(process.execPath, [helper], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    const messages: Record<string, unknown>[] = [];
    const result = new Promise<Record<string, unknown>>((resolve, reject) => {
      let buffer = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", chunk => {
        buffer += chunk;
        for (;;) {
          const end = buffer.indexOf("\n");
          if (end < 0) break;
          const message = JSON.parse(buffer.slice(0, end));
          buffer = buffer.slice(end + 1);
          messages.push(message);
          if (message.type === "ready") child.stdin.write(JSON.stringify({ type: "start", requestId: "wmi", generation: 1,
            plan: { backend: { id: "windows-mxc" }, cwd, filesystem: [{ path: cwd, access: "read", granularity: "directory" }],
              protectedPaths: [], network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot },
              operation: { kind: "shell", shell, command } } }) + "\n");
          if (message.type === "result" || message.type === "rejected" || message.type === "error") resolve(message);
        }
      });
      child.on("error", reject);
      child.on("exit", code => reject(new Error(`helper exited before result: ${code}`)));
    });
    child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "wmi", generation: 1 }) + "\n");
    try {
      expect(await result).toMatchObject({ type: "result", started: true });
      expect(JSON.stringify(messages)).not.toContain("return=0");
      await new Promise(resolve => setTimeout(resolve, 2000));
      expect(existsSync(marker)).toBe(false);
    } finally { child.kill(); rmSync(root, { recursive: true, force: true }); }
  }, 25_000);

  it.each(["relative path", "parent traversal", "native failure"])("handles %s before a start notification", async scenario => {
    const cwd = mkdtempSync(join(tmpdir(), "mxc-native-failure-"));
    const child = spawn(process.execPath, [helper], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    const result = new Promise<Record<string, unknown>>((resolve, reject) => {
      let buffer = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", chunk => {
        buffer += chunk;
        for (;;) {
          const end = buffer.indexOf("\n");
          if (end < 0) break;
          const message = JSON.parse(buffer.slice(0, end));
          buffer = buffer.slice(end + 1);
          if (message.type === "ready") child.stdin.write(JSON.stringify({ type: "start", requestId: "failure", generation: 1,
            plan: { backend: { id: "windows-mxc" }, cwd, filesystem: [{ path: scenario === "relative path" ? "relative" : scenario === "parent traversal" ? `${cwd}\\..\\${basename(cwd)}` : cwd, access: "read", granularity: "directory" }],
              protectedPaths: [], network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot, ...(scenario === "native failure" ? { INVALID: 1 } : {}) },
              operation: { kind: "shell", shell: join(process.env.SystemRoot!, "System32", "cmd.exe"), command: "echo started" } } }) + "\n");
          if (message.type === "error" || message.type === "result" || message.type === "rejected") resolve(message);
        }
      });
      child.on("error", reject);
      child.on("exit", code => reject(new Error(`helper exited before result: ${code}`)));
    });
    child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "failure", generation: 1 }) + "\n");
    try { expect(await result).toMatchObject(scenario !== "native failure" ? { type: "rejected", code: "unsupported", started: false } : { type: "error", code: "setup" }); }
    finally { child.kill(); rmSync(cwd, { recursive: true, force: true }); }
  }, 15_000);

  it("reports an unknown start state when cancelled before the start notification", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "mxc-early-cancel-"));
    const child = spawn(process.execPath, [helper], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    const result = new Promise<Record<string, unknown>>((resolve, reject) => {
      let buffer = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", chunk => {
        buffer += chunk;
        for (;;) {
          const end = buffer.indexOf("\n");
          if (end < 0) break;
          const message = JSON.parse(buffer.slice(0, end));
          buffer = buffer.slice(end + 1);
          if (message.type === "ready") {
            const start = { type: "start", requestId: "early", generation: 1,
              plan: { backend: { id: "windows-mxc" }, cwd, filesystem: [{ path: cwd, access: "read", granularity: "directory" }],
                protectedPaths: [], network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot },
                operation: { kind: "shell", shell: join(process.env.SystemRoot!, "System32", "cmd.exe"), command: "echo started" } } };
            child.stdin.write(JSON.stringify(start) + "\n" + JSON.stringify({ type: "cancel", requestId: "early", generation: 1 }) + "\n");
          }
          if (message.type === "cancelled" || message.type === "result" || message.type === "rejected") resolve(message);
        }
      });
      child.on("error", reject);
      child.on("exit", code => reject(new Error(`helper exited before result: ${code}`)));
    });
    child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "early", generation: 1 }) + "\n");
    try { expect(await result).toMatchObject({ type: "cancelled", started: "unknown" }); }
    finally { child.kill(); rmSync(cwd, { recursive: true, force: true }); }
  }, 15_000);

  it.each([
    { method: "Process.Start", create: "[Diagnostics.Process]::Start($exe, '-NoProfile -Command Start-Sleep -Seconds 30')" },
    { method: "Start-Process", create: "Start-Process -FilePath $exe -ArgumentList '-NoProfile -Command Start-Sleep -Seconds 30' -WorkingDirectory $initial -PassThru" },
    { method: "Start-Process after Set-Location", create: "$(Set-Location -LiteralPath $initial; Start-Process -FilePath $exe -ArgumentList '-NoProfile -Command Start-Sleep -Seconds 30' -PassThru)" },
  ])("terminates a $method descendant when execution is cancelled", async ({ create }) => {
    const cwd = mkdtempSync(join(tmpdir(), "mxc-cancel-"));
    const child = spawn(process.execPath, [helper], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    let descendant = 0;
    let diagnostics = "";
    const result = new Promise<Record<string, unknown>>((resolve, reject) => {
      let buffer = "";
      const timeout = setTimeout(() => reject(new Error(`missing child PID: ${diagnostics}`)), 8_000);
      timeout.unref();
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", chunk => {
        buffer += chunk;
        for (;;) {
          const end = buffer.indexOf("\n");
          if (end < 0) break;
          const message = JSON.parse(buffer.slice(0, end));
          buffer = buffer.slice(end + 1);
          if (message.type === "ready") child.stdin.write(JSON.stringify({ type: "start", requestId: "cancel", generation: 1,
            plan: { backend: { id: "windows-mxc" }, cwd, filesystem: [{ path: cwd, access: "read", granularity: "directory" }],
              protectedPaths: [], network: { kind: "none" }, environment: { SystemRoot: process.env.SystemRoot,
                PATH: process.env.PATH, USERPROFILE: process.env.USERPROFILE, TEMP: process.env.TEMP, TMP: process.env.TMP, ComSpec: process.env.ComSpec },
              operation: { kind: "shell", shell: join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
                command: `$initial='${cwd.replaceAll("'", "''")}'; $exe=$env:SystemRoot + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'; $p=${create}; Write-Output ('childpid=' + $p.Id); Start-Sleep -Seconds 30` } } }) + "\n");
          if (message.type === "output") {
            if (message.stream === "stderr") diagnostics += String(message.data);
            const match = /childpid=(\d+)/u.exec(String(message.data));
            if (match && !descendant) { descendant = Number(match[1]); child.stdin.write(JSON.stringify({ type: "cancel", requestId: "cancel", generation: 1 }) + "\n"); }
          }
          if (message.type === "cancelled" || message.type === "result" || message.type === "rejected") { clearTimeout(timeout); resolve(message); }
        }
      });
      child.on("error", reject);
      child.on("exit", code => reject(new Error(`helper exited before result: ${code}`)));
    });
    child.stdin.write(JSON.stringify({ type: "hello", protocolVersion: 2, requestId: "cancel", generation: 1 }) + "\n");
    try {
      const message = await result;
      expect(message, JSON.stringify(message)).toMatchObject({ type: "cancelled", started: true });
      expect(descendant).toBeGreaterThan(0);
      let alive = true;
      for (let attempt = 0; attempt < 40 && alive; attempt++) {
        try { process.kill(descendant, 0); await new Promise(resolve => setTimeout(resolve, 100)); }
        catch { alive = false; }
      }
      expect(alive).toBe(false);
    } finally { child.kill(); rmSync(cwd, { recursive: true, force: true }); }
  }, 20_000);
});
