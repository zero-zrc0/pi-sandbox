import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const executable = fileURLToPath(new URL("../../../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url));

function probeScript(): string {
  return [
    "(async () => {",
    'const fs = require("node:fs");',
    'const { spawnSync } = require("node:child_process");',
    'const read = (path) => { try { return { allowed: true, value: fs.readFileSync(path, "utf8") }; } catch (error) { return { allowed: false, error: error.code || error.message }; } };',
    'const child = spawnSync(process.execPath, ["-e", "process.stdout.write(\\\"spawn-child-ok\\\")"], { encoding: "utf8", timeout: 2000 });',
    'const network = await fetch("http://127.0.0.1:" + process.env.PROBE_PORT, { signal: AbortSignal.timeout(1500) }).then((response) => ({ allowed: true, status: response.status })).catch((error) => ({ allowed: false, error: error.cause?.code || error.name }));',
    'process.stdout.write(JSON.stringify({ cFile: read(process.env.PROTECTED_C_FILE), eFile: read(process.env.PROTECTED_E_FILE), credentialFile: read(process.env.PROTECTED_CREDENTIAL_FILE), secretPresent: process.env.PI_RUNTIME_TEST_SECRET !== undefined, spawn: { status: child.status, error: child.error?.code || null, stdout: child.stdout || "" }, network }));',
    '})().catch((error) => { console.error(error); process.exitCode = 1; });',
  ].join("\n");
}

function runHostProbe(node: string, script: string, env: NodeJS.ProcessEnv) {
  return spawnSync(node, ["-e", script], { cwd: process.cwd(), env, encoding: "utf8", timeout: 10_000, windowsHide: true });
}

describe.skipIf(process.platform !== "win32" || !existsSync(executable))("Windows Codemode Runtime process boundary", () => {
  it("denies nearby files, loopback, and child processes at the restricted process layer", async () => {
    const root = mkdtempSync(join(tmpdir(), "pi-codemode-runtime-"));
    const cwd = join(root, "runtime");
    const protectedC = join(root, "sibling-secret.txt");
    const credentialDirectory = join(root, "credential-store");
    const credentialFile = join(credentialDirectory, "auth.json");
    const cache = join(process.cwd(), ".cache", "codemode", "native");
    mkdirSync(cwd);
    mkdirSync(credentialDirectory);
    mkdirSync(cache, { recursive: true });
    const protectedEdir = mkdtempSync(join(cache, "probe-"));
    const protectedE = join(protectedEdir, "workspace-secret.txt");
    writeFileSync(protectedC, "c-drive-secret");
    writeFileSync(protectedE, "e-drive-secret");
    writeFileSync(credentialFile, "credential-store-secret");

    const server = createServer((_request, response) => response.end("host-network-reachable"));
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : 0;
    const node = realpathSync.native(process.execPath);
    const env = {
      ...process.env,
      PROBE_PORT: String(port),
      PROTECTED_C_FILE: protectedC,
      PROTECTED_E_FILE: protectedE,
      PROTECTED_CREDENTIAL_FILE: credentialFile,
      PI_RUNTIME_TEST_SECRET: "host-credential-marker",
    };
    const script = probeScript();

    try {
      const host = runHostProbe(node, script, env);
      expect(host.status, host.stderr).toBe(0);
      expect(JSON.parse(host.stdout)).toMatchObject({
        cFile: { allowed: true, value: "c-drive-secret" },
        eFile: { allowed: true, value: "e-drive-secret" },
        credentialFile: { allowed: true, value: "credential-store-secret" },
        secretPresent: true,
        spawn: { status: 0, stdout: "spawn-child-ok" },
      });
      await expect(fetch(`http://127.0.0.1:${port}`).then((response) => response.text())).resolves.toBe("host-network-reachable");

      const request = {
        runtimeProfile: "codemode",
        plan: {
          backend: { id: "windows-mxc" },
          cwd,
          filesystem: [
            { path: node, access: "read", granularity: "file" },
            { path: executable, access: "read", granularity: "file" },
            { path: cwd, access: "read", granularity: "directory" },
          ],
          protectedPaths: [],
          network: { kind: "none" },
          environment: {
            PROBE_PORT: String(port),
            PROTECTED_C_FILE: protectedC,
            PROTECTED_E_FILE: protectedE,
            PROTECTED_CREDENTIAL_FILE: credentialFile,
          },
        },
        argv: [node, "-e", script],
      };
      const restricted = spawnSync(executable, ["stdio"], {
        cwd,
        env: {
          SystemRoot: process.env.SystemRoot!,
          SystemDrive: process.env.SystemDrive!,
          LOCALAPPDATA: process.env.LOCALAPPDATA!,
          PI_MXC_REQUEST: JSON.stringify(request),
        },
        encoding: "utf8",
        timeout: 15_000,
        windowsHide: true,
      });
      expect(restricted.status, JSON.stringify({ stderr: restricted.stderr, stdout: restricted.stdout, error: restricted.error?.message })).toBe(0);
      expect(JSON.parse(restricted.stdout)).toMatchObject({
        cFile: { allowed: false },
        eFile: { allowed: false },
        credentialFile: { allowed: false },
        secretPresent: false,
        spawn: { status: null, error: expect.any(String) },
        network: { allowed: false },
      });
    } finally {
      server.close();
      rmSync(root, { recursive: true, force: true });
      rmSync(protectedEdir, { recursive: true, force: true });
    }
  }, 25_000);

  it("propagates a Runtime child crash through MXC stdio", () => {
    const root = mkdtempSync(join(tmpdir(), "pi-codemode-runtime-crash-"));
    const cwd = join(root, "runtime");
    mkdirSync(cwd);
    const node = realpathSync.native(process.execPath);
    const request = {
      runtimeProfile: "codemode",
      plan: {
        backend: { id: "windows-mxc" },
        cwd,
        filesystem: [
          { path: node, access: "read", granularity: "file" },
          { path: executable, access: "read", granularity: "file" },
          { path: cwd, access: "read", granularity: "directory" },
        ],
        protectedPaths: [],
        network: { kind: "none" },
        environment: {},
      },
      argv: [node, "-e", 'process.stderr.write("codemode-runtime-crash"); process.exit(77);'],
    };

    try {
      const result = spawnSync(executable, ["stdio"], {
        cwd,
        env: {
          SystemRoot: process.env.SystemRoot!,
          SystemDrive: process.env.SystemDrive!,
          LOCALAPPDATA: process.env.LOCALAPPDATA!,
          PI_MXC_REQUEST: JSON.stringify(request),
        },
        encoding: "utf8",
        timeout: 15_000,
        windowsHide: true,
      });

      expect(result.error).toBeUndefined();
      expect(result.status).toBe(77);
      expect(result.stderr).toContain("codemode-runtime-crash");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 20_000);

  it("reclaims the Runtime process when the MXC parent exits", async () => {
    const root = mkdtempSync(join(tmpdir(), "pi-codemode-runtime-stop-"));
    const cwd = join(root, "runtime");
    mkdirSync(cwd);
    const node = realpathSync.native(process.execPath);
    const request = {
      runtimeProfile: "codemode",
      plan: {
        backend: { id: "windows-mxc" },
        cwd,
        filesystem: [
          { path: node, access: "read", granularity: "file" },
          { path: executable, access: "read", granularity: "file" },
          { path: cwd, access: "read", granularity: "directory" },
        ],
        protectedPaths: [],
        network: { kind: "none" },
        environment: {},
      },
      argv: [node, "-e", 'setTimeout(() => {}, 30000); console.log(JSON.stringify({ pid: process.pid }));'],
    };
    const child = spawn(executable, ["stdio"], {
      cwd,
      env: {
        SystemRoot: process.env.SystemRoot!,
        SystemDrive: process.env.SystemDrive!,
        LOCALAPPDATA: process.env.LOCALAPPDATA!,
        PI_MXC_REQUEST: JSON.stringify(request),
      },
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    let output = "";
    let errorOutput = "";
    let runtimePid = 0;
    const waitForChildExit = (timeoutMs: number) => new Promise<boolean>((resolve) => {
      if (child.exitCode !== null) {
        resolve(true);
        return;
      }
      const timer = setTimeout(() => {
        child.off("exit", onExit);
        resolve(false);
      }, timeoutMs);
      const onExit = () => {
        clearTimeout(timer);
        resolve(true);
      };
      child.once("exit", onExit);
    });
    const started = new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`Runtime did not start: ${output} ${errorOutput}`)), 10_000);
      child.stdout.setEncoding("utf8");
      child.stderr.setEncoding("utf8");
      child.stdout.on("data", (chunk) => {
        output += chunk;
        const match = /\{"pid":(\d+)\}/u.exec(output);
        if (match) {
          runtimePid = Number(match[1]);
          clearTimeout(timer);
          resolve();
        }
      });
      child.stderr.on("data", (chunk) => { errorOutput += chunk; });
      child.once("error", (error) => { clearTimeout(timer); reject(error); });
      child.once("exit", (code) => {
        if (!runtimePid) {
          clearTimeout(timer);
          reject(new Error(`MXC exited before Runtime start (${code}): ${output} ${errorOutput}`));
        }
      });
    });

    try {
      await started;
      expect(() => process.kill(runtimePid, 0)).not.toThrow();
      child.kill();
      expect(await waitForChildExit(5_000), errorOutput).toBe(true);
      const deadline = Date.now() + 5_000;
      while (Date.now() < deadline) {
        try {
          process.kill(runtimePid, 0);
          await new Promise((resolve) => setTimeout(resolve, 50));
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code === "ESRCH") return;
          throw error;
        }
      }
      throw new Error(`Runtime process ${runtimePid} remained after MXC exit`);
    } finally {
      if (child.exitCode === null) {
        child.kill();
        await waitForChildExit(3_000);
      }
      rmSync(root, { recursive: true, force: true });
    }
  }, 25_000);
});
