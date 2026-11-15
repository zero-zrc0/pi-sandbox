import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { createServer as createHttpServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { ExecutionController, type EgressProvider } from "#sandbox/lifecycle";
import { EgressService } from "#sandbox/egress/index";
import type { EgressNetworkEvent } from "#sandbox/egress/types";
import type { TrustedHelperInstallation } from "#sandbox/helper";
import { PROTECTED_CONTROL_DIRECTORY_NAMES } from "#sandbox/path";
import {
  compileTestPlan,
  makeInvocation,
} from "../../fixtures/harness";
import { installLinuxTestRuntime } from "../../fixtures/runtime";

const backendId = "linux-bwrap-landlock-seccomp";
const backendVersion = "1.1.0";
const backendSource = fileURLToPath(
  new URL("../../../../src/sandbox/backend/linux/", import.meta.url),
);

describe.skipIf(process.platform !== "linux")("native Linux execution backend", () => {
  let root: string | undefined;
  let installRoot: string;
  let helperCwd: string;
  let workspace: string;
  let sessionWorkspace: string;
  let outside: string;
  let nativeBinary: string;
  let processSpawnProbe: string;
  let controller: ExecutionController | undefined;

  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), "plan13-linux-native-"));
    installRoot = join(root, "trusted-install");
    helperCwd = join(root, "helper-cwd");
    workspace = join(root, "workspace");
    sessionWorkspace = join(root, "agent", "workspaces", "pi-sandbox", "session-hash");
    outside = join(root, "outside.txt");
    mkdirSync(installRoot, { recursive: true });
    mkdirSync(helperCwd, { recursive: true });
    mkdirSync(workspace, { recursive: true });
    mkdirSync(join(sessionWorkspace, "tmp"), { recursive: true });
    for (const name of PROTECTED_CONTROL_DIRECTORY_NAMES) {
      mkdirSync(join(workspace, name), { recursive: true });
    }
    nativeBinary = join(installRoot, "linux-sandbox");
    execFileSync("bash", [join(backendSource, "build.sh"), nativeBinary]);
    processSpawnProbe = join(installRoot, "process-spawn-probe");
    execFileSync("cc", ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread",
      fileURLToPath(new URL("./process-spawn-probe.c", import.meta.url)), "-o", processSpawnProbe]);
    copyFileSync(join(backendSource, "helper.mjs"), join(installRoot, "helper.mjs"));
    installLinuxTestRuntime(installRoot);
    const installation: TrustedHelperInstallation = {
      installRoot,
      executable: process.execPath,
      args: [join(installRoot, "helper.mjs")],
      expectedBackendId: backendId,
      expectedBackendVersion: backendVersion,
    };
    controller = new ExecutionController({
      installation,
      helperCwd,
      workspace,
      helperEnvironment: {
        HOME: "/nonexistent",
        LANG: "C.UTF-8",
        PATH: "/usr/bin:/bin",
        PI_SANDBOX_RUNTIME_DIR: installRoot,
        PI_SANDBOX_WORKSPACE_ROOT: workspace,
      },
      startTimeoutMs: 5_000,
      cancelGraceMs: 250,
    });
  });

  afterAll(async () => {
    await controller?.dispose();
    if (root) rmSync(root, { recursive: true, force: true });
  });

  function getController(): ExecutionController {
    if (!controller) throw new Error("Linux helper was not installed");
    return controller;
  }

  function runProcessProbe(spawn: "allow" | "deny" | undefined, mode: string, marker: string): string {
    const args = ["run", "--ready", "none"];
    if (spawn) args.push("--process-spawn", spawn);
    args.push("--network", "all", "--cwd", workspace, "--write-dir", workspace,
      "--execute-file", processSpawnProbe, "--", processSpawnProbe, mode, marker);
    return execFileSync(nativeBinary, args, { encoding: "utf8" });
  }

  function shellPlan(command: string, network: "none" | "all" = "none") {
    const invocation = makeInvocation({
      cwd: workspace,
      toolName: "bash",
      args: { command },
    });
    return compileTestPlan({
      invocation,
      operation: { kind: "shell", command, shell: "/bin/sh" },
      workspace,
      backendId,
      shell: "/bin/sh",
      network: { kind: network },
    });
  }

  it("probes the installed helper and reports only its negotiated Linux capabilities", async () => {
    const probe = await getController().probe();

    expect(probe).toMatchObject({
      status: "available",
      backend: { id: backendId, version: backendVersion },
      capabilities: {
        filesystem: {
          read: true,
          write: true,
          granularity: "file",
          protectedPaths: true,
          environment: true,
        },
        // The bridge is built next to the launcher in this suite, so the
        // backend must advertise destination enforcement, not a coarse
        // unrestricted network claim.
        network: "domains",
        cancel: true,
        streamOutput: true,
        startedNotification: true,
        processTree: true,
      },
    });
  });

  it("executes a non-system Node runtime only with an explicit executable grant", () => {
    const runtime = join(installRoot, "node-runtime");
    copyFileSync(process.execPath, runtime);
    const flags = ["run", "--ready", "none", "--network", "none", "--cwd", workspace, "--read-dir", workspace, "--read-file", runtime];
    const command = ["--", runtime, "-e", "const child = require('node:child_process').spawnSync('/usr/bin/true', [], { stdio: 'pipe' }); if (child.error) throw child.error; process.stdout.write('restricted-node')"];
    const binary = join(installRoot, "linux-sandbox");
    expect(() => execFileSync(binary, [...flags, ...command], { stdio: "pipe" })).toThrow();
    expect(execFileSync(binary, [...flags, "--execute-file", runtime, ...command], { encoding: "utf8" })).toBe("restricted-node");
  });

  it("denies process-creating syscalls while allowing thread creation", () => {
    for (const mode of ["fork", "vfork", "clone-process", "clone-vm-process", "clone-vfork"]) {
      const marker = join(workspace, `${mode}.allow`);
      expect(runProcessProbe("allow", mode, marker)).toContain("spawned");
      expect(existsSync(marker)).toBe(true);
    }

    for (const mode of ["fork", "vfork", "clone-process", "clone-vm-process", "clone-vfork",
      "clone-namespace", "clone-thread-missing", "clone-thread-signal", "clone-high"]) {
      const marker = join(workspace, `${mode}.deny`);
      expect(runProcessProbe("deny", mode, marker)).toContain("error=1");
      expect(existsSync(marker)).toBe(false);
    }

    const clone3Marker = join(workspace, "clone3.deny");
    expect(runProcessProbe("deny", "clone3", clone3Marker)).toContain("error=38");
    expect(existsSync(clone3Marker)).toBe(false);

    const threadMarker = join(workspace, "thread.deny");
    expect(runProcessProbe("deny", "thread", threadMarker)).toContain("thread");
    expect(existsSync(threadMarker)).toBe(true);

    const defaultMarker = join(workspace, "fork.default");
    expect(runProcessProbe(undefined, "fork", defaultMarker)).toContain("spawned");
    expect(existsSync(defaultMarker)).toBe(true);
  });

  it("rejects an invalid process-spawn policy before starting the target", () => {
    const marker = join(workspace, "invalid-process-spawn");
    expect(() => execFileSync(nativeBinary, ["run", "--process-spawn", "maybe", "--network", "all",
      "--cwd", workspace, "--execute-file", processSpawnProbe, "--", processSpawnProbe, "fork", marker], {
      encoding: "utf8",
    })).toThrow(/invalid or unsupported launch plan/u);
    expect(existsSync(marker)).toBe(false);
  });

  it("allows Node and Python worker threads while denying their child process attempts", () => {
    const nodeExecutable = realpathSync(process.execPath);
    const nodeProgram = [
      "const { Worker } = require('node:worker_threads');",
      "const { pbkdf2 } = require('node:crypto');",
      "let workerDone = false, poolDone = false;",
      "function finish() { if (!workerDone || !poolDone) return; process.stdout.write('node-threads-ok\\n'); }",
      "const worker = new Worker(`const { parentPort } = require('node:worker_threads'); const { spawnSync } = require('node:child_process'); const r = spawnSync('/usr/bin/true'); parentPort.postMessage(r.error?.code ?? 'spawned');`, { eval: true });",
      "worker.once('message', code => { if (code !== 'EPERM') process.exitCode = 1; workerDone = true; finish(); });",
      "worker.once('error', () => { process.exitCode = 1; workerDone = true; finish(); });",
      "pbkdf2('secret', 'salt', 1, 16, 'sha256', error => { if (error) process.exitCode = 1; poolDone = true; finish(); });",
    ].join("\n");
    const nodeOutput = execFileSync(nativeBinary, ["run", "--ready", "none", "--process-spawn", "deny",
      "--network", "all", "--cwd", workspace, "--write-dir", workspace,
      "--execute-file", nodeExecutable, "--", nodeExecutable, "-e", nodeProgram], { encoding: "utf8" });
    expect(nodeOutput).toContain("node-threads-ok");

    const pythonExecutable = realpathSync("/usr/bin/python3");
    const pythonProgram = [
      "import concurrent.futures, errno, subprocess",
      "def attempt():",
      "    try:",
      "        subprocess.run(['/usr/bin/true'], check=True)",
      "    except OSError as error:",
      "        return error.errno",
      "with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:",
      "    result = executor.submit(attempt).result()",
      "if result != errno.EPERM:",
      "    raise SystemExit(f'unexpected process result: {result}')",
      "print('python-threads-ok')",
    ].join("\n");
    const pythonOutput = execFileSync(nativeBinary, ["run", "--ready", "none", "--process-spawn", "deny",
      "--network", "all", "--cwd", workspace, "--execute-file", pythonExecutable,
      "--", pythonExecutable, "-c", pythonProgram], { encoding: "utf8" });
    expect(pythonOutput).toContain("python-threads-ok");
  });

  it("runs an approved workspace write while the OS blocks a sibling write", async () => {
    const inside = join(workspace, "inside.txt");
    const command = `printf allowed > '${inside}'; printf denied > '${outside}'`;
    const result = await getController().execute({ plan: shellPlan(command) });

    expect(result.state, JSON.stringify(result)).toBe("completed");
    expect(result.state === "completed" ? result.exitCode : undefined).not.toBe(0);
    expect(readFileSync(inside, "utf8")).toBe("allowed");
    expect(existsSync(outside)).toBe(false);
  });

  it("uses a session workspace grant while keeping host /tmp outside default access", async () => {
    const artifact = join(sessionWorkspace, "artifacts", "result.txt");
    const environmentFile = join(sessionWorkspace, "tmp", "environment.txt");
    const inaccessibleCopy = join(sessionWorkspace, "tmp", "host-temp-copy.txt");
    mkdirSync(join(sessionWorkspace, "artifacts"), { recursive: true });
    writeFileSync(outside, "host temp secret");
    const command = [
      `printf allowed > '${artifact}'`,
      `printf '%s\\n' "$PI_SANDBOX_WORK_DIR" "$TEMP" "$TMP" "$TMPDIR" > '${environmentFile}'`,
      `cat '${outside}' > '${inaccessibleCopy}'`,
    ].join("; ");
    const result = await getController().execute({
      plan: compileTestPlan({
        invocation: makeInvocation({ cwd: workspace, toolName: "bash", args: { command } }),
        operation: { kind: "shell", command, shell: "/bin/sh" },
        workspace,
        baselineFilesystem: [
          { path: sessionWorkspace, access: "read", granularity: "directory" },
          { path: sessionWorkspace, access: "write", granularity: "directory" },
        ],
        environment: {
          PI_SANDBOX_WORK_DIR: sessionWorkspace,
          TEMP: join(sessionWorkspace, "tmp"),
          TMP: join(sessionWorkspace, "tmp"),
          TMPDIR: join(sessionWorkspace, "tmp"),
          PATH: "/usr/bin:/bin",
        },
        backendId,
        shell: "/bin/sh",
      }),
    });

    expect(result.state, JSON.stringify(result)).toBe("completed");
    expect(result.state === "completed" ? result.exitCode : undefined).not.toBe(0);
    expect(readFileSync(artifact, "utf8")).toBe("allowed");
    expect(readFileSync(environmentFile, "utf8").trim().split(/[\r\n]+/)).toEqual([
      sessionWorkspace,
      join(sessionWorkspace, "tmp"),
      join(sessionWorkspace, "tmp"),
      join(sessionWorkspace, "tmp"),
    ]);
    expect(readFileSync(inaccessibleCopy, "utf8")).not.toContain("host temp secret");
    rmSync(outside, { force: true });
  });

  it("keeps project and session writes, including host /tmp, outside read-only access", async () => {
    const projectTarget = join(workspace, "readonly-project.txt");
    const sessionTarget = join(sessionWorkspace, "tmp", "readonly-session.txt");
    const hostTempTarget = join(tmpdir(), `pi-sandbox-readonly-host-temp-${process.pid}-${Date.now()}.txt`);
    const command = [
      `printf denied > '${projectTarget}'`,
      `printf denied > '${sessionTarget}'`,
      `printf denied > '${hostTempTarget}'`,
    ].join("; ");
    try {
      const result = await getController().execute({
        plan: compileTestPlan({
          invocation: makeInvocation({ cwd: workspace, toolName: "bash", args: { command } }),
          operation: { kind: "shell", command, shell: "/bin/sh" },
          workspace,
          mode: "read-only",
          baselineFilesystem: [
            { path: workspace, access: "read", granularity: "directory" },
            { path: sessionWorkspace, access: "read", granularity: "directory" },
          ],
          environment: {
            PI_SANDBOX_WORK_DIR: sessionWorkspace,
            TEMP: join(sessionWorkspace, "tmp"),
            TMP: join(sessionWorkspace, "tmp"),
            TMPDIR: join(sessionWorkspace, "tmp"),
            PATH: "/usr/bin:/bin",
          },
          backendId,
          shell: "/bin/sh",
        }),
      });

      expect(result.state, JSON.stringify(result)).toBe("completed");
      expect(existsSync(projectTarget)).toBe(false);
      expect(existsSync(sessionTarget)).toBe(false);
      expect(existsSync(hostTempTarget)).toBe(false);
    } finally {
      rmSync(projectTarget, { force: true });
      rmSync(sessionTarget, { force: true });
      rmSync(hostTempTarget, { force: true });
    }
  });

  it("reads approved file bytes through the native sandbox", async () => {
    const target = join(workspace, "read-bytes.bin");
    const content = Buffer.from([0x00, 0x80, 0xff, 0x41]);
    writeFileSync(target, content);
    const plan = compileTestPlan({
      invocation: makeInvocation({
        cwd: workspace,
        toolName: "read",
        args: { path: target },
      }),
      operation: { kind: "read-file", path: target },
      workspace,
      backendId,
    });

    const result = await getController().execute({ plan });

    expect(result.state, JSON.stringify(result)).toBe("completed");
    expect(result.state === "completed" ? result.dataBase64 : undefined).toBe(
      content.toString("base64"),
    );
  });

  it("writes an approved file through the native sandbox", async () => {
    const target = join(workspace, "written.txt");
    const content = "native write bytes";
    const plan = compileTestPlan({
      invocation: makeInvocation({
        cwd: workspace,
        toolName: "write",
        args: { path: target, content },
      }),
      operation: { kind: "write-file", path: target, content },
      workspace,
      backendId,
    });

    const result = await getController().execute({ plan });

    expect(result.state, JSON.stringify(result)).toBe("completed");
    expect(readFileSync(target, "utf8")).toBe(content);
  });

  it("keeps protected control directories read-only under a workspace write grant", async () => {
    const protectedFile = join(workspace, ".git", "config");
    const result = await getController().execute({
      plan: shellPlan(`printf denied > '${protectedFile}'`),
    });

    expect(result.state, JSON.stringify(result)).toBe("completed");
    expect(result.state === "completed" ? result.exitCode : undefined).not.toBe(0);
    expect(existsSync(protectedFile)).toBe(false);
  });

  it("fails closed before start when a protected control directory is missing", async () => {
    const missing = join(workspace, PROTECTED_CONTROL_DIRECTORY_NAMES[0]);
    const marker = join(workspace, "missing-protection-started.txt");
    rmSync(missing, { recursive: true, force: true });
    try {
      const result = await getController().execute({
        plan: shellPlan(`printf started > '${marker}'`),
      });

      expect(result.state).toBe("failed");
      expect(result.started).toBe(false);
      expect(result.state === "failed" ? result.code : undefined).toBe(
        "sandbox-path-missing",
      );
      expect(existsSync(marker)).toBe(false);
    } finally {
      mkdirSync(missing, { recursive: true });
    }
  });

  it("checks file access and creates then inspects an approved directory", async () => {
    const file = join(workspace, "access.txt");
    writeFileSync(file, "read-write");
    const accessResult = await getController().execute({
      plan: compileTestPlan({
        invocation: makeInvocation({
          cwd: workspace,
          toolName: "edit",
          args: { path: file },
        }),
        operation: { kind: "access-file", path: file, mode: "read-write" },
        workspace,
        backendId,
      }),
    });
    expect(accessResult.state, JSON.stringify(accessResult)).toBe("completed");

    const directory = join(workspace, "nested", "created");
    const target = join(directory, "output.txt");
    const mkdirResult = await getController().execute({
      plan: compileTestPlan({
        invocation: makeInvocation({
          cwd: workspace,
          toolName: "write",
          args: { path: target, content: "" },
        }),
        operation: { kind: "mkdir", path: directory },
        workspace,
        backendId,
      }),
    });
    expect(mkdirResult.state, JSON.stringify(mkdirResult)).toBe("completed");
    expect(existsSync(directory)).toBe(true);

    const accessDirResult = await getController().execute({
      plan: compileTestPlan({
        invocation: makeInvocation({
          cwd: workspace,
          toolName: "write",
          args: { path: target, content: "" },
        }),
        operation: { kind: "access-dir", path: directory, forFile: target },
        workspace,
        backendId,
      }),
    });
    expect(accessDirResult.state, JSON.stringify(accessDirResult)).toBe("completed");
  });

  it("blocks direct IP egress in the no-network namespace", async () => {
    const result = await getController().execute({
      plan: shellPlan(
        "/usr/bin/python3 -c 'import socket; s=socket.socket(); s.settimeout(1); s.connect((\"1.1.1.1\", 443))'",
      ),
    });

    expect(result.state, JSON.stringify(result)).toBe("completed");
    expect(result.state === "completed" ? result.exitCode : undefined).not.toBe(0);
    expect(result.stderr).toMatch(/Network is unreachable|Operation not permitted/u);
  });

  it.skipIf(process.arch !== "x64")(
    "rejects x32 ABI syscall numbers on x86_64, including the socket bypass",
    async () => {
      const result = await getController().execute({
        plan: shellPlan(
          "/usr/bin/python3 -c 'import ctypes; libc=ctypes.CDLL(None, use_errno=True); libc.syscall.restype=ctypes.c_long; libc.syscall.argtypes=[ctypes.c_long, ctypes.c_long, ctypes.c_long, ctypes.c_long]; ctypes.set_errno(0); pid=libc.syscall(0x40000027, 0, 0, 0); pidError=ctypes.get_errno(); ctypes.set_errno(0); sock=libc.syscall(0x40000029, 2, 1, 0); sockError=ctypes.get_errno(); print(pid, pidError, sock, sockError)'",
        ),
      });

      expect(result.state, JSON.stringify(result)).toBe("completed");
      expect(result.state === "completed" ? result.exitCode : undefined).toBe(0);
      expect(result.stdout.trim()).toBe("-1 1 -1 1");
    },
  );

  it("keeps the ordinary syscall deny list effective", async () => {
    const result = await getController().execute({
      plan: shellPlan(
        "/usr/bin/python3 -c 'import ctypes; libc=ctypes.CDLL(None, use_errno=True); libc.ptrace.restype=ctypes.c_int; libc.ptrace.argtypes=[ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]; ctypes.set_errno(0); print(libc.ptrace(0, 0, None, None), ctypes.get_errno())'",
      ),
    });

    expect(result.state, JSON.stringify(result)).toBe("completed");
    expect(result.state === "completed" ? result.exitCode : undefined).toBe(0);
    expect(result.stdout.trim()).toBe("-1 1");
  });

  it("blocks host pathname Unix sockets with no network and preserves them with network access", async () => {
    const socketPath = join(root!, "host.sock");
    const server = createServer((socket) => socket.end("host-visible\n"));
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(socketPath, resolve);
    });
    try {
      const result = await getController().execute({
        plan: shellPlan(
          `/usr/bin/python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.settimeout(1); s.connect("${socketPath}"); print(s.recv(64).decode())'`,
        ),
      });

      expect(result.state, JSON.stringify(result)).toBe("completed");
      expect(result.state === "completed" ? result.exitCode : undefined).not.toBe(0);
      expect(result.stderr).toMatch(/Permission denied|No such file|Operation not permitted|Connection refused/u);
      expect(result.stdout).not.toContain("host-visible");

      const pairResult = await getController().execute({
        plan: shellPlan(
          "/usr/bin/python3 -c 'import socket; a,b=socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM); a.sendall(b\"internal\"); print(b.recv(8).decode())'",
        ),
      });

      expect(pairResult.state, JSON.stringify(pairResult)).toBe("completed");
      expect(pairResult.state === "completed" ? pairResult.exitCode : undefined).toBe(0);
      expect(pairResult.stdout).toContain("internal");

      const reconnectResult = await getController().execute({
        plan: shellPlan(`/usr/bin/python3 -c 'import socket; a,b=socket.socketpair(); a.connect("${socketPath}")'`),
      });
      expect(reconnectResult.state === "completed" ? reconnectResult.exitCode : undefined).not.toBe(0);
      expect(reconnectResult.stderr).toMatch(/Operation not permitted/u);
      const datagramResult = await getController().execute({
        plan: shellPlan("/usr/bin/python3 -c 'import socket; socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)'"),
      });
      expect(datagramResult.state === "completed" ? datagramResult.exitCode : undefined).not.toBe(0);
      expect(datagramResult.stderr).toMatch(/Operation not permitted/u);

      const vsockResult = await getController().execute({
        plan: shellPlan(
          "/usr/bin/python3 -c 'import socket; socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)'",
        ),
      });

      expect(vsockResult.state, JSON.stringify(vsockResult)).toBe("completed");
      expect(vsockResult.state === "completed" ? vsockResult.exitCode : undefined).not.toBe(0);
      expect(vsockResult.stderr).toMatch(/Operation not permitted/u);

      const allowedResult = await getController().execute({
        plan: shellPlan(
          `/usr/bin/python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.settimeout(1); s.connect("${socketPath}"); print(s.recv(64).decode())'`,
          "all",
        ),
      });

      expect(allowedResult.state, JSON.stringify(allowedResult)).toBe("completed");
      expect(allowedResult.state === "completed" ? allowedResult.exitCode : undefined).toBe(0);
      expect(allowedResult.stdout).toContain("host-visible");
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
    }
  });

  it("rejects domain allowlists before running without an egress proxy", async () => {
    const marker = join(workspace, "domain-plan-started.txt");
    const command = `printf started > '${marker}'`;
    const plan = compileTestPlan({
      invocation: makeInvocation({
        cwd: workspace,
        toolName: "bash",
        args: { command },
        scopes: [{
          id: "network-allow",
          surface: "network",
          target: "example.com:443",
          access: "network",
          state: "allow",
          source: "user",
        }],
      }),
      operation: { kind: "shell", command },
      workspace,
      backendId,
      approved: { network: [{ host: "example.com", port: 443 }] },
    });
    const result = await getController().execute({ plan });

    expect(result.state).toBe("failed");
    expect(result.started).toBe(false);
    expect(result.state === "failed" ? result.code : undefined).toBe(
      "sandbox-capability-unsupported",
    );
    expect(existsSync(marker)).toBe(false);
  });

  it("does not inherit helper environment values or file descriptors", async () => {
    const command = "/usr/bin/env; /usr/bin/python3 -c 'import os; f=[]; exec(\"for fd in range(3,64):\\n try: os.fstat(fd); f.append(fd)\\n except OSError: pass\"); print(f)'";
    const result = await getController().execute({ plan: shellPlan(command) });

    expect(result.state, JSON.stringify(result)).toBe("completed");
    expect(result.state === "completed" ? result.exitCode : undefined).toBe(0);
    expect(result.stdout).toContain("PATH=/usr/bin:/bin");
    expect(result.stdout).not.toMatch(/(?:HOME|TOKEN|PI_|OPENAI|AWS_)=/u);
    expect(result.stdout.trim().split("\n").at(-1)).toBe("[]");
  });

  it("cancels the shell and its child process", async () => {
    const abort = new AbortController();
    let markOutput!: () => void;
    const output = new Promise<void>((resolve) => { markOutput = resolve; });
    const execution = getController().execute({
      plan: shellPlan("/usr/bin/sleep 23991 & wait"),
      signal: abort.signal,
      onOutput: markOutput,
    });
    await Promise.race([output, new Promise((resolve) => setTimeout(resolve, 1_000))]);
    abort.abort();
    const result = await execution;
    const processes = execFileSync("ps", ["-eo", "args"], { encoding: "utf8" });

    expect(result.state, JSON.stringify(result)).toBe("cancelled");
    expect(processes.split("\n").filter((line) => line.includes("/usr/bin/sleep 23991"))).toHaveLength(0);
  });
  describe("controlled network egress (native bridge + host policy proxy)", () => {
    let egress: EgressService | undefined;
    let events: EgressNetworkEvent[];
    let egressController: ExecutionController | undefined;
    let httpServer: ReturnType<typeof createHttpServer> | undefined;
    let httpPort = 0;
    let deniedListener: ReturnType<typeof createServer> | undefined;
    let deniedConnections = 0;

    function destinationPlan(command: string, port: number, requestId = `egress-${Math.random().toString(16).slice(2)}`) {
      const invocation = makeInvocation({
        cwd: workspace,
        toolName: "bash",
        args: { command },
        requestId,
        toolCallId: `call-${requestId}`,
        scopes: [
          {
            id: "scope-net",
            surface: "native",
            target: `127.0.0.1:${port}`,
            access: "network",
            state: "allow",
            source: "native-test",
          },
        ],
      });
      return compileTestPlan({
        invocation,
        operation: { kind: "shell", command },
        workspace,
        backendId,
        shell: "/bin/sh",
        network: { kind: "none" },
        approved: { filesystem: [], network: [{ host: "127.0.0.1", port }] },
      });
    }

    beforeAll(async () => {
      events = [];
      egress = new EgressService({ onEvent: (event) => events.push(event) });
      const provider: EgressProvider = {
        acquire: async (plan) => {
          const acquired = await egress!.acquireForPlan(plan);
          return acquired ? acquired.grant : null;
        },
        revoke: (leaseId) => {
          egress!.revoke(leaseId);
        },
      };
      egressController = new ExecutionController({
        installation: {
          installRoot,
          executable: process.execPath,
          args: [join(installRoot, "helper.mjs")],
          expectedBackendId: backendId,
          expectedBackendVersion: backendVersion,
        },
        helperCwd,
        workspace,
        helperEnvironment: { HOME: "/nonexistent", LANG: "C.UTF-8", PATH: "/usr/bin:/bin",
          PI_SANDBOX_RUNTIME_DIR: installRoot, PI_SANDBOX_WORKSPACE_ROOT: workspace },
        startTimeoutMs: 5_000,
        cancelGraceMs: 250,
        egress: provider,
      });

      httpServer = createHttpServer((request, response) => {
        if (request.url === "/hello") {
          response.writeHead(200, { "content-type": "text/plain" });
          response.end("native-egress-ok");
          return;
        }
        response.writeHead(404);
        response.end("missing");
      });
      await new Promise<void>((done) => httpServer!.listen(0, "127.0.0.1", done));
      const address = httpServer!.address();
      if (typeof address === "string" || address === null) throw new Error("no address");
      httpPort = address.port;

      deniedConnections = 0;
      deniedListener = createServer(() => {
        deniedConnections += 1;
      });
      await new Promise<void>((done) => deniedListener!.listen(0, "127.0.0.1", done));
    });

    afterAll(async () => {
      await egressController?.dispose();
      await egress?.dispose();
      await new Promise<void>((done) => httpServer?.close(() => done()));
      await new Promise<void>((done) => deniedListener?.close(() => done()));
    });

    it("NET-01: proxies an allowed destination through the bridge and the Pi policy proxy", async () => {
      const result = await egressController!.execute({
        plan: destinationPlan(`/usr/bin/curl -s http://127.0.0.1:${httpPort}/hello`, httpPort),
      });
      expect(result.state, JSON.stringify(result)).toBe("completed");
      expect(result.state === "completed" ? result.stdout : "").toContain("native-egress-ok");
      expect(events.some((event) => event.result === "connected" && event.targetPort === httpPort)).toBe(true);
    });

    it("NET-01 (SOCKS5): the same allowed destination works over socks5h", async () => {
      // ALL_PROXY inside the sandbox points at the entry port; forcing curl
      // through it exercises the SOCKS5 path the bridge forwards segment by
      // segment (greeting arrives after the auth frame).
      const result = await egressController!.execute({
        plan: destinationPlan(
          `/usr/bin/curl -s --proxy "$ALL_PROXY" http://127.0.0.1:${httpPort}/hello`,
          httpPort,
        ),
      });
      expect(result.state, JSON.stringify(result)).toBe("completed");
      expect(result.state === "completed" ? result.stdout : "").toContain("native-egress-ok");
      expect(
        events.some(
          (event) =>
            event.result === "connected" &&
            event.targetPort === httpPort &&
            event.leaseId !== undefined,
        ),
      ).toBe(true);
    });

    it("NET-02: refuses a target outside the scope before any external connection", async () => {
      const deniedAddress = deniedListener!.address();
      if (typeof deniedAddress === "string" || deniedAddress === null) throw new Error("no address");
      const result = await egressController!.execute({
        plan: destinationPlan(
          `/usr/bin/curl -s -m 5 -o /dev/null -w "%{http_code}" http://127.0.0.1:${deniedAddress.port}/`,
          httpPort,
        ),
      });
      expect(result.state, JSON.stringify(result)).toBe("completed");
      expect(result.state === "completed" ? result.stdout : "").toContain("403");
      await new Promise((done) => setTimeout(done, 200));
      expect(deniedConnections).toBe(0);
      expect(events.some((event) => event.result === "denied")).toBe(true);
    });

    it("NET-03: direct connections cannot bypass the proxy", async () => {
      const result = await egressController!.execute({
        plan: destinationPlan(
          `/usr/bin/curl -s -m 5 --noproxy '*' http://127.0.0.1:${httpPort}/hello`,
          httpPort,
        ),
      });
      expect(result.state).toBe("completed");
      expect(result.state === "completed" ? result.exitCode : 0).not.toBe(0);
      expect(result.state === "completed" ? result.stdout : "x").not.toContain("native-egress-ok");
    });

    it("NET-05: the tool environment carries no lease, credential or proxy secret", async () => {
      const result = await egressController!.execute({
        plan: destinationPlan("/usr/bin/env | /usr/bin/sort", httpPort),
      });
      expect(result.state, JSON.stringify(result)).toBe("completed");
      const stdout = result.state === "completed" ? result.stdout : "";
      expect(stdout).toMatch(/HTTP_PROXY=http:\/\/127\.0\.0\.1:\d+/u);
      expect(stdout).not.toMatch(/PI_EGRESS_/u);
      const leaseEvents = events.filter((event) => event.result === "connected");
      expect(leaseEvents.length).toBeGreaterThan(0);
      expect(stdout).not.toContain(leaseEvents[0].leaseId);
    });

  });
});
