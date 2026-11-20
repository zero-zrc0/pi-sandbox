import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, parse } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { prepareWindowsRuntimeExecutable } from "#sandbox/runtime-windows-integrity";
import { probeSandboxRuntime } from "#sandbox/runtime-probe";
import type { ResolvedRuntimeFiles } from "#sandbox/runtime-store";

const executable = fileURLToPath(new URL("../../../../src/sandbox/backend/windows/mxc/target/x86_64-pc-windows-msvc/debug/pi-sandbox-windows-mxc.exe", import.meta.url));
const oldExecutable = fileURLToPath(new URL("../../../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url));

describe.skipIf(process.platform !== "win32" || !existsSync(executable))("Windows unified filesystem rules", () => {
  it("keeps writable siblings while protecting existing files and directories", () => {
    const root = mkdtempSync(join(tmpdir(), "mxc-unified-"));
    try {
      const sandbox = join(root, "sandbox");
      const work = join(root, "work");
      mkdirSync(sandbox);
      mkdirSync(work);
      const binary = join(sandbox, "mxc.exe");
      copyFileSync(executable, binary);
      prepareWindowsRuntimeExecutable(binary);
      const readonly = join(work, "readonly");
      const secretDir = join(work, "secret-dir");
      const secretFile = join(work, "secret.txt");
      mkdirSync(readonly);
      mkdirSync(secretDir);
      writeFileSync(join(readonly, "data.txt"), "readable");
      writeFileSync(join(secretDir, "data.txt"), "directory-secret");
      writeFileSync(secretFile, "file-secret");
      const restriction = (path: string, granularity: "file" | "directory") => {
        const identity = statSync(path, { bigint: true });
        return { path: realpathSync.native(path), requestedPath: path, granularity, access: "deny-access",
          identity: { device: String(identity.dev), inode: String(identity.ino) } };
      };
      const shell = join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
      const request = {
        plan: { version: 3, filesystem: [
          { path: process.env.SystemRoot, access: "read", granularity: "directory" },
          { path: parse(work).root, access: "read", granularity: "directory" },
          { path: work, access: "read", granularity: "directory" },
          { path: work, access: "write", granularity: "directory" },
          { path: readonly, access: "deny-write", granularity: "directory" },
          restriction(secretDir, "directory"), restriction(secretFile, "file"),
        ], network: { kind: "none" }, metadataRead: "none", digest: "0".repeat(64) },
        operation: { kind: "shell" }, cwd: work,
        environment: { SystemRoot: process.env.SystemRoot, SystemDrive: process.env.SystemDrive, LOCALAPPDATA: process.env.LOCALAPPDATA },
        deadlineAt: Date.now() + 30_000,
        argv: [shell, "-NoProfile", "-NonInteractive", "-Command", [
          "$ErrorActionPreference='Stop'",
          "if ([IO.File]::ReadAllText('readonly/data.txt') -ne 'readable') { exit 10 }",
          "try { [IO.File]::WriteAllText('readonly/data.txt', 'changed'); exit 11 } catch {}",
          "[IO.File]::WriteAllText('sibling.txt', 'sibling')",
          "try { [void][IO.File]::ReadAllText('secret-dir/data.txt'); exit 12 } catch {}",
          "try { [void][IO.File]::ReadAllText('secret.txt'); exit 13 } catch {}",
          "try { [void](Get-Item -LiteralPath 'secret.txt' -ErrorAction Stop).Length; exit 14 } catch {}",
          "exit 0",
        ].join("; ")],
      };
      const result = spawnSync(binary, [], { cwd: work, input: JSON.stringify(request), encoding: "utf8", timeout: 30_000,
        env: process.env, windowsHide: true });
      expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
      expect(readFileSync(join(work, "sibling.txt"), "utf8")).toBe("sibling");
      expect(readFileSync(join(readonly, "data.txt"), "utf8")).toBe("readable");
      expect(readFileSync(secretFile, "utf8")).toBe("file-secret");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 60_000);

  it.skipIf(!existsSync(oldExecutable))("rejects an older native runtime during host probing", async ({ skip }) => {
    const oldProbe = spawnSync(oldExecutable, ["probe"], { encoding: "utf8", timeout: 6_000, windowsHide: true });
    if (oldProbe.status !== 0) skip();
    if (JSON.parse(oldProbe.stdout).planVersion === 3) skip();
    const root = mkdtempSync(join(dirname(tmpdir()), "mxc-old-version-"));
    try {
      const directory = join(root, "runtime");
      const workspace = join(root, "workspace");
      mkdirSync(directory);
      mkdirSync(workspace);
      const nativePath = join(directory, "pi-sandbox-windows-mxc.exe");
      const manifestPath = join(directory, "mxc-runtime.json");
      copyFileSync(oldExecutable, nativePath);
      prepareWindowsRuntimeExecutable(nativePath);
      copyFileSync(join(fileURLToPath(new URL("../../../../src/sandbox/backend/windows/mxc/", import.meta.url)), "mxc-runtime.json"), manifestPath);
      const hash = (path: string) => createHash("sha256").update(readFileSync(path)).digest("hex");
      const manifest = { schemaVersion: 1, version: "1.0.0", stable: true, platform: "win32", arch: process.arch,
        protocolVersion: 3, minPluginVersion: "1.0.0", maxPluginVersionExclusive: "2.0.0", backendId: "windows-mxc",
        files: [
          { role: "windowsExecutable", path: "pi-sandbox-windows-mxc.exe", executable: true, sha256: hash(nativePath) },
          { role: "mxcManifest", path: "mxc-runtime.json", executable: false, sha256: hash(manifestPath) },
        ] };
      writeFileSync(join(directory, "runtime.json"), JSON.stringify(manifest));
      const runtime = { directory, storageRoot: root, source: "manual", manifest,
        files: { windowsExecutable: nativePath, mxcManifest: manifestPath } } as ResolvedRuntimeFiles;
      const result = await probeSandboxRuntime({ runtime, workspaceRoot: workspace, signal: new AbortController().signal });
      expect(result).toMatchObject({ available: false, reason: expect.stringContaining("execution plan version 3") });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 30_000);
});
