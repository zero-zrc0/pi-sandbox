import { copyFileSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { expect, it } from "vitest";
import { prepareWindowsRuntimeExecutable } from "#sandbox/runtime-windows-integrity";

const native = fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url));

it.skipIf(process.platform !== "win32" || !existsSync(native))(
  "prepares an inherited Low executable without changing its directory or bytes", () => {
    const directory = mkdtempSync(join(tmpdir(), "runtime-integrity-"));
    const executable = join(directory, "runtime.exe");
    try {
      const label = spawnSync("icacls.exe", [directory, "/setintegritylevel", "(OI)(CI)L"], { encoding: "utf8" });
      expect(label.status, label.stderr).toBe(0);
      copyFileSync(native, executable);
      const original = readFileSync(executable);
      const before = spawnSync(executable, ["probe"], { encoding: "utf8", timeout: 10_000 });
      expect(JSON.parse(before.stdout).available).toBe(false);
      prepareWindowsRuntimeExecutable(executable);
      const after = spawnSync(executable, ["probe"], { encoding: "utf8", timeout: 10_000 });
      expect(after.status, after.stderr).toBe(0);
      expect(JSON.parse(after.stdout).available).toBe(true);
      expect(readFileSync(executable)).toEqual(original);
      const inode = statSync(executable).ino;
      prepareWindowsRuntimeExecutable(executable);
      expect(statSync(executable).ino).toBe(inode);
      const directoryLabel = spawnSync("icacls.exe", [directory], { encoding: "utf8" });
      expect(directoryLabel.stdout).toContain("(OI)(CI)(NW)");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }, 30_000,
);
