import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export function prepareWindowsRuntimeExecutable(executable: string): void {
  if (process.platform !== "win32") return;
  const systemRoot = process.env.SystemRoot;
  if (!systemRoot) throw new Error("sandbox-unavailable: Windows SystemRoot is missing");
  try {
    execFileSync(join(systemRoot, "System32/WindowsPowerShell/v1.0/powershell.exe"), [
      "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
      fileURLToPath(new URL("./windows-runtime-integrity.ps1", import.meta.url)), "-Executable", executable,
    ], { windowsHide: true, timeout: 30_000, stdio: ["ignore", "pipe", "pipe"] });
  } catch (cause) {
    throw new Error("sandbox-unavailable: cannot prepare Windows runtime integrity; run Pi from a normal host process and retry", { cause });
  }
}
