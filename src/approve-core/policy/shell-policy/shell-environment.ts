import { delimiter, join } from "node:path";
import { getAgentDir } from "@earendil-works/pi-coding-agent";

export function getShellExecutionEnvironment(): NodeJS.ProcessEnv {
  // Pi prepends this directory to PATH for both Bash and PowerShell launches.
  const binDir = join(getAgentDir(), "bin");
  const pathKey = Object.keys(process.env).find((key) => key.toLowerCase() === "path") ?? "PATH";
  const currentPath = process.env[pathKey] ?? "";
  const pathEntries = currentPath.split(delimiter).filter(Boolean);
  const updatedPath = pathEntries.includes(binDir)
    ? currentPath
    : [binDir, currentPath].filter(Boolean).join(delimiter);
  return { ...process.env, [pathKey]: updatedPath };
}
