/**
 * Windows Bash (MSYS) token shapes.
 *
 * On win32 a Bash token is one of four shapes. Device recognition runs
 * before drive-mount recognition. On POSIX every token is plain.
 */

export type BashTokenShape = "device" | "drive-mount" | "posix-absolute" | "plain";

export const BASH_DEVICES = ["/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr"] as const;

export function classifyBashToken(token: string, flavorKind: "posix" | "win32"): BashTokenShape {
  if (flavorKind !== "win32") return "plain";
  if ((BASH_DEVICES as readonly string[]).includes(token)) return "device";
  if (isDriveMountToken(token)) return "drive-mount";
  if (token.startsWith("/")) return "posix-absolute";
  return "plain";
}

function isDriveMountToken(token: string): boolean {
  // `/c`, `/c/` or `/c/...` with a single-letter first segment.
  if (token.length < 2 || token[0] !== "/") return false;
  if (!/[A-Za-z]/.test(token[1])) return false;
  return token.length === 2 || token[2] === "/";
}

/**
 * Convert a drive-mount token (`/c/...`) to its uppercase-drive backslash
 * spelling. Device tokens and posix-absolute tokens keep their literal
 * spelling because their target depends on the MSYS install location.
 */
export function resolveMsysToken(token: string, flavorKind: "posix" | "win32"): string {
  const shape = classifyBashToken(token, flavorKind);
  if (shape !== "drive-mount") return token;
  const drive = token[1].toUpperCase();
  const tail = token.slice(2).replace(/\//g, "\\");
  return tail.length === 0 ? `${drive}:\\` : `${drive}:${tail}`;
}
