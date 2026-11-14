export interface PathTokenClassification {
  readonly bare: boolean;
  readonly path: boolean;
  readonly external: boolean;
}

export function classifyPathToken(token: string, flavor: "posix" | "win32"): PathTokenClassification {
  const slash = token.indexOf("/");
  const equals = token.indexOf("=");
  const rejected = !token || token.startsWith("-") ||
    (equals >= 0 && (slash < 0 || equals < slash)) ||
    (/^[a-zA-Z][a-zA-Z\d+.-]*:/.test(token) && !/^[a-zA-Z]:/.test(token)) ||
    (token.startsWith("@") && !token.startsWith("@/"));
  if (rejected) return { bare: false, path: false, external: false };

  const segments = token.split(flavor === "win32" ? /[\\/]/ : /\//);
  const traversal = segments.includes("..");
  const driveAbsolute = /^[a-zA-Z]:[\\/]/.test(token);
  const external = token.startsWith("/") || token.startsWith("~/") || traversal || driveAbsolute;
  const path = external || token.startsWith(".") || token.includes("/") ||
    (flavor === "win32" && token.includes("\\")) || /^[a-zA-Z]:/.test(token);
  return { bare: true, path, external };
}
