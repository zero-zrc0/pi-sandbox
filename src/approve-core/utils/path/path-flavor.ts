/**
 * Platform path languages.
 *
 * The permission engine only understands two path languages, POSIX and
 * win32, selected by an explicit platform input. Business modules consume
 * this narrow surface instead of scattering `process.platform` branches.
 */
import posixPath from "node:path/posix";
import win32Path from "node:path/win32";

export type PathFlavorKind = "posix" | "win32";

export interface PathWildcardOptions {
  readonly caseInsensitive: boolean;
  /** Treat `/` and `\\` as the same separator when matching. */
  readonly separatorEquivalence: boolean;
}

export interface FileUrlDecodeResult {
  readonly ok: boolean;
  readonly path?: string;
}

export interface PathFlavor {
  readonly kind: PathFlavorKind;
  readonly separators: readonly [string, ...string[]];

  resolve(...parts: readonly string[]): string;
  normalize(path: string): string;
  relative(from: string, to: string): string;
  join(...parts: readonly string[]): string;
  isAbsolute(path: string): boolean;
  dirname(path: string): string;
  basename(path: string): string;

  /** Comparison folding: lowercase on win32, identity on POSIX. */
  fold(path: string): string;
  /** Lexically comparable value: resolve against `base`, normalize, fold. */
  lexicalValue(base: string, path: string): string;
  /**
   * Geometric containment on folded absolute operands: the directory itself
   * and true children are inside. `..` escapes, absolute relative results
   * (another win32 drive) and empty operands are never inside.
   */
  contains(dir: string, item: string): boolean;
  /** Index of the last separator recognized by this language, or -1. */
  lastSeparatorIndex(path: string): number;
  readonly wildcard: PathWildcardOptions;
  /** Decode a `file://` URL into this language's path spelling. */
  decodeFileUrl(url: string): FileUrlDecodeResult;
}

function makeFlavor(kind: PathFlavorKind, impl: typeof posixPath): PathFlavor {
  const separators: readonly [string, ...string[]] = kind === "win32" ? ["/", "\\"] : ["/"];
  const fold = (path: string): string => (kind === "win32" ? path.toLowerCase() : path);

  const contains = (dir: string, item: string): boolean => {
    if (dir.length === 0 || item.length === 0) return false;
    const from = fold(impl.normalize(dir));
    const to = fold(impl.normalize(item));
    const rel = impl.relative(from, to);
    if (rel.length === 0) return true;
    if (impl.isAbsolute(rel)) return false;
    const first = rel.split(/[\\/]/, 1)[0];
    return first !== ".." && first !== ".";
  };

  const lastSeparatorIndex = (path: string): number => {
    let last = -1;
    for (let i = 0; i < path.length; i += 1) {
      const ch = path[i];
      if (ch === "/" || (kind === "win32" && ch === "\\")) last = i;
    }
    return last;
  };

  const decodeFileUrl = (url: string): FileUrlDecodeResult => {
    if (!url.startsWith("file://")) return { ok: false };
    let rest = url.slice("file://".length);
    // An authority component is only acceptable for localhost.
    if (!rest.startsWith("/")) {
      const end = rest.indexOf("/");
      const host = end === -1 ? rest : rest.slice(0, end);
      if (host !== "localhost") return { ok: false };
      rest = end === -1 ? "/" : rest.slice(end);
    }
    let decoded: string;
    try {
      decoded = decodeURIComponent(rest);
    } catch {
      return { ok: false };
    }
    if (kind === "win32") {
      const drive = /^\/([A-Za-z]):([\/\\]?)/.exec(decoded);
      if (drive) {
        const tail = decoded.slice(drive[0].length).replace(/\//g, "\\");
        return { ok: true, path: `${drive[1].toUpperCase()}:\\${tail}`.replace(/\\$/, "") };
      }
      if (decoded.startsWith("\\\\")) return { ok: true, path: decoded };
      // A posix-style absolute spelling has no win32 meaning here.
      if (decoded.startsWith("/")) return { ok: false };
      return { ok: true, path: decoded };
    }
    if (!decoded.startsWith("/")) return { ok: false };
    return { ok: true, path: posixPath.normalize(decoded) };
  };

  return {
    kind,
    separators,
    resolve: (...parts) => impl.resolve(...parts),
    normalize: (path) => impl.normalize(path),
    relative: (from, to) => impl.relative(from, to),
    join: (...parts) => impl.join(...parts),
    isAbsolute: (path) => impl.isAbsolute(path),
    dirname: (path) => impl.dirname(path),
    basename: (path) => impl.basename(path),
    fold,
    lexicalValue: (base, path) => fold(impl.normalize(impl.resolve(base, path))),
    contains,
    lastSeparatorIndex,
    wildcard:
      kind === "win32"
        ? { caseInsensitive: true, separatorEquivalence: true }
        : { caseInsensitive: false, separatorEquivalence: false },
    decodeFileUrl,
  };
}

const POSIX_FLAVOR: PathFlavor = makeFlavor("posix", posixPath);
const WIN32_FLAVOR: PathFlavor = makeFlavor("win32", win32Path);

/** Select the path language for an explicit platform input. */
export function pathFlavorForPlatform(platform: string): PathFlavor {
  return platform === "win32" ? WIN32_FLAVOR : POSIX_FLAVOR;
}

export const POSIX_PATH_FLAVOR: PathFlavor = POSIX_FLAVOR;
export const WIN32_PATH_FLAVOR: PathFlavor = WIN32_FLAVOR;
