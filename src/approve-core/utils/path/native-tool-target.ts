/**
 * Native tool targets.
 *
 * The built-in file tools resolve the path they actually open, not merely
 * the spelling the user typed. The seven processing steps are ordered; only
 * steps that change the opened target count as rewriting.
 */
import type { PathFlavor } from "./path-flavor";
import { expandHome } from "./expand-home";

export interface NativeToolTargetOptions {
  readonly cwd: string;
  readonly flavor: PathFlavor;
  /** Only `read` gets non-existent-target fallback variants. */
  readonly readFallbacks: boolean;
  readonly exists: (path: string) => boolean;
  readonly home?: string;
}

export interface NativeToolTarget {
  /** Absolute path the tool actually opens. */
  readonly target: string;
  /** True when a processing step changed the opened target. */
  readonly rewritten: boolean;
  /** Relative spelling kept for relative-rule compatibility, when any. */
  readonly relativeSpelling?: string;
}

// Unicode whitespace that terminals commonly substitute into typed paths.
const UNICODE_WHITESPACE = /[\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000\uFEFF]/g;

const READ_FALLBACK_VARIANTS: readonly ((path: string) => string)[] = [
  // macOS AM/PM narrow no-break space.
  (path) => path.replace(/\u202F/g, "\u00A0"),
  // NFD.
  (path) => path.normalize("NFD"),
  // Curly apostrophe.
  (path) => path.replace(/'/g, "\u2019"),
  // NFD + curly apostrophe.
  (path) => path.normalize("NFD").replace(/'/g, "\u2019"),
];

/** Convert the native-tool drive-mount shapes (`/c/x`, `/mnt/c/x`, `/cygdrive/c/x`). */
export function convertNativeDriveMount(input: string): string | undefined {
  let match = /^\/([A-Za-z])\//.exec(input);
  if (match) {
    return `${match[1].toUpperCase()}:${input.slice(2).replace(/\//g, "\\")}`;
  }
  match = /^\/(?:mnt|cygdrive)\/([A-Za-z])(?:\/|$)/.exec(input);
  if (match) {
    const rest = input.slice(match[0].length).replace(/\//g, "\\");
    return `${match[1].toUpperCase()}:\\${rest}`;
  }
  return undefined;
}

/**
 * Resolve the absolute target for a built-in file tool input.
 */
export function resolveNativeToolTarget(
  input: string,
  options: NativeToolTargetOptions,
): NativeToolTarget {
  const { flavor, cwd } = options;
  let current = input;
  let rewritten = false;

  const spaced = current.replace(UNICODE_WHITESPACE, " ");
  if (spaced !== current) {
    current = spaced;
    rewritten = true;
  }

  if (current.startsWith("@")) current = current.slice(1);

  if (flavor.kind === "win32") {
    const converted = convertNativeDriveMount(current);
    if (converted !== undefined) {
      current = converted;
      rewritten = true;
    }
  }

  if (current === "~" || current.startsWith("~/") || current.startsWith("~\\")) {
    current = expandHome(current, options.home ?? defaultHome());
  }

  if (current.startsWith("file://")) {
    const decoded = flavor.decodeFileUrl(current);
    if (decoded.ok && decoded.path !== undefined) {
      if (decoded.path !== current) rewritten = true;
      current = decoded.path;
    }
  }

  let relativeSpelling: string | undefined;
  if (!flavor.isAbsolute(current)) {
    relativeSpelling = current;
    current = flavor.resolve(cwd, current);
  } else {
    current = flavor.normalize(current);
  }

  if (options.readFallbacks && !options.exists(current)) {
    for (const variant of READ_FALLBACK_VARIANTS) {
      const candidate = variant(current);
      if (candidate !== current && options.exists(candidate)) {
        current = candidate;
        rewritten = true;
        break;
      }
    }
  }

  return relativeSpelling === undefined
    ? { target: current, rewritten }
    : { target: current, rewritten, relativeSpelling };
}

function defaultHome(): string {
  // Lazy require keeps the seam injectable in tests.
  return process.env.HOME ?? process.env.USERPROFILE ?? "";
}
