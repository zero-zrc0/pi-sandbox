/**
 * Session path normalizer.
 *
 * One normalizer fixes a cwd and a path language for a resolution pass. It
 * produces complete path value objects (display / match / boundary /
 * redirect note), interprets Bash `cd` targets, judges out-of-tree access
 * against the pre-canonicalized cwd, and probes the file system through
 * injectable seams.
 */
import type { PathFlavor } from "./path-flavor";
import { canonicalizePathSync, canonicalizePathSyncWithStatus } from "./canonicalize-path";
import { expandHome } from "./expand-home";
import { resolveNativeToolTarget } from "./native-tool-target";
import { isOutsideCanonicalCwd } from "./path-containment";
import { isInfrastructureRead } from "./pi-infrastructure-read";
import { sessionApprovalPatterns } from "./approval-pattern";
import { classifyBashToken, resolveMsysToken, type BashTokenShape } from "../access-intent/bash/msys-bash-tokens";
import { cleanPolicyLiteral } from "../access-intent/path-normalization";
import { existsSync, lstatSync, realpathSync, statSync } from "node:fs";

export interface ResolvedPathValue {
  /** Cleaned absolute lexical path for prompts, logs and session patterns. */
  readonly display: string;
  /** Deduped lexical / project-relative / raw-relative / canonical aliases. */
  readonly matchValues: readonly string[];
  /** Canonical value with symlinks resolved as far as possible; may be empty. */
  readonly boundary: string;
  readonly boundaryUnproven?: boolean;
  readonly boundaryFromAncestor?: boolean;
  readonly boundaryMissingPaths?: readonly string[];
  /** Supplementary note naming the actually opened target, when it differs. */
  readonly redirectNote?: string;
}

export interface PathNormalizerDeps {
  readonly home?: string;
  readonly realpathSync?: (path: string) => string;
  readonly existsSync?: (path: string) => boolean;
  readonly lstatSync?: (path: string) => unknown;
  readonly statSync?: (path: string) => unknown;
  /** Configured infrastructure read paths (home prefixes and globs allowed). */
  readonly infrastructureReadPaths?: readonly string[];
  /** Additional session-local directories treated as in-tree access. */
  readonly additionalLocalPaths?: readonly string[];
  /** Directories excluded from the infrastructure read exemption. */
  readonly infrastructureExclusions?: readonly string[];
}

export type CdInterpretation = "absolute" | "relative" | "unknown";

export interface CdTarget {
  readonly kind: CdInterpretation;
  readonly shape: BashTokenShape;
}

export class PathNormalizer {
  readonly flavor: PathFlavor;
  readonly cwd: string;
  readonly home: string;
  private readonly deps: PathNormalizerDeps;
  private canonicalCwdCache: string | undefined;
  private canonicalCwdResolved = false;

  constructor(flavor: PathFlavor, cwd: string, deps: PathNormalizerDeps = {}) {
    this.flavor = flavor;
    this.cwd = cwd;
    this.deps = deps;
    this.home = deps.home ?? process.env.HOME ?? process.env.USERPROFILE ?? "";
  }

  private realpath(path: string): string {
    return (this.deps.realpathSync ?? realpathSync)(path);
  }

  /** Canonical cwd, or undefined when the location cannot be proven. */
  canonicalCwd(): string | undefined {
    if (this.canonicalCwdResolved) return this.canonicalCwdCache;
    this.canonicalCwdResolved = true;
    try {
      // A hard realpath failure means the location is unprovable; callers
      // take the conservative branch instead of judging against a lexical cwd.
      this.canonicalCwdCache = this.realpath(this.cwd);
    } catch {
      this.canonicalCwdCache = undefined;
    }
    return this.canonicalCwdCache;
  }

  canonicalize(path: string): string {
    if (path.length === 0) return path;
    try {
      return canonicalizePathSync(path, { realpath: (p) => this.realpath(p) });
    } catch {
      return path;
    }
  }

  /** Clean a policy path literal: trim, unquote at most once per end, drop `@`, expand home. */
  cleanLiteral(literal: string): string {
    return cleanPolicyLiteral(literal, this.home);
  }

  /**
   * Resolve a normal policy path. With a known base directory the display
   * value is the normalized absolute lexical path; without one, relative
   * literals stay literal and gain no invented aliases.
   */
  normalPath(literal: string, baseDir?: string): ResolvedPathValue {
    const cleaned = this.cleanLiteral(literal);
    if (cleaned.length === 0) return { display: "", matchValues: [], boundary: "" };
    if (cleaned.includes("*")) return { display: cleaned, matchValues: [cleaned], boundary: "" };

    if (!this.flavor.isAbsolute(cleaned)) {
      if (baseDir === undefined || baseDir.length === 0) {
        return { display: cleaned, matchValues: [cleaned], boundary: "" };
      }
      const display = this.flavor.normalize(this.flavor.resolve(baseDir, cleaned));
      return this.withAliases(display, [cleaned]);
    }
    const display = this.flavor.normalize(cleaned);
    return this.withAliases(display, [cleaned]);
  }

  /** Resolve a literal-only path (unknown base directory). */
  literalPath(literal: string): ResolvedPathValue {
    return this.normalPath(literal, undefined);
  }

  /** Resolve a path for a native file tool using the tool's own target rules. */
  nativeToolPath(toolName: string, literal: string): ResolvedPathValue {
    const resolved = resolveNativeToolTarget(literal, {
      cwd: this.cwd,
      flavor: this.flavor,
      readFallbacks: toolName === "read",
      exists: (p) => this.exists(p),
      home: this.home,
    });
    const boundary = this.canonicalize(resolved.target);
    const matchValues: string[] = [resolved.target];
    if (resolved.relativeSpelling !== undefined && !matchValues.includes(resolved.relativeSpelling)) {
      matchValues.push(resolved.relativeSpelling);
    }
    const canonicalDiffers =
      boundary.length > 0 && this.flavor.fold(boundary) !== this.flavor.fold(resolved.target);
    const redirectNote = resolved.rewritten
      ? resolved.target
      : canonicalDiffers
        ? boundary
        : undefined;
    return { display: resolved.target, matchValues, boundary, ...(redirectNote !== undefined ? { redirectNote } : {}) };
  }

  /** Resolve a Bash token, honoring MSYS device / drive-mount shapes on win32. */
  bashTokenPath(token: string, baseDir?: string): ResolvedPathValue {
    const shape = classifyBashToken(token, this.flavor.kind);
    if (shape === "device") {
      // Safe devices keep their literal spelling in every representation.
      return { display: token, matchValues: [token], boundary: token };
    }
    if (shape === "posix-absolute") {
      // Target depends on the MSYS install location: keep the literal only.
      return { display: token, matchValues: [token], boundary: "" };
    }
    const resolved = resolveMsysToken(token, this.flavor.kind);
    return this.normalPath(resolved, baseDir);
  }

  private withAliases(display: string, rawLiterals: readonly string[]): ResolvedPathValue {
    const matchValues: string[] = [display];
    if (this.cwd.length > 0) {
      const rel = this.flavor.relative(this.flavor.normalize(this.cwd), display);
      if (rel.length > 0 && rel !== "." && !rel.startsWith("..")) {
        matchValues.push(rel);
      }
    }
    for (const raw of rawLiterals) {
      if (!matchValues.includes(raw)) matchValues.push(raw);
    }
    const canonical = canonicalizePathSyncWithStatus(display, { realpath: (path) => this.realpath(path) });
    const boundary = canonical.path;
    if (boundary.length > 0 && !matchValues.some((v) => this.flavor.fold(v) === this.flavor.fold(boundary))) {
      matchValues.push(boundary);
    }
    const canonicalDiffers = boundary.length > 0 && this.flavor.fold(boundary) !== this.flavor.fold(display);
    return {
      display,
      matchValues,
      boundary,
      ...(canonical.proven ? {} : { boundaryUnproven: true }),
      ...(canonical.fromAncestor ? { boundaryFromAncestor: true } : {}),
      ...(canonical.missingPaths ? { boundaryMissingPaths: canonical.missingPaths } : {}),
      ...(canonicalDiffers ? { redirectNote: boundary } : {}),
    };
  }

  /** Interpret a Bash `cd` target. */
  interpretCd(target: string): CdTarget {
    const shape = classifyBashToken(target, this.flavor.kind);
    if (shape === "device") return { kind: "unknown", shape };
    if (shape === "drive-mount") return { kind: "absolute", shape };
    if (shape === "posix-absolute") return { kind: "unknown", shape };
    return { kind: this.flavor.isAbsolute(target) ? "absolute" : "relative", shape: "plain" };
  }

  /** Join a relative `cd` offset onto a known base; empty offset keeps the base. */
  resolveCdOffset(base: string, offset: string): string {
    if (offset.length === 0) return base;
    return this.flavor.normalize(this.flavor.resolve(base, offset));
  }

  isAbsolute(path: string): boolean {
    return this.flavor.isAbsolute(path);
  }

  containsDir(dir: string, item: string): boolean {
    return this.flavor.contains(dir, item);
  }

  /**
   * True when the path is provably outside the session tree. Unprovable
   * locations are not external here; callers take the conservative branch.
   */
  isOutside(path: string): boolean {
    const canonicalCwd = this.canonicalCwd();
    if (canonicalCwd === undefined) return false;
    const canonical = this.canonicalize(path);
    if (canonical.length === 0) return false;
    if (!isOutsideCanonicalCwd(canonical, canonicalCwd, this.flavor)) return false;
    for (const localPath of this.deps.additionalLocalPaths ?? []) {
      const canonicalLocal = this.canonicalize(localPath);
      if (canonicalLocal.length > 0 && !isOutsideCanonicalCwd(canonical, canonicalLocal, this.flavor)) return false;
    }
    return true;
  }

  /** Native-tool style existence probe; follows symbolic links. */
  exists(path: string): boolean {
    try {
      return (this.deps.existsSync ?? existsSync)(path);
    } catch {
      return false;
    }
  }

  /** Bare-token existence probe; a dangling symlink still counts as an entry. */
  entryExists(path: string): boolean {
    return this.observeEntry(path).exists;
  }

  observeEntry(path: string): { readonly exists: boolean; readonly symlink: boolean; readonly uncertain?: boolean } {
    try {
      const stat = this.deps.lstatSync !== undefined ? this.deps.lstatSync(path) : lstatSync(path);
      if (stat === undefined) return { exists: false, symlink: false };
      const symlink = typeof stat === "object" && stat !== null && "isSymbolicLink" in stat &&
        typeof stat.isSymbolicLink === "function" && stat.isSymbolicLink();
      return { exists: true, symlink };
    } catch (error) {
      const code = (error as { code?: string } | null)?.code;
      return { exists: false, symlink: false, ...(code === "ENOENT" || code === "ENOTDIR" ? {} : { uncertain: true }) };
    }
  }

  /** Directory check following symlinks; unprobed or failing paths are not directories. */
  isDirectory(path: string): boolean {
    try {
      const stat = this.deps.statSync !== undefined ? this.deps.statSync(path) : statSync(path);
      return typeof stat === "object" && stat !== null && "isDirectory" in stat
        ? (stat as { isDirectory(): boolean }).isDirectory()
        : false;
    } catch {
      return false;
    }
  }

  /** True when a read-family tool gets the infrastructure read exemption. */
  isInfrastructureRead(path: string): boolean {
    return isInfrastructureRead(path, {
      flavor: this.flavor,
      cwd: this.cwd,
      home: this.home,
      configuredPaths: this.deps.infrastructureReadPaths ?? [],
      exclusions: this.deps.infrastructureExclusions ?? [],
    });
  }

  /** Build the session authorization patterns for an approved path value. */
  approvalPatterns(value: string, isConfirmedDir: (path: string) => boolean): readonly string[] {
    return sessionApprovalPatterns(value, { flavor: this.flavor, isConfirmedDir });
  }
}
