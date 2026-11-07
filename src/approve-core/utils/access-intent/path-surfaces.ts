/**
 * Path capability surfaces.
 *
 * Two families, `path` and `external_directory`, own direction suffixes.
 * A bare family name covers unknown or mixed effects and evaluates both
 * directions; only these families may carry `_read` / `_write`.
 */
import type { AccessEffect } from "./effect";

export const PATH_SURFACE_FAMILIES = ["path", "external_directory"] as const;
export type PathSurfaceFamily = (typeof PATH_SURFACE_FAMILIES)[number];

export type EffectDirection = "read" | "write";

export interface PathSurfaceParts {
  readonly family: PathSurfaceFamily;
  readonly direction: EffectDirection | undefined;
}

/** Split a surface name into family and direction. Non-family names return undefined. */
export function splitPathSurface(surface: string): PathSurfaceParts | undefined {
  for (const family of PATH_SURFACE_FAMILIES) {
    if (surface === family) return { family, direction: undefined };
    if (surface === `${family}_read`) return { family, direction: "read" };
    if (surface === `${family}_write`) return { family, direction: "write" };
  }
  return undefined;
}

export function directionalSurface(family: PathSurfaceFamily, direction: EffectDirection): string {
  return `${family}_${direction}`;
}

/** True when the surface name merely looks directional without being one. */
export function isMisfoldedDirectionSurface(surface: string): boolean {
  return (surface.endsWith("_read") || surface.endsWith("_write")) && splitPathSurface(surface) === undefined;
}

/**
 * Effect proved by the tool's own identity. `edit` and any other tool prove
 * no single direction.
 */
export function builtinToolIdentityEffect(toolName: string): AccessEffect {
  switch (toolName) {
    case "read":
    case "find":
    case "grep":
    case "ls":
      return "read";
    case "write":
      return "write";
    default:
      return "unproven";
  }
}
