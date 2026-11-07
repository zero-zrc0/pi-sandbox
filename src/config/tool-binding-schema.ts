/**
 * Tool binding configuration (specs/config-schema.md §7).
 *
 * A binding names one captured tool by exact origin identity or by npm package
 * identity and declares how pointers into the tool input map to file access.
 * The two identity forms are mutually exclusive strict objects, and JSON
 * Pointer validation lives here so the config loader and the declarative
 * compiler reject exactly the same pointers.
 */
import { z } from "zod";
import { nonEmptyStringSchema } from "./config-schema";

/** The file-access profiles a tool can be bound to. */
export const TOOL_BINDING_PROFILES = ["file-reader", "file-search", "file-writer", "file-editor"] as const;

/** The access directions a location can grant. */
export const TOOL_BINDING_ACCESSES = ["read", "write"] as const;

/** What happens when a declared location is absent from the tool input. */
export const TOOL_BINDING_WHEN_ABSENT = ["error", "cwd"] as const;

export type ToolBindingProfile = (typeof TOOL_BINDING_PROFILES)[number];

/**
 * Exact lowercase npm package name: a plain name or one `@scope/name` pair.
 * The first character of every part is alphanumeric; later characters may also
 * be `.`, `_` or `-`.
 */
export const NPM_PACKAGE_NAME_PATTERN = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;

/**
 * A JSON Pointer is non-empty, starts with `/`, every segment is non-empty,
 * and `~` only introduces the `~0`/`~1` escapes.
 */
export function isValidJsonPointer(pointer: string): boolean {
  if (pointer.length === 0 || !pointer.startsWith("/")) return false;
  return pointer
    .slice(1)
    .split("/")
    .every((segment) => segment.length > 0 && !/~(?![01])/u.test(segment));
}

/** The JSON Pointer string form of a location. */
export const jsonPointerSchema = z.string().refine(isValidJsonPointer, "expected a valid JSON Pointer");

/** One location: a pointer into the tool input, its access and the absent-value fallback. */
export const toolBindingLocationSchema = z.strictObject({
  pointer: jsonPointerSchema,
  access: z.enum(TOOL_BINDING_ACCESSES),
  whenAbsent: z.enum(TOOL_BINDING_WHEN_ABSENT).optional(),
});

/** Fields both identity forms share. */
const toolBindingCommonShape = {
  tool: nonEmptyStringSchema,
  profile: z.enum(TOOL_BINDING_PROFILES),
  locations: z.array(toolBindingLocationSchema).min(1),
} as const;

/** Bind by exact origin identity. No package or entry is allowed in this form. */
const originToolBindingSchema = z.strictObject({
  ...toolBindingCommonShape,
  origin: nonEmptyStringSchema,
});

/** Bind by npm package identity, optionally restricted to one package entry. */
const packageToolBindingSchema = z.strictObject({
  ...toolBindingCommonShape,
  package: z.string().regex(NPM_PACKAGE_NAME_PATTERN, "expected a lowercase npm package name"),
  entry: nonEmptyStringSchema.optional(),
});

/** One binding: either the origin form or the package form, never both. */
export const toolBindingDeclarationSchema = z.union([originToolBindingSchema, packageToolBindingSchema]);

/** The `toolBindings` scope: an ordered list of declarations. */
export const toolBindingsSchema = z.array(toolBindingDeclarationSchema);

export type ToolBindingLocation = z.infer<typeof toolBindingLocationSchema>;
export type ToolBindingDeclaration = z.infer<typeof toolBindingDeclarationSchema>;
