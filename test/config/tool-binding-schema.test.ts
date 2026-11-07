/**
 * Tool binding configuration (specs/config-schema.md §7).
 *
 * A binding is either an origin form or a package form and never both; each
 * location points into the tool input with a JSON Pointer and declares the
 * file access that pointer grants.
 */
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { issuesFromZodError } from "#config/config-schema";
import {
  NPM_PACKAGE_NAME_PATTERN,
  TOOL_BINDING_ACCESSES,
  TOOL_BINDING_PROFILES,
  TOOL_BINDING_WHEN_ABSENT,
  isValidJsonPointer,
  jsonPointerSchema,
  toolBindingDeclarationSchema,
  toolBindingLocationSchema,
  toolBindingsSchema,
  type ToolBindingDeclaration,
  type ToolBindingLocation,
  type ToolBindingProfile,
} from "#config/tool-binding-schema";

interface Case {
  readonly label: string;
  readonly value: unknown;
}

function accept(schema: z.ZodType, value: unknown): boolean {
  return schema.safeParse(value).success;
}

function issueCodes(schema: z.ZodType, value: unknown): readonly string[] {
  const result = schema.safeParse(value);
  if (result.success) return [];
  return issuesFromZodError(result.error).map((issue) => issue.code);
}

function jsonSchema(schema: z.ZodType): Record<string, unknown> {
  return z.toJSONSchema(schema, { target: "draft-2020-12", io: "input" }) as Record<string, unknown>;
}

const ORIGIN_DECLARATION = {
  tool: "read",
  profile: "file-reader",
  locations: [{ pointer: "/path", access: "read" }],
  origin: "sdk",
};

const PACKAGE_DECLARATION = {
  tool: "read",
  profile: "file-reader",
  locations: [{ pointer: "/path", access: "read" }],
  package: "@acme/file-tools",
  entry: "dist/index.js",
};

describe("tool binding constants", () => {
  it("publishes the four supported profiles", () => {
    expect(TOOL_BINDING_PROFILES).toEqual(["file-reader", "file-search", "file-writer", "file-editor"]);
  });

  it("publishes the two access directions", () => {
    expect(TOOL_BINDING_ACCESSES).toEqual(["read", "write"]);
  });

  it("publishes the two when-absent fallbacks", () => {
    expect(TOOL_BINDING_WHEN_ABSENT).toEqual(["error", "cwd"]);
  });
});

describe("npm package names", () => {
  it("exports a pattern that accepts plain and scoped lowercase names", () => {
    expect(NPM_PACKAGE_NAME_PATTERN).toBeInstanceOf(RegExp);
    for (const name of ["a", "read-tool", "tool2", "tool_2", "tool.name", "@acme/file-tools", "@a/b", "@acme/name.mjs"]) {
      expect(NPM_PACKAGE_NAME_PATTERN.test(name), name).toBe(true);
    }
  });

  it("rejects names outside the exact lowercase convention", () => {
    for (const name of [
      "",
      "Read-Tool",
      "@Acme/file-tools",
      "@acme/File-Tools",
      "tool/name",
      "@acme",
      "@acme/",
      "_private",
      ".hidden",
      "tool name",
    ]) {
      expect(NPM_PACKAGE_NAME_PATTERN.test(name), name).toBe(false);
    }
  });
});

describe("JSON pointers", () => {
  const validPointers = [
    "/a",
    "/0",
    "/path",
    "/profile/name",
    "/items/0/path",
    "/a~0b",
    "/a~1b",
    "/~0",
    "/~1",
    "/nested/deep~1pointer/leaf",
  ];
  const invalidPointers = ["", "x", "//", "/a/", "/~2", "/a~", "~0", "/a~x", "/a/~", "a/b", "/a//b"];

  it.each(validPointers)("accepts %s", (pointer) => {
    expect(isValidJsonPointer(pointer)).toBe(true);
    expect(accept(jsonPointerSchema, pointer)).toBe(true);
  });

  it.each(invalidPointers)("rejects %s", (pointer) => {
    expect(isValidJsonPointer(pointer)).toBe(false);
    expect(accept(jsonPointerSchema, pointer)).toBe(false);
  });

  it("rejects non-string pointer values", () => {
    for (const value of [0, null, ["/a"], { pointer: "/a" }]) {
      expect(accept(jsonPointerSchema, value)).toBe(false);
    }
  });
});

describe("tool binding location", () => {
  const valid: readonly Case[] = [
    { label: "a read location", value: { pointer: "/path", access: "read" } },
    { label: "a write location", value: { pointer: "/content", access: "write" } },
    { label: "a location with the error fallback", value: { pointer: "/path", access: "read", whenAbsent: "error" } },
    { label: "a location with the cwd fallback", value: { pointer: "/query", access: "read", whenAbsent: "cwd" } },
    { label: "a location with a nested pointer", value: { pointer: "/input/file/path", access: "read" } },
    { label: "a location with an escaped pointer segment", value: { pointer: "/input/a~0b~1c", access: "read" } },
  ];
  const invalid: readonly Case[] = [
    { label: "a missing pointer", value: { access: "read" } },
    { label: "a missing access", value: { pointer: "/path" } },
    { label: "an empty pointer", value: { pointer: "", access: "read" } },
    { label: "a pointer without a leading slash", value: { pointer: "path", access: "read" } },
    { label: "a pointer with a trailing slash", value: { pointer: "/path/", access: "read" } },
    { label: "a pointer with an invalid escape", value: { pointer: "/path~2", access: "read" } },
    { label: "an unknown access", value: { pointer: "/path", access: "execute" } },
    { label: "an empty access", value: { pointer: "/path", access: "" } },
    { label: "an unknown when-absent value", value: { pointer: "/path", access: "read", whenAbsent: "fallback" } },
    { label: "an extra location field", value: { pointer: "/path", access: "read", granularity: "file" } },
    { label: "a bare string", value: "/path" },
  ];

  it.each(valid)("accepts $label", ({ value }) => {
    expect(toolBindingLocationSchema.parse(value)).toEqual(value);
  });

  it.each(invalid)("rejects $label", ({ value }) => {
    expect(accept(toolBindingLocationSchema, value)).toBe(false);
  });

  it("reports extra location fields as unknown keys", () => {
    expect(issueCodes(toolBindingLocationSchema, { pointer: "/path", access: "read", extra: 1 })).toEqual(["unknown-key"]);
  });
});

describe("origin tool binding declarations", () => {
  it("accepts an origin declaration", () => {
    expect(toolBindingDeclarationSchema.parse(ORIGIN_DECLARATION)).toEqual(ORIGIN_DECLARATION);
  });

  it("accepts every supported profile", () => {
    for (const profile of TOOL_BINDING_PROFILES) {
      expect(accept(toolBindingDeclarationSchema, { ...ORIGIN_DECLARATION, profile })).toBe(true);
    }
  });

  it("accepts several locations", () => {
    const value = {
      ...ORIGIN_DECLARATION,
      locations: [
        { pointer: "/path", access: "read" },
        { pointer: "/fallback", access: "read", whenAbsent: "cwd" },
      ],
    };
    expect(accept(toolBindingDeclarationSchema, value)).toBe(true);
  });

  const invalid: readonly Case[] = [
    { label: "an origin and package together", value: { ...ORIGIN_DECLARATION, package: "@acme/file-tools" } },
    { label: "an origin with an entry", value: { ...ORIGIN_DECLARATION, entry: "dist/index.js" } },
    { label: "neither identity", value: { tool: "read", profile: "file-reader", locations: [{ pointer: "/path", access: "read" }] } },
    { label: "an empty tool name", value: { ...ORIGIN_DECLARATION, tool: "" } },
    { label: "a whitespace-only tool name", value: { ...ORIGIN_DECLARATION, tool: "  " } },
    { label: "a non-string tool name", value: { ...ORIGIN_DECLARATION, tool: 1 } },
    { label: "an empty origin", value: { ...ORIGIN_DECLARATION, origin: "" } },
    { label: "a non-string origin", value: { ...ORIGIN_DECLARATION, origin: null } },
    { label: "an empty profile", value: { ...ORIGIN_DECLARATION, profile: "" } },
    { label: "an unknown profile", value: { ...ORIGIN_DECLARATION, profile: "file-namer" } },
    { label: "a missing profile", value: { tool: "read", locations: [{ pointer: "/path", access: "read" }], origin: "sdk" } },
    { label: "an empty location list", value: { ...ORIGIN_DECLARATION, locations: [] } },
    { label: "a non-array location list", value: { ...ORIGIN_DECLARATION, locations: { pointer: "/path", access: "read" } } },
    { label: "an invalid location", value: { ...ORIGIN_DECLARATION, locations: [{ pointer: "/path", access: "execute" }] } },
    { label: "an unknown top-level field", value: { ...ORIGIN_DECLARATION, revision: 1 } },
    { label: "an array", value: [ORIGIN_DECLARATION] },
  ];

  it.each(invalid)("rejects $label", ({ value }) => {
    expect(accept(toolBindingDeclarationSchema, value)).toBe(false);
  });

  it("reports unknown top-level fields as unknown keys", () => {
    const codes = issueCodes(toolBindingDeclarationSchema, { ...ORIGIN_DECLARATION, extra: true });
    expect(codes).toContain("unknown-key");
  });
});

describe("package tool binding declarations", () => {
  it("accepts a package declaration with an entry", () => {
    expect(toolBindingDeclarationSchema.parse(PACKAGE_DECLARATION)).toEqual(PACKAGE_DECLARATION);
  });

  it("accepts plain, scoped and entry-less package declarations", () => {
    const { entry: _entry, ...withoutEntry } = PACKAGE_DECLARATION;
    for (const declaration of [
      { ...withoutEntry, package: "read-tool" },
      { ...withoutEntry, package: "@acme/file-tools" },
      withoutEntry,
    ]) {
      expect(accept(toolBindingDeclarationSchema, declaration)).toBe(true);
    }
  });

  it("accepts every supported profile in the package form", () => {
    for (const profile of TOOL_BINDING_PROFILES) {
      expect(accept(toolBindingDeclarationSchema, { ...PACKAGE_DECLARATION, profile })).toBe(true);
    }
  });

  const invalid: readonly Case[] = [
    { label: "an uppercase package name", value: { ...PACKAGE_DECLARATION, package: "Read-Tool" } },
    { label: "an uppercase scoped package name", value: { ...PACKAGE_DECLARATION, package: "@Acme/file-tools" } },
    { label: "an uppercase scoped name segment", value: { ...PACKAGE_DECLARATION, package: "@acme/File-Tools" } },
    { label: "a scope without a name", value: { ...PACKAGE_DECLARATION, package: "@acme" } },
    { label: "a scope with an empty name", value: { ...PACKAGE_DECLARATION, package: "@acme/" } },
    { label: "a package name with a slash", value: { ...PACKAGE_DECLARATION, package: "tool/name" } },
    { label: "a package name starting with an underscore", value: { ...PACKAGE_DECLARATION, package: "_private" } },
    { label: "an empty package name", value: { ...PACKAGE_DECLARATION, package: "" } },
    { label: "an empty entry", value: { ...PACKAGE_DECLARATION, entry: "" } },
    { label: "a whitespace-only entry", value: { ...PACKAGE_DECLARATION, entry: "   " } },
    { label: "a non-string entry", value: { ...PACKAGE_DECLARATION, entry: 7 } },
    { label: "an origin field alongside the package form", value: { ...PACKAGE_DECLARATION, origin: "sdk" } },
    { label: "a package declaration without locations", value: { tool: "read", profile: "file-reader", package: "@acme/tools" } },
    { label: "an unknown top-level field", value: { ...PACKAGE_DECLARATION, version: "1.0.0" } },
  ];

  it.each(invalid)("rejects $label", ({ value }) => {
    expect(accept(toolBindingDeclarationSchema, value)).toBe(false);
  });
});

describe("tool binding lists", () => {
  it("accepts an empty list", () => {
    expect(toolBindingsSchema.parse([])).toEqual([]);
  });

  it("accepts a list mixing both declaration forms", () => {
    expect(toolBindingsSchema.parse([ORIGIN_DECLARATION, PACKAGE_DECLARATION])).toEqual([
      ORIGIN_DECLARATION,
      PACKAGE_DECLARATION,
    ]);
  });

  const invalid: readonly Case[] = [
    { label: "a single declaration instead of a list", value: ORIGIN_DECLARATION },
    { label: "an object", value: {} },
    { label: "a list with an invalid declaration", value: [ORIGIN_DECLARATION, { tool: "" }] },
    { label: "a list with a bare string", value: ["read"] },
  ];

  it.each(invalid)("rejects $label", ({ value }) => {
    expect(accept(toolBindingsSchema, value)).toBe(false);
  });
});

describe("tool binding types", () => {
  it("matches the declaration shape", () => {
    const location: ToolBindingLocation = { pointer: "/path", access: "read", whenAbsent: "error" };
    const profile: ToolBindingProfile = "file-reader";
    const origin: ToolBindingDeclaration = { tool: "read", profile, locations: [location], origin: "sdk" };
    const pkg: ToolBindingDeclaration = {
      tool: "read",
      profile,
      locations: [location],
      package: "@acme/file-tools",
      entry: "dist/index.js",
    };
    expect(toolBindingsSchema.parse([origin, pkg])).toEqual([
      { tool: "read", profile: "file-reader", locations: [location], origin: "sdk" },
      {
        tool: "read",
        profile: "file-reader",
        locations: [location],
        package: "@acme/file-tools",
        entry: "dist/index.js",
      },
    ]);
  });
});

describe("tool binding JSON schema", () => {
  it.each([
    { label: "a JSON pointer", schema: jsonPointerSchema },
    { label: "a binding location", schema: toolBindingLocationSchema },
    { label: "a binding declaration", schema: toolBindingDeclarationSchema },
    { label: "a binding list", schema: toolBindingsSchema },
  ])("generates draft 2020-12 input JSON for $label", ({ schema }) => {
    expect(() => jsonSchema(schema)).not.toThrow();
    expect(jsonSchema(schema)["$schema"]).toBe("https://json-schema.org/draft/2020-12/schema");
  });

  it("publishes the location as a closed object", () => {
    const published = jsonSchema(toolBindingLocationSchema);
    expect(published.type).toBe("object");
    expect(published.additionalProperties).toBe(false);
    expect(published.required).toEqual(["pointer", "access"]);
  });

  it("publishes the binding list as an array of declarations", () => {
    const published = jsonSchema(toolBindingsSchema);
    expect(published.type).toBe("array");
    expect(published.items).toBeTypeOf("object");
  });
});
