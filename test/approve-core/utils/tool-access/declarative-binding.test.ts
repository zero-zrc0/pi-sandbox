/**
 * Declarative tool bindings (specs/tool-access.md §4, config-schema.md §7).
 *
 * The compiler is a pure table-driven gate over one declaration and the
 * captured tool definition: identity, closed schema, JSON Pointer locations,
 * profile safe parameters and the file-search cwd fallback are all validated
 * before a binding exists. Extraction later trusts only the compiled binding.
 */
import { describe, expect, it } from "vitest";
import {
  compileDeclarativeBinding,
  extractDeclaredToolAccess,
  type DeclarativeCompileResult,
} from "#approve-core/utils/tool-access/declarative-binding";
import type { ToolAccessFactsResult } from "#approve-core/utils/tool-access/access-facts";
import type { ToolDefinition } from "#approve-core/utils/tool-access/tool-definition";

function definition(name: string, origin: string, parameters: Record<string, unknown>): ToolDefinition {
  return { identity: { name, origin, revision: "rev-1" }, description: "", parameters };
}

const READER_SCHEMA: Record<string, unknown> = {
  type: "object",
  additionalProperties: false,
  properties: {
    path: { type: "string" },
    offset: { type: "number" },
    limit: { type: "number" },
    encoding: { type: "string" },
  },
  required: ["path"],
};

const SEARCH_SCHEMA: Record<string, unknown> = {
  type: "object",
  additionalProperties: false,
  properties: {
    query: { type: "string" },
    path: { type: "string", default: "$cwd" },
    glob: { type: "string" },
    caseSensitive: { type: "boolean" },
    contextLines: { type: "number" },
  },
  required: ["query"],
};

const WRITER_SCHEMA: Record<string, unknown> = {
  type: "object",
  additionalProperties: false,
  properties: {
    path: { type: "string" },
    content: { type: "string" },
    overwrite: { type: "boolean" },
  },
  required: ["path", "content"],
};

const EDITOR_SCHEMA: Record<string, unknown> = {
  type: "object",
  additionalProperties: false,
  properties: {
    path: { type: "string" },
    oldText: { type: "string" },
    newText: { type: "string" },
    replaceAll: { type: "boolean" },
  },
  required: ["path", "oldText", "newText"],
};

const NESTED_SCHEMA: Record<string, unknown> = {
  type: "object",
  additionalProperties: false,
  properties: {
    files: {
      type: "object",
      additionalProperties: false,
      properties: {
        target: { type: "string" },
        limit: { type: "number" },
      },
      required: ["target"],
    },
  },
  required: ["files"],
};

const ARRAY_SCHEMA: Record<string, unknown> = {
  type: "object",
  additionalProperties: false,
  properties: {
    paths: { type: "array", items: { type: "string" } },
  },
  required: ["paths"],
};

const READER_TOOL = definition("reader_tool", "plugin:acme", READER_SCHEMA);
const SEARCH_TOOL = definition("search_tool", "plugin:acme", SEARCH_SCHEMA);
const WRITER_TOOL = definition("writer_tool", "plugin:acme", WRITER_SCHEMA);
const EDITOR_TOOL = definition("editor_tool", "plugin:acme", EDITOR_SCHEMA);

const READER_DECLARATION = {
  tool: "reader_tool",
  profile: "file-reader",
  locations: [{ pointer: "/path", access: "read" }],
  origin: "plugin:acme",
};

const SEARCH_DECLARATION = {
  tool: "search_tool",
  profile: "file-search",
  locations: [{ pointer: "/path", access: "read", whenAbsent: "cwd" }],
  package: "@acme/tools",
  entry: "dist/index.js",
};

function bound(result: DeclarativeCompileResult): Extract<DeclarativeCompileResult, { status: "bound" }> {
  expect(result.status).toBe("bound");
  if (result.status !== "bound") throw new Error("expected a bound declaration");
  return result;
}

function accessesOf(result: ToolAccessFactsResult): string[] {
  return result.accesses.map((access) => `${access.access}|${access.operation ?? "-"}|${access.path}`);
}

describe("compileDeclarativeBinding successes", () => {
  it("compiles an origin reader and derives safe parameters", () => {
    const result = bound(compileDeclarativeBinding(READER_DECLARATION, READER_TOOL));
    expect(result.binding.profile).toBe("file-reader");
    expect(result.binding.identity).toEqual({ kind: "origin", name: "reader_tool", origin: "plugin:acme" });
    expect(result.binding.tool).toEqual({ name: "reader_tool", origin: "plugin:acme", revision: "rev-1" });
    expect(result.binding.locations).toEqual([{ pointer: "/path", access: "read", whenAbsent: "error" }]);
    expect(result.binding.safeParams).toEqual([
      { pointer: "/offset", type: "number" },
      { pointer: "/limit", type: "number" },
      { pointer: "/encoding", type: "string" },
    ]);
  });

  it("compiles a package search declaration with an entry", () => {
    const result = bound(compileDeclarativeBinding(SEARCH_DECLARATION, SEARCH_TOOL));
    expect(result.binding.profile).toBe("file-search");
    expect(result.binding.identity).toEqual({
      kind: "package",
      name: "search_tool",
      package: "@acme/tools",
      entry: "dist/index.js",
    });
    expect(result.binding.locations).toEqual([{ pointer: "/path", access: "read", whenAbsent: "cwd" }]);
    expect(result.binding.safeParams).toEqual([
      { pointer: "/query", type: "string" },
      { pointer: "/glob", type: "string" },
      { pointer: "/caseSensitive", type: "boolean" },
      { pointer: "/contextLines", type: "number" },
    ]);
  });

  it("compiles a writer declaration with a write access", () => {
    const result = bound(compileDeclarativeBinding({
      tool: "writer_tool",
      profile: "file-writer",
      locations: [{ pointer: "/path", access: "write" }],
      origin: "plugin:acme",
    }, WRITER_TOOL));
    expect(result.binding.safeParams).toEqual([
      { pointer: "/content", type: "string" },
      { pointer: "/overwrite", type: "boolean" },
    ]);
  });

  it("compiles an editor declaration with read and write locations on the same pointer", () => {
    const result = bound(compileDeclarativeBinding({
      tool: "editor_tool",
      profile: "file-editor",
      locations: [
        { pointer: "/path", access: "read" },
        { pointer: "/path", access: "write" },
      ],
      origin: "plugin:acme",
    }, EDITOR_TOOL));
    expect(result.binding.locations).toEqual([
      { pointer: "/path", access: "read", whenAbsent: "error" },
      { pointer: "/path", access: "write", whenAbsent: "error" },
    ]);
  });

  it("accepts a nested location with an object prefix", () => {
    const tool = definition("nested_tool", "plugin:acme", NESTED_SCHEMA);
    const result = bound(compileDeclarativeBinding({
      tool: "nested_tool",
      profile: "file-reader",
      locations: [{ pointer: "/files/target", access: "read" }],
      origin: "plugin:acme",
    }, tool));
    expect(result.binding.locations[0]?.pointer).toBe("/files/target");
    expect(result.binding.safeParams).toEqual([{ pointer: "/files/limit", type: "number" }]);
  });

  it("decodes ~1 and ~0 JSON Pointer escapes", () => {
    const slashTool = definition("slash_tool", "plugin:acme", {
      type: "object",
      additionalProperties: false,
      properties: { "a/b": { type: "string" } },
      required: ["a/b"],
    });
    const slash = bound(compileDeclarativeBinding({
      tool: "slash_tool",
      profile: "file-reader",
      locations: [{ pointer: "/a~1b", access: "read" }],
      origin: "plugin:acme",
    }, slashTool));
    expect(slash.binding.locations[0]?.pointer).toBe("/a~1b");

    const tildeTool = definition("tilde_tool", "plugin:acme", {
      type: "object",
      additionalProperties: false,
      properties: { "c~d": { type: "string" } },
      required: ["c~d"],
    });
    const tilde = bound(compileDeclarativeBinding({
      tool: "tilde_tool",
      profile: "file-reader",
      locations: [{ pointer: "/c~0d", access: "read" }],
      origin: "plugin:acme",
    }, tildeTool));
    expect(tilde.binding.locations[0]?.pointer).toBe("/c~0d");
  });

  it("accepts a string-array location", () => {
    const tool = definition("array_tool", "plugin:acme", ARRAY_SCHEMA);
    const result = bound(compileDeclarativeBinding({
      tool: "array_tool",
      profile: "file-reader",
      locations: [{ pointer: "/paths", access: "read" }],
      origin: "plugin:acme",
    }, tool));
    expect(result.binding.locations).toEqual([{ pointer: "/paths", access: "read", whenAbsent: "error" }]);
  });

  it("treats a non-string required entry as an empty required set", () => {
    const tool = definition("search_tool", "plugin:acme", { ...SEARCH_SCHEMA, required: [1] });
    const result = bound(compileDeclarativeBinding(SEARCH_DECLARATION, tool));
    expect(result.binding.locations[0]?.whenAbsent).toBe("cwd");
  });

  it("treats mixed required entries as an empty required set", () => {
    const tool = definition("search_tool", "plugin:acme", { ...SEARCH_SCHEMA, required: ["query", 1] });
    const result = bound(compileDeclarativeBinding(SEARCH_DECLARATION, tool));
    expect(result.binding.locations[0]?.whenAbsent).toBe("cwd");
  });
});

interface CompileFailureCase {
  readonly name: string;
  readonly declaration: unknown;
  readonly tool: ToolDefinition;
  readonly status: "unbound" | "incomplete";
  readonly reason: string;
}

const COMPILE_FAILURE_CASES: readonly CompileFailureCase[] = [
  { name: "rejects a null declaration", declaration: null, tool: READER_TOOL, status: "unbound", reason: "invalid-declaration" },
  { name: "rejects a string declaration", declaration: "reader", tool: READER_TOOL, status: "unbound", reason: "invalid-declaration" },
  { name: "rejects an array declaration", declaration: [], tool: READER_TOOL, status: "unbound", reason: "invalid-declaration" },
  { name: "rejects a declaration without fields", declaration: {}, tool: READER_TOOL, status: "unbound", reason: "invalid-declaration" },
  {
    name: "rejects an unknown declaration field",
    declaration: { ...READER_DECLARATION, extra: true },
    tool: READER_TOOL,
    status: "unbound",
    reason: "invalid-declaration",
  },
  {
    name: "rejects mixing origin and package",
    declaration: { ...READER_DECLARATION, package: "@acme/tools" },
    tool: READER_TOOL,
    status: "unbound",
    reason: "invalid-declaration",
  },
  {
    name: "rejects an entry on an origin declaration",
    declaration: { ...READER_DECLARATION, entry: "dist/index.js" },
    tool: READER_TOOL,
    status: "unbound",
    reason: "invalid-declaration",
  },
  {
    name: "rejects a declaration with a non-array locations value",
    declaration: { ...READER_DECLARATION, locations: "/path" },
    tool: READER_TOOL,
    status: "unbound",
    reason: "invalid-declaration",
  },
  {
    name: "rejects a declaration with an empty tool name",
    declaration: { ...READER_DECLARATION, tool: "" },
    tool: READER_TOOL,
    status: "unbound",
    reason: "invalid-declaration",
  },
  {
    name: "rejects an unknown profile",
    declaration: { ...READER_DECLARATION, profile: "file-indexer" },
    tool: READER_TOOL,
    status: "unbound",
    reason: "unknown-profile",
  },
  {
    name: "rejects a non-string origin",
    declaration: { ...READER_DECLARATION, origin: 42 },
    tool: READER_TOOL,
    status: "unbound",
    reason: "invalid-identity",
  },
  {
    name: "rejects a non-string package",
    declaration: { ...READER_DECLARATION, origin: undefined, package: 42 },
    tool: READER_TOOL,
    status: "unbound",
    reason: "invalid-identity",
  },
  {
    name: "rejects an empty package entry",
    declaration: { ...READER_DECLARATION, origin: undefined, package: "@acme/tools", entry: "" },
    tool: READER_TOOL,
    status: "unbound",
    reason: "invalid-identity",
  },
  {
    name: "rejects a non-string package entry",
    declaration: { ...READER_DECLARATION, origin: undefined, package: "@acme/tools", entry: 5 },
    tool: READER_TOOL,
    status: "unbound",
    reason: "invalid-identity",
  },
  {
    name: "rejects an origin mismatch",
    declaration: { ...READER_DECLARATION, origin: "plugin:other" },
    tool: READER_TOOL,
    status: "unbound",
    reason: "identity-mismatch",
  },
  {
    name: "rejects a tool name mismatch",
    declaration: { ...READER_DECLARATION, tool: "other_tool" },
    tool: READER_TOOL,
    status: "unbound",
    reason: "identity-mismatch",
  },
  {
    name: "rejects a package tool name mismatch",
    declaration: { ...SEARCH_DECLARATION, tool: "other_tool" },
    tool: SEARCH_TOOL,
    status: "unbound",
    reason: "identity-mismatch",
  },
  {
    name: "rejects a schema without additionalProperties",
    declaration: READER_DECLARATION,
    tool: definition("reader_tool", "plugin:acme", { ...READER_SCHEMA, additionalProperties: undefined }),
    status: "incomplete",
    reason: "schema-not-closed",
  },
  {
    name: "rejects an open schema",
    declaration: READER_DECLARATION,
    tool: definition("reader_tool", "plugin:acme", { ...READER_SCHEMA, additionalProperties: true }),
    status: "incomplete",
    reason: "schema-not-closed",
  },
  {
    name: "rejects a schema without a type",
    declaration: READER_DECLARATION,
    tool: definition("reader_tool", "plugin:acme", { ...READER_SCHEMA, type: undefined }),
    status: "incomplete",
    reason: "schema-not-closed",
  },
  {
    name: "rejects a non-object schema",
    declaration: READER_DECLARATION,
    tool: definition("reader_tool", "plugin:acme", { ...READER_SCHEMA, type: "array" }),
    status: "incomplete",
    reason: "schema-not-closed",
  },
  {
    name: "rejects a non-array required set",
    declaration: READER_DECLARATION,
    tool: definition("reader_tool", "plugin:acme", { ...READER_SCHEMA, required: "path" }),
    status: "incomplete",
    reason: "required-not-array",
  },
  {
    name: "rejects a missing required set",
    declaration: READER_DECLARATION,
    tool: definition("reader_tool", "plugin:acme", { ...READER_SCHEMA, required: undefined }),
    status: "incomplete",
    reason: "required-not-array",
  },
  {
    name: "rejects an empty locations array",
    declaration: { ...READER_DECLARATION, locations: [] },
    tool: READER_TOOL,
    status: "incomplete",
    reason: "no-locations",
  },
  {
    name: "rejects a non-object location item",
    declaration: { ...READER_DECLARATION, locations: [null] },
    tool: READER_TOOL,
    status: "incomplete",
    reason: "invalid-location",
  },
  {
    name: "rejects a location without a pointer",
    declaration: { ...READER_DECLARATION, locations: [{ access: "read" }] },
    tool: READER_TOOL,
    status: "incomplete",
    reason: "invalid-location",
  },
  {
    name: "rejects an unknown location access",
    declaration: { ...READER_DECLARATION, locations: [{ pointer: "/path", access: "execute" }] },
    tool: READER_TOOL,
    status: "incomplete",
    reason: "invalid-location",
  },
  {
    name: "rejects a location without an access",
    declaration: { ...READER_DECLARATION, locations: [{ pointer: "/path" }] },
    tool: READER_TOOL,
    status: "incomplete",
    reason: "invalid-location",
  },
  {
    name: "rejects an unknown whenAbsent value",
    declaration: { ...READER_DECLARATION, locations: [{ pointer: "/path", access: "read", whenAbsent: "home" }] },
    tool: READER_TOOL,
    status: "incomplete",
    reason: "invalid-location",
  },
  {
    name: "rejects an empty pointer",
    declaration: { ...READER_DECLARATION, locations: [{ pointer: "", access: "read" }] },
    tool: READER_TOOL,
    status: "incomplete",
    reason: "invalid-location-pointer",
  },
  {
    name: "rejects a pointer without a leading slash",
    declaration: { ...READER_DECLARATION, locations: [{ pointer: "path", access: "read" }] },
    tool: READER_TOOL,
    status: "incomplete",
    reason: "invalid-location-pointer",
  },
  {
    name: "rejects a pointer to a missing property",
    declaration: { ...READER_DECLARATION, locations: [{ pointer: "/missing", access: "read" }] },
    tool: READER_TOOL,
    status: "incomplete",
    reason: "invalid-location-pointer",
  },
  {
    name: "rejects an invalid pointer escape",
    declaration: { ...READER_DECLARATION, locations: [{ pointer: "/a~2b", access: "read" }] },
    tool: READER_TOOL,
    status: "incomplete",
    reason: "invalid-location-pointer",
  },
  {
    name: "rejects a number location schema",
    declaration: { ...READER_DECLARATION, locations: [{ pointer: "/offset", access: "read" }] },
    tool: READER_TOOL,
    status: "incomplete",
    reason: "invalid-location-schema",
  },
  {
    name: "rejects an array location of non-strings",
    declaration: { ...READER_DECLARATION, locations: [{ pointer: "/tags", access: "read" }] },
    tool: definition("reader_tool", "plugin:acme", {
      type: "object",
      additionalProperties: false,
      properties: { tags: { type: "array", items: { type: "number" } } },
      required: ["tags"],
    }),
    status: "incomplete",
    reason: "invalid-location-schema",
  },
  {
    name: "rejects a non-object nested location prefix",
    declaration: { ...READER_DECLARATION, locations: [{ pointer: "/options/path", access: "read" }] },
    tool: definition("reader_tool", "plugin:acme", {
      type: "object",
      additionalProperties: false,
      properties: { options: { type: "string" } },
      required: ["options"],
    }),
    status: "incomplete",
    reason: "nested-location-prefix-not-object",
  },
  {
    name: "rejects a write access for a reader profile",
    declaration: { ...READER_DECLARATION, locations: [{ pointer: "/path", access: "write" }] },
    tool: READER_TOOL,
    status: "incomplete",
    reason: "profile-access-mismatch",
  },
  {
    name: "rejects a read access for a writer profile",
    declaration: {
      tool: "writer_tool",
      profile: "file-writer",
      locations: [{ pointer: "/path", access: "read" }],
      origin: "plugin:acme",
    },
    tool: WRITER_TOOL,
    status: "incomplete",
    reason: "profile-access-mismatch",
  },
  {
    name: "rejects a write access for a search profile",
    declaration: { ...SEARCH_DECLARATION, locations: [{ pointer: "/path", access: "write" }] },
    tool: SEARCH_TOOL,
    status: "incomplete",
    reason: "profile-access-mismatch",
  },
  {
    name: "rejects whenAbsent=cwd outside a search profile",
    declaration: { ...READER_DECLARATION, locations: [{ pointer: "/path", access: "read", whenAbsent: "cwd" }] },
    tool: READER_TOOL,
    status: "incomplete",
    reason: "invalid-when-absent",
  },
  {
    name: "rejects whenAbsent=cwd on a nested location",
    declaration: { ...SEARCH_DECLARATION, locations: [{ pointer: "/options/path", access: "read", whenAbsent: "cwd" }] },
    tool: definition("search_tool", "plugin:acme", {
      type: "object",
      additionalProperties: false,
      properties: {
        query: { type: "string" },
        options: {
          type: "object",
          additionalProperties: false,
          properties: { path: { type: "string", default: "$cwd" } },
          required: ["path"],
        },
      },
      required: ["query"],
    }),
    status: "incomplete",
    reason: "invalid-when-absent",
  },
  {
    name: "rejects whenAbsent=cwd when the location is required",
    declaration: { ...SEARCH_DECLARATION },
    tool: definition("search_tool", "plugin:acme", { ...SEARCH_SCHEMA, required: ["query", "path"] }),
    status: "incomplete",
    reason: "invalid-when-absent",
  },
  {
    name: "rejects whenAbsent=cwd without a $cwd default",
    declaration: SEARCH_DECLARATION,
    tool: definition("search_tool", "plugin:acme", {
      ...SEARCH_SCHEMA,
      properties: {
        query: { type: "string" },
        path: { type: "string" },
        glob: { type: "string" },
        caseSensitive: { type: "boolean" },
        contextLines: { type: "number" },
      },
    }),
    status: "incomplete",
    reason: "invalid-when-absent",
  },
  {
    name: "rejects whenAbsent=cwd with a different default",
    declaration: SEARCH_DECLARATION,
    tool: definition("search_tool", "plugin:acme", {
      ...SEARCH_SCHEMA,
      properties: {
        query: { type: "string" },
        path: { type: "string", default: "other" },
        glob: { type: "string" },
        caseSensitive: { type: "boolean" },
        contextLines: { type: "number" },
      },
    }),
    status: "incomplete",
    reason: "invalid-when-absent",
  },
  {
    name: "rejects a non-location parameter outside the safe table",
    declaration: READER_DECLARATION,
    tool: definition("reader_tool", "plugin:acme", {
      type: "object",
      additionalProperties: false,
      properties: {
        path: { type: "string" },
        mode: { type: "string" },
      },
      required: ["path"],
      }),
    status: "incomplete",
    reason: "unsafe-parameter",
  },
  {
    name: "rejects a safe parameter with the wrong type",
    declaration: READER_DECLARATION,
    tool: definition("reader_tool", "plugin:acme", {
      type: "object",
      additionalProperties: false,
      properties: {
        path: { type: "string" },
        offset: { type: "string" },
      },
      required: ["path"],
    }),
    status: "incomplete",
    reason: "parameter-type-mismatch",
  },
  {
    name: "rejects a duplicated location",
    declaration: {
      ...READER_DECLARATION,
      locations: [
        { pointer: "/path", access: "read" },
        { pointer: "/path", access: "read" },
      ],
    },
    tool: READER_TOOL,
    status: "incomplete",
    reason: "duplicate-location",
  },
];

describe("compileDeclarativeBinding failures", () => {
  for (const testCase of COMPILE_FAILURE_CASES) {
    it(testCase.name, () => {
      const result = compileDeclarativeBinding(testCase.declaration, testCase.tool);
      expect(result.status).toBe(testCase.status);
      if (result.status !== "bound") expect(result.reason).toBe(testCase.reason);
    });
  }
});

function compileReader(): Parameters<typeof extractDeclaredToolAccess>[0] {
  return bound(compileDeclarativeBinding(READER_DECLARATION, READER_TOOL)).binding;
}

function compileSearch(declaration: unknown = SEARCH_DECLARATION, tool: ToolDefinition = SEARCH_TOOL): Parameters<typeof extractDeclaredToolAccess>[0] {
  return bound(compileDeclarativeBinding(declaration, tool)).binding;
}

interface ExtractCase {
  readonly name: string;
  readonly binding: Parameters<typeof extractDeclaredToolAccess>[0];
  readonly input: unknown;
  readonly cwd: string;
  readonly expected: readonly string[];
}

const EXTRACT_CASES: readonly ExtractCase[] = [
  {
    name: "extracts a resolved reader access",
    binding: compileReader(),
    input: { path: "src/a.ts", offset: 3 },
    cwd: "C:\\repo",
    expected: ["read|read|C:\\repo\\src\\a.ts"],
  },
  {
    name: "extracts a resolved writer access",
    binding: bound(compileDeclarativeBinding({
      tool: "writer_tool",
      profile: "file-writer",
      locations: [{ pointer: "/path", access: "write" }],
      origin: "plugin:acme",
    }, WRITER_TOOL)).binding,
    input: { path: "out.txt", content: "hello" },
    cwd: "C:\\repo",
    expected: ["write|write|C:\\repo\\out.txt"],
  },
  {
    name: "extracts read and write accesses for an editor binding",
    binding: bound(compileDeclarativeBinding({
      tool: "editor_tool",
      profile: "file-editor",
      locations: [
        { pointer: "/path", access: "read" },
        { pointer: "/path", access: "write" },
      ],
      origin: "plugin:acme",
    }, EDITOR_TOOL)).binding,
    input: { path: "f.txt", oldText: "a", newText: "b" },
    cwd: "/tmp/repo",
    expected: ["read|read|/tmp/repo/f.txt", "write|write|/tmp/repo/f.txt"],
  },
  {
    name: "falls back to cwd for an absent search location",
    binding: compileSearch(),
    input: { query: "needle" },
    cwd: "/tmp/repo",
    expected: ["read|read|/tmp/repo"],
  },
  {
    name: "resolves a present search location",
    binding: compileSearch(),
    input: { query: "needle", path: "docs" },
    cwd: "/tmp/repo",
    expected: ["read|read|/tmp/repo/docs"],
  },
  {
    name: "keeps an absolute search location",
    binding: compileSearch(),
    input: { query: "needle", path: "D:\\docs" },
    cwd: "C:\\repo",
    expected: ["read|read|D:\\docs"],
  },
  {
    name: "extracts every string-array location item",
    binding: bound(compileDeclarativeBinding({
      tool: "array_tool",
      profile: "file-reader",
      locations: [{ pointer: "/paths", access: "read" }],
      origin: "plugin:acme",
    }, definition("array_tool", "plugin:acme", ARRAY_SCHEMA))).binding,
    input: { paths: ["a.md", "b.md"] },
    cwd: "/tmp/repo",
    expected: ["read|read|/tmp/repo/a.md", "read|read|/tmp/repo/b.md"],
  },
  {
    name: "extracts a nested location",
    binding: bound(compileDeclarativeBinding({
      tool: "nested_tool",
      profile: "file-reader",
      locations: [{ pointer: "/files/target", access: "read" }],
      origin: "plugin:acme",
    }, definition("nested_tool", "plugin:acme", NESTED_SCHEMA))).binding,
    input: { files: { target: "a.ts", limit: 2 } },
    cwd: "/tmp/repo",
    expected: ["read|read|/tmp/repo/a.ts"],
  },
  {
    name: "extracts an escaped JSON Pointer property",
    binding: bound(compileDeclarativeBinding({
      tool: "slash_tool",
      profile: "file-reader",
      locations: [{ pointer: "/a~1b", access: "read" }],
      origin: "plugin:acme",
    }, definition("slash_tool", "plugin:acme", {
      type: "object",
      additionalProperties: false,
      properties: { "a/b": { type: "string" } },
      required: ["a/b"],
    }))).binding,
    input: { "a/b": "dir" },
    cwd: "/tmp/repo",
    expected: ["read|read|/tmp/repo/dir"],
  },
];

describe("extractDeclaredToolAccess verified facts", () => {
  for (const testCase of EXTRACT_CASES) {
    it(testCase.name, () => {
      const result = extractDeclaredToolAccess(testCase.binding, testCase.input, testCase.cwd);
      expect(result.status).toBe("verified");
      expect(result.source).toBe("declared");
      expect(result.tool).toEqual({ name: testCase.binding.tool.name, origin: testCase.binding.tool.origin, revision: testCase.binding.tool.revision });
      expect(accessesOf(result)).toEqual(testCase.expected);
    });
  }
});

interface ExtractFailureCase {
  readonly name: string;
  readonly binding: Parameters<typeof extractDeclaredToolAccess>[0];
  readonly input: unknown;
  readonly cwd: string;
}

const EXTRACT_FAILURE_CASES: readonly ExtractFailureCase[] = [
  { name: "rejects a null input", binding: compileReader(), input: null, cwd: "C:\\repo" },
  { name: "rejects an array input", binding: compileReader(), input: [], cwd: "C:\\repo" },
  { name: "rejects an unmodeled input key", binding: compileReader(), input: { path: "a.ts", mode: "r" }, cwd: "C:\\repo" },
  { name: "rejects a missing required location", binding: compileReader(), input: {}, cwd: "C:\\repo" },
  { name: "rejects an empty path", binding: compileReader(), input: { path: "" }, cwd: "C:\\repo" },
  { name: "rejects a URL path", binding: compileReader(), input: { path: "https://example.com/a" }, cwd: "C:\\repo" },
  { name: "rejects a non-string path", binding: compileReader(), input: { path: 42 }, cwd: "C:\\repo" },
  {
    name: "rejects an empty search path array",
    binding: compileSearch(),
    input: { query: "needle", path: [] },
    cwd: "/tmp/repo",
  },
  {
    name: "rejects a non-string search path array item",
    binding: compileSearch(),
    input: { query: "needle", path: [1] },
    cwd: "/tmp/repo",
  },
  {
    name: "rejects an empty path inside a search path array",
    binding: compileSearch(),
    input: { query: "needle", path: ["a.md", ""] },
    cwd: "/tmp/repo",
  },
  {
    name: "rejects an unmodeled nested key",
    binding: bound(compileDeclarativeBinding({
      tool: "nested_tool",
      profile: "file-reader",
      locations: [{ pointer: "/files/target", access: "read" }],
      origin: "plugin:acme",
    }, definition("nested_tool", "plugin:acme", NESTED_SCHEMA))).binding,
    input: { files: { target: "a.ts", extra: 1 } },
    cwd: "/tmp/repo",
  },
  {
    name: "rejects a missing fallback cwd",
    binding: compileSearch(),
    input: { query: "needle" },
    cwd: "",
  },
];

describe("extractDeclaredToolAccess incomplete facts", () => {
  for (const testCase of EXTRACT_FAILURE_CASES) {
    it(testCase.name, () => {
      const result = extractDeclaredToolAccess(testCase.binding, testCase.input, testCase.cwd);
      expect(result.status).toBe("incomplete");
      expect(result.complete).toBe(false);
      expect(result.accesses).toEqual([]);
    });
  }
});
