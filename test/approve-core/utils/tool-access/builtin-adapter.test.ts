/**
 * Builtin read/write/edit adapters (specs/tool-access.md §3).
 *
 * The builtin identity needs both a known tool name and a host builtin origin;
 * the captured schema must match the frozen shape exactly, and any drift or
 * extra input key returns incomplete instead of a partial verified report.
 */
import { describe, expect, it } from "vitest";
import {
  extractBuiltinToolAccess,
  isBuiltinToolIdentity,
} from "#approve-core/utils/tool-access/builtin-adapter";
import type { ToolAccessFactsResult } from "#approve-core/utils/tool-access/access-facts";
import type { ToolDefinition } from "#approve-core/utils/tool-access/tool-definition";

function definition(name: string, origin: string, parameters: Record<string, unknown>): ToolDefinition {
  return { identity: { name, origin, revision: "rev-1" }, description: "", parameters };
}

const READ_SCHEMA: Record<string, unknown> = {
  type: "object",
  additionalProperties: false,
  properties: {
    path: { type: "string" },
    offset: { type: "number" },
    limit: { type: "number" },
  },
  required: ["path"],
};

const WRITE_SCHEMA: Record<string, unknown> = {
  type: "object",
  additionalProperties: false,
  properties: {
    path: { type: "string" },
    content: { type: "string" },
  },
  required: ["path", "content"],
};

const EDIT_SCHEMA: Record<string, unknown> = {
  type: "object",
  additionalProperties: false,
  properties: {
    path: { type: "string" },
    edits: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        properties: {
          oldText: { type: "string" },
          newText: { type: "string" },
        },
        required: ["oldText", "newText"],
      },
    },
  },
  required: ["path", "edits"],
};

const readTool = (): ToolDefinition => definition("read", "builtin", READ_SCHEMA);
const writeTool = (): ToolDefinition => definition("write", "builtin:write", WRITE_SCHEMA);
const editTool = (): ToolDefinition => definition("edit", "builtin:edit", EDIT_SCHEMA);

/** Compact `access|operation|path` projection for assertions. */
function accessesOf(result: ToolAccessFactsResult): string[] {
  return result.accesses.map((access) => `${access.access}|${access.operation ?? "-"}|${access.path}`);
}

interface IdentityCase {
  readonly name: string;
  readonly tool: ToolDefinition;
  readonly expected: boolean;
}

const IDENTITY_CASES: readonly IdentityCase[] = [
  { name: "accepts read/builtin", tool: definition("read", "builtin", {}), expected: true },
  { name: "accepts write/builtin:write", tool: definition("write", "builtin:write", {}), expected: true },
  { name: "accepts edit/host:builtin", tool: definition("edit", "host:builtin", {}), expected: true },
  { name: "accepts read/pi:builtin", tool: definition("read", "pi:builtin", {}), expected: true },
  { name: "rejects an npm package origin", tool: definition("read", "npm:@acme/tools", {}), expected: false },
  { name: "rejects a plugin origin", tool: definition("read", "plugin:acme", {}), expected: false },
  { name: "rejects an empty origin", tool: definition("read", "", {}), expected: false },
  { name: "rejects a lookalike origin", tool: definition("read", "builtinish", {}), expected: false },
  { name: "rejects a non-builtin tool name", tool: definition("grep", "builtin", {}), expected: false },
  { name: "rejects a custom tool name", tool: definition("my_reader", "builtin", {}), expected: false },
];

describe("isBuiltinToolIdentity", () => {
  for (const testCase of IDENTITY_CASES) {
    it(testCase.name, () => {
      expect(isBuiltinToolIdentity(testCase.tool)).toBe(testCase.expected);
    });
  }

  it("only reads identity and ignores schema drift", () => {
    expect(isBuiltinToolIdentity(definition("read", "builtin", { type: "string" }))).toBe(true);
  });
});

interface VerifiedCase {
  readonly name: string;
  readonly tool: ToolDefinition;
  readonly input: unknown;
  readonly cwd: string;
  readonly expected: readonly string[];
}

const VERIFIED_CASES: readonly VerifiedCase[] = [
  {
    name: "resolves a relative read path against the Windows cwd",
    tool: readTool(),
    input: { path: "src/a.ts" },
    cwd: "C:\\repo",
    expected: ["read|read|C:\\repo\\src\\a.ts"],
  },
  {
    name: "keeps an absolute Windows read path",
    tool: readTool(),
    input: { path: "D:\\elsewhere\\a.ts" },
    cwd: "C:\\repo",
    expected: ["read|read|D:\\elsewhere\\a.ts"],
  },
  {
    name: "resolves a relative read path against a POSIX cwd",
    tool: readTool(),
    input: { path: "a.ts" },
    cwd: "/tmp/repo",
    expected: ["read|read|/tmp/repo/a.ts"],
  },
  {
    name: "does not double the separator when cwd ends with one",
    tool: readTool(),
    input: { path: "a.ts" },
    cwd: "C:\\repo\\",
    expected: ["read|read|C:\\repo\\a.ts"],
  },
  {
    name: "accepts the optional offset/limit numbers",
    tool: readTool(),
    input: { path: "src/a.ts", offset: 10, limit: 5 },
    cwd: "C:\\repo",
    expected: ["read|read|C:\\repo\\src\\a.ts"],
  },
  {
    name: "produces one write access",
    tool: writeTool(),
    input: { path: "out.txt", content: "hello" },
    cwd: "C:\\repo",
    expected: ["write|write|C:\\repo\\out.txt"],
  },
  {
    name: "accepts empty write content",
    tool: writeTool(),
    input: { path: "out.txt", content: "" },
    cwd: "C:\\repo",
    expected: ["write|write|C:\\repo\\out.txt"],
  },
  {
    name: "produces read and write for one edit path",
    tool: editTool(),
    input: { path: "f.txt", edits: [{ oldText: "a", newText: "b" }] },
    cwd: "C:\\repo",
    expected: ["read|read|C:\\repo\\f.txt", "write|write|C:\\repo\\f.txt"],
  },
  {
    name: "produces only one read/write pair for multiple edits",
    tool: editTool(),
    input: {
      path: "f.txt",
      edits: [
        { oldText: "a", newText: "b" },
        { oldText: "c", newText: "d" },
      ],
    },
    cwd: "C:\\repo",
    expected: ["read|read|C:\\repo\\f.txt", "write|write|C:\\repo\\f.txt"],
  },
];

describe("extractBuiltinToolAccess verified facts", () => {
  for (const testCase of VERIFIED_CASES) {
    it(testCase.name, () => {
      const result = extractBuiltinToolAccess(testCase.tool, testCase.input, testCase.cwd);
      expect(result.status).toBe("verified");
      expect(result.source).toBe("builtin");
      expect(accessesOf(result)).toEqual(testCase.expected);
    });
  }
});

interface IncompleteCase {
  readonly name: string;
  readonly tool: ToolDefinition;
  readonly input: unknown;
  readonly cwd?: string;
}

const INCOMPLETE_CASES: readonly IncompleteCase[] = [
  // Schema drift: any deviation from the frozen shape keeps facts incomplete.
  {
    name: "rejects a read schema without a type",
    tool: definition("read", "builtin", { additionalProperties: false, properties: READ_SCHEMA.properties, required: ["path"] }),
    input: { path: "a.ts" },
  },
  {
    name: "rejects a read schema typed as string",
    tool: definition("read", "builtin", { type: "string" }),
    input: { path: "a.ts" },
  },
  {
    name: "rejects a read schema without properties",
    tool: definition("read", "builtin", { type: "object", additionalProperties: false, required: ["path"] }),
    input: { path: "a.ts" },
  },
  {
    name: "rejects a read schema with an extra property",
    tool: definition("read", "builtin", {
      ...READ_SCHEMA,
      properties: { ...(READ_SCHEMA.properties as Record<string, unknown>), mode: { type: "string" } },
    }),
    input: { path: "a.ts" },
  },
  {
    name: "rejects a read schema missing a property",
    tool: definition("read", "builtin", {
      ...READ_SCHEMA,
      properties: { path: { type: "string" }, offset: { type: "number" } },
    }),
    input: { path: "a.ts" },
  },
  {
    name: "rejects an empty read required set",
    tool: definition("read", "builtin", { ...READ_SCHEMA, required: [] }),
    input: { path: "a.ts" },
  },
  {
    name: "rejects a read required set with extra entries",
    tool: definition("read", "builtin", { ...READ_SCHEMA, required: ["path", "offset"] }),
    input: { path: "a.ts" },
  },
  {
    name: "rejects a missing read required set",
    tool: definition("read", "builtin", { ...READ_SCHEMA, required: undefined }),
    input: { path: "a.ts" },
  },
  {
    name: "rejects a non-string read required entry",
    tool: definition("read", "builtin", { ...READ_SCHEMA, required: ["path", 1] }),
    input: { path: "a.ts" },
  },
  {
    name: "rejects a read path typed as number",
    tool: definition("read", "builtin", {
      ...READ_SCHEMA,
      properties: { ...(READ_SCHEMA.properties as Record<string, unknown>), path: { type: "number" } },
    }),
    input: { path: "a.ts" },
  },
  {
    name: "rejects a read offset typed as string",
    tool: definition("read", "builtin", {
      ...READ_SCHEMA,
      properties: { ...(READ_SCHEMA.properties as Record<string, unknown>), offset: { type: "string" } },
    }),
    input: { path: "a.ts" },
  },
  {
    name: "rejects a write schema missing the content requirement",
    tool: definition("write", "builtin", { ...WRITE_SCHEMA, required: ["path"] }),
    input: { path: "out.txt", content: "x" },
  },
  {
    name: "rejects a write schema with a non-string content",
    tool: definition("write", "builtin", {
      ...WRITE_SCHEMA,
      properties: { path: { type: "string" }, content: { type: "number" } },
    }),
    input: { path: "out.txt", content: "x" },
  },
  {
    name: "rejects an edit schema with a non-array edits property",
    tool: definition("edit", "builtin", {
      ...EDIT_SCHEMA,
      properties: { path: { type: "string" }, edits: { type: "string" } },
    }),
    input: { path: "f.txt", edits: [{ oldText: "a", newText: "b" }] },
  },
  {
    name: "rejects an edit schema without edit items",
    tool: definition("edit", "builtin", {
      ...EDIT_SCHEMA,
      properties: { path: { type: "string" }, edits: { type: "array" } },
    }),
    input: { path: "f.txt", edits: [{ oldText: "a", newText: "b" }] },
  },
  {
    name: "rejects edit items with an extra property",
    tool: definition("edit", "builtin", {
      ...EDIT_SCHEMA,
      properties: {
        path: { type: "string" },
        edits: {
          type: "array",
          items: {
            type: "object",
            properties: { oldText: { type: "string" }, newText: { type: "string" }, source: { type: "string" } },
            required: ["oldText", "newText"],
          },
        },
      },
    }),
    input: { path: "f.txt", edits: [{ oldText: "a", newText: "b" }] },
  },
  {
    name: "rejects edit items missing a required property",
    tool: definition("edit", "builtin", {
      ...EDIT_SCHEMA,
      properties: {
        path: { type: "string" },
        edits: {
          type: "array",
          items: {
            type: "object",
            properties: { oldText: { type: "string" }, newText: { type: "string" } },
            required: ["oldText"],
          },
        },
      },
    }),
    input: { path: "f.txt", edits: [{ oldText: "a", newText: "b" }] },
  },
  {
    name: "rejects edit items with a non-string required entry",
    tool: definition("edit", "builtin", {
      ...EDIT_SCHEMA,
      properties: {
        path: { type: "string" },
        edits: {
          type: "array",
          items: {
            type: "object",
            properties: { oldText: { type: "string" }, newText: { type: "string" } },
            required: ["oldText", "newText", 1],
          },
        },
      },
    }),
    input: { path: "f.txt", edits: [{ oldText: "a", newText: "b" }] },
  },
  {
    name: "rejects edit items with a non-string text",
    tool: definition("edit", "builtin", {
      ...EDIT_SCHEMA,
      properties: {
        path: { type: "string" },
        edits: {
          type: "array",
          items: {
            type: "object",
            properties: { oldText: { type: "number" }, newText: { type: "string" } },
            required: ["oldText", "newText"],
          },
        },
      },
    }),
    input: { path: "f.txt", edits: [{ oldText: "a", newText: "b" }] },
  },

  // Runtime input failures.
  { name: "rejects a null read input", tool: readTool(), input: null },
  { name: "rejects a string read input", tool: readTool(), input: "path" },
  { name: "rejects an array read input", tool: readTool(), input: [] },
  { name: "rejects a read input without a path", tool: readTool(), input: {} },
  { name: "rejects an extra read input key", tool: readTool(), input: { path: "a.ts", mode: "r" } },
  { name: "rejects a non-string read path", tool: readTool(), input: { path: 42 } },
  { name: "rejects an empty read path", tool: readTool(), input: { path: "" } },
  { name: "rejects a whitespace read path", tool: readTool(), input: { path: "   " } },
  { name: "rejects a URL read path", tool: readTool(), input: { path: "https://example.com/a.ts" } },
  { name: "rejects a string offset", tool: readTool(), input: { path: "a.ts", offset: "10" } },
  { name: "rejects a non-finite offset", tool: readTool(), input: { path: "a.ts", offset: Number.NaN } },
  { name: "rejects a null limit", tool: readTool(), input: { path: "a.ts", limit: null } },
  { name: "rejects a write input without a path", tool: writeTool(), input: { content: "x" } },
  { name: "rejects a write input without content", tool: writeTool(), input: { path: "out.txt" } },
  { name: "rejects a non-string write content", tool: writeTool(), input: { path: "out.txt", content: 42 } },
  { name: "rejects an extra write input key", tool: writeTool(), input: { path: "out.txt", content: "x", mode: "w" } },
  { name: "rejects an empty write path", tool: writeTool(), input: { path: "", content: "x" } },
  { name: "rejects a URL write path", tool: writeTool(), input: { path: "file:///tmp/out.txt", content: "x" } },
  { name: "rejects an edit input without edits", tool: editTool(), input: { path: "f.txt" } },
  { name: "rejects an empty edits array", tool: editTool(), input: { path: "f.txt", edits: [] } },
  { name: "rejects a non-array edits value", tool: editTool(), input: { path: "f.txt", edits: "a" } },
  { name: "rejects a non-object edit item", tool: editTool(), input: { path: "f.txt", edits: [null] } },
  { name: "rejects an edit item missing newText", tool: editTool(), input: { path: "f.txt", edits: [{ oldText: "a" }] } },
  {
    name: "rejects an edit item with an extra key",
    tool: editTool(),
    input: { path: "f.txt", edits: [{ oldText: "a", newText: "b", count: 1 }] },
  },
  {
    name: "rejects an edit item with a non-string newText",
    tool: editTool(),
    input: { path: "f.txt", edits: [{ oldText: "a", newText: 2 }] },
  },
  { name: "rejects an empty edit path", tool: editTool(), input: { path: " ", edits: [{ oldText: "a", newText: "b" }] } },
  { name: "rejects a URL edit path", tool: editTool(), input: { path: "https://x/y", edits: [{ oldText: "a", newText: "b" }] } },
  { name: "rejects an extra edit input key", tool: editTool(), input: { path: "f.txt", edits: [{ oldText: "a", newText: "b" }], mode: "e" } },
];

describe("extractBuiltinToolAccess incomplete facts", () => {
  for (const testCase of INCOMPLETE_CASES) {
    it(testCase.name, () => {
      const result = extractBuiltinToolAccess(testCase.tool, testCase.input, testCase.cwd ?? "C:\\repo");
      expect(result.status).toBe("incomplete");
      expect(result.complete).toBe(false);
      expect(result.unknownEffects.length).toBeGreaterThan(0);
    });
  }
});

interface UnboundCase {
  readonly name: string;
  readonly tool: ToolDefinition;
}

const UNBOUND_CASES: readonly UnboundCase[] = [
  { name: "unbinds a non-builtin tool name", tool: definition("grep", "builtin", READ_SCHEMA) },
  { name: "unbinds an npm origin", tool: definition("read", "npm:@acme/tools", READ_SCHEMA) },
  { name: "unbinds a plugin origin", tool: definition("write", "plugin:acme", WRITE_SCHEMA) },
  { name: "unbinds an empty origin", tool: definition("edit", "", EDIT_SCHEMA) },
];

describe("extractBuiltinToolAccess unbound facts", () => {
  for (const testCase of UNBOUND_CASES) {
    it(testCase.name, () => {
      const result = extractBuiltinToolAccess(testCase.tool, { path: "a.ts" }, "C:\\repo");
      expect(result.status).toBe("unbound");
      expect(result.accesses).toEqual([]);
    });
  }

  it("checks identity before schema drift", () => {
    const result = extractBuiltinToolAccess(definition("grep", "plugin:acme", { type: "string" }), null, "C:\\repo");
    expect(result.status).toBe("unbound");
  });
});
