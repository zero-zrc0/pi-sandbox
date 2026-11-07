import { describe, expect, it } from "vitest";
import {
  normalizeToolDefinition,
  toolDefinitionDigest,
  type ToolDefinition,
} from "#approve-core/utils/tool-access/tool-definition";

const flatTool = {
  name: "read",
  origin: "builtin:read",
  revision: "7",
  description: "Read a file",
  parameters: {
    type: "object",
    properties: { path: { type: "string" }, offset: { type: "number" } },
    required: ["path"],
    additionalProperties: false,
  },
  annotations: { readOnlyHint: true },
  namespace: "filesystem",
};

function nested(raw: typeof flatTool): Record<string, unknown> {
  return {
    identity: { name: raw.name, origin: raw.origin, revision: raw.revision },
    description: raw.description,
    parameters: raw.parameters,
    ...(raw.annotations === undefined ? {} : { annotations: raw.annotations }),
    ...(raw.namespace === undefined ? {} : { namespace: raw.namespace }),
  };
}

function digestOf(raw: Record<string, unknown>): string {
  const definition = normalizeToolDefinition(raw);
  if (definition === undefined) throw new Error("fixture definition is invalid");
  return toolDefinitionDigest(definition);
}

describe("normalizeToolDefinition", () => {
  it("normalizes a flat registered tool definition into a frozen definition", () => {
    const definition = normalizeToolDefinition(flatTool);

    expect(definition).toEqual({
      identity: { name: "read", origin: "builtin:read", revision: "7" },
      description: "Read a file",
      parameters: flatTool.parameters,
      annotations: { readOnlyHint: true },
      namespace: "filesystem",
    });
    expect(Object.isFrozen(definition)).toBe(true);
    expect(Object.isFrozen(definition!.identity)).toBe(true);
    expect(Object.isFrozen(definition!.parameters)).toBe(true);
    expect(Object.isFrozen((definition!.parameters as { properties: object }).properties)).toBe(true);
  });

  it("accepts an already-nested definition", () => {
    expect(normalizeToolDefinition(nested(flatTool))).toEqual(normalizeToolDefinition(flatTool));
  });

  it("accepts an empty description and omits optional annotations/namespace", () => {
    const definition = normalizeToolDefinition({
      name: "read",
      origin: "builtin:read",
      revision: "7",
      description: "",
      parameters: { type: "object" },
    });
    expect(definition?.description).toBe("");
    expect(definition).not.toHaveProperty("annotations");
    expect(definition).not.toHaveProperty("namespace");
  });

  it("rejects non-object, missing or non-string identity fields", () => {
    expect(normalizeToolDefinition(null)).toBeUndefined();
    expect(normalizeToolDefinition([])).toBeUndefined();
    expect(normalizeToolDefinition("read")).toBeUndefined();
    expect(normalizeToolDefinition(42)).toBeUndefined();
    expect(normalizeToolDefinition({ ...flatTool, name: undefined })).toBeUndefined();
    expect(normalizeToolDefinition({ ...flatTool, origin: "" })).toBeUndefined();
    expect(normalizeToolDefinition({ ...flatTool, revision: "  " })).toBeUndefined();
    expect(normalizeToolDefinition({ ...flatTool, name: 7 })).toBeUndefined();
    expect(normalizeToolDefinition({ ...nested(flatTool) as Record<string, unknown>, identity: { name: "read" } })).toBeUndefined();
  });

  it("rejects an invalid description, parameters, annotations or namespace", () => {
    expect(normalizeToolDefinition({ ...flatTool, description: 7 })).toBeUndefined();
    expect(normalizeToolDefinition({ ...flatTool, description: undefined })).toBeUndefined();
    expect(normalizeToolDefinition({ ...flatTool, parameters: undefined })).toBeUndefined();
    expect(normalizeToolDefinition({ ...flatTool, parameters: [] })).toBeUndefined();
    expect(normalizeToolDefinition({ ...flatTool, parameters: "object" })).toBeUndefined();
    expect(normalizeToolDefinition({ ...flatTool, annotations: [] })).toBeUndefined();
    expect(normalizeToolDefinition({ ...flatTool, annotations: "hint" })).toBeUndefined();
    expect(normalizeToolDefinition({ ...flatTool, namespace: 7 })).toBeUndefined();
    expect(normalizeToolDefinition({ ...flatTool, namespace: "" })).toBeUndefined();
  });

  it("rejects unknown fields and a mixed flat/nested identity", () => {
    expect(normalizeToolDefinition({ ...flatTool, extra: 1 })).toBeUndefined();
    expect(normalizeToolDefinition({
      identity: { name: "read", origin: "builtin:read", revision: "7", extra: "x" },
      description: "Read a file",
      parameters: { type: "object" },
    })).toBeUndefined();
    expect(normalizeToolDefinition({
      identity: { name: "read", origin: "builtin:read", revision: "7" },
      name: "read",
      description: "Read a file",
      parameters: { type: "object" },
    })).toBeUndefined();
  });

  it("rejects values that cannot be frozen as JSON", () => {
    expect(normalizeToolDefinition({ ...flatTool, parameters: { run: () => 1 } })).toBeUndefined();
    expect(normalizeToolDefinition({ ...flatTool, parameters: { limit: Number.NaN } })).toBeUndefined();
    expect(normalizeToolDefinition({ ...flatTool, parameters: { value: undefined } })).toBeUndefined();

    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(normalizeToolDefinition({ ...flatTool, parameters: cyclic })).toBeUndefined();
  });
});

describe("toolDefinitionDigest", () => {
  it("returns a stable sha256 hex digest for equivalent definitions", () => {
    const first = digestOf(flatTool);
    const second = digestOf(nested(flatTool));

    expect(first).toMatch(/^[0-9a-f]{64}$/);
    expect(second).toBe(first);
    expect(digestOf({ ...flatTool, description: "" })).not.toBe(first);
  });

  it("does not depend on object key insertion order", () => {
    const reordered = {
      ...flatTool,
      parameters: {
        additionalProperties: false,
        required: ["path"],
        properties: { offset: { type: "number" }, path: { type: "string" } },
        type: "object",
      },
    };
    expect(digestOf(reordered)).toBe(digestOf(flatTool));
  });

  it("covers identity, description, parameters, annotations and namespace", () => {
    const base = digestOf(flatTool);
    const variants: Record<string, unknown>[] = [
      { ...flatTool, name: "write" },
      { ...flatTool, origin: "builtin:write" },
      { ...flatTool, revision: "8" },
      { ...flatTool, description: "Write a file" },
      { ...flatTool, parameters: { type: "object", properties: {}, additionalProperties: false } },
      { ...flatTool, annotations: { readOnlyHint: false } },
      { ...flatTool, namespace: "other" },
      ((() => { const { annotations: _omitted, ...rest } = flatTool; return rest; })()),
    ];
    for (const variant of variants) expect(digestOf(variant)).not.toBe(base);
  });

  it("treats omitted optional fields as absent from the digest payload", () => {
    const withoutOptional = normalizeToolDefinition({
      name: "read",
      origin: "builtin:read",
      revision: "7",
      description: "Read a file",
      parameters: { type: "object" },
    }) as ToolDefinition;
    const explicitUndefined = normalizeToolDefinition({
      name: "read",
      origin: "builtin:read",
      revision: "7",
      description: "Read a file",
      parameters: { type: "object" },
      annotations: undefined,
      namespace: undefined,
    }) as ToolDefinition;

    expect(toolDefinitionDigest(explicitUndefined)).toBe(toolDefinitionDigest(withoutOptional));
  });
});
