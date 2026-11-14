import { describe, expect, it } from "vitest";
import { z } from "zod";
import { issuesFromZodError } from "#config/config-schema";
import {
  GRANT_GRANULARITIES,
  executionConfigSchema,
  executionFilesystemPermissionsSchema,
  filesystemGrantSchema,
  networkDestinationSchema,
  networkScopeSchema,
  shellExecutionPermissionsSchema,
  type ExecutionConfig,
} from "#config/execution-source-schema";

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
  return issuesFromZodError(result.error).map(issue => issue.code);
}

function jsonSchema(schema: z.ZodType): Record<string, unknown> {
  return z.toJSONSchema(schema, { target: "draft-2020-12", io: "input" }) as Record<string, unknown>;
}

describe("execution filesystem configuration", () => {
  it("publishes file and directory granularities", () => {
    expect(GRANT_GRANULARITIES).toEqual(["file", "directory"]);
  });

  it.each([
    { path: "/workspace/README.md", granularity: "file" },
    { path: "/workspace/src", granularity: "directory" },
    { path: "src", granularity: "directory" },
    { path: "C:\\workspace\\src", granularity: "directory" },
  ])("accepts %j", value => {
    expect(filesystemGrantSchema.parse(value)).toEqual(value);
  });

  it.each([
    {},
    { path: "" },
    { path: "/a", granularity: "symlink" },
    { path: "/a", granularity: "file", access: "read" },
  ])("rejects %j", value => {
    expect(accept(filesystemGrantSchema, value)).toBe(false);
  });

  it("reports extra grant fields as unknown keys", () => {
    expect(issueCodes(filesystemGrantSchema, { path: "/a", granularity: "file", extra: 1 })).toEqual(["unknown-key"]);
  });

  it("accepts independent empty read and write lists", () => {
    expect(executionFilesystemPermissionsSchema.parse({ read: [], write: [] })).toEqual({ read: [], write: [] });
  });

  it.each([
    {},
    { read: [] },
    { write: [] },
    { read: [], write: [], execute: [] },
  ])("rejects incomplete or extended filesystem permissions %j", value => {
    expect(accept(executionFilesystemPermissionsSchema, value)).toBe(false);
  });
});

describe("network destinations", () => {
  it.each([
    { host: "api.example.com" },
    { host: "api.example.com", port: "any" },
    { host: "localhost", port: 1 },
    { host: "localhost", port: 65535 },
  ])("accepts %j", value => {
    expect(networkDestinationSchema.parse(value)).toEqual(value);
  });

  it.each([
    { port: 443 },
    { host: "" },
    { host: "localhost", port: 0 },
    { host: "localhost", port: 65536 },
    { host: "localhost", port: 1.5 },
    { host: "localhost", port: "443" },
    { host: "localhost", protocol: "https" },
  ])("rejects %j", value => {
    expect(accept(networkDestinationSchema, value)).toBe(false);
  });
});

describe("network scope", () => {
  it.each([
    { mode: "none" },
    { mode: "all" },
    { mode: "allowlist", allow: [{ host: "api.example.com", port: 443 }] },
    { mode: "allowlist", allow: [{ host: "api.example.com" }, { host: "localhost", port: 8080 }] },
  ])("accepts %j", value => {
    expect(networkScopeSchema.parse(value)).toEqual(value);
  });

  it.each([
    { mode: "allowlist", allow: [] },
    { mode: "allowlist" },
    { mode: "some" },
    { allow: [{ host: "api.example.com" }] },
    { mode: "none", allow: [] },
    { mode: "allowlist", allow: [{ host: "a" }], proxy: true },
    { kind: "destinations", destinations: [{ host: "api.example.com" }] },
  ])("rejects %j", value => {
    expect(accept(networkScopeSchema, value)).toBe(false);
  });
});

describe("execution configuration", () => {
  it("uses an empty object by default", () => {
    expect(executionConfigSchema.parse({})).toEqual({});
  });

  it("accepts shared network and shell grants without per-service sources", () => {
    const value: ExecutionConfig = {
      network: { mode: "allowlist", allow: [{ host: "github.com" }] },
      shell: {
        filesystem: { read: [{ path: "/workspace", granularity: "directory" }], write: [] },
        network: { mode: "all" },
      },
    };
    expect(executionConfigSchema.parse(value)).toEqual(value);
    expect(shellExecutionPermissionsSchema.parse(value.shell)).toEqual(value.shell);
  });

  it.each([
    { sources: [] },
    { secrets: {} },
    { network: { kind: "none" } },
    [],
  ])("rejects removed or invalid execution fields %j", value => {
    expect(accept(executionConfigSchema, value)).toBe(false);
  });
});

describe("execution JSON schema", () => {
  it("generates draft 2020-12 input JSON", () => {
    const published = jsonSchema(executionConfigSchema);
    expect(published["$schema"]).toBe("https://json-schema.org/draft/2020-12/schema");
    expect(published.properties).not.toHaveProperty("sources");
  });

  it("publishes allowlists with a minimum of one item", () => {
    const published = jsonSchema(networkScopeSchema);
    const branches = published.oneOf as readonly Record<string, unknown>[];
    const allowlist = branches.find(branch => JSON.stringify(branch).includes("allowlist")) as
      | { properties?: Record<string, { minItems?: number }> }
      | undefined;
    expect(allowlist?.properties?.allow?.minItems).toBe(1);
  });
});
