import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
  DIRECTIONAL_PERMISSION_SURFACE_NAMES,
  MAX_DENY_REASON_LENGTH,
  NAMED_PERMISSION_SURFACES,
  denyWithReasonSchema,
  environmentVariableNameSchema,
  issuesFromZodError,
  jsonObjectSchema,
  nonEmptyStringListSchema,
  nonEmptyStringSchema,
  patternValueSchema,
  permissionConfigSchema,
  permissionStateSchema,
  positiveIntegerSchema,
  ratioSchema,
  safeIntegerSchema,
} from "#config/config-schema";

function accept(schema: z.ZodType, value: unknown): boolean {
  return schema.safeParse(value).success;
}

function issuePaths(schema: z.ZodType, value: unknown): readonly string[] {
  const result = schema.safeParse(value);
  if (result.success) return [];
  return issuesFromZodError(result.error).map((issue) => issue.path);
}

function issueCodes(schema: z.ZodType, value: unknown): readonly string[] {
  const result = schema.safeParse(value);
  if (result.success) return [];
  return issuesFromZodError(result.error).map((issue) => issue.code);
}

describe("configuration validation primitives", () => {
  describe("non-empty strings", () => {
    it("accepts text with at least one non-whitespace character", () => {
      expect(accept(nonEmptyStringSchema, "x")).toBe(true);
      expect(accept(nonEmptyStringSchema, "  x  ")).toBe(true);
      expect(accept(nonEmptyStringSchema, "a b")).toBe(true);
    });

    it("rejects empty, whitespace-only and non-string values", () => {
      expect(accept(nonEmptyStringSchema, "")).toBe(false);
      expect(accept(nonEmptyStringSchema, "   ")).toBe(false);
      expect(accept(nonEmptyStringSchema, "\t\n")).toBe(false);
      expect(accept(nonEmptyStringSchema, 1)).toBe(false);
      expect(accept(nonEmptyStringSchema, null)).toBe(false);
    });

    it("keeps the original text instead of trimming it", () => {
      expect(nonEmptyStringSchema.parse("  keep  ")).toBe("  keep  ");
    });
  });

  describe("positive integers", () => {
    it("accepts 1 and the largest safe integer", () => {
      expect(accept(positiveIntegerSchema, 1)).toBe(true);
      expect(accept(positiveIntegerSchema, Number.MAX_SAFE_INTEGER)).toBe(true);
    });

    it("rejects zero, negatives, fractions and non-numbers", () => {
      expect(accept(positiveIntegerSchema, 0)).toBe(false);
      expect(accept(positiveIntegerSchema, -1)).toBe(false);
      expect(accept(positiveIntegerSchema, 1.5)).toBe(false);
      expect(accept(positiveIntegerSchema, "5")).toBe(false);
      expect(accept(positiveIntegerSchema, Number.POSITIVE_INFINITY)).toBe(false);
      expect(accept(positiveIntegerSchema, Number.NaN)).toBe(false);
    });
  });

  describe("safe integers", () => {
    it("accepts negative, zero and positive safe integers", () => {
      expect(accept(safeIntegerSchema, -3)).toBe(true);
      expect(accept(safeIntegerSchema, 0)).toBe(true);
      expect(accept(safeIntegerSchema, 3)).toBe(true);
      expect(accept(safeIntegerSchema, Number.MIN_SAFE_INTEGER)).toBe(true);
    });

    it("rejects fractions and unsafe integers", () => {
      expect(accept(safeIntegerSchema, 0.5)).toBe(false);
      expect(accept(safeIntegerSchema, Number.MAX_SAFE_INTEGER + 1)).toBe(false);
    });
  });

  describe("ratios", () => {
    it("accepts finite numbers between zero and one", () => {
      for (const value of [0, 0.5, 0.9, 1]) {
        expect(accept(ratioSchema, value)).toBe(true);
      }
    });

    it("rejects values outside the closed unit interval", () => {
      expect(accept(ratioSchema, -0.01)).toBe(false);
      expect(accept(ratioSchema, 1.01)).toBe(false);
      expect(accept(ratioSchema, Number.NaN)).toBe(false);
      expect(accept(ratioSchema, Number.POSITIVE_INFINITY)).toBe(false);
    });
  });

  describe("JSON objects", () => {
    it("accepts flat and nested JSON objects", () => {
      expect(accept(jsonObjectSchema, {})).toBe(true);
      expect(accept(jsonObjectSchema, { text: "x", count: 2, flag: false, none: null })).toBe(true);
      expect(accept(jsonObjectSchema, { nested: { list: [1, "a", null, { deep: true }] } })).toBe(true);
    });

    it("rejects arrays and non-JSON values", () => {
      expect(accept(jsonObjectSchema, [])).toBe(false);
      expect(accept(jsonObjectSchema, { fn: () => 1 })).toBe(false);
      expect(accept(jsonObjectSchema, { value: Number.NaN })).toBe(false);
      expect(accept(jsonObjectSchema, { missing: undefined })).toBe(false);
    });
  });

  describe("environment variable names", () => {
    it("accepts portable environment variable names", () => {
      for (const name of ["PATH", "_private", "A1", "LC_ALL"]) {
        expect(accept(environmentVariableNameSchema, name)).toBe(true);
      }
    });

    it("rejects names that are not portable", () => {
      for (const name of ["", "1ABC", "WITH-DASH", "with space", "É"]) {
        expect(accept(environmentVariableNameSchema, name)).toBe(false);
      }
    });
  });

  describe("non-empty string lists", () => {
    it("accepts a list of non-empty strings and the empty list", () => {
      expect(accept(nonEmptyStringListSchema, [])).toBe(true);
      expect(accept(nonEmptyStringListSchema, ["a", "b c"])).toBe(true);
    });

    it("rejects a list containing an empty or non-string item", () => {
      expect(accept(nonEmptyStringListSchema, [""])).toBe(false);
      expect(accept(nonEmptyStringListSchema, ["a", " "])).toBe(false);
      expect(accept(nonEmptyStringListSchema, [1])).toBe(false);
    });
  });
});

describe("issue reporting", () => {
  const nested = z.strictObject({
    list: z.array(z.strictObject({ name: z.string() })),
  });

  it("reports one issue per unknown key with a dotted field path", () => {
    const result = nested.safeParse({ list: [{ name: "n", extra: 1 }], another: 2 });
    expect(result.success).toBe(false);
    if (result.success) return;
    const issues = issuesFromZodError(result.error);
    expect(issues.map((issue) => issue.path).sort()).toEqual(["another", "list[0].extra"]);
    expect(issues.every((issue) => issue.code === "unknown-key")).toBe(true);
  });

  it("renders array indexes with brackets", () => {
    expect(issuePaths(nested, { list: [{ name: 1 }] })).toEqual(["list[0].name"]);
    expect(issueCodes(nested, { list: [{ name: 1 }] })).toEqual(["invalid"]);
  });

  it("uses the empty string for the document root and quotes non-identifier keys", () => {
    expect(issuePaths(z.strictObject({ a: z.string() }), {})).toEqual(["a"]);
    expect(issueCodes(z.strictObject({ a: z.string() }), {})).toEqual(["invalid"]);
    expect(issuePaths(z.record(z.string().min(1), z.string()), { "": "x" })).toEqual([`[""]`]);
    expect(issueCodes(z.record(z.string().min(1), z.string()), { "": "x" })).toEqual(["invalid-key"]);
    expect(issuePaths(z.record(z.string(), z.string()), { "not an identifier": 1 }))
      .toEqual([`["not an identifier"]`]);
  });

  it("keeps the zod message so callers can explain the failure", () => {
    const result = z.strictObject({ count: z.number() }).safeParse({ count: "x" });
    expect(result.success).toBe(false);
    if (result.success) return;
    const [issue] = issuesFromZodError(result.error);
    expect(issue?.message.length).toBeGreaterThan(0);
    expect(issue?.path).toBe("count");
  });

  it("reports the field of an unknown discriminated-union tag", () => {
    const union = z.discriminatedUnion("kind", [
      z.strictObject({ kind: z.literal("none") }),
      z.strictObject({ kind: z.literal("all") }),
    ]);
    expect(issuePaths(union, { kind: "nope" })).toEqual(["kind"]);
    expect(issueCodes(union, { kind: "nope" })).toEqual(["invalid"]);
  });
});

describe("permission state", () => {
  it("accepts only allow, ask and deny", () => {
    expect(permissionStateSchema.options).toEqual(["allow", "ask", "deny"]);
    for (const state of ["allow", "ask", "deny"]) {
      expect(accept(permissionStateSchema, state)).toBe(true);
    }
    for (const state of ["Allow", "permit", "", 1, null]) {
      expect(accept(permissionStateSchema, state)).toBe(false);
    }
  });

  it("exposes the deny-with-reason shape for a maximum reason length", () => {
    expect(MAX_DENY_REASON_LENGTH).toBe(500);
    expect(accept(denyWithReasonSchema, { action: "deny" })).toBe(true);
    expect(accept(denyWithReasonSchema, { action: "deny", reason: "why" })).toBe(true);
    expect(accept(denyWithReasonSchema, { action: "deny", reason: "x".repeat(MAX_DENY_REASON_LENGTH) })).toBe(true);
    expect(accept(denyWithReasonSchema, { action: "deny", reason: "x".repeat(MAX_DENY_REASON_LENGTH + 1) })).toBe(false);
  });

  it("rejects deny-with-reason shapes that are not a plain deny", () => {
    expect(accept(denyWithReasonSchema, { action: "allow" })).toBe(false);
    expect(accept(denyWithReasonSchema, { action: "deny", reason: 7 })).toBe(false);
    expect(accept(denyWithReasonSchema, { action: "deny", extra: true })).toBe(false);
    expect(accept(denyWithReasonSchema, "deny")).toBe(false);
  });

  it("pattern values are an action or a deny-with-reason object", () => {
    for (const value of ["allow", "ask", "deny", { action: "deny" }, { action: "deny", reason: "no" }]) {
      expect(accept(patternValueSchema, value)).toBe(true);
    }
    for (const value of ["permit", { action: "ask" }, { reason: "no" }, 1, null]) {
      expect(accept(patternValueSchema, value)).toBe(false);
    }
  });
});

describe("permission configuration", () => {
  it("accepts an empty permission map", () => {
    expect(permissionConfigSchema.parse({})).toEqual({});
  });

  it("accepts a surface catch-all string", () => {
    expect(accept(permissionConfigSchema, { bash: "ask" })).toBe(true);
    expect(accept(permissionConfigSchema, { "*": "allow" })).toBe(true);
  });

  it("accepts a pattern map for a surface", () => {
    expect(accept(permissionConfigSchema, { bash: { "ls": "allow", "rm -rf /": "deny" } })).toBe(true);
    expect(accept(permissionConfigSchema, {
      bash: { "git status": { action: "deny", reason: "use the status tool" } },
    })).toBe(true);
    expect(accept(permissionConfigSchema, { path_write: { "**/*.env": "deny" } })).toBe(true);
  });

  it("distinguishes an empty pattern map from an empty pattern key", () => {
    expect(accept(permissionConfigSchema, { bash: {} })).toBe(true);
    expect(accept(permissionConfigSchema, { bash: { "": "allow" } })).toBe(false);
    expect(issueCodes(permissionConfigSchema, { bash: { "": "allow" } })).toEqual(["invalid-key"]);
    expect(issuePaths(permissionConfigSchema, { bash: { "": "allow" } })).toEqual(["bash[\"\"]"]);
  });

  it("rejects an empty surface key", () => {
    expect(accept(permissionConfigSchema, { "": "allow" })).toBe(false);
    expect(issueCodes(permissionConfigSchema, { "": "allow" })).toEqual(["invalid-key"]);
  });

  it("accepts every named surface and rejects misspelled directions", () => {
    expect(NAMED_PERMISSION_SURFACES).toEqual([
      "*", "path", "path_read", "path_write", "external_directory",
      "external_directory_read", "external_directory_write", "bash", "mcp", "skill",
    ]);
    expect(DIRECTIONAL_PERMISSION_SURFACE_NAMES).toEqual([
      "path_read", "path_write", "external_directory_read", "external_directory_write",
    ]);
    for (const surface of NAMED_PERMISSION_SURFACES) {
      expect(accept(permissionConfigSchema, { [surface]: "ask" })).toBe(true);
    }
    expect(accept(permissionConfigSchema, { read: "allow", write: "deny" })).toBe(true);
    for (const surface of ["path_reed", "path_writee", "external_directory_reed", "path_", "external_directory_x"]) {
      expect(accept(permissionConfigSchema, { [surface]: "allow" })).toBe(false);
    }
  });

  it("accepts a catch-all for an arbitrary tool name", () => {
    expect(accept(permissionConfigSchema, { my_tool: "allow" })).toBe(true);
    expect(accept(permissionConfigSchema, { "mcp__server__tool": { "*": "ask" } })).toBe(true);
  });

  it("rejects malformed surface values", () => {
    expect(accept(permissionConfigSchema, { bash: 1 })).toBe(false);
    expect(accept(permissionConfigSchema, { bash: null })).toBe(false);
    expect(accept(permissionConfigSchema, { bash: ["allow"] })).toBe(false);
    expect(accept(permissionConfigSchema, { bash: { ls: "permit" } })).toBe(false);
    expect(accept(permissionConfigSchema, { bash: { ls: { action: "ask" } } })).toBe(false);
    expect(accept(permissionConfigSchema, [] as unknown)).toBe(false);
  });

  it("reports the offending surface path", () => {
    expect(issuePaths(permissionConfigSchema, { bash: { ls: "permit" } })).toEqual(["bash.ls"]);
    expect(issuePaths(permissionConfigSchema, { path_reed: "allow" })).toEqual(["path_reed"]);
  });
});

describe("permission JSON schema", () => {
  const jsonSchema = z.toJSONSchema(permissionConfigSchema, { target: "draft-2020-12", io: "input" }) as Record<string, unknown>;

  it("publishes the draft 2020-12 object form with per-key value validation", () => {
    expect(jsonSchema["$schema"]).toBe("https://json-schema.org/draft/2020-12/schema");
    expect(jsonSchema.type).toBe("object");
    expect(jsonSchema.propertyNames).toEqual({ type: "string", minLength: 1 });
    expect(jsonSchema.additionalProperties).toBeTypeOf("object");
  });
});
