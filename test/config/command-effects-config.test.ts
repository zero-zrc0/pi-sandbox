import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
  commandEffectDeclarationSchema,
  commandEffectListSchema,
  commandEffectsSchema,
} from "#config/command-effects-config";
import { issuesFromZodError } from "#config/config-schema";

function accept(schema: z.ZodType, value: unknown): boolean {
  return schema.safeParse(value).success;
}

function issuePaths(schema: z.ZodType, value: unknown): readonly string[] {
  const result = schema.safeParse(value);
  if (result.success) return [];
  return issuesFromZodError(result.error).map((issue) => issue.path);
}

describe("command effect lists", () => {
  const validEffects: readonly unknown[] = [
    "read",
    "write",
    ["read"],
    ["write"],
    ["read", "write"],
    [],
  ];
  for (const effect of validEffects) {
    it(`accepts ${JSON.stringify(effect)}`, () => {
      expect(accept(commandEffectListSchema, effect)).toBe(true);
    });
  }

  const invalidEffects: readonly unknown[] = [
    "execute",
    "READ",
    "",
    "read write",
    1,
    null,
    {},
    ["read", "execute"],
    ["read", 1],
  ];
  for (const effect of invalidEffects) {
    it(`rejects ${JSON.stringify(effect)}`, () => {
      expect(accept(commandEffectListSchema, effect)).toBe(false);
    });
  }

  it("keeps the parsed effect values untouched", () => {
    expect(commandEffectListSchema.parse("read")).toBe("read");
    expect(commandEffectListSchema.parse(["read", "write"])).toEqual(["read", "write"]);
    expect(commandEffectListSchema.parse([])).toEqual([]);
  });
});

describe("command effect declarations", () => {
  it("accepts an empty declaration", () => {
    expect(commandEffectDeclarationSchema.parse({})).toEqual({});
  });

  const validDeclarations: readonly unknown[] = [
    { effects: "read" },
    { effects: ["read", "write"] },
    { effects: [] },
    { unlessOption: ["-v"] },
    { unlessOption: ["-v", "--dry-run"] },
    { effects: "write", unlessOption: ["--force"] },
    { subcommands: { status: "read" } },
  ];
  for (const declaration of validDeclarations) {
    it(`accepts ${JSON.stringify(declaration)}`, () => {
      expect(accept(commandEffectDeclarationSchema, declaration)).toBe(true);
    });
  }

  it("rejects unknown entry fields", () => {
    for (const declaration of [
      { effects: "read", extra: true },
      { command: "git" },
      { source: "agent" },
      { subcommands: { status: "read" }, agent: "reviewer" },
    ]) {
      expect(accept(commandEffectDeclarationSchema, declaration)).toBe(false);
    }
    const result = commandEffectDeclarationSchema.safeParse({ effects: "read", extra: true });
    expect(result.success).toBe(false);
    if (result.success) return;
    const [issue] = issuesFromZodError(result.error);
    expect(issue).toMatchObject({ path: "extra", code: "unknown-key" });
  });

  it("accepts subcommand shorthand as a string or an array", () => {
    const parsed = commandEffectDeclarationSchema.parse({
      subcommands: {
        status: "read",
        commit: "write",
        diff: ["read", "write"],
        noop: [],
      },
    });
    expect(parsed).toEqual({
      subcommands: {
        status: "read",
        commit: "write",
        diff: ["read", "write"],
        noop: [],
      },
    });
  });

  it("accepts nested subcommand declarations", () => {
    const declaration = {
      effects: "read",
      unlessOption: ["--dry-run"],
      subcommands: {
        remote: {
          subcommands: {
            add: "write",
            show: ["read", "write"],
            prune: { effects: "write", unlessOption: ["--dry-run"] },
          },
        },
        status: "read",
      },
    };
    expect(commandEffectDeclarationSchema.parse(declaration)).toEqual(declaration);
  });

  it("rejects malformed subcommand keys", () => {
    for (const key of ["", "-v", "--dry-run", "a b", "a\tb", " git"]) {
      expect(accept(commandEffectDeclarationSchema, { subcommands: { [key]: "read" } })).toBe(false);
    }
    expect(issuePaths(commandEffectDeclarationSchema, { subcommands: { "": "read" } })).toEqual([
      "subcommands[\"\"]",
    ]);
  });

  it("rejects malformed subcommand values", () => {
    for (const value of [1, null, "execute", ["read", "execute"], { effects: "execute" }, { unknown: true }]) {
      expect(accept(commandEffectDeclarationSchema, { subcommands: { status: value } })).toBe(false);
    }
  });

  it("accepts dash-prefixed option stems", () => {
    for (const option of ["-v", "-q", "--dry-run", "--force", "-abc"]) {
      expect(accept(commandEffectDeclarationSchema, { unlessOption: [option] })).toBe(true);
    }
  });

  it("rejects malformed option stems", () => {
    for (const option of ["", "-", "--dry run", "--a=b", "x", "dry-run", "-a b"]) {
      expect(accept(commandEffectDeclarationSchema, { unlessOption: [option] })).toBe(false);
    }
    expect(accept(commandEffectDeclarationSchema, { unlessOption: "-v" })).toBe(false);
    expect(accept(commandEffectDeclarationSchema, { unlessOption: [1] })).toBe(false);
  });
});

describe("command effects map", () => {
  it("accepts an empty map", () => {
    expect(commandEffectsSchema.parse({})).toEqual({});
  });

  it("rejects a non-object document", () => {
    expect(accept(commandEffectsSchema, null)).toBe(false);
    expect(accept(commandEffectsSchema, [])).toBe(false);
    expect(accept(commandEffectsSchema, "git")).toBe(false);
  });

  it("accepts bare commands with recursive declarations", () => {
    const declarations = {
      git: {
        effects: "read",
        subcommands: {
          status: "read",
          remote: {
            subcommands: {
              add: "write",
              show: ["read", "write"],
            },
          },
        },
      },
      npm: { effects: ["write"], unlessOption: ["--dry-run"] },
      rg: {},
    };
    expect(commandEffectsSchema.parse(declarations)).toEqual(declarations);
  });

  it("rejects command keys with path separators or whitespace", () => {
    for (const key of ["", "git/status", "git\\status", "git status", "git\tstatus", "git\nstatus"]) {
      expect(accept(commandEffectsSchema, { [key]: {} })).toBe(false);
    }
    expect(issuePaths(commandEffectsSchema, { "git/status": {} })).toEqual(["[\"git/status\"]"]);
  });

  it("rejects unknown fields at every declaration level", () => {
    expect(accept(commandEffectsSchema, { git: { effects: "read", unknown: 1 } })).toBe(false);
    expect(accept(commandEffectsSchema, {
      git: { subcommands: { status: { effects: "read", unknown: 1 } } },
    })).toBe(false);
  });

  it("does not accept an agent frontmatter declaration channel", () => {
    expect(accept(commandEffectsSchema, { git: { effects: "read", source: "agent" } })).toBe(false);
    expect(accept(commandEffectsSchema, { git: { effects: "read", frontmatter: true } })).toBe(false);
  });

  it("rejects malformed declarations inside the map", () => {
    expect(accept(commandEffectsSchema, { git: "read" })).toBe(false);
    expect(accept(commandEffectsSchema, { git: ["read"] })).toBe(false);
    expect(accept(commandEffectsSchema, { git: { effects: "execute" } })).toBe(false);
  });
});

describe("command effects JSON schema", () => {
  const jsonSchemaOptions = { target: "draft-2020-12", io: "input" } as const;

  it("exports the effect list without throwing", () => {
    expect(() => z.toJSONSchema(commandEffectListSchema, jsonSchemaOptions)).not.toThrow();
    const jsonSchema = z.toJSONSchema(commandEffectListSchema, jsonSchemaOptions) as Record<string, unknown>;
    expect(jsonSchema["$schema"]).toBe("https://json-schema.org/draft/2020-12/schema");
    expect(jsonSchema.anyOf).toBeInstanceOf(Array);
  });

  it("exports the recursive declaration without throwing", () => {
    expect(() => z.toJSONSchema(commandEffectDeclarationSchema, jsonSchemaOptions)).not.toThrow();
    const jsonSchema = z.toJSONSchema(commandEffectDeclarationSchema, jsonSchemaOptions) as Record<string, unknown>;
    expect(jsonSchema.type).toBe("object");
  });

  it("exports the declaration map without throwing", () => {
    expect(() => z.toJSONSchema(commandEffectsSchema, jsonSchemaOptions)).not.toThrow();
    const jsonSchema = z.toJSONSchema(commandEffectsSchema, jsonSchemaOptions) as Record<string, unknown>;
    expect(jsonSchema["$schema"]).toBe("https://json-schema.org/draft/2020-12/schema");
    expect(jsonSchema.type).toBe("object");
    expect(jsonSchema.additionalProperties).toBeTypeOf("object");
  });
});
