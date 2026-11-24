import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
  BINDABLE_DIALOG_PUNCTUATION,
  DEFAULT_DIALOG_KEYS,
  DIALOG_KEY_ACTIONS,
  RESERVED_DIALOG_KEYS,
  isBindableDialogKey,
  permissionDialogKeysSchema,
  resolveDialogKeys,
  type DialogKeyIssue,
} from "#config/dialog-keys";

/** The default shortcut per dialog action, written out independently of the module. */
const EXPECTED_DEFAULTS = {
  approve: "y",
  approveSession: "s",
  approveSessionBoth: "b",
  deny: "n",
  denyWithReason: "r",
} as const;

/** Printable ASCII punctuation minus "+", the set a dialog shortcut may use. */
const EXPECTED_PUNCTUATION = [
  "!",
  "\"",
  "#",
  "$",
  "%",
  "&",
  "'",
  "(",
  ")",
  "*",
  ",",
  "-",
  ".",
  "/",
  ":",
  ";",
  "<",
  "=",
  ">",
  "?",
  "@",
  "[",
  "\\",
  "]",
  "^",
  "_",
  "`",
  "{",
  "|",
  "}",
  "~",
] as const;

function accept(schema: z.ZodType, value: unknown): boolean {
  return schema.safeParse(value).success;
}

function issuesFor(value: unknown): readonly DialogKeyIssue[] {
  return resolveDialogKeys(value).issues;
}

describe("dialog key definitions", () => {
  it("maps every action to its default character and freezes the table", () => {
    expect(DEFAULT_DIALOG_KEYS).toEqual(EXPECTED_DEFAULTS);
    expect(Object.isFrozen(DEFAULT_DIALOG_KEYS)).toBe(true);
  });

  it("reserves j and k for navigation", () => {
    expect(RESERVED_DIALOG_KEYS).toEqual(["j", "k"]);
  });

  it("publishes printable punctuation except the key modifier", () => {
    expect([...BINDABLE_DIALOG_PUNCTUATION]).toEqual(EXPECTED_PUNCTUATION);
    expect(BINDABLE_DIALOG_PUNCTUATION).not.toContain("+");
    for (const character of BINDABLE_DIALOG_PUNCTUATION) {
      expect(character).toHaveLength(1);
      expect(character.trim()).toBe(character);
    }
  });
});

describe("bindable dialog characters", () => {
  const bindable = ["a", "z", "0", "9", "j", "k", "-", "?", "~", "/", "=", ":"];
  for (const value of bindable) {
    it(`accepts ${JSON.stringify(value)}`, () => {
      expect(isBindableDialogKey(value)).toBe(true);
    });
  }

  const unbindable = ["A", "Z", "+", " ", "", "yy", "1.5", "é", "\t"];
  for (const value of unbindable) {
    it(`rejects ${JSON.stringify(value)}`, () => {
      expect(isBindableDialogKey(value)).toBe(false);
    });
  }
});

describe("resolveDialogKeys", () => {
  it("returns the default table for an empty configuration", () => {
    expect(resolveDialogKeys({})).toEqual({ keys: EXPECTED_DEFAULTS, issues: [] });
  });

  const nonObjectInputs: readonly [string, unknown][] = [
    ["null", null],
    ["undefined", undefined],
    ["an array", ["approve", "y"]],
    ["a string", "approve: y"],
    ["a number", 7],
  ];
  for (const [label, input] of nonObjectInputs) {
    it(`falls back to the default table for ${label}`, () => {
      expect(resolveDialogKeys(input)).toEqual({ keys: EXPECTED_DEFAULTS, issues: [] });
    });
  }

  it("returns a fresh table of all five actions", () => {
    const { keys } = resolveDialogKeys({});
    expect(keys).not.toBe(DEFAULT_DIALOG_KEYS);
    expect(Object.keys(keys)).toEqual([...DIALOG_KEY_ACTIONS]);
  });

  it("applies a single override", () => {
    expect(resolveDialogKeys({ approve: "a" })).toEqual({
      keys: { ...EXPECTED_DEFAULTS, approve: "a" },
      issues: [],
    });
  });

  it("applies several independent overrides", () => {
    expect(resolveDialogKeys({ approve: "a", approveSession: "c", deny: "x" })).toEqual({
      keys: {
        approve: "a",
        approveSession: "c",
        approveSessionBoth: "b",
        deny: "x",
        denyWithReason: "r",
      },
      issues: [],
    });
  });

  it("keeps every action bound when only some are overridden", () => {
    const { keys } = resolveDialogKeys({ deny: "?" });
    expect(Object.keys(keys)).toEqual([...DIALOG_KEY_ACTIONS]);
    expect(keys.deny).toBe("?");
    expect(keys.approve).toBe("y");
  });

  it("ignores unknown action keys without reporting a problem", () => {
    for (const input of [
      { approveAll: "n" },
      { approveSession_other: "s" },
      { extra: "anything" },
      { extra: 7 },
      { approve: "a", extra: "zzz" },
    ]) {
      expect(issuesFor(input)).toEqual([]);
    }
    expect(resolveDialogKeys({ extra: "n" })).toEqual({ keys: EXPECTED_DEFAULTS, issues: [] });
  });

  it("falls back to the default for an uppercase letter", () => {
    expect(resolveDialogKeys({ approve: "A" })).toEqual({
      keys: EXPECTED_DEFAULTS,
      issues: [{ action: "approve", value: "A", code: "unbindable" }],
    });
  });

  it("treats the key modifier character + as unbindable", () => {
    expect(issuesFor({ approve: "+" })).toEqual([{ action: "approve", value: "+", code: "unbindable" }]);
    expect(resolveDialogKeys({ approve: "+" }).keys).toEqual(EXPECTED_DEFAULTS);
  });

  for (const reserved of ["j", "k"]) {
    it(`reports the navigation character ${reserved} as reserved`, () => {
      expect(resolveDialogKeys({ deny: reserved })).toEqual({
        keys: EXPECTED_DEFAULTS,
        issues: [{ action: "deny", value: reserved, code: "reserved" }],
      });
    });
  }

  it("treats a multi-character binding as unbindable", () => {
    expect(resolveDialogKeys({ approve: "yy" })).toEqual({
      keys: EXPECTED_DEFAULTS,
      issues: [{ action: "approve", value: "yy", code: "unbindable" }],
    });
  });

  const nonStringValues: readonly [string, unknown, string][] = [
    ["null", null, "null"],
    ["a number", 7, "7"],
    ["a boolean", true, "true"],
    ["an object", { key: "y" }, "[object Object]"],
    ["an array", ["y"], "y"],
  ];
  for (const [label, value, rendered] of nonStringValues) {
    it(`reports ${label} as an unbindable value`, () => {
      expect(resolveDialogKeys({ approve: value })).toEqual({
        keys: EXPECTED_DEFAULTS,
        issues: [{ action: "approve", value: rendered, code: "unbindable" }],
      });
    });
  }

  it("removes an override that collides with another action's default", () => {
    expect(resolveDialogKeys({ approve: "n" })).toEqual({
      keys: EXPECTED_DEFAULTS,
      issues: [{ action: "approve", value: "n", code: "conflict" }],
    });
  });

  it("accepts a swap of two default characters", () => {
    expect(resolveDialogKeys({ approve: "n", deny: "y" })).toEqual({
      keys: { ...EXPECTED_DEFAULTS, approve: "n", deny: "y" },
      issues: [],
    });
  });

  it("resolves a collision between an override and another override", () => {
    expect(resolveDialogKeys({ approve: "r", deny: "r" })).toEqual({
      keys: EXPECTED_DEFAULTS,
      issues: [
        { action: "approve", value: "r", code: "conflict" },
        { action: "deny", value: "r", code: "conflict" },
      ],
    });
  });

  it("resolves a redundant override that repeats its own default", () => {
    // approve takes over approveSession's default "s". The explicit
    // approveSession:"s" changes nothing, so only the approve override is
    // removed and the final table is unique.
    expect(resolveDialogKeys({ approve: "s", approveSession: "s" })).toEqual({
      keys: EXPECTED_DEFAULTS,
      issues: [{ action: "approve", value: "s", code: "conflict" }],
    });
  });

  it("resolves several actions competing for the same character", () => {
    expect(resolveDialogKeys({ approve: "x", approveSession: "x", deny: "x" })).toEqual({
      keys: { ...EXPECTED_DEFAULTS, approve: "x" },
      issues: [
        { action: "approveSession", value: "x", code: "conflict" },
        { action: "deny", value: "x", code: "conflict" },
      ],
    });
  });

  it("keeps the first override when later ones collide with it", () => {
    expect(resolveDialogKeys({ approve: "q", approveSession: "q" })).toEqual({
      keys: { ...EXPECTED_DEFAULTS, approve: "q" },
      issues: [{ action: "approveSession", value: "q", code: "conflict" }],
    });
  });

  it("never mutates the shared default table", () => {
    resolveDialogKeys({ approve: "n", deny: "y", denyWithReason: "r" });
    expect(DEFAULT_DIALOG_KEYS).toEqual(EXPECTED_DEFAULTS);
  });
});

describe("permissionDialogKeysSchema", () => {
  it("accepts an empty display preference map", () => {
    expect(permissionDialogKeysSchema.parse({})).toEqual({});
  });

  it("accepts known, unknown and malformed bindings alike", () => {
    const displayPreferences = {
      approve: "a",
      approveSession: "j",
      approveSessionBoth: "A+",
      unknownAction: "7",
    };
    expect(permissionDialogKeysSchema.parse(displayPreferences)).toEqual(displayPreferences);
  });

  it("rejects maps whose values are not strings", () => {
    expect(accept(permissionDialogKeysSchema, { approve: 1 })).toBe(false);
    expect(accept(permissionDialogKeysSchema, { approve: null })).toBe(false);
    expect(accept(permissionDialogKeysSchema, { approve: ["a"] })).toBe(false);
    expect(accept(permissionDialogKeysSchema, { approve: {} })).toBe(false);
  });

  it("rejects non-object documents", () => {
    expect(accept(permissionDialogKeysSchema, null)).toBe(false);
    expect(accept(permissionDialogKeysSchema, [])).toBe(false);
    expect(accept(permissionDialogKeysSchema, "approve")).toBe(false);
  });

  it("exports as a draft 2020-12 object schema", () => {
    const jsonSchema = z.toJSONSchema(permissionDialogKeysSchema, {
      target: "draft-2020-12",
      io: "input",
    }) as Record<string, unknown>;
    expect(jsonSchema["$schema"]).toBe("https://json-schema.org/draft/2020-12/schema");
    expect(jsonSchema.type).toBe("object");
    expect(jsonSchema.additionalProperties).toEqual({ type: "string" });
  });
});
