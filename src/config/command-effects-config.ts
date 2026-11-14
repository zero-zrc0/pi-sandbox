/**
 * Declared command effects for the permission engine (config schema §3).
 *
 * A `commandEffects` entry maps a bare command name to a recursive declaration
 * of what that command does to the filesystem, optionally refined per
 * subcommand and guarded by option stems. This module only declares and
 * validates the model; loading, source folding and merging belong to the
 * configuration loader. Agent frontmatter is not a declaration channel here.
 *
 * The shape is compatible with the runtime consumer in
 * `src/approve-core/utils/access-intent/bash/declared-command-effects.ts`, which
 * reads `effects`, `unlessOption` and `subcommands` from each declaration.
 */
import { z } from "zod";

/** A single filesystem effect of a command invocation. */
export type CommandEffect = "read" | "write";

/** One effect, or a list of effects where an empty list means no file access. */
export type CommandEffectList = CommandEffect | readonly CommandEffect[];

/** Recursive declaration for one command or subcommand. */
export interface CommandEffectDeclaration {
  readonly effects?: CommandEffectList;
  readonly unlessOption?: readonly string[];
  readonly subcommands?: Readonly<Record<string, CommandEffectDeclaration | CommandEffectList>>;
}

/** Bare command name to its recursive declaration. */
export type CommandEffectDeclarations = Readonly<Record<string, CommandEffectDeclaration>>;

const commandEffectValueSchema = z.enum(["read", "write"]);

/** A declaration's own effect list: a single effect or an array of effects. */
export const commandEffectListSchema: z.ZodType<CommandEffectList> = z.union([
  commandEffectValueSchema,
  z.array(commandEffectValueSchema),
]);

const PATH_SEPARATOR = /[\\/]/u;
const WHITESPACE = /\s/u;

/** A command key is a bare command name: non-empty, no path separator, no whitespace. */
const commandKeySchema = z
  .string()
  .min(1, "expected a non-empty command key")
  .refine((key) => !PATH_SEPARATOR.test(key), "expected a command key without a path separator")
  .refine((key) => !WHITESPACE.test(key), "expected a command key without whitespace");

/** A subcommand key is non-empty, contains no whitespace and cannot look like an option. */
const subcommandKeySchema = z
  .string()
  .min(1, "expected a non-empty subcommand key")
  .refine((key) => !WHITESPACE.test(key), "expected a subcommand key without whitespace")
  .refine((key) => !key.startsWith("-"), "expected a subcommand key that does not start with a dash");

/** An option stem starts with a dash, has at least two characters, and carries no value. */
const unlessOptionSchema = z
  .string()
  .min(2, "expected an option stem with at least two characters")
  .refine((option) => option.startsWith("-"), "expected an option stem that starts with a dash")
  .refine((option) => !WHITESPACE.test(option), "expected an option stem without whitespace")
  .refine((option) => !option.includes("="), "expected an option stem without an equals sign");

/**
 * One command or subcommand declaration.
 *
 * Strict: only `effects`, `unlessOption` and `subcommands` are allowed, all of
 * them optional. `subcommands` values are either a nested declaration or an
 * effects shorthand (a string or an array of effects).
 */
export const commandEffectDeclarationSchema: z.ZodType<CommandEffectDeclaration> = z
  .lazy(() =>
    z.strictObject({
      effects: commandEffectListSchema.optional(),
      unlessOption: z.array(unlessOptionSchema).optional(),
      subcommands: z
        .record(
          subcommandKeySchema,
          z.union([commandEffectDeclarationSchema, commandEffectListSchema]),
        )
        .optional(),
    }),
  )
  // The id only names the recursive `$defs` entry in the published JSON Schema.
  .meta({ id: "CommandEffectDeclaration" });

/** The `commandEffects` map: bare command name to a strict recursive declaration. */
export const commandEffectsSchema: z.ZodType<CommandEffectDeclarations> = z.record(
  commandKeySchema,
  commandEffectDeclarationSchema,
);

export type CommandEffects = z.infer<typeof commandEffectsSchema>;
