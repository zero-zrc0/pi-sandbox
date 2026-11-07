import { wrapperKindOf, type CommandWord } from "./wrapper-analysis";
import { hasGuardedOption } from "./option-guards";
import { PURE_READER_CORE } from "./command-effects";

type Effects = "read" | "write" | readonly ("read" | "write")[];

export interface EffectDeclaration {
  readonly effects?: Effects;
  readonly unlessOption?: readonly string[];
  readonly subcommands?: Readonly<Record<string, EffectDeclaration | Effects>>;
}

export interface EffectDeclarations {
  readonly global?: Readonly<Record<string, EffectDeclaration>>;
  readonly project?: Readonly<Record<string, EffectDeclaration>>;
}

export interface DeclaredEffect {
  readonly effect: "read" | "write" | "unknown" | "inert";
  readonly source: "global-declared" | "project-declared" | "declaration-retracted";
}

export function declaredCommandEffect(words: readonly CommandWord[], declarations: EffectDeclarations): DeclaredEffect | undefined {
  const name = words[0];
  if (!name || name.computed || /[\\/]/.test(name.value)) return undefined;
  if (PURE_READER_CORE.has(name.value) || wrapperKindOf(name.value, words)) return undefined;
  const entry = declarations.project?.[name.value] ?? declarations.global?.[name.value];
  if (!entry) return undefined;
  const source = declarations.project?.[name.value] ? "project-declared" : "global-declared";
  let selected = entry;
  const guards = [...(entry.unlessOption ?? [])];
  for (const word of words.slice(1)) {
    if (!selected.subcommands || Object.keys(selected.subcommands).length === 0) break;
    if (word.computed || word.value.startsWith("-")) return { effect: "unknown", source };
    const child = selected.subcommands[word.value];
    if (!child) break;
    selected = typeof child === "string" || Array.isArray(child) ? { effects: child as Effects } : child as EffectDeclaration;
    guards.push(...(selected.unlessOption ?? []));
  }
  if (hasGuardedOption(words.slice(1), guards)) return { effect: "unknown", source: "declaration-retracted" };
  const effects = selected.effects;
  const unique = Array.isArray(effects) ? [...new Set(effects)] : undefined;
  const effect = typeof effects === "string" ? effects : !unique ? "unknown" : unique.length === 0 ? "inert" : unique.length === 1 ? unique[0]! : "unknown";
  return { effect, source };
}
