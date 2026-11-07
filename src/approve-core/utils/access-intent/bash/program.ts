/**
 * Shared Bash program view.
 *
 * One parse per tool call feeds every consumer: the ordered command units, the
 * path-rule candidates, the deduplicated external accesses and each unit's
 * equivalent spellings. Both entries build the same immutable view; the sync
 * entry refuses to wait for a cold parser, and the async entry primes one.
 */
import type { BashCommand } from "./command-enumeration";
import { enumerateCommands, withPathEquivalents } from "./command-enumeration";
import {
  bashParser,
  type LocalReparser,
  type SyntaxNode,
  type SyntaxParser,
  type SyntaxTree,
} from "./parser";
import {
  scanRebindings,
  type ReboundVariables,
  type ShellWordContext,
} from "./shell-variable-expansion";
import { withSalvagedRoots } from "./unresolved-salvage";
import type { PathNormalizer } from "../../path/path-normalizer";

export interface PathFactValue {
  value(): string;
  matchValues(): readonly string[];
}

export interface PathFactEffect {
  readonly effect: "read" | "write" | "unknown";
}

export interface PathRuleCandidate {
  readonly path: PathFactValue;
  readonly effect: PathFactEffect;
}

export type ExternalAccess = PathRuleCandidate;

export interface BashPathFacts {
  readonly pathRuleCandidates: readonly PathRuleCandidate[];
  readonly externalAccesses: readonly ExternalAccess[];
  readonly absoluteSpellings?: readonly { readonly startIndex: number; readonly endIndex: number; readonly value: string }[];
}

export interface BashProgramRoot {
  readonly root: SyntaxNode;
  /** Text the root's local offsets slice; a salvage root uses its region. */
  readonly source: string;
  readonly salvaged: boolean;
  readonly region?: { readonly startIndex: number; readonly endIndex: number };
}

export interface BashPathFactsInput {
  readonly source: string;
  readonly roots: readonly BashProgramRoot[];
  readonly commands: readonly BashCommand[];
  readonly normalizer: PathNormalizer;
  /** Effective initial working directory after applying the optional workdir. */
  readonly workdir: string;
  readonly baseDir: string;
  readonly homeRebound: boolean;
  readonly pwdRebound: boolean;
  readonly home?: string;
  readonly commandEffects?: unknown;
}

export type BashPathFactsProvider = (input: BashPathFactsInput) => BashPathFacts;

export interface BashProgramOptions {
  /** Injected corrected parser; production uses the shared runtime. */
  readonly parser?: SyntaxParser;
  /** Injected reparser for unresolved regions; defaults to the raw parser. */
  readonly reparser?: LocalReparser;
  /** Optional initial `cd`, resolved against the normalizer's cwd. */
  readonly workdir?: string;
  /** Home used for static `~`/`$HOME` expansion. */
  readonly home?: string;
  /** Declared command effects snapshot; path analysis consumes it. */
  readonly commandEffects?: unknown;
  /** Path-analysis provider supplied by the path domain. */
  readonly pathFacts?: BashPathFactsProvider;
}

const EMPTY_PATH_FACTS: BashPathFacts = Object.freeze({
  pathRuleCandidates: Object.freeze([]),
  externalAccesses: Object.freeze([]),
});

/** Internal frozen view. Callers treat it as opaque. */
export interface BashProgramView {
  readonly source: string;
  readonly baseDir: string;
  readonly commands: readonly BashCommand[];
  readonly pathFacts: BashPathFacts;
  readonly rebinding: ReboundVariables;
  readonly parsed: boolean;
  readonly parseUnresolved: boolean;
  readonly pathFactsAvailable: boolean;
}

function freezePathFacts(facts: BashPathFacts): BashPathFacts {
  const seen = new Set<string>();
  const externalAccesses: ExternalAccess[] = [];
  for (const access of facts.externalAccesses) {
    const key = `${access.effect.effect}\0${access.path.value()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    externalAccesses.push(access);
  }
  return Object.freeze({
    pathRuleCandidates: Object.freeze([...facts.pathRuleCandidates]),
    externalAccesses: Object.freeze(externalAccesses),
    ...(facts.absoluteSpellings ? { absoluteSpellings: Object.freeze([...facts.absoluteSpellings]) } : {}),
  });
}

export class BashProgram {
  private constructor(private readonly view: BashProgramView) {}

  /** Wrap a frozen view. Used by the module's parser entry points. */
  static fromView(view: BashProgramView): BashProgram {
    return new BashProgram(view);
  }

  static async parse(
    command: string,
    normalizer: PathNormalizer,
    options: BashProgramOptions = {},
  ): Promise<BashProgram> {
    const parser = options.parser ?? await bashParser.corrected();
    const reparser = options.reparser ?? (
      options.parser === undefined ? await bashParser.raw() : parser
    );
    return build(command, normalizer, parser, reparser, options);
  }

  /**
   * The advisory entry. It never waits: a cold parser yields `undefined`, and
   * callers fall back to a whole-command rule match.
   */
  static parseSync(
    command: string,
    normalizer: PathNormalizer,
    options: BashProgramOptions = {},
  ): BashProgram | undefined {
    const parser = options.parser ?? bashParser.warm();
    if (parser === undefined) return undefined;
    return build(command, normalizer, parser, options.reparser ?? parser, options);
  }

  get source(): string {
    return this.view.source;
  }

  commands(): readonly BashCommand[] {
    return this.view.commands;
  }

  pathRuleCandidates(): readonly PathRuleCandidate[] {
    return this.view.pathFacts.pathRuleCandidates;
  }

  externalAccesses(): readonly ExternalAccess[] {
    return this.view.pathFacts.externalAccesses;
  }

  get parsed(): boolean {
    return this.view.parsed;
  }

  get parseUnresolved(): boolean {
    return this.view.parseUnresolved;
  }

  get pathFactsAvailable(): boolean {
    return this.view.pathFactsAvailable;
  }

  get rebinding(): ReboundVariables {
    return this.view.rebinding;
  }

  get baseDir(): string {
    return this.view.baseDir;
  }
}

function build(
  command: string,
  normalizer: PathNormalizer,
  parser: SyntaxParser,
  reparser: LocalReparser,
  options: BashProgramOptions,
): BashProgram {
  const workdir = options.workdir;
  const baseDir = workdir === undefined ? normalizer.cwd
    : !workdir || workdir === "-" || workdir.startsWith("~") || /[$`*?\[\]{}]/.test(workdir) || normalizer.interpretCd(workdir).kind === "unknown"
      ? ""
      : normalizer.resolveCdOffset(normalizer.cwd, workdir);
  const home = options.home ?? normalizer.home;
  const tree: SyntaxTree | null = parser.parse(command);
  if (tree === null) {
    return BashProgram.fromView({
      source: command,
      baseDir,
      commands: Object.freeze([]),
      pathFacts: EMPTY_PATH_FACTS,
      rebinding: { home: false, pwd: false },
      parsed: false,
      parseUnresolved: true,
      pathFactsAvailable: false,
    });
  }

  try {
    const view = withSalvagedRoots(tree.rootNode, { source: command, reparser }, (salvaged) => {
      const roots: readonly BashProgramRoot[] = Object.freeze([
        { root: tree.rootNode, source: command, salvaged: false },
        ...salvaged.map((entry) => Object.freeze({
          root: entry.root,
          source: command.slice(entry.region.startIndex, entry.region.endIndex),
          salvaged: true,
          region: entry.region,
        })),
      ]);
      const rebinding = scanRebindings(roots.map((entry) => entry.root));
      const wordContext: ShellWordContext = {
        home,
        homeRebound: rebinding.home,
        pwdRebound: rebinding.pwd,
      };
      const isAbsolutePath = (value: string): boolean => normalizer.isAbsolute(value);

      const main = enumerateCommands(tree.rootNode, {
        source: command,
        wordContext,
        isAbsolutePath,
        salvaged: false,
      });
      const salvagedUnits = salvaged.flatMap((entry) =>
        enumerateCommands(entry.root, {
          source: command.slice(entry.region.startIndex, entry.region.endIndex),
          wordContext,
          isAbsolutePath,
          salvaged: true,
        })
      );
      let commands: readonly BashCommand[] = Object.freeze([...main, ...salvagedUnits]);

      const pathFacts = options.pathFacts === undefined
        ? EMPTY_PATH_FACTS
        : freezePathFacts(options.pathFacts({
            source: command,
            roots,
            commands,
            normalizer,
            workdir: baseDir,
            baseDir,
            homeRebound: rebinding.home,
            pwdRebound: rebinding.pwd,
            home,
            ...(options.commandEffects === undefined
              ? {}
              : { commandEffects: options.commandEffects }),
          }));

      if (pathFacts.absoluteSpellings?.length) {
        commands = Object.freeze(commands.map((unit) => withPathEquivalents(unit, pathFacts.absoluteSpellings!)));
      }

      return {
        source: command,
        baseDir,
        commands,
        pathFacts,
        rebinding,
        parsed: true,
        parseUnresolved: tree.rootNode.hasError || salvagedUnits.length > 0,
        pathFactsAvailable: options.pathFacts !== undefined,
      };
    });
    return BashProgram.fromView(view);
  } finally {
    tree.delete();
  }
}
