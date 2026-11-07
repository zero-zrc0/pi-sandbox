import type { PathNormalizer } from "../../path/path-normalizer";
import type { BashPathFacts, BashPathFactsInput, PathRuleCandidate } from "./program";
import { collectPathTokens, type PathToken } from "./token-collection";
import { classifyPathToken } from "./token-classification";
import { isSafeDevice } from "../../path/safe-system-paths";
import { isOutsideCanonicalCwd } from "../../path/path-containment";
import { trackWorkingDirectories } from "./cwd-tracking";
import type { EffectDeclarations } from "./declared-command-effects";

export interface LocatedPathToken extends PathToken {
  readonly baseDir?: string;
}

export function bashPathFacts(input: BashPathFactsInput): BashPathFacts {
  const context = { home: input.home ?? input.normalizer.home, homeRebound: input.homeRebound, pwdRebound: input.pwdRebound };
  const declarations = (input.commandEffects ?? {}) as EffectDeclarations;
  const tokens: LocatedPathToken[] = [];
  for (const root of input.roots) {
    const bases = trackWorkingDirectories(root.root, input.normalizer, root.salvaged ? undefined : input.baseDir || undefined, context);
    for (const item of collectPathTokens(root.root, context, declarations)) {
      if (input.homeRebound && /^(?:~(?:\/|$)|\$HOME(?:\/|$)|\$\{HOME\}(?:\/|$))/.test(item.value)) continue;
      const offset = item.span?.startIndex ?? item.sourceOffset;
      const baseDir = root.salvaged || offset === undefined ? undefined : bases.baseAt(offset);
      if (root.salvaged) {
        const { span: _span, sourceOffset: _sourceOffset, ...rest } = item;
        tokens.push(rest);
      } else {
        tokens.push({ ...item, ...(baseDir === undefined ? {} : { baseDir }) });
      }
    }
  }
  return projectPathTokens(tokens, input.normalizer, input.workdir);
}

export function projectPathTokens(tokens: readonly LocatedPathToken[], normalizer: PathNormalizer, workdir?: string): BashPathFacts {
  const pathRuleCandidates: PathRuleCandidate[] = [];
  const seen = new Map<string, number>();
  const externalAccesses: PathRuleCandidate[] = [];
  const absoluteSpellings: Array<{ startIndex: number; endIndex: number; value: string }> = [];
  const externalSeen = new Map<string, number>();
  const observations = new Map<string, ReturnType<PathNormalizer["bashTokenPath"]>>();
  const existence = new Map<string, ReturnType<PathNormalizer["observeEntry"]>>();
  const entriesByPath = new Map<string, ReturnType<PathNormalizer["observeEntry"]>>();
  const observeEntry = (path: string) => {
    const key = normalizer.flavor.fold(normalizer.flavor.normalize(path));
    let entry = entriesByPath.get(key);
    if (!entry) { entry = normalizer.observeEntry(path); entriesByPath.set(key, entry); }
    return entry;
  };
  const entries: Array<LocatedPathToken & { readonly workdirEntry?: boolean }> = [...tokens];
  if (workdir) entries.push({ value: workdir, role: "file_redirect", effect: { effect: "unproven", source: "unknown" }, baseDir: normalizer.cwd, workdirEntry: true });
  for (const token of entries) {
    if (token.role === "inert") continue;
    const shape = classifyPathToken(token.value, normalizer.flavor.kind);
    if (token.role !== "file_redirect" && !shape.bare) continue;
    const cleaned = normalizer.cleanLiteral(token.value);
    const foreignDrive = normalizer.flavor.kind === "posix" && /^[A-Za-z]:[\\/]/.test(cleaned);
    const baseDir = token.computed ? undefined : token.baseDir;
    const observationKey = JSON.stringify([token.value, token.computed ? "computed" : normalizer.isAbsolute(cleaned) || foreignDrive ? null : baseDir]);
    let resolved = observations.get(observationKey);
    if (!resolved) {
      resolved = token.computed ? { display: cleaned, matchValues: cleaned ? [cleaned] : [], boundary: "" }
        : foreignDrive ? normalizer.literalPath(token.value) : normalizer.bashTokenPath(token.value, baseDir);
      observations.set(observationKey, resolved);
    }
    if (!resolved.display) continue;
    if (token.role !== "file_redirect" && !shape.path) {
      if (!baseDir) continue;
      if (!existence.has(observationKey)) existence.set(observationKey, observeEntry(resolved.display));
      if (!existence.get(observationKey)?.exists) continue;
    }
    const matchValues = resolved.matchValues.filter((value) => value.length > 0);
    if (!token.workdirEntry && matchValues.length > 0 && !token.computed && token.span && token.baseDir && !/[*?\[\]{}]/.test(token.value) && normalizer.isAbsolute(resolved.display) && token.value !== resolved.display) {
      absoluteSpellings.push({ ...token.span, value: resolved.display });
    }
    const effect = token.computed || token.effect.effect === "unproven" ? "unknown" : token.effect.effect;
    const key = JSON.stringify([...new Set(matchValues.map((value) => normalizer.flavor.fold(
      normalizer.flavor.kind === "win32" ? value.replaceAll("/", "\\") : value,
    )))].sort());
    const previous = seen.get(key);
    if (!token.workdirEntry && matchValues.length > 0 && previous !== undefined) {
      const old = pathRuleCandidates[previous]!;
      if (old.effect.effect !== effect) pathRuleCandidates[previous] = { ...old, effect: { effect: "unknown" } };
    } else if (!token.workdirEntry && matchValues.length > 0) {
      seen.set(key, pathRuleCandidates.length);
      pathRuleCandidates.push({ path: { value: () => resolved.display, matchValues: () => matchValues }, effect: { effect } });
    }
    if (baseDir && ((!shape.external && token.role !== "file_redirect") || resolved.boundaryFromAncestor) && !existence.has(observationKey)) {
      existence.set(observationKey, observeEntry(resolved.display));
    }
    const unknownRelative = !baseDir && !normalizer.isAbsolute(resolved.display);
    const entry = existence.get(observationKey);
    const unprovenBoundary = resolved.boundaryUnproven === true ||
      (resolved.boundaryMissingPaths?.some((path) => {
        const observed = observeEntry(path);
        return observed.symlink || observed.uncertain === true;
      }) ?? false);
    const externalCandidate = token.role === "file_redirect" || shape.external || entry?.exists === true || (unknownRelative && shape.path) || (unprovenBoundary && shape.path);
    const cwd = normalizer.canonicalCwd();
    const outside = !isSafeDevice(resolved.display) && (unprovenBoundary || (resolved.boundary
      ? cwd === undefined || isOutsideCanonicalCwd(resolved.boundary, cwd, normalizer.flavor)
      : unknownRelative || shape.external));
    if (externalCandidate && outside) {
      const externalKey = normalizer.flavor.fold(unprovenBoundary ? resolved.display : resolved.boundary || resolved.display);
      const oldIndex = externalSeen.get(externalKey);
      if (oldIndex !== undefined) {
        const old = externalAccesses[oldIndex]!;
        if (!token.workdirEntry && old.effect.effect !== effect) externalAccesses[oldIndex] = { ...old, effect: { effect: "unknown" } };
      } else {
        externalSeen.set(externalKey, externalAccesses.length);
        externalAccesses.push({ path: { value: () => resolved.display, matchValues: () => resolved.matchValues }, effect: { effect } });
      }
    }
  }
  return { pathRuleCandidates, externalAccesses, absoluteSpellings };
}
