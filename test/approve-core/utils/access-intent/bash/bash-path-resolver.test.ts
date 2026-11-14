import { describe, expect, it } from "vitest";
import { projectPathTokens } from "#approve-core/utils/access-intent/bash/bash-path-resolver";
import { PathNormalizer } from "#approve-core/utils/path/path-normalizer";
import { POSIX_PATH_FLAVOR, WIN32_PATH_FLAVOR } from "#approve-core/utils/path/path-flavor";
import { BashProgram } from "#approve-core/utils/access-intent/bash/program";
import { bashPathFacts } from "#approve-core/utils/access-intent/bash/bash-path-resolver";
import { syntax, token, treeOf } from "./fake-syntax";
import { wordsOf } from "#approve-core/utils/access-intent/bash/command-enumeration";

describe("Bash path projections", () => {
  it("admits a new redirect target without requiring it to exist", () => {
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", {
      home: "/home/user", lstatSync: () => undefined, realpathSync: (path) => path,
    });
    const result = projectPathTokens([{ value: "new.txt", role: "file_redirect", effect: { effect: "write", source: "syntax" }, baseDir: "/work" }], normalizer);
    expect(result.pathRuleCandidates.map((candidate) => [candidate.path.value(), candidate.effect.effect])).toEqual([["/work/new.txt", "write"]]);
  });

  it("merges conflicting effects for the same path as unknown", () => {
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { realpathSync: (path) => path });
    const result = projectPathTokens([
      { value: "same.txt", role: "file_redirect", effect: { effect: "read", source: "syntax" }, baseDir: "/work" },
      { value: "same.txt", role: "file_redirect", effect: { effect: "write", source: "syntax" }, baseDir: "/work" },
    ], normalizer);
    expect(result.pathRuleCandidates.map((candidate) => [candidate.path.value(), candidate.effect.effect])).toEqual([["/work/same.txt", "unknown"]]);
  });

  it("merges case-insensitive Windows path aliases before combining effects", () => {
    const normalizer = new PathNormalizer(WIN32_PATH_FLAVOR, "C:\\work", { realpathSync: (path) => path });
    const result = projectPathTokens([
      { value: "C:\\work\\FILE", role: "file_redirect", effect: { effect: "read", source: "syntax" }, baseDir: "C:\\work" },
      { value: "c:\\WORK\\file", role: "file_redirect", effect: { effect: "write", source: "syntax" }, baseDir: "C:\\work" },
    ], normalizer);
    expect(result.pathRuleCandidates.map((item) => item.effect.effect)).toEqual(["unknown"]);
  });

  it("merges Windows paths with different separator spellings", () => {
    const normalizer = new PathNormalizer(WIN32_PATH_FLAVOR, "C:\\work", { realpathSync: (path) => path });
    const result = projectPathTokens([
      { value: "C:\\work\\file", role: "file_redirect", effect: { effect: "read", source: "syntax" }, baseDir: "C:\\work" },
      { value: "C:/work/file", role: "file_redirect", effect: { effect: "write", source: "syntax" }, baseDir: "C:\\work" },
    ], normalizer);
    expect(result.pathRuleCandidates.map((item) => item.effect.effect)).toEqual(["unknown"]);
  });

  it("admits existing bare operands and caches repeated existence observations", () => {
    let probes = 0;
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", {
      realpathSync: (path) => path,
      lstatSync: (path) => { probes++; return path === "/work/input" ? {} : undefined; },
    });
    const item = { value: "input", role: "operand" as const, effect: { effect: "read" as const, source: "builtin-core" as const }, baseDir: "/work" };
    const result = projectPathTokens([item, item], normalizer);
    expect(result.pathRuleCandidates.map((candidate) => candidate.path.value())).toEqual(["/work/input"]);
    expect(probes).toBe(1);
  });

  it("records an absolute outside path as external", () => {
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { realpathSync: (path) => path });
    const result = projectPathTokens([{ value: "/other/data", role: "operand", effect: { effect: "read", source: "builtin-core" }, baseDir: "/work" }], normalizer);
    expect(result.externalAccesses.map((candidate) => [candidate.path.value(), candidate.effect.effect])).toEqual([["/other/data", "read"]]);
  });

  it("does not recanonicalize an already resolved external candidate", () => {
    const counts = new Map<string, number>();
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { realpathSync: (path) => {
      counts.set(path, (counts.get(path) ?? 0) + 1);
      return path;
    } });
    const item = { value: "/other/data", role: "operand" as const, effect: { effect: "read" as const, source: "builtin-core" as const }, baseDir: "/work" };
    projectPathTokens([item, item], normalizer);
    expect(counts.get("/other/data")).toBe(1);
  });

  it("treats a foreign absolute drive path conservatively", () => {
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { realpathSync: (path) => path });
    const result = projectPathTokens([{ value: "C:\\private\\file", role: "operand", effect: { effect: "read", source: "builtin-core" }, baseDir: "/work" }], normalizer);
    expect(result.externalAccesses).toHaveLength(1);
    expect(result.externalAccesses[0]!.path.value()).toBe("C:\\private\\file");
  });

  it("detects an existing bare symlink that resolves outside the working tree", () => {
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", {
      lstatSync: (path) => path === "/work/link" ? {} : undefined,
      realpathSync: (path) => path === "/work/link" ? "/outside/data" : path,
    });
    const result = projectPathTokens([{ value: "link", role: "operand", effect: { effect: "read", source: "builtin-core" }, baseDir: "/work" }], normalizer);
    expect(result.externalAccesses.map((candidate) => candidate.path.value())).toEqual(["/work/link"]);
  });

  it("merges external effects for lexical aliases of the same canonical path", () => {
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", {
      lstatSync: (path) => path === "/work/link" ? { isSymbolicLink: () => true } : undefined,
      realpathSync: (path) => path === "/work/link" ? "/outside/file" : path,
    });
    const result = projectPathTokens([
      { value: "link", role: "operand", effect: { effect: "read", source: "builtin-core" }, baseDir: "/work" },
      { value: "/outside/file", role: "file_redirect", effect: { effect: "write", source: "syntax" }, baseDir: "/work" },
    ], normalizer);
    expect(result.externalAccesses.map((item) => item.effect.effect)).toEqual(["unknown"]);
  });

  it("does not assume a dangling bare symlink remains inside the working tree", () => {
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", {
      lstatSync: (path) => path === "/work/link" ? { isSymbolicLink: () => true } : undefined,
      realpathSync: (path) => {
        if (path === "/work/link") throw Object.assign(new Error("missing"), { code: "ENOENT" });
        return path;
      },
    });
    const result = projectPathTokens([{ value: "link", role: "operand", effect: { effect: "read", source: "builtin-core" }, baseDir: "/work" }], normalizer);
    expect(result.externalAccesses.map((item) => item.path.value())).toEqual(["/work/link"]);
  });

  it("does not assume a target beneath a dangling symlink remains inside", () => {
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", {
      lstatSync: (path) => path === "/work/link" ? { isSymbolicLink: () => true } : undefined,
      realpathSync: (path) => {
        if (path === "/work/link" || path === "/work/link/new") throw Object.assign(new Error("missing"), { code: "ENOENT" });
        return path;
      },
    });
    const result = projectPathTokens([{ value: "./link/new", role: "file_redirect", effect: { effect: "write", source: "syntax" }, baseDir: "/work" }], normalizer);
    expect(result.externalAccesses.map((item) => item.path.value())).toEqual(["/work/link/new"]);
  });

  it("reuses missing ancestor observations for repeated tokens", () => {
    const counts = new Map<string, number>();
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", {
      lstatSync: (path) => { counts.set(path, (counts.get(path) ?? 0) + 1); return undefined; },
      realpathSync: (path) => {
        if (path === "/work/new") throw Object.assign(new Error("missing"), { code: "ENOENT" });
        return path;
      },
    });
    const item = { value: "./new", role: "file_redirect" as const, effect: { effect: "write" as const, source: "syntax" as const }, baseDir: "/work" };
    projectPathTokens([item, item], normalizer);
    expect(counts.get("/work/new")).toBe(1);
  });

  it("treats a failed lstat on an unresolved ancestor as unknown", () => {
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", {
      lstatSync: (path) => {
        if (path === "/work/locked") throw Object.assign(new Error("denied"), { code: "EACCES" });
        return undefined;
      },
      realpathSync: (path) => {
        if (path === "/work/locked" || path === "/work/locked/new") throw Object.assign(new Error("missing"), { code: "ENOENT" });
        return path;
      },
    });
    const result = projectPathTokens([{ value: "./locked/new", role: "file_redirect", effect: { effect: "write", source: "syntax" }, baseDir: "/work" }], normalizer);
    expect(result.externalAccesses.map((item) => item.path.value())).toEqual(["/work/locked/new"]);
  });

  it("detects a new redirect target beneath a symlink to an external directory", () => {
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { realpathSync: (path) => {
      if (path === "/work/link/new.txt") throw Object.assign(new Error("missing"), { code: "ENOENT" });
      if (path === "/work/link") return "/outside";
      return path;
    } });
    const result = projectPathTokens([{ value: "./link/new.txt", role: "file_redirect", effect: { effect: "write", source: "syntax" }, baseDir: "/work" }], normalizer);
    expect(result.externalAccesses.map((item) => [item.path.value(), item.effect.effect])).toEqual([["/work/link/new.txt", "write"]]);
  });

  it("treats a relative path under an unknown base as external while preserving its literal", () => {
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { realpathSync: (path) => path });
    const result = projectPathTokens([{ value: "../secret", role: "operand", effect: { effect: "unproven", source: "unknown" } }], normalizer);
    expect(result.pathRuleCandidates[0]?.path.matchValues()).toEqual(["../secret"]);
    expect(result.externalAccesses[0]?.path.value()).toBe("../secret");
  });

  it("keeps literal-only and known-base observations separate", () => {
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { realpathSync: (path) => path, lstatSync: () => undefined });
    const effect = { effect: "read" as const, source: "builtin-core" as const };
    const result = projectPathTokens([
      { value: "./item", role: "operand", effect },
      { value: "./item", role: "operand", effect, baseDir: "/work" },
    ], normalizer);
    expect(result.pathRuleCandidates.map((candidate) => candidate.path.value())).toEqual(["./item", "/work/item"]);
    expect(result.externalAccesses.map((candidate) => candidate.path.value())).toEqual(["./item"]);
  });

  it("drops a path-rule candidate when the normalizer supplies no match values", () => {
    class EmptyAliasesNormalizer extends PathNormalizer {
      override bashTokenPath() { return { display: "/work/item", matchValues: [], boundary: "/work/item" }; }
    }
    const normalizer = new EmptyAliasesNormalizer(POSIX_PATH_FLAVOR, "/work", { realpathSync: (path) => path });
    const result = projectPathTokens([{ value: "./item", role: "operand", effect: { effect: "read", source: "builtin-core" }, baseDir: "/work" }], normalizer);
    expect(result.pathRuleCandidates).toEqual([]);
  });


  it("does not flag a safe device as an external directory", () => {
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { realpathSync: (path) => path });
    const result = projectPathTokens([{ value: "/dev/null", role: "file_redirect", effect: { effect: "write", source: "syntax" }, baseDir: "/work" }], normalizer);
    expect(result.externalAccesses).toEqual([]);
  });

  it("treats an unprovable canonical working directory conservatively", () => {
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { realpathSync: () => { throw new Error("unavailable"); } });
    const result = projectPathTokens([{ value: "/other/data", role: "operand", effect: { effect: "read", source: "builtin-core" }, baseDir: "/work" }], normalizer);
    expect(result.externalAccesses.map((candidate) => candidate.path.value())).toEqual(["/other/data"]);
  });

  it("treats a path with a canonicalization permission error conservatively", () => {
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { realpathSync: (path) => {
      if (path === "/work") return path;
      throw Object.assign(new Error("denied"), { code: "EACCES" });
    } });
    const result = projectPathTokens([{ value: "./locked/file", role: "operand", effect: { effect: "read", source: "builtin-core" }, baseDir: "/work" }], normalizer);
    expect(result.externalAccesses.map((item) => item.path.value())).toEqual(["/work/locked/file"]);
  });

  it("projects command paths using the base after a preceding cd", async () => {
    const change = syntax("command", "cd src", [syntax("command_name", "cd", [syntax("word", "cd")]), syntax("word", "src")]);
    const read = syntax("command", "cat ./file", [syntax("command_name", "cat", [syntax("word", "cat")]), syntax("word", "./file")]);
    const root = syntax("program", "cd src; cat ./file", [change, token(";", ";"), read]);
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { realpathSync: (path) => path, lstatSync: () => undefined });
    const program = await BashProgram.parse("cd src; cat ./file", normalizer, { parser: { parse: () => treeOf(root) }, pathFacts: bashPathFacts });
    expect(program.pathRuleCandidates().map((candidate) => candidate.path.value())).toContain("/work/src/file");
  });

  it("includes an outside workdir even when the command names no path", async () => {
    const root = syntax("program", "true", [syntax("command", "true", [syntax("command_name", "true", [syntax("word", "true")])])]);
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { realpathSync: (path) => path });
    const program = await BashProgram.parse("true", normalizer, { parser: { parse: () => treeOf(root) }, workdir: "/outside", pathFacts: bashPathFacts });
    expect(program.externalAccesses().map((access) => [access.path.value(), access.effect.effect])).toEqual([["/outside", "unknown"]]);
  });

  it("reuses an absolute workdir observation when a command names the same path", async () => {
    const root = syntax("program", "cat /outside", [syntax("command", "cat /outside", [
      syntax("command_name", "cat", [syntax("word", "cat")]), syntax("word", "/outside"),
    ])]);
    let resolutions = 0;
    class CountingNormalizer extends PathNormalizer {
      override bashTokenPath(value: string, base?: string) {
        if (value === "/outside") resolutions++;
        return super.bashTokenPath(value, base);
      }
    }
    const normalizer = new CountingNormalizer(POSIX_PATH_FLAVOR, "/work", { realpathSync: (path) => path });
    const program = await BashProgram.parse(root.text, normalizer, { parser: { parse: () => treeOf(root) }, workdir: "/outside", pathFacts: bashPathFacts });
    expect(program.externalAccesses().map((item) => item.effect.effect)).toEqual(["read"]);
    expect(resolutions).toBe(1);
  });

  it("resolves an attached option value relative to the command's working directory", async () => {
    const root = syntax("program", "tool --config=./settings.json", [syntax("command", "tool --config=./settings.json", [
      syntax("command_name", "tool", [syntax("word", "tool")]), syntax("word", "--config=./settings.json"),
    ])]);
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { realpathSync: (path) => path, lstatSync: () => undefined });
    const program = await BashProgram.parse(root.text, normalizer, { parser: { parse: () => treeOf(root) }, pathFacts: bashPathFacts });
    expect(program.pathRuleCandidates().map((candidate) => candidate.path.value())).toContain("/work/settings.json");
  });

  it("does not invent a directory for a dynamic workdir", async () => {
    const root = syntax("program", "cat ./file", [syntax("command", "cat ./file", [
      syntax("command_name", "cat", [syntax("word", "cat")]), syntax("word", "./file"),
    ])]);
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { realpathSync: (path) => path });
    const program = await BashProgram.parse(root.text, normalizer, { parser: { parse: () => treeOf(root) }, workdir: "$DIR", pathFacts: bashPathFacts });
    expect(program.pathRuleCandidates().map((candidate) => candidate.path.value())).toContain("./file");
    expect(program.externalAccesses().map((candidate) => candidate.path.value())).toContain("./file");
  });

  it("uses the program's configured home for shell word expansion", async () => {
    const root = syntax("program", "cat ~/file", [syntax("command", "cat ~/file", [
      syntax("command_name", "cat", [syntax("word", "cat")]), syntax("word", "~/file"),
    ])]);
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { home: "/default", realpathSync: (path) => path });
    const program = await BashProgram.parse(root.text, normalizer, { parser: { parse: () => treeOf(root) }, home: "/custom", pathFacts: bashPathFacts });
    expect(program.pathRuleCandidates().map((candidate) => candidate.path.value())).toContain("/custom/file");
  });

  it("uses the normalizer home when the provider input omits the optional override", () => {
    const root = syntax("program", "cat ~/file", [syntax("command", "cat ~/file", [
      syntax("command_name", "cat", [syntax("word", "cat")]), syntax("word", "~/file"),
    ])]);
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { home: "/home/user", realpathSync: (path) => path });
    const result = bashPathFacts({ source: root.text, roots: [{ root, source: root.text, salvaged: false }], commands: [], normalizer,
      workdir: "/work", baseDir: "/work", homeRebound: false, pwdRebound: false });
    expect(result.pathRuleCandidates.map((candidate) => candidate.path.value())).toContain("/home/user/file");
  });

  it("keeps a salvaged root's paths literal even after an absolute cd", () => {
    const change = syntax("command", "cd /tmp", [syntax("command_name", "cd", [syntax("word", "cd")]), syntax("word", "/tmp")]);
    const read = syntax("command", "cat ./file", [syntax("command_name", "cat", [syntax("word", "cat")]), syntax("word", "./file")]);
    const root = syntax("program", "cd /tmp; cat ./file", [change, token(";", ";"), read]);
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { realpathSync: (path) => path });
    const result = bashPathFacts({ source: root.text, roots: [{ root, source: root.text, salvaged: true }], commands: [], normalizer,
      workdir: "/work", baseDir: "/work", homeRebound: false, pwdRebound: false });
    expect(result.pathRuleCandidates.map((candidate) => candidate.path.value())).toContain("./file");
    expect(result.absoluteSpellings ?? []).toEqual([]);
  });

  it("provides an absolute command spelling for each resolved argument occurrence", async () => {
    const root = syntax("program", "cat ./file ./file", [syntax("command", "cat ./file ./file", [
      syntax("command_name", "cat", [syntax("word", "cat")]), syntax("word", "./file"), syntax("word", "./file"),
    ])]);
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { realpathSync: (path) => path, lstatSync: () => undefined });
    const program = await BashProgram.parse(root.text, normalizer, { parser: { parse: () => treeOf(root) }, pathFacts: bashPathFacts });
    expect(program.commands()[0]?.equivalents).toEqual(expect.arrayContaining(["cat /work/file ./file", "cat ./file /work/file"]));
    expect(wordsOf(program.commands()[0]!).map((word) => word.value)).toEqual(["cat", "./file", "./file"]);
  });

  it("does not generate an absolute spelling for a computed argument", async () => {
    const root = syntax("program", "cat ./dir/$name", [syntax("command", "cat ./dir/$name", [
      syntax("command_name", "cat", [syntax("word", "cat")]),
      syntax("concatenation", "./dir/$name", [syntax("word", "./dir/"), syntax("simple_expansion", "$name")]),
    ])]);
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { realpathSync: (path) => path });
    const program = await BashProgram.parse(root.text, normalizer, { parser: { parse: () => treeOf(root) }, pathFacts: bashPathFacts });
    expect(program.commands()[0]?.equivalents ?? []).toEqual([]);
  });

  it("does not canonicalize an absolute computed operand as a literal file", () => {
    let observed = false;
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { realpathSync: (path) => {
      if (path.includes("$name")) observed = true;
      return path;
    } });
    const result = projectPathTokens([{ value: "/outside/$name", role: "operand", computed: true,
      effect: { effect: "read", source: "builtin-core" }, baseDir: "/work" }], normalizer);
    expect(result.pathRuleCandidates.map((item) => [item.path.value(), item.effect.effect])).toEqual([["/outside/$name", "unknown"]]);
    expect(result.externalAccesses.map((item) => item.path.value())).toEqual(["/outside/$name"]);
    expect(observed).toBe(false);
  });

  it("quotes absolute command spellings that contain shell whitespace", async () => {
    const root = syntax("program", "cat './my file'", [syntax("command", "cat './my file'", [
      syntax("command_name", "cat", [syntax("word", "cat")]), syntax("raw_string", "'./my file'"),
    ])]);
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { realpathSync: (path) => path });
    const program = await BashProgram.parse(root.text, normalizer, { parser: { parse: () => treeOf(root) }, pathFacts: bashPathFacts });
    expect(program.commands()[0]?.equivalents).toContain("cat '/work/my file'");
  });

  it("escapes a single quote in an absolute command spelling", async () => {
    const root = syntax("program", `cat "./it's"`, [syntax("command", `cat "./it's"`, [
      syntax("command_name", "cat", [syntax("word", "cat")]), syntax("string", `"./it's"`),
    ])]);
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { realpathSync: (path) => path });
    const program = await BashProgram.parse(root.text, normalizer, { parser: { parse: () => treeOf(root) }, pathFacts: bashPathFacts });
    expect(program.commands()[0]?.equivalents).toContain(`cat '/work/it'\\''s'`);
  });

  it("does not project a HOME-prefixed path after HOME is rebound", async () => {
    const assignment = syntax("variable_assignment", "HOME=/else", [syntax("variable_name", "HOME"), syntax("word", "/else")]);
    const read = syntax("command", "cat ~/file", [syntax("command_name", "cat", [syntax("word", "cat")]), syntax("word", "~/file")]);
    const root = syntax("program", "HOME=/else; cat ~/file", [assignment, token(";", ";"), read]);
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { home: "/home/user", realpathSync: (path) => path });
    const program = await BashProgram.parse(root.text, normalizer, { parser: { parse: () => treeOf(root) }, pathFacts: bashPathFacts });
    expect(program.rebinding.home).toBe(true);
    expect(program.pathRuleCandidates()).toEqual([]);
  });
});
