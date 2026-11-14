import { describe, expect, it } from "vitest";
import { BashProgram } from "#approve-core/utils/access-intent/bash/program";
import {
  bashParser,
  type SyntaxNode,
  type SyntaxParser,
  type SyntaxTree,
} from "#approve-core/utils/access-intent/bash/parser";
import { PathNormalizer } from "#approve-core/utils/path/path-normalizer";
import { pathFlavorForPlatform } from "#approve-core/utils/path/path-flavor";
import { syntax, treeOf } from "./fake-syntax";

function normalizer(cwd = "/work"): PathNormalizer {
  return new PathNormalizer(pathFlavorForPlatform("linux"), cwd, { home: "/home/tester" });
}

function word(text: string): SyntaxNode {
  return syntax("word", text);
}

function command(name: string, ...args: string[]): SyntaxNode {
  return syntax("command", [name, ...args].join(" "), [
    syntax("command_name", name, [word(name)]),
    ...args.map((arg) => word(arg)),
  ]);
}

function parserOf(root: SyntaxNode, counter?: { count: number }): SyntaxParser {
  return {
    parse: () => {
      if (counter) counter.count += 1;
      return treeOf(root);
    },
  };
}

describe("shared program view", () => {
  it("parses the command once and exposes its units", async () => {
    const counter = { count: 0 };
    const root = syntax("program", "echo hi && ls", [
      syntax("list", "echo hi && ls", [command("echo", "hi"), command("ls")]),
    ]);
    const program = await BashProgram.parse("echo hi && ls", normalizer(), {
      parser: parserOf(root, counter),
    });
    expect(counter.count).toBe(1);
    expect(program.commands().map((unit) => unit.text)).toEqual(["echo hi", "ls"]);
    expect(program.parsed).toBe(true);
  });

  it("returns an empty view when the parser returns nothing", async () => {
    const program = await BashProgram.parse("echo hi", normalizer(), {
      parser: { parse: (): SyntaxTree | null => null },
    });
    expect(program.commands()).toEqual([]);
    expect(program.parsed).toBe(false);
  });

  it("produces the same view from the warm sync entry", async () => {
    const root = syntax("program", "echo hi", [command("echo", "hi")]);
    const parser = parserOf(root);
    const asyncProgram = await BashProgram.parse("echo hi", normalizer(), { parser });
    const syncProgram = BashProgram.parseSync("echo hi", normalizer(), { parser });

    expect(syncProgram).toBeDefined();
    expect(syncProgram!.commands().map((unit) => unit.text))
      .toEqual(asyncProgram.commands().map((unit) => unit.text));
    expect(syncProgram!.parsed).toBe(asyncProgram.parsed);
  });

  it("reports unavailable on a cold sync entry", () => {
    bashParser.resetWarm();
    expect(BashProgram.parseSync("echo hi", normalizer())).toBeUndefined();
  });

  it("keeps main units and adds salvaged units from an unresolved region", async () => {
    const broken = syntax("command", "push --force", [
      syntax("command_name", "push", [word("push")]),
      word("--force"),
    ], { error: true });
    const root = syntax("program", "push --force", [broken], { error: true });
    const clean = syntax("program", "push --force", [command("push", "--force")]);
    let reparses = 0;
    const program = await BashProgram.parse("push --force", normalizer(), {
      parser: parserOf(root),
      reparser: {
        parse: () => {
          reparses += 1;
          return treeOf(clean);
        },
      },
    });
    expect(reparses).toBeGreaterThan(0);
    const salvaged = program.commands().filter((unit) => unit.salvaged === true);
    expect(salvaged.map((unit) => unit.text)).toContain("push --force");
    expect(program.parseUnresolved).toBe(true);
  });

  it("lets an injected path provider see the roots and workdir", async () => {
    const root = syntax("program", "cat x", [command("cat", "x")]);
    let seenBase: string | undefined;
    let seenRoots = 0;
    const program = await BashProgram.parse("cat x", normalizer(), {
      parser: parserOf(root),
      workdir: "/tmp/elsewhere",
      pathFacts: (input) => {
        seenBase = input.baseDir;
        seenRoots = input.roots.length;
        return {
          pathRuleCandidates: [{
            path: { value: () => "/tmp/elsewhere/x", matchValues: () => ["/tmp/elsewhere/x"] },
            effect: { effect: "read" as const },
          }],
          externalAccesses: [{
            path: { value: () => "/etc/hosts", matchValues: () => ["/etc/hosts"] },
            effect: { effect: "read" as const },
          }],
        };
      },
    });
    expect(seenBase).toBe("/tmp/elsewhere");
    expect(seenRoots).toBe(1);
    expect(program.pathRuleCandidates()).toHaveLength(1);
    expect(program.externalAccesses()[0]!.path.value()).toBe("/etc/hosts");
    expect(program.pathFactsAvailable).toBe(true);
  });

  it("has no path facts when no provider is injected", async () => {
    const root = syntax("program", "cat x", [command("cat", "x")]);
    const program = await BashProgram.parse("cat x", normalizer(), { parser: parserOf(root) });
    expect(program.pathRuleCandidates()).toEqual([]);
    expect(program.externalAccesses()).toEqual([]);
    expect(program.pathFactsAvailable).toBe(false);
  });

  it("deduplicates external accesses by path and effect", async () => {
    const root = syntax("program", "cat x", [command("cat", "x")]);
    const access = {
      path: { value: () => "/etc/hosts", matchValues: () => ["/etc/hosts"] },
      effect: { effect: "read" as const },
    };
    const program = await BashProgram.parse("cat x", normalizer(), {
      parser: parserOf(root),
      pathFacts: () => ({
        pathRuleCandidates: [],
        externalAccesses: [access, access],
      }),
    });
    expect(program.externalAccesses()).toHaveLength(1);
  });

  it("stops offering home spellings after a program-wide rebinding", async () => {
    const assignment = syntax("variable_assignment", "HOME=/x", [
      syntax("variable_name", "HOME"),
    ]);
    const root = syntax("program", "HOME=/x; ~/bin/tool", [
      assignment,
      command("~/bin/tool"),
    ]);
    const program = await BashProgram.parse("HOME=/x; ~/bin/tool", normalizer(), {
      parser: parserOf(root),
    });
    const tool = program.commands().find((unit) => unit.text === "~/bin/tool");
    expect(tool?.equivalents ?? []).toEqual([]);
  });
});

describe("real parser integration", () => {
  it("repairs a stranded redirect and enumerates both chain stages", async () => {
    const program = await BashProgram.parse(
      "git 2>/dev/null push --force | cat",
      normalizer(),
    );
    expect(program.commands().map((unit) => unit.text)).toEqual([
      "git push --force",
      "cat",
    ]);
  });

  it("enumerates a substitution inside a real heredoc", async () => {
    const program = await BashProgram.parse(
      "cat <<EOF\nbody $(date)\nEOF",
      normalizer(),
    );
    expect(program.commands().map((unit) => unit.text)).toContain("date");
  });

  it("enumerates a c-style loop body", async () => {
    const program = await BashProgram.parse(
      "for ((i=0;i<2;i++)); do echo $i; done",
      normalizer(),
    );
    expect(program.commands().map((unit) => unit.text)).toContain("echo $i");
  });

  it("attaches wrapper facts from the real grammar", async () => {
    const program = await BashProgram.parse("sudo -u root rm x", normalizer());
    const unit = program.commands()[0]!;
    expect(unit.wrapperKind).toBe("privilege");
    expect(unit.executedUnit).toBe("rm x");
  });
});
