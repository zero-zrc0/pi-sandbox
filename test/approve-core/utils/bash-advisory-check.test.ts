import { describe, expect, it } from "vitest";
import {
  checkBashAdvisory,
} from "#approve-core/utils/bash-advisory-check";
import {
  checkBashCommand,
  type BashUnitResolver,
} from "#approve-core/utils/bash-command-check";
import { BashProgram } from "#approve-core/utils/access-intent/bash/program";
import type { SyntaxNode, SyntaxParser } from "#approve-core/utils/access-intent/bash/parser";
import { PathNormalizer } from "#approve-core/utils/path/path-normalizer";
import { pathFlavorForPlatform } from "#approve-core/utils/path/path-flavor";
import type { PermissionCheckResult } from "#approve-core/contracts";
import { syntax, treeOf } from "#approve-core-test/utils/access-intent/bash/fake-syntax";

function normalizer(): PathNormalizer {
  return new PathNormalizer(pathFlavorForPlatform("linux"), "/work");
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

function root(text: string): SyntaxNode {
  return syntax("program", text, [command("echo", "hi"), command("ls")]);
}

function allow(overrides: Partial<PermissionCheckResult> = {}): PermissionCheckResult {
  return {
    toolName: "bash",
    state: "allow",
    source: "bash",
    origin: "global",
    ...overrides,
  };
}

function parserOf(parse: (text: string) => ReturnType<typeof treeOf> | null): SyntaxParser {
  return { parse };
}

describe("synchronous advisory check", () => {
  it("falls back to a whole-command match when the parser is cold", () => {
    const calls: string[] = [];
    const result = checkBashAdvisory({
      command: "echo hi && ls",
      normalizer: normalizer(),
      parser: { warm: () => undefined },
      resolve: (text) => {
        calls.push(text);
        return allow({ command: text });
      },
    });
    expect(result.mode).toBe("whole-command");
    expect(calls).toEqual(["echo hi && ls"]);
    expect(result.check.state).toBe("allow");
  });

  it("uses the same decomposition and adjudication as the forced gate when warm", () => {
    const parser = parserOf(() => treeOf(root("echo hi && ls")));
    const resolve: BashUnitResolver = (text) => allow({ command: text });

    const result = checkBashAdvisory({
      command: "echo hi && ls",
      normalizer: normalizer(),
      parser: { warm: () => parser },
      resolve,
    });
    expect(result.mode).toBe("decomposed");
    expect(result.program).toBeDefined();

    const gate = checkBashCommand({
      command: "echo hi && ls",
      units: result.program!.commands(),
      resolve,
    });
    expect(result.check).toEqual(gate.check);
    expect(result.program!.commands().map((unit) => unit.text)).toEqual(["echo hi", "ls"]);
  });

  it("does not parse when the warm slot is empty", () => {
    let parses = 0;
    const parser = parserOf(() => {
      parses += 1;
      return treeOf(root("echo hi && ls"));
    });
    checkBashAdvisory({
      command: "echo hi && ls",
      normalizer: normalizer(),
      parser: { warm: () => undefined },
      resolve: (text) => allow({ command: text }),
    });
    expect(parses).toBe(0);
  });

  it("shares the program's path facts with the caller", () => {
    const parser = parserOf(() => treeOf(root("echo hi && ls")));
    const result = checkBashAdvisory({
      command: "echo hi && ls",
      normalizer: normalizer(),
      parser: { warm: () => parser },
      resolve: (text) => allow({ command: text }),
      pathFacts: () => ({
        pathRuleCandidates: [],
        externalAccesses: [{
          path: { value: () => "/etc/hosts", matchValues: () => ["/etc/hosts"] },
          effect: { effect: "read" as const },
        }],
      }),
    });
    expect(result.program!.externalAccesses()[0]!.path.value()).toBe("/etc/hosts");
  });

  it("matches BashProgram.parseSync for the same warm parser", () => {
    const parser = parserOf(() => treeOf(root("echo hi && ls")));
    const program = BashProgram.parseSync("echo hi && ls", normalizer(), { parser });
    expect(program).toBeDefined();
    expect(program!.commands().map((unit) => unit.text)).toEqual(["echo hi", "ls"]);
  });
});
