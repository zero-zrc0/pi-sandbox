import { describe, expect, it } from "vitest";
import {
  enumerateCommands,
  redirectFactsOf,
} from "#approve-core/utils/access-intent/bash/command-enumeration";
import type { SyntaxNode } from "#approve-core/utils/access-intent/bash/parser";
import type { ShellWordContext } from "#approve-core/utils/access-intent/bash/shell-variable-expansion";
import { syntax, token } from "./fake-syntax";

const WORD_CONTEXT: ShellWordContext = {
  home: "/home/tester",
  homeRebound: false,
  pwdRebound: false,
};

function word(text: string): SyntaxNode {
  return syntax("word", text);
}

function command(name: string, args: readonly (string | SyntaxNode)[] = []): SyntaxNode {
  const texts = args.map((arg) => typeof arg === "string" ? arg : arg.text);
  const children: SyntaxNode[] = [syntax("command_name", name, [word(name)])];
  for (const arg of args) children.push(typeof arg === "string" ? word(arg) : arg);
  return syntax("command", [name, ...texts].join(" "), children);
}

function fileRedirect(text: string, operator: string, target: string): SyntaxNode {
  return syntax("file_redirect", text, [token(operator, operator), word(target)]);
}

function enumerate(
  root: SyntaxNode,
  options: {
    salvaged?: boolean;
    homeRebound?: boolean;
    isAbsolutePath?: (value: string) => boolean;
  } = {},
) {
  return enumerateCommands(root, {
    source: root.text,
    wordContext: { ...WORD_CONTEXT, homeRebound: options.homeRebound ?? false },
    isAbsolutePath: options.isAbsolutePath ?? ((value) => value.startsWith("/")),
    salvaged: options.salvaged ?? false,
  });
}

function texts(commands: readonly { text: string }[]): string[] {
  return commands.map((entry) => entry.text);
}

describe("statement enumeration", () => {
  it("emits each statement of a program, list and pipeline", () => {
    const root = syntax("program", "a && b | c; d & e", [
      command("a"),
      token("&&", "&&"),
      command("b"),
      token("|", "|"),
      command("c"),
      token(";", ";"),
      command("d"),
      token("&", "&"),
      command("e"),
    ]);
    expect(texts(enumerate(root))).toEqual(["a", "b", "c", "d", "e"]);
  });

  it("drops leading assignments from the rule text", () => {
    const assignment = syntax("variable_assignment", "FOO=1", [
      syntax("variable_name", "FOO"),
      token("=", "="),
      syntax("number", "1"),
    ]);
    const root = syntax("command", "FOO=1 bar baz", [
      assignment,
      syntax("command_name", "bar", [word("bar")]),
      word("baz"),
    ]);
    expect(texts(enumerate(root))).toEqual(["bar baz"]);
  });

  it("keeps a pure assignment statement", () => {
    const root = syntax("variable_assignment", "FOO=1");
    expect(texts(enumerate(root))).toEqual(["FOO=1"]);
  });

  it("removes redirects and exposes their facts", () => {
    const root = syntax("redirected_statement", "echo hi > out", [
      command("echo", ["hi"]),
      fileRedirect("> out", ">", "out"),
    ]);
    const units = enumerate(root);
    expect(texts(units)).toEqual(["echo hi"]);
    expect(redirectFactsOf(units[0]!)).toEqual([
      expect.objectContaining({ operator: ">", targetValue: "out", writesFile: true }),
    ]);
  });

  it("keeps a heredoc out of rule text but inspects its substitution", () => {
    const dates = syntax("command_substitution", "$(date)", [command("date")]);
    const heredoc = syntax("heredoc_redirect", "<<EOF\nbody $(date)\nEOF", [
      token("<<", "<<"),
      syntax("heredoc_start", "EOF"),
      syntax("heredoc_body", "body $(date)\n", [dates]),
      syntax("heredoc_end", "EOF"),
    ]);
    const root = syntax("redirected_statement", "cat <<EOF\nbody $(date)\nEOF", [
      command("cat"),
      heredoc,
    ]);
    const units = enumerate(root);
    expect(texts(units)).toEqual(["cat", "date"]);
    expect(units[1]!.context).toBe("command_substitution");
    expect(redirectFactsOf(units[0]!)[0]!.writesFile).toBe(false);
  });
});

describe("compound statements", () => {
  it("emits an if statement whole and then its real commands", () => {
    const root = syntax("if_statement", "if true; then echo hi; else echo no; fi", [
      command("true"),
      command("echo", ["hi"]),
      syntax("else_clause", "else echo no;", [command("echo", ["no"])]),
    ]);
    expect(texts(enumerate(root))).toEqual([
      "if true; then echo hi; else echo no; fi",
      "true",
      "echo hi",
      "echo no",
    ]);
  });

  it("emits a loop and its body without treating the loop variable as a command", () => {
    const root = syntax("for_statement", "for f in a b; do echo $f; done", [
      syntax("variable_name", "f"),
      word("a"),
      word("b"),
      syntax("do_group", "do echo $f; done", [command("echo", ["$f"])]),
    ]);
    expect(texts(enumerate(root))).toEqual([
      "for f in a b; do echo $f; done",
      "echo $f",
    ]);
  });

  it("emits a case statement and its body without the subject or patterns", () => {
    const root = syntax("case_statement", "case $x in a) echo a;; esac", [
      syntax("simple_expansion", "$x", [syntax("variable_name", "x")]),
      syntax("case_item", "a) echo a;;", [word("a"), command("echo", ["a"])]),
    ]);
    expect(texts(enumerate(root))).toEqual([
      "case $x in a) echo a;; esac",
      "echo a",
    ]);
  });

  it("emits a function definition and its body without the function name", () => {
    const root = syntax("function_definition", "f() { echo hi; }", [
      word("f"),
      syntax("compound_statement", "{ echo hi; }", [command("echo", ["hi"])]),
    ]);
    expect(texts(enumerate(root))).toEqual(["f() { echo hi; }", "echo hi"]);
  });

  it("emits a negated command and the command it negates", () => {
    const root = syntax("negated_command", "! grep x file", [
      command("grep", ["x", "file"]),
    ]);
    expect(texts(enumerate(root))).toEqual(["! grep x file", "grep x file"]);
  });

  it("emits a subshell whole and its inner commands with subshell context", () => {
    const root = syntax("subshell", "(cd /tmp && ls)", [
      syntax("list", "cd /tmp && ls", [
        command("cd", ["/tmp"]),
        token("&&", "&&"),
        command("ls"),
      ]),
    ]);
    const units = enumerate(root);
    expect(texts(units)).toEqual(["(cd /tmp && ls)", "cd /tmp", "ls"]);
    expect(units[0]!.context).toBeUndefined();
    expect(units[1]!.context).toBe("subshell");
    expect(units[2]!.context).toBe("subshell");
  });
});

describe("substitutions", () => {
  it("adds command substitution units with their context", () => {
    const substitution = syntax("command_substitution", "$(date)", [command("date")]);
    const root = command("echo", [substitution]);
    const units = enumerate(root);
    expect(texts(units)).toEqual(["echo $(date)", "date"]);
    expect(units[1]!.context).toBe("command_substitution");
  });

  it("adds process substitution units with their context", () => {
    const substitution = syntax("process_substitution", "<(ls)", [command("ls")]);
    const root = command("cat", [substitution]);
    const units = enumerate(root);
    expect(texts(units)).toEqual(["cat <(ls)", "ls"]);
    expect(units[1]!.context).toBe("process_substitution");
  });

  it("does not let a nested command inherit the outer redirect", () => {
    const inner = syntax("command", "cat x > out", [
      syntax("command_name", "cat", [word("cat")]),
      word("x"),
      fileRedirect("> out", ">", "out"),
    ]);
    const substitution = syntax("command_substitution", "$(cat x > out)", [inner]);
    const root = command("echo", [substitution]);
    const units = enumerate(root);
    expect(redirectFactsOf(units[0]!)).toEqual([]);
    expect(redirectFactsOf(units[1]!).map((fact) => fact.writesFile)).toEqual([true]);
  });
});

describe("parse health", () => {
  it("emits an ERROR region as uncertain text and does not descend", () => {
    const root = syntax("program", 'echo "unterminated', [
      command("echo"),
      syntax("ERROR", '"unterminated', [], { error: true }),
    ]);
    const units = enumerate(root);
    expect(texts(units)).toEqual(["echo", '"unterminated']);
    expect(units[1]!.parseUnresolved).toBe(true);
  });

  it("adds a whole-command uncertain unit when an error has no statement unit", () => {
    const empty = syntax("command", "", [
      syntax("command_name", "", [syntax("word", "", [], { error: true })], { error: true }),
    ], { error: true });
    const root = syntax("program", "echo ok &&", [
      syntax("list", "echo ok &&", [command("echo", ["ok"]), token("&&", "&&"), empty], { error: true }),
    ], { error: true });
    const units = enumerate(root);
    expect(texts(units)).toEqual(["echo ok", "echo ok &&"]);
    expect(units[1]!.parseUnresolved).toBe(true);
  });

  it("marks every unit of a salvaged tree", () => {
    const root = syntax("program", "push --force", [command("push", ["--force"])]);
    const units = enumerate(root, { salvaged: true });
    expect(units[0]!.salvaged).toBe(true);
    expect(units[0]!.parseUnresolved).toBe(true);
  });

  it("never offers equivalent spellings from a salvaged tree", () => {
    const units = enumerate(command("~/bin/tool", ["/tmp/x"]), { salvaged: true });
    expect(units[0]!.equivalents ?? []).toEqual([]);
  });
});

describe("wrapper and spelling facts", () => {
  it("attaches wrapper metadata and the displayed executed unit", () => {
    const root = command("sudo", ["rm", "x"]);
    const unit = enumerate(root)[0]!;
    expect(unit.wrapperKind).toBe("privilege");
    expect(unit.executedUnit).toBe("rm x");
  });

  it("records an execution-modifier exemption", () => {
    const unit = enumerate(command("time", ["ls"]))[0]!;
    expect(unit.floorExemption).toBe("execution-modifier");
  });

  it("keeps an opaque payload as display only", () => {
    const unit = enumerate(command("bash", ["-c", "rm x"]))[0]!;
    expect(unit.wrapperKind).toBe("opaque-payload");
    expect(unit.executedUnit).toBe("rm x");
    expect(unit.floorExemption).toBeUndefined();
  });

  it("offers a home-prefix command spelling", () => {
    const unit = enumerate(command("~/bin/tool", ["/tmp/x"]))[0]!;
    expect(unit.equivalents).toContain("/home/tester/bin/tool /tmp/x");
  });

  it("offers a full-argument absolute spelling", () => {
    const quoted = syntax("string", '"/tmp/x"', [syntax("string_content", "/tmp/x")]);
    const unit = enumerate(command("cat", [quoted]))[0]!;
    expect(unit.equivalents).toContain("cat /tmp/x");
  });

  it("does not offer spellings for computed arguments", () => {
    const file = syntax("simple_expansion", "$FILE", [syntax("variable_name", "FILE")]);
    const unit = enumerate(command("cat", [file]))[0]!;
    expect(unit.equivalents ?? []).toEqual([]);
  });

  it("stops offering a home spelling when HOME is rebound", () => {
    const unit = enumerate(command("~/bin/tool", []), { homeRebound: true })[0]!;
    expect(unit.equivalents ?? []).toEqual([]);
  });
});
