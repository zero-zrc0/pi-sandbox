import { describe, expect, it } from "vitest";
import type { SyntaxNode } from "#approve-core/utils/access-intent/bash/parser";
import {
  NO_REBINDING,
  readShellWord,
  scanRebindings,
  type ShellWordContext,
} from "#approve-core/utils/access-intent/bash/shell-variable-expansion";
import { syntax, token } from "./fake-syntax";

const HOME = "/home/tester";

function context(overrides: Partial<ShellWordContext> = {}): ShellWordContext {
  return {
    home: HOME,
    homeRebound: false,
    pwdRebound: false,
    ...overrides,
  };
}

function command(name: string, args: readonly (SyntaxNode | string)[] = []): SyntaxNode {
  const children: SyntaxNode[] = [syntax("command_name", name, [syntax("word", name)])];
  for (const arg of args) children.push(typeof arg === "string" ? syntax("word", arg) : arg);
  return syntax("command", [name, ...args.map((arg) => typeof arg === "string" ? arg : arg.text)].join(" "), children);
}

function simple(name: string): SyntaxNode {
  return syntax("simple_expansion", `$${name}`, [syntax("variable_name", name)]);
}

function expansion(name: string, operator?: string, value?: string): SyntaxNode {
  const text = operator === undefined ? `\${${name}}` : `\${${name}${operator}${value ?? ""}}`;
  const children: SyntaxNode[] = [syntax("variable_name", name)];
  if (operator !== undefined) {
    children.push(token(operator, operator));
    if (value !== undefined) children.push(syntax("word", value));
  }
  return syntax("expansion", text, children);
}

describe("shell word reading", () => {
  it("keeps a plain word literal", () => {
    expect(readShellWord(syntax("word", "plain"), context())).toEqual({
      value: "plain",
      computed: false,
      mayLeadWithDash: false,
    });
  });

  it("marks a literal option as dash-leading", () => {
    expect(readShellWord(syntax("word", "-la"), context())).toEqual({
      value: "-la",
      computed: false,
      mayLeadWithDash: true,
    });
  });

  it("strips one pair of single quotes without expanding", () => {
    expect(readShellWord(syntax("raw_string", "'$HOME'"), context())).toEqual({
      value: "$HOME",
      computed: false,
      mayLeadWithDash: false,
    });
  });

  it("joins static double-quoted content", () => {
    const node = syntax("string", '"a b"', [syntax("string_content", "a b")]);
    expect(readShellWord(node, context()).value).toBe("a b");
  });

  it("resolves a plain HOME reference", () => {
    expect(readShellWord(simple("HOME"), context()).value).toBe(HOME);
  });

  it("resolves a braced HOME reference", () => {
    expect(readShellWord(expansion("HOME"), context()).value).toBe(HOME);
  });

  it("resolves PWD to the current-base marker", () => {
    expect(readShellWord(expansion("PWD"), context()).value).toBe(".");
  });

  it("keeps quoted HOME concatenation static", () => {
    const node = syntax("string", '"$HOME/x"', [simple("HOME"), syntax("string_content", "/x")]);
    expect(readShellWord(node, context())).toEqual({
      value: `${HOME}/x`,
      computed: false,
      mayLeadWithDash: false,
    });
  });

  it("stops resolving a rebound HOME", () => {
    const word = readShellWord(simple("HOME"), context({ homeRebound: true }));
    expect(word.value).toBe("$HOME");
    expect(word.computed).toBe(true);
    expect(word.mayLeadWithDash).toBe(true);
  });

  it("stops resolving a rebound PWD", () => {
    const word = readShellWord(expansion("PWD"), context({ pwdRebound: true }));
    expect(word.value).toBe("${PWD}");
    expect(word.computed).toBe(true);
  });

  it("does not resolve a default-operator expansion", () => {
    const node = expansion("HOME", ":-", "/fallback");
    const word = readShellWord(node, context());
    expect(word.value).toBe("${HOME:-/fallback}");
    expect(word.computed).toBe(true);
  });

  it("expands a leading tilde with the current home", () => {
    expect(readShellWord(syntax("word", "~/bin/tool"), context())).toEqual({
      value: `${HOME}/bin/tool`,
      computed: false,
      mayLeadWithDash: false,
    });
  });

  it("keeps an unknown user tilde computed", () => {
    const word = readShellWord(syntax("word", "~root/x"), context());
    expect(word.value).toBe("~root/x");
    expect(word.computed).toBe(true);
  });

  it("treats PWD/OLDPWD tilde aliases as runtime values", () => {
    expect(readShellWord(syntax("word", "~+/x"), context()).computed).toBe(true);
    expect(readShellWord(syntax("word", "~-/x"), context()).computed).toBe(true);
  });

  it("marks glob and escape syntax as computed", () => {
    expect(readShellWord(syntax("word", "*.txt"), context()).computed).toBe(true);
    expect(readShellWord(syntax("word", "\\~x"), context()).computed).toBe(true);
  });

  it("keeps a brace expansion computed", () => {
    const node = syntax("concatenation", "a{b,c}", [
      syntax("word", "a"),
      syntax("word", "{"),
      syntax("word", "b,c"),
      syntax("word", "}"),
    ]);
    const word = readShellWord(node, context());
    expect(word.value).toBe("a{b,c}");
    expect(word.computed).toBe(true);
  });

  it("keeps command substitution computed and dash-capable", () => {
    const node = syntax("command_substitution", "$(date)");
    const word = readShellWord(node, context());
    expect(word.value).toBe("$(date)");
    expect(word.computed).toBe(true);
    expect(word.mayLeadWithDash).toBe(true);
  });

  it("keeps process substitution computed but not dash-capable", () => {
    const node = syntax("process_substitution", "<(ls)");
    const word = readShellWord(node, context());
    expect(word.computed).toBe(true);
    expect(word.mayLeadWithDash).toBe(false);
  });

  it("does not let a literal prefix imply a dash", () => {
    const node = syntax("string", '"prefix-$VAR"', [
      syntax("string_content", "prefix-"),
      simple("VAR"),
    ]);
    expect(readShellWord(node, context()).mayLeadWithDash).toBe(false);
  });

  it("keeps the dash possible when an expansion leads the word", () => {
    const node = syntax("string", '"$VAR-suffix"', [
      simple("VAR"),
      syntax("string_content", "-suffix"),
    ]);
    expect(readShellWord(node, context()).mayLeadWithDash).toBe(true);
  });

  it("marks ansi-c strings computed", () => {
    expect(readShellWord(syntax("ansi_c_string", "$'a\\nb'"), context()).computed).toBe(true);
  });

  it("marks unknown nodes computed", () => {
    const word = readShellWord(syntax("mystery_token", "[abc]"), context());
    expect(word.computed).toBe(true);
    expect(word.value).toBe("[abc]");
  });
});

describe("HOME/PWD rebinding scan", () => {
  it("reports nothing for read-only references", () => {
    const root = syntax("program", "echo $HOME ${PWD}", [command("echo", [simple("HOME"), expansion("PWD")])]);
    expect(scanRebindings([root])).toEqual(NO_REBINDING);
  });

  it("detects a leading assignment", () => {
    const withAssignment = syntax("program", "HOME=/x cmd", [
      syntax("command", "HOME=/x cmd", [
        syntax("variable_assignment", "HOME=/x", [
          syntax("variable_name", "HOME"),
          token("=", "="),
          syntax("word", "/x"),
        ]),
        syntax("command_name", "cmd", [syntax("word", "cmd")]),
      ]),
    ]);
    expect(scanRebindings([withAssignment]).home).toBe(true);
  });

  it("detects a declaration binding", () => {
    const root = syntax("declaration_command", "export PWD=/x", [
      token("export", "export"),
      syntax("variable_assignment", "PWD=/x", [
        syntax("variable_name", "PWD"),
        token("=", "="),
        syntax("word", "/x"),
      ]),
    ]);
    expect(scanRebindings([root]).pwd).toBe(true);
  });

  it("detects a declaration word without a value", () => {
    const root = syntax("declaration_command", "declare HOME", [
      token("declare", "declare"),
      syntax("word", "HOME"),
    ]);
    expect(scanRebindings([root]).home).toBe(true);
  });

  it("detects a loop variable", () => {
    const root = syntax("for_statement", "for HOME in a; do :; done", [
      syntax("variable_name", "HOME"),
      syntax("word", "a"),
      syntax("do_group", "do :; done", [command(":")]),
    ]);
    expect(scanRebindings([root]).home).toBe(true);
  });

  it("detects read binding by argument", () => {
    const root = command("read", ["-r", "PWD"]);
    expect(scanRebindings([root]).pwd).toBe(true);
  });

  it("detects printf -v binding", () => {
    const root = command("printf", ["-v", "HOME", "x"]);
    expect(scanRebindings([root]).home).toBe(true);
  });

  it("detects let binding", () => {
    const root = command("let", ["HOME=1"]);
    expect(scanRebindings([root]).home).toBe(true);
  });

  it("detects arithmetic assignment", () => {
    const root = syntax("compound_statement", "((PWD+=1))", [
      syntax("binary_expression", "PWD+=1", [
        syntax("variable_name", "PWD"),
        token("+=", "+="),
        syntax("number", "1"),
      ]),
    ]);
    expect(scanRebindings([root]).pwd).toBe(true);
  });

  it("detects an assignment-operator expansion", () => {
    expect(scanRebindings([expansion("HOME", ":=", "x")]).home).toBe(true);
  });

  it("detects unset", () => {
    const root = syntax("unset_command", "unset HOME", [
      token("unset", "unset"),
      syntax("variable_name", "HOME"),
    ]);
    expect(scanRebindings([root]).home).toBe(true);
  });

  it("treats visible-code execution as rebinding both names", () => {
    for (const name of ["eval", "source", "."]) {
      const root = command(name, ["script"]);
      const rebound = scanRebindings([root]);
      expect(rebound.home, name).toBe(true);
      expect(rebound.pwd, name).toBe(true);
    }
  });

  it("detects a nested assignment inside a substitution", () => {
    const assignment = syntax("variable_assignment", "HOME=1", [
      syntax("variable_name", "HOME"),
      token("=", "="),
      syntax("number", "1"),
    ]);
    const inner = syntax("command", "HOME=1 cmd", [
      assignment,
      syntax("command_name", "cmd", [syntax("word", "cmd")]),
    ]);
    const substitution = syntax("command_substitution", "$(HOME=1 cmd)", [inner]);
    const root = command("echo", [substitution]);
    expect(scanRebindings([root]).home).toBe(true);
  });
});
