import { describe, expect, it } from "vitest";
import { collectPathTokens } from "#approve-core/utils/access-intent/bash/token-collection";
import { syntax, token } from "./fake-syntax";

describe("path token collection", () => {
  it("collects a command operand with its own read effect and source span", () => {
    const root = syntax("program", "cat file.txt", [syntax("command", "cat file.txt", [
      syntax("command_name", "cat", [syntax("word", "cat")]), syntax("word", "file.txt"),
    ])]);
    expect(collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false })).toEqual([
      { value: "file.txt", role: "operand", effect: { effect: "read", source: "builtin-core" }, span: { startIndex: 4, endIndex: 12 } },
    ]);
  });

  it("does not collect comment text as a command operand", () => {
    const root = syntax("command", "cat file # /not-a-path", [
      syntax("command_name", "cat", [syntax("word", "cat")]), syntax("word", "file"), syntax("comment", "# /not-a-path"),
    ]);
    expect(collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((item) => item.value)).toEqual(["file"]);
  });

  it("does not treat parser recovery nodes inside ERROR as executed commands", () => {
    const root = syntax("ERROR", "cat ./file", [syntax("command", "cat ./file", [
      syntax("command_name", "cat", [syntax("word", "cat")]), syntax("word", "./file"),
    ])], { error: true });
    expect(collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false })).toEqual([]);
  });

  it("collects a new redirect target with a syntax-proven write effect", () => {
    const root = syntax("program", "cat file > output", [syntax("redirected_statement", "cat file > output", [
      syntax("command", "cat file", [syntax("command_name", "cat", [syntax("word", "cat")]), syntax("word", "file")]),
      syntax("file_redirect", "> output", [token(">", ">"), syntax("word", "output")]),
    ])]);
    expect(collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false })).toContainEqual({
      value: "output", role: "file_redirect", effect: { effect: "write", source: "syntax" }, span: { startIndex: 11, endIndex: 17 },
    });
  });

  it("does not claim a redirect effect when its position is unresolved", () => {
    const root = syntax("redirected_statement", "broken > output", [
      syntax("ERROR", "broken", [], { error: true }),
      syntax("file_redirect", "> output", [token(">", ">"), syntax("word", "output")]),
    ]);
    expect(collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false })).toContainEqual({
      value: "output", role: "file_redirect", effect: { effect: "unproven", source: "unknown" }, span: { startIndex: 9, endIndex: 15 },
    });
  });

  it("keeps nested command effects separate from the outer command", () => {
    const root = syntax("program", "echo $(rm file)", [syntax("command", "echo $(rm file)", [
      syntax("command_name", "echo", [syntax("word", "echo")]),
      syntax("command_substitution", "$(rm file)", [syntax("command", "rm file", [
        syntax("command_name", "rm", [syntax("word", "rm")]), syntax("word", "file"),
      ])]),
    ])]);
    expect(collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false })).toContainEqual({
      value: "file", role: "operand", effect: { effect: "unproven", source: "unknown" }, span: { startIndex: 10, endIndex: 14 },
    });
  });

  it("collects the value of an attached option as a separate candidate", () => {
    const root = syntax("command", "tool --config=settings.json", [
      syntax("command_name", "tool", [syntax("word", "tool")]), syntax("word", "--config=settings.json"),
    ]);
    expect(collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false })).toContainEqual({
      value: "settings.json", role: "operand", effect: { effect: "unproven", source: "unknown" }, sourceOffset: 5,
    });
  });

  it("preserves computed status on an attached option value", () => {
    const root = syntax("command", "tool --file=$dir/file", [
      syntax("command_name", "tool", [syntax("word", "tool")]),
      syntax("concatenation", "--file=$dir/file", [syntax("word", "--file="), syntax("simple_expansion", "$dir"), syntax("word", "/file")]),
    ]);
    const tokens = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false });
    expect(tokens).toContainEqual(expect.objectContaining({ value: "$dir/file", computed: true }));
  });

  it("collects nested commands inside a dynamic redirect target", () => {
    const root = syntax("file_redirect", "> $(cat filename)", [token(">", ">"),
      syntax("command_substitution", "$(cat filename)", [syntax("command", "cat filename", [
        syntax("command_name", "cat", [syntax("word", "cat")]), syntax("word", "filename"),
      ])]),
    ]);
    expect(collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false })).toContainEqual(
      { value: "filename", role: "operand", effect: { effect: "read", source: "builtin-core" }, span: { startIndex: 8, endIndex: 16 } },
    );
  });

  it("visits command substitutions inside leading assignments", () => {
    const root = syntax("command", "A=$(cat file) echo ok", [
      syntax("variable_assignment", "A=$(cat file)", [syntax("command_substitution", "$(cat file)", [
        syntax("command", "cat file", [syntax("command_name", "cat", [syntax("word", "cat")]), syntax("word", "file")]),
      ])]), syntax("command_name", "echo", [syntax("word", "echo")]), syntax("word", "ok"),
    ]);
    expect(collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false })).toContainEqual({
      value: "file", role: "operand", effect: { effect: "read", source: "builtin-core" }, span: { startIndex: 8, endIndex: 12 },
    });
  });

  it("does not treat grep's pattern as a file operand", () => {
    const root = syntax("command", "grep /pattern/ input.txt", [
      syntax("command_name", "grep", [syntax("word", "grep")]), syntax("word", "/pattern/"), syntax("word", "input.txt"),
    ]);
    expect(collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((entry) => entry.value)).toEqual(["input.txt"]);
  });

  it("retains the file when grep receives its pattern through -e", () => {
    const root = syntax("command", "grep -e /pattern/ input.txt", [
      syntax("command_name", "grep", [syntax("word", "grep")]), syntax("word", "-e"), syntax("word", "/pattern/"), syntax("word", "input.txt"),
    ]);
    const values = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((entry) => entry.value);
    expect(values).toContain("input.txt");
    expect(values).not.toContain("/pattern/");
  });

  it("collects grep's pattern file and input when using -f", () => {
    const root = syntax("command", "grep -f patterns.txt input.txt", [
      syntax("command_name", "grep", [syntax("word", "grep")]), syntax("word", "-f"), syntax("word", "patterns.txt"), syntax("word", "input.txt"),
    ]);
    const values = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((entry) => entry.value);
    expect(values).toContain("patterns.txt");
    expect(values).toContain("input.txt");
  });

  it("treats a pending pattern-file argument as a file even when it resembles an option", () => {
    const root = syntax("command", "grep -f --context ./input", [
      syntax("command_name", "grep", [syntax("word", "grep")]), syntax("word", "-f"), syntax("word", "--context"), syntax("word", "./input"),
    ]);
    const values = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((item) => item.value);
    expect(values).toContain("--context");
    expect(values).toContain("./input");
  });

  it("collects a script file supplied as a glued short option", () => {
    const root = syntax("command", "grep -fpatterns.txt input.txt", [
      syntax("command_name", "grep", [syntax("word", "grep")]), syntax("word", "-fpatterns.txt"), syntax("word", "input.txt"),
    ]);
    const values = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((entry) => entry.value);
    expect(values).toContain("patterns.txt");
    expect(values).toContain("input.txt");
  });

  it("collects a pattern file even after an explicit expression", () => {
    const root = syntax("command", "grep -efoo -fpatterns.txt input.txt", [
      syntax("command_name", "grep", [syntax("word", "grep")]), syntax("word", "-efoo"), syntax("word", "-fpatterns.txt"), syntax("word", "input.txt"),
    ]);
    const values = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((entry) => entry.value);
    expect(values).toContain("patterns.txt");
    expect(values).toContain("input.txt");
  });

  it("does not treat an unrecognized sd option as a file flag", () => {
    const root = syntax("command", "sd -flook search replace input.txt", [
      syntax("command_name", "sd", [syntax("word", "sd")]), syntax("word", "-flook"), syntax("word", "search"), syntax("word", "replace"), syntax("word", "input.txt"),
    ]);
    const values = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((entry) => entry.value);
    expect(values).not.toContain("look");
    expect(values).toContain("input.txt");
  });

  it("collects for-in words as operands with unknown effects", () => {
    const root = syntax("for_statement", "for x in ./a ./b; do true; done", [
      token("for", "for"), syntax("variable_name", "x"), token("in", "in"), syntax("word", "./a"), syntax("word", "./b"),
      syntax("do_group", "do true; done", [syntax("command", "true", [syntax("command_name", "true", [syntax("word", "true")])])]),
    ]);
    const tokens = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false });
    expect(tokens.map((item) => [item.value, item.effect.effect])).toEqual([["./a", "unproven"], ["./b", "unproven"]]);
  });

  it("marks a computed for-in word as dynamic", () => {
    const root = syntax("for_statement", "for x in $dir/file; do true; done", [
      token("for", "for"), syntax("variable_name", "x"), token("in", "in"),
      syntax("concatenation", "$dir/file", [syntax("simple_expansion", "$dir"), syntax("word", "/file")]),
      token(";", ";"), syntax("do_group", "do true; done"),
    ]);
    const tokens = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false });
    expect(tokens).toContainEqual(expect.objectContaining({ value: "$dir/file", computed: true }));
  });

  it("does not collect a comment inside a for-in word list", () => {
    const root = syntax("for_statement", "for x in ./a # /not-a-file\ndo true; done", [
      token("for", "for"), syntax("variable_name", "x"), token("in", "in"), syntax("word", "./a"),
      syntax("comment", "# /not-a-file"), syntax("do_group", "do true; done", [syntax("command", "true", [syntax("command_name", "true", [syntax("word", "true")])])]),
    ]);
    expect(collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((item) => item.value)).toEqual(["./a"]);
  });

  it("collects the case subject without collecting case patterns", () => {
    const root = syntax("case_statement", "case ./input in pattern) true;; esac", [
      token("case", "case"), syntax("word", "./input"), token("in", "in"),
      syntax("case_item", "pattern) true;;", [syntax("word", "pattern"), syntax("command", "true", [syntax("command_name", "true", [syntax("word", "true")])])]),
      token("esac", "esac"),
    ]);
    const tokens = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false });
    expect(tokens.map((item) => item.value)).toEqual(["./input"]);
  });

  it("marks a computed case subject as dynamic", () => {
    const root = syntax("case_statement", "case $dir/file in x) true;; esac", [
      token("case", "case"), syntax("concatenation", "$dir/file", [syntax("simple_expansion", "$dir"), syntax("word", "/file")]),
      token("in", "in"), syntax("case_item", "x) true;;", [syntax("word", "x")]), token("esac", "esac"),
    ]);
    const tokens = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false });
    expect(tokens).toContainEqual(expect.objectContaining({ value: "$dir/file", computed: true }));
  });

  it("does not collect comments around a case subject", () => {
    const root = syntax("case_statement", "case ./input # /not-a-file\nin x) true;; esac", [
      token("case", "case"), syntax("word", "./input"), syntax("comment", "# /not-a-file"), token("in", "in"),
      syntax("case_item", "x) true;;", [syntax("word", "x")]), token("esac", "esac"),
    ]);
    expect(collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((item) => item.value)).toEqual(["./input"]);
  });

  it("retains input after an attached grep expression", () => {
    const root = syntax("command", "grep -efoo input.txt", [
      syntax("command_name", "grep", [syntax("word", "grep")]), syntax("word", "-efoo"), syntax("word", "input.txt"),
    ]);
    expect(collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((entry) => entry.value)).toContain("input.txt");
  });

  it("preserves possible files when grep context arity differs across implementations", () => {
    const root = syntax("command", "grep --context 3 /pattern/ input.txt", [
      syntax("command_name", "grep", [syntax("word", "grep")]), syntax("word", "--context"), syntax("number", "3"),
      syntax("word", "/pattern/"), syntax("word", "input.txt"),
    ]);
    const values = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((entry) => entry.value);
    expect(values).toContain("/pattern/");
    expect(values).toContain("input.txt");
  });

  it("retains a possible file after grep's ambiguous context option", () => {
    const root = syntax("command", "grep --context pattern ./input", [
      syntax("command_name", "grep", [syntax("word", "grep")]), syntax("word", "--context"), syntax("word", "pattern"), syntax("word", "./input"),
    ]);
    const values = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((entry) => entry.value);
    expect(values).toContain("./input");
  });

  it("consumes ripgrep's separated context count before the pattern", () => {
    const root = syntax("command", "rg --context 3 /pattern/ input.txt", [
      syntax("command_name", "rg", [syntax("word", "rg")]), syntax("word", "--context"), syntax("number", "3"),
      syntax("word", "/pattern/"), syntax("word", "input.txt"),
    ]);
    const values = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((entry) => entry.value);
    expect(values).not.toContain("/pattern/");
    expect(values).not.toContain("3");
    expect(values).toContain("input.txt");
  });

  it("distinguishes ripgrep's required -C value from grep's ambiguous -C", () => {
    function make(name: string) {
      return syntax("command", `${name} -C 3 /pattern/ ./input`, [
        syntax("command_name", name, [syntax("word", name)]), syntax("word", "-C"), syntax("number", "3"),
        syntax("word", "/pattern/"), syntax("word", "./input"),
      ]);
    }
    const context = { home: "/home/user", homeRebound: false, pwdRebound: false };
    const rg = collectPathTokens(make("rg"), context).map((item) => item.value);
    const grep = collectPathTokens(make("grep"), context).map((item) => item.value);
    expect(rg).not.toContain("/pattern/");
    expect(rg).toContain("./input");
    expect(grep).toContain("/pattern/");
    expect(grep).toContain("./input");
  });

  it("consumes ripgrep glob filter values without turning them into file operands", () => {
    const root = syntax("command", "rg --glob **/test pattern ./input", [
      syntax("command_name", "rg", [syntax("word", "rg")]), syntax("word", "--glob"), syntax("word", "**/test"),
      syntax("word", "pattern"), syntax("word", "./input"),
    ]);
    const values = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((item) => item.value);
    expect(values).not.toContain("**/test");
    expect(values).not.toContain("pattern");
    expect(values).toContain("./input");
  });

  it("consumes grep context and count option values without consuming the pattern", () => {
    const root = syntax("command", "grep -A 2 --max-count 3 /pattern/ ./input", [
      syntax("command_name", "grep", [syntax("word", "grep")]), syntax("word", "-A"), syntax("number", "2"),
      syntax("word", "--max-count"), syntax("number", "3"), syntax("word", "/pattern/"), syntax("word", "./input"),
    ]);
    const values = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((item) => item.value);
    expect(values).not.toContain("2");
    expect(values).not.toContain("3");
    expect(values).not.toContain("/pattern/");
    expect(values).toContain("./input");
  });

  it("does not create path candidates from attached count values", () => {
    const root = syntax("command", "grep --max-count=3 -A2 pattern ./input", [
      syntax("command_name", "grep", [syntax("word", "grep")]), syntax("word", "--max-count=3"), syntax("word", "-A2"),
      syntax("word", "pattern"), syntax("word", "./input"),
    ]);
    const values = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((item) => item.value);
    expect(values).not.toContain("3");
    expect(values).toContain("./input");
  });

  it("consumes an awk separator value before the program", () => {
    const root = syntax("command", "awk -F : program ./input", [
      syntax("command_name", "awk", [syntax("word", "awk")]), syntax("word", "-F"), syntax("word", ":"),
      syntax("word", "program"), syntax("word", "./input"),
    ]);
    const values = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((item) => item.value);
    expect(values).not.toContain(":");
    expect(values).not.toContain("program");
    expect(values).toContain("./input");
  });

  it("consumes only an explicitly empty sed in-place suffix before the script", () => {
    const root = syntax("command", "sed -i '' s/a/b/ ./input", [
      syntax("command_name", "sed", [syntax("word", "sed")]), syntax("word", "-i"), syntax("raw_string", "''"),
      syntax("word", "s/a/b/"), syntax("word", "./input"),
    ]);
    const values = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((entry) => entry.value);
    expect(values).not.toContain("s/a/b/");
    expect(values).toContain("./input");
  });

  it("treats gawk --source as program text and retains the input file", () => {
    const root = syntax("command", "gawk --source=program ./input", [
      syntax("command_name", "gawk", [syntax("word", "gawk")]), syntax("word", "--source=program"), syntax("word", "./input"),
    ]);
    const values = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((item) => item.value);
    expect(values).not.toContain("program");
    expect(values).toContain("./input");
  });

  it("retains a possible input after an ambiguous awk long option", () => {
    const root = syntax("command", "awk --source=program ./input", [
      syntax("command_name", "awk", [syntax("word", "awk")]), syntax("word", "--source=program"), syntax("word", "./input"),
    ]);
    const values = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((item) => item.value);
    expect(values).toContain("./input");
  });

  it("preserves inert operands as command facts without treating them as paths", () => {
    const root = syntax("command", "tool data.txt", [syntax("command_name", "tool", [syntax("word", "tool")]), syntax("word", "data.txt")]);
    const tokens = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }, { global: { tool: { effects: [] } } });
    expect(tokens[0]).toMatchObject({ value: "data.txt", role: "inert" });
  });

  it("does not let a user declaration override a withdrawn core proof", () => {
    const root = syntax("command", "sort -o output input", [syntax("command_name", "sort", [syntax("word", "sort")]),
      syntax("word", "-o"), syntax("word", "output"), syntax("word", "input")]);
    const tokens = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }, { project: { sort: { effects: "read" } } });
    expect(tokens.find((item) => item.value === "output")?.effect.effect).toBe("unproven");
  });

  it("keeps redirect syntax independent from a command's inert declaration", () => {
    const root = syntax("redirected_statement", "tool data > output", [
      syntax("command", "tool data", [syntax("command_name", "tool", [syntax("word", "tool")]), syntax("word", "data")]),
      syntax("file_redirect", "> output", [token(">", ">"), syntax("word", "output")]),
    ]);
    const tokens = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }, { project: { tool: { effects: [] } } });
    expect(tokens.find((item) => item.value === "data")?.role).toBe("inert");
    expect(tokens.find((item) => item.value === "output")).toMatchObject({ role: "file_redirect", effect: { effect: "write", source: "syntax" } });
  });

  it("retains a computed redirect target without claiming a static destination", () => {
    const root = syntax("file_redirect", "> $HOME/file", [token(">", ">"), syntax("concatenation", "$HOME/file", [
      syntax("simple_expansion", "$HOME", [syntax("variable_name", "HOME")]), syntax("word", "/file"),
    ])]);
    const tokens = collectPathTokens(root, { home: "/home/user", homeRebound: true, pwdRebound: false });
    expect(tokens).toContainEqual({ value: "$HOME/file", role: "operand", effect: { effect: "unproven", source: "unknown" }, computed: true, span: { startIndex: 2, endIndex: 12 } });
  });

  it("uses redirect syntax for a statically resolved HOME target", () => {
    const root = syntax("file_redirect", ">$HOME/file", [token(">", ">"), syntax("concatenation", "$HOME/file", [
      syntax("simple_expansion", "$HOME", [syntax("variable_name", "HOME")]), syntax("word", "/file"),
    ])]);
    const tokens = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false });
    expect(tokens).toContainEqual(expect.objectContaining({ value: "/home/user/file", role: "file_redirect", effect: { effect: "write", source: "syntax" } }));
  });

  it("retains a computed output-duplication target without treating it as a static file", () => {
    const root = syntax("file_redirect", ">&$dir/file", [token(">&", ">&"), syntax("concatenation", "$dir/file", [
      syntax("simple_expansion", "$dir"), syntax("word", "/file"),
    ])]);
    const tokens = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false });
    expect(tokens).toContainEqual(expect.objectContaining({ value: "$dir/file", role: "operand", effect: { effect: "unproven", source: "unknown" } }));
  });

  it("consumes interpreter inline code without dropping the following file", () => {
    const root = syntax("command", "node -e code.js input.txt", [
      syntax("command_name", "node", [syntax("word", "node")]), syntax("word", "-e"),
      syntax("word", "code.js"), syntax("word", "input.txt"),
    ]);
    const values = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((entry) => entry.value);
    expect(values).not.toContain("code.js");
    expect(values).toContain("input.txt");
  });

  it("does not split an attached interpreter script into a path", () => {
    const root = syntax("command", "node --eval=code.js input.txt", [
      syntax("command_name", "node", [syntax("word", "node")]), syntax("word", "--eval=code.js"), syntax("word", "input.txt"),
    ]);
    const values = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((item) => item.value);
    expect(values).not.toContain("code.js");
    expect(values).toContain("input.txt");
  });

  it("retains the value of an unrecognized grep option", () => {
    const root = syntax("command", "grep --expression=./config pattern ./input", [
      syntax("command_name", "grep", [syntax("word", "grep")]), syntax("word", "--expression=./config"),
      syntax("word", "pattern"), syntax("word", "./input"),
    ]);
    const values = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((item) => item.value);
    expect(values).toContain("./config");
    expect(values).toContain("./input");
  });

  it("consumes Python's -c program and retains its remaining arguments", () => {
    const root = syntax("command", "python3 -c code.py input.txt", [
      syntax("command_name", "python3", [syntax("word", "python3")]), syntax("word", "-c"),
      syntax("word", "code.py"), syntax("word", "input.txt"),
    ]);
    const values = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((entry) => entry.value);
    expect(values).not.toContain("code.py");
    expect(values).toContain("input.txt");
  });

  it("does not consume an interpreter option after the option terminator", () => {
    const root = syntax("command", "python3 -- -c input.txt", [
      syntax("command_name", "python3", [syntax("word", "python3")]), syntax("word", "--"),
      syntax("word", "-c"), syntax("word", "input.txt"),
    ]);
    expect(collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((entry) => entry.value)).toContain("input.txt");
  });

  it("consumes a quoted dash-leading grep pattern as a positional word", () => {
    const root = syntax("command", "grep '-abc' input.txt", [
      syntax("command_name", "grep", [syntax("word", "grep")]), syntax("raw_string", "'-abc'"), syntax("word", "input.txt"),
    ]);
    const values = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((entry) => entry.value);
    expect(values).toContain("input.txt");
    expect(values).not.toContain("-abc");
  });

  it("does not consume the input file when the grep flag spelling is quoted", () => {
    const root = syntax("command", "grep '-e' input.txt", [
      syntax("command_name", "grep", [syntax("word", "grep")]), syntax("raw_string", "'-e'"), syntax("word", "input.txt"),
    ]);
    const values = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((entry) => entry.value);
    expect(values).toContain("input.txt");
    expect(values).not.toContain("-e");
  });

  it("does not consume the input file when a quoted spelling resembles an interpreter flag", () => {
    const root = syntax("command", "node '-e' input.txt", [
      syntax("command_name", "node", [syntax("word", "node")]), syntax("raw_string", "'-e'"), syntax("word", "input.txt"),
    ]);
    expect(collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((entry) => entry.value)).toContain("input.txt");
  });

  it("does not treat a quoted dash-leading prefix as a flag", () => {
    const root = syntax("command", 'grep "-e"foo input.txt', [
      syntax("command_name", "grep", [syntax("word", "grep")]),
      syntax("concatenation", '"-e"foo', [syntax("string", '"-e"'), syntax("word", "foo")]),
      syntax("word", "input.txt"),
    ]);
    const values = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((entry) => entry.value);
    expect(values).toContain("input.txt");
    expect(values).not.toContain("-efoo");
  });

  it("treats a dash-leading pattern after the option terminator as positional", () => {
    const root = syntax("command", "grep -- -abc input.txt", [
      syntax("command_name", "grep", [syntax("word", "grep")]), syntax("word", "--"), syntax("word", "-abc"), syntax("word", "input.txt"),
    ]);
    const values = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false }).map((entry) => entry.value);
    expect(values).toContain("input.txt");
    expect(values).not.toContain("-abc");
  });
});
