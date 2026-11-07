import { describe, expect, it } from "vitest";
import { trackWorkingDirectories } from "#approve-core/utils/access-intent/bash/cwd-tracking";
import { PathNormalizer } from "#approve-core/utils/path/path-normalizer";
import { POSIX_PATH_FLAVOR } from "#approve-core/utils/path/path-flavor";
import { syntax, token } from "./fake-syntax";

describe("working-directory tracking", () => {
  it("applies a literal cd to later commands in the current shell", () => {
    const first = syntax("command", "cd src", [syntax("command_name", "cd", [syntax("word", "cd")]), syntax("word", "src")]);
    const second = syntax("command", "cat file", [syntax("command_name", "cat", [syntax("word", "cat")]), syntax("word", "file")]);
    const root = syntax("program", "cd src; cat file", [first, token(";", ";"), second]);
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work");
    const bases = trackWorkingDirectories(root, normalizer, "/work", { home: "/home/user", homeRebound: false, pwdRebound: false });
    expect(bases.baseAt(first.startIndex)).toBe("/work");
    expect(bases.baseAt(second.startIndex)).toBe("/work/src");
  });

  it("recovers an unknown base after a literal absolute cd", () => {
    const dynamic = syntax("command", "cd $dir", [syntax("command_name", "cd", [syntax("word", "cd")]), syntax("simple_expansion", "$dir")]);
    const absolute = syntax("command", "cd /safe", [syntax("command_name", "cd", [syntax("word", "cd")]), syntax("word", "/safe")]);
    const last = syntax("command", "cat file", [syntax("command_name", "cat", [syntax("word", "cat")]), syntax("word", "file")]);
    const root = syntax("program", "cd $dir; cd /safe; cat file", [dynamic, token(";", ";"), absolute, token(";", ";"), last]);
    const bases = trackWorkingDirectories(root, new PathNormalizer(POSIX_PATH_FLAVOR, "/work"), "/work", { home: "/home/user", homeRebound: false, pwdRebound: false });
    expect(bases.baseAt(absolute.startIndex)).toBeUndefined();
    expect(bases.baseAt(last.startIndex)).toBe("/safe");
  });

  it("tracks cd within a subshell without leaking it to the parent", () => {
    const change = syntax("command", "cd src", [syntax("command_name", "cd", [syntax("word", "cd")]), syntax("word", "src")]);
    const inside = syntax("command", "cat inner", [syntax("command_name", "cat", [syntax("word", "cat")]), syntax("word", "inner")]);
    const subshell = syntax("subshell", "(cd src; cat inner)", [change, token(";", ";"), inside]);
    const after = syntax("command", "cat outer", [syntax("command_name", "cat", [syntax("word", "cat")]), syntax("word", "outer")]);
    const root = syntax("program", "(cd src; cat inner); cat outer", [subshell, token(";", ";"), after]);
    const bases = trackWorkingDirectories(root, new PathNormalizer(POSIX_PATH_FLAVOR, "/work"), "/work", { home: "/home/user", homeRebound: false, pwdRebound: false });
    expect(bases.baseAt(inside.startIndex)).toBe("/work/src");
    expect(bases.baseAt(after.startIndex)).toBe("/work");
  });

  it("uses the entering directory for a redirect on a cd command", () => {
    const change = syntax("command", "cd src", [syntax("command_name", "cd", [syntax("word", "cd")]), syntax("word", "src")]);
    const redirect = syntax("file_redirect", "> output", [token(">", ">"), syntax("word", "output")]);
    const statement = syntax("redirected_statement", "cd src > output", [change, redirect]);
    const after = syntax("command", "cat file", [syntax("command_name", "cat", [syntax("word", "cat")]), syntax("word", "file")]);
    const root = syntax("program", "cd src > output; cat file", [statement, token(";", ";"), after]);
    const bases = trackWorkingDirectories(root, new PathNormalizer(POSIX_PATH_FLAVOR, "/work"), "/work", { home: "/home/user", homeRebound: false, pwdRebound: false });
    expect(bases.baseAt(redirect.startIndex)).toBe("/work");
    expect(bases.baseAt(after.startIndex)).toBe("/work/src");
  });

  it("does not leak a background cd into the next command", () => {
    const change = syntax("command", "cd src", [syntax("command_name", "cd", [syntax("word", "cd")]), syntax("word", "src")]);
    const after = syntax("command", "cat file", [syntax("command_name", "cat", [syntax("word", "cat")]), syntax("word", "file")]);
    const root = syntax("program", "cd src & cat file", [change, token("&", "&"), after]);
    const bases = trackWorkingDirectories(root, new PathNormalizer(POSIX_PATH_FLAVOR, "/work"), "/work", { home: "/home/user", homeRebound: false, pwdRebound: false });
    expect(bases.baseAt(after.startIndex)).toBe("/work");
  });

  it("recognizes background separators without relying on node identity", () => {
    const change = syntax("command", "cd src", [syntax("command_name", "cd", [syntax("word", "cd")]), syntax("word", "src")]);
    const after = syntax("command", "cat file", [syntax("command_name", "cat", [syntax("word", "cat")]), syntax("word", "file")]);
    const root = syntax("program", "cd src & cat file", [change, token("&", "&"), after]);
    const wrapped = { ...root, type: root.type, text: root.text, startIndex: root.startIndex, endIndex: root.endIndex, isNamed: true, hasError: false, childCount: root.childCount,
      child: (index: number) => { const child = root.child(index); return child && { type: child.type, text: child.text, startIndex: child.startIndex, endIndex: child.endIndex, childCount: child.childCount, isNamed: child.isNamed, hasError: child.hasError, child: child.child.bind(child), previousSibling: child.previousSibling.bind(child) }; },
      previousSibling: () => null };
    const bases = trackWorkingDirectories(wrapped, new PathNormalizer(POSIX_PATH_FLAVOR, "/work"), "/work", { home: "/home/user", homeRebound: false, pwdRebound: false });
    expect(bases.baseAt(after.startIndex)).toBe("/work");
  });

  it("isolates pipeline stages and the following command", () => {
    const change = syntax("command", "cd src", [syntax("command_name", "cd", [syntax("word", "cd")]), syntax("word", "src")]);
    const piped = syntax("command", "cat inner", [syntax("command_name", "cat", [syntax("word", "cat")]), syntax("word", "inner")]);
    const pipeline = syntax("pipeline", "cd src | cat inner", [change, token("|", "|"), piped]);
    const after = syntax("command", "cat outer", [syntax("command_name", "cat", [syntax("word", "cat")]), syntax("word", "outer")]);
    const root = syntax("program", "cd src | cat inner; cat outer", [pipeline, token(";", ";"), after]);
    const bases = trackWorkingDirectories(root, new PathNormalizer(POSIX_PATH_FLAVOR, "/work"), "/work", { home: "/home/user", homeRebound: false, pwdRebound: false });
    expect(bases.baseAt(piped.startIndex)).toBe("/work");
    expect(bases.baseAt(after.startIndex)).toBe("/work");
  });

  it("does not treat a home expansion as a proven cd base", () => {
    const change = syntax("command", "cd ~/src", [syntax("command_name", "cd", [syntax("word", "cd")]), syntax("word", "~/src")]);
    const after = syntax("command", "cat file", [syntax("command_name", "cat", [syntax("word", "cat")]), syntax("word", "file")]);
    const root = syntax("program", "cd ~/src; cat file", [change, token(";", ";"), after]);
    const bases = trackWorkingDirectories(root, new PathNormalizer(POSIX_PATH_FLAVOR, "/work"), "/work", { home: "/home/user", homeRebound: false, pwdRebound: false });
    expect(bases.baseAt(after.startIndex)).toBeUndefined();
  });

  it("treats a variable expansion target as unknown even when it expands statically", () => {
    const cases = [
      syntax("simple_expansion", "$HOME", [token("$", "$"), syntax("variable_name", "HOME")]),
      syntax("expansion", "${HOME}", [token("${", "${"), syntax("variable_name", "HOME"), token("}", "}")]),
      syntax("string", '"$HOME"', [syntax("simple_expansion", "$HOME", [token("$", "$"), syntax("variable_name", "HOME")])]),
    ];
    for (const target of cases) {
      const change = syntax("command", `cd ${target.text}`, [syntax("command_name", "cd", [syntax("word", "cd")]), target]);
      const after = syntax("command", "cat file", [syntax("command_name", "cat", [syntax("word", "cat")]), syntax("word", "file")]);
      const root = syntax("program", `cd ${target.text}; cat file`, [change, token(";", ";"), after]);
      const bases = trackWorkingDirectories(root, new PathNormalizer(POSIX_PATH_FLAVOR, "/work"), "/work", { home: "/home/user", homeRebound: false, pwdRebound: false });
      expect(bases.baseAt(after.startIndex)).toBeUndefined();
    }
  });

  it("treats HOME variable expansion in cd as an unknown base", () => {
    const change = syntax("command", "cd $HOME", [syntax("command_name", "cd", [syntax("word", "cd")]), syntax("simple_expansion", "$HOME")]);
    const after = syntax("command", "cat file", [syntax("command_name", "cat", [syntax("word", "cat")]), syntax("word", "file")]);
    const root = syntax("program", "cd $HOME; cat file", [change, token(";", ";"), after]);
    const bases = trackWorkingDirectories(root, new PathNormalizer(POSIX_PATH_FLAVOR, "/work"), "/work", { home: "/home/user", homeRebound: false, pwdRebound: false });
    expect(bases.baseAt(after.startIndex)).toBeUndefined();
  });
});
