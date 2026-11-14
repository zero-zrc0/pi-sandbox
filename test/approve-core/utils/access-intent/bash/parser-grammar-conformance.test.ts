import { beforeAll, describe, expect, it } from "vitest";
import {
  createCorrectedParser,
  createTreeSitterBashParser,
  type SyntaxNode,
  type SyntaxParser,
} from "#approve-core/utils/access-intent/bash/parser";
import { applyParseView } from "#approve-core/utils/access-intent/bash/parse-view";
import { analyzeRedirect, redirectMayWriteFile } from "#approve-core/utils/access-intent/bash/redirect-analysis";
import { redirectPositionUnresolved } from "#approve-core/utils/access-intent/bash/parse-health";
import { findNestedExecutions } from "#approve-core/utils/access-intent/bash/nested-execution";
import { buildHeredocFreeLine } from "#approve-core/utils/access-intent/bash/heredoc-free-lines";
import { withSalvagedRoots } from "#approve-core/utils/access-intent/bash/unresolved-salvage";
import { collectPathTokens } from "#approve-core/utils/access-intent/bash/token-collection";
import { trackWorkingDirectories } from "#approve-core/utils/access-intent/bash/cwd-tracking";
import { PathNormalizer } from "#approve-core/utils/path/path-normalizer";
import { POSIX_PATH_FLAVOR } from "#approve-core/utils/path/path-flavor";
import { BashProgram } from "#approve-core/utils/access-intent/bash/program";
import { bashPathFacts } from "#approve-core/utils/access-intent/bash/bash-path-resolver";

let raw: SyntaxParser;
let corrected: SyntaxParser;

beforeAll(async () => {
  raw = await createTreeSitterBashParser();
  corrected = createCorrectedParser(raw);
});

function children(node: SyntaxNode): SyntaxNode[] {
  const result: SyntaxNode[] = [];
  for (let index = 0; index < node.childCount; index += 1) {
    const child = node.child(index);
    if (child) result.push(child);
  }
  return result;
}

function types(node: SyntaxNode): string[] {
  return children(node).map((child) => child.type);
}

function collect(node: SyntaxNode, type: string): SyntaxNode[] {
  const found: SyntaxNode[] = [];
  const visit = (current: SyntaxNode): void => {
    if (current.type === type) found.push(current);
    for (const child of children(current)) visit(child);
  };
  visit(node);
  return found;
}

function commandNames(node: SyntaxNode): string[] {
  return collect(node, "command_name").map((name) => name.text);
}

/** Unwrap the single statement a one-line program contains. */
function statement(root: SyntaxNode): SyntaxNode {
  const named = children(root).filter((child) => child.isNamed);
  return root.type === "program" && named.length === 1 ? named[0]! : root;
}

function withTree<T>(parser: SyntaxParser, source: string, use: (root: SyntaxNode) => T): T {
  const tree = parser.parse(source);
  expect(tree).not.toBeNull();
  try {
    return use(tree!.rootNode);
  } finally {
    tree!.delete();
  }
}

describe("tree-sitter-bash 0.25.1 conformance", () => {
  it("retains redirect semantics when a redirect is inside a corrected command", () => {
    withTree(corrected, "cat 2>output input", (root) => {
      const tokens = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false });
      expect(tokens).toContainEqual(expect.objectContaining({ value: "output", role: "file_redirect", effect: { effect: "write", source: "syntax" } }));
      expect(tokens).toContainEqual(expect.objectContaining({ value: "input", role: "operand", effect: { effect: "read", source: "builtin-core" } }));
    });
  });

  it("projects the write target of a corrected redirect with a real parser", async () => {
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { realpathSync: (path) => path, lstatSync: () => undefined });
    const program = await BashProgram.parse("cat 2>output input", normalizer, { parser: corrected, pathFacts: bashPathFacts });
    expect(program.pathRuleCandidates().map((item) => [item.path.value(), item.effect.effect])).toContainEqual(["/work/output", "write"]);
  });

  it("projects a statically expanded HOME redirect as a write", async () => {
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { home: "/home/user", realpathSync: (path) => path });
    const program = await BashProgram.parse("cat >$HOME/file", normalizer, { parser: corrected, pathFacts: bashPathFacts });
    expect(program.pathRuleCandidates().map((item) => [item.path.value(), item.effect.effect])).toContainEqual(["/home/user/file", "write"]);
  });

  it("does not treat a HOME expansion with a default operator as static", () => {
    withTree(corrected, "cat >${HOME:-/other}/file", (root) => {
      const tokens = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false });
      expect(tokens).toContainEqual(expect.objectContaining({ role: "operand", computed: true, effect: { effect: "unproven", source: "unknown" } }));
    });
  });

  it("collects words from a real for-in statement", () => {
    withTree(corrected, "for f in ./a ./b; do true; done", (root) => {
      const tokens = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false });
      expect(tokens.map((item) => item.value)).toEqual(["./a", "./b"]);
    });
  });

  it("finds nested executions in a heredoc without treating its body as a path", () => {
    withTree(corrected, "cat <<EOF\n$(cat ./file)\nEOF", (root) => {
      const tokens = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false });
      expect(tokens.map((item) => item.value)).toContain("./file");
      expect(tokens.map((item) => item.value)).not.toContain("EOF");
    });
  });

  it("collects nested executions in a here-string without treating its text as a path", () => {
    withTree(corrected, 'cat <<<"$(cat ./inner)"', (root) => {
      const tokens = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false });
      expect(tokens.map((item) => item.value)).toEqual(["./inner"]);
    });
  });

  it("does not turn here-string text into a path token", () => {
    withTree(corrected, 'cat <<<"./input.txt"', (root) => {
      expect(collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false })).toEqual([]);
    });
  });

  it("keeps a quoted dash-leading prefix out of flag parsing", () => {
    withTree(corrected, 'grep "-e"foo ./input.txt', (root) => {
      const tokens = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false });
      expect(tokens.map((item) => item.value)).toContain("./input.txt");
      expect(tokens.map((item) => item.value)).not.toContain("-efoo");
    });
  });

  it("collects a real case subject without collecting its patterns", () => {
    withTree(corrected, "case ./subject in *.txt) true;; esac", (root) => {
      const tokens = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false });
      expect(tokens.map((item) => item.value)).toEqual(["./subject"]);
    });
  });

  it("keeps a quoted dash-leading word as grep's positional pattern", () => {
    withTree(corrected, "grep '-e' ./input.txt", (root) => {
      const tokens = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false });
      expect(tokens.map((item) => item.value)).toContain("./input.txt");
      expect(tokens.map((item) => item.value)).not.toContain("-e");
    });
  });

  it("records an absolute spelling for a quoted operand with whitespace", async () => {
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { realpathSync: (path) => path });
    const program = await BashProgram.parse("cat './my file'", normalizer, { parser: corrected, pathFacts: bashPathFacts });
    expect(program.commands()[0]?.equivalents).toContain("cat '/work/my file'");
  });

  it("keeps the base unknown after a variable cd target", async () => {
    const source = "cd $HOME; cat ./outer";
    withTree(corrected, source, (root) => {
      const bases = trackWorkingDirectories(root, new PathNormalizer(POSIX_PATH_FLAVOR, "/work"), "/work", { home: "/home/user", homeRebound: false, pwdRebound: false });
      expect(bases.baseAt(source.indexOf("cat"))).toBeUndefined();
    });
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { home: "/home/user", realpathSync: (path) => path });
    const program = await BashProgram.parse(source, normalizer, { parser: corrected, pathFacts: bashPathFacts });
    expect(program.pathRuleCandidates().map((item) => item.path.value())).toContain("./outer");
  });

  it("does not propagate a real background cd to the following command", () => {
    const source = "cd src & cat ./file";
    withTree(corrected, source, (root) => {
      const bases = trackWorkingDirectories(root, new PathNormalizer(POSIX_PATH_FLAVOR, "/work"), "/work", { home: "/home/user", homeRebound: false, pwdRebound: false });
      expect(bases.baseAt(source.indexOf("cat"))).toBe("/work");
    });
  });

  it("keeps directory changes inside a timed subshell", () => {
    const source = "time (cd src; cat ./inner); cat ./outer";
    withTree(corrected, source, (root) => {
      const bases = trackWorkingDirectories(root, new PathNormalizer(POSIX_PATH_FLAVOR, "/work"), "/work", { home: "/home/user", homeRebound: false, pwdRebound: false });
      expect(bases.baseAt(source.indexOf("cat ./inner"))).toBe("/work/src");
      expect(bases.baseAt(source.indexOf("cat ./outer"))).toBe("/work");
    });
  });

  it("propagates a directory change from a brace group", () => {
    const source = "{ cd src; }; cat ./file";
    withTree(corrected, source, (root) => {
      const bases = trackWorkingDirectories(root, new PathNormalizer(POSIX_PATH_FLAVOR, "/work"), "/work", { home: "/home/user", homeRebound: false, pwdRebound: false });
      expect(bases.baseAt(source.indexOf("cat"))).toBe("/work/src");
    });
  });

  it("retains a current-shell prefix before a redirect-bearing pipeline", () => {
    const source = "cd src && cat inner 2>&1 | cat outer; cat later";
    withTree(corrected, source, (root) => {
      const bases = trackWorkingDirectories(root, new PathNormalizer(POSIX_PATH_FLAVOR, "/work"), "/work", { home: "/home/user", homeRebound: false, pwdRebound: false });
      expect(bases.baseAt(source.indexOf("cat inner"))).toBe("/work/src");
      expect(bases.baseAt(source.indexOf("cat outer"))).toBe("/work/src");
      expect(bases.baseAt(source.indexOf("cat later"))).toBe("/work/src");
    });
  });

  it("does not propagate the terminal command of a redirect-bearing pipeline stage", () => {
    const source = "true && cd src 2>&1 | cat outer; cat later";
    withTree(corrected, source, (root) => {
      const bases = trackWorkingDirectories(root, new PathNormalizer(POSIX_PATH_FLAVOR, "/work"), "/work", { home: "/home/user", homeRebound: false, pwdRebound: false });
      expect(bases.baseAt(source.indexOf("cat outer"))).toBe("/work");
      expect(bases.baseAt(source.indexOf("cat later"))).toBe("/work");
    });
  });

  it("keeps the prefix directory while isolating the pipeline's terminal cd", () => {
    const source = "cd src && cd nested 2>&1 | cat outer; cat later";
    withTree(corrected, source, (root) => {
      const bases = trackWorkingDirectories(root, new PathNormalizer(POSIX_PATH_FLAVOR, "/work"), "/work", { home: "/home/user", homeRebound: false, pwdRebound: false });
      expect(bases.baseAt(source.indexOf("cat outer"))).toBe("/work/src");
      expect(bases.baseAt(source.indexOf("cat later"))).toBe("/work/src");
    });
  });

  it("tracks cd when a redirect is embedded in the command", () => {
    const source = "cd 2>output src; cat ./file";
    withTree(corrected, source, (root) => {
      const bases = trackWorkingDirectories(root, new PathNormalizer(POSIX_PATH_FLAVOR, "/work"), "/work", { home: "/home/user", homeRebound: false, pwdRebound: false });
      expect(bases.baseAt(source.indexOf("output"))).toBe("/work");
      expect(bases.baseAt(source.indexOf("cat"))).toBe("/work/src");
    });
  });

  it("does not turn a descriptor duplication into a file target", () => {
    withTree(corrected, "cat input 2>&1", (root) => {
      const tokens = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false });
      expect(tokens.some((item) => item.value === "1")).toBe(false);
      expect(tokens.map((item) => item.value)).toContain("input");
    });
  });

  it("treats a moved file descriptor as descriptor syntax, not a file path", () => {
    withTree(corrected, "cat 2>&1-", (root) => {
      const tokens = collectPathTokens(root, { home: "/home/user", homeRebound: false, pwdRebound: false });
      expect(tokens.some((item) => item.value === "1-")).toBe(false);
      expect(analyzeRedirect(collect(root, "file_redirect")[0]!).mayWriteFile).toBe(false);
    });
  });

  it("does not grant a reader exemption when output redirection names a file", async () => {
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { realpathSync: (path) => path });
    withTree(corrected, "sudo cat input >&output", (root) => {
      expect(analyzeRedirect(collect(root, "file_redirect")[0]!).mayWriteFile).toBe(true);
    });
    const program = await BashProgram.parse("sudo cat input >&output", normalizer, { parser: corrected, pathFacts: bashPathFacts });
    expect(program.commands()[0]?.floorExemption).toBeUndefined();
    expect(program.pathRuleCandidates().map((item) => [item.path.value(), item.effect.effect])).toContainEqual(["/work/output", "write"]);
  });

  it("keeps a dynamic output-duplication target out of the reader exemption", async () => {
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { realpathSync: (path) => path });
    const program = await BashProgram.parse('sudo cat input >&"$target"', normalizer, { parser: corrected, pathFacts: bashPathFacts });
    expect(program.commands()[0]?.floorExemption).toBeUndefined();
  });

  it("retains a dynamic output target with a path shape as unknown", async () => {
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/work", { realpathSync: (path) => path });
    const program = await BashProgram.parse('sudo cat input >&"$dir/file"', normalizer, { parser: corrected, pathFacts: bashPathFacts });
    expect(program.pathRuleCandidates().map((item) => [item.path.value(), item.effect.effect])).toContainEqual(["$dir/file", "unknown"]);
    expect(program.externalAccesses().map((item) => item.path.value())).toContain("$dir/file");
  });

  it("returns redirected command arguments to the command", () => {
    const source = "git 2>/dev/null push --force";
    const rawPush = withTree(raw, source, (root) => {
      const redirect = collect(root, "file_redirect")[0]!;
      return { text: redirect.child(3)!.text, start: redirect.child(3)!.startIndex };
    });

    withTree(corrected, source, (program) => {
      const root = statement(program);
      expect(root.type).toBe("command");
      expect(types(root)).toEqual(["command_name", "file_redirect", "word", "word"]);
      expect(children(root)[2]!.text).toBe(rawPush.text);
      expect(children(root)[2]!.startIndex).toBe(rawPush.start);
      expect(children(root)[1]!.childCount).toBe(3);
    });
  });

  it("lifts a redirect that followed a heredoc delimiter", () => {
    const source = "cat <<EOF > out\nbody\nEOF";
    withTree(corrected, source, (program) => {
      const root = statement(program);
      expect(root.type).toBe("redirected_statement");
      expect(types(root)).toEqual(["command", "heredoc_redirect", "file_redirect"]);
      const heredoc = children(root)[1]!;
      expect(types(heredoc)).toEqual(["<<", "heredoc_start", "heredoc_body", "heredoc_end"]);
      expect(collect(heredoc, "heredoc_body")[0]!.text).toBe("body\n");
    });
  });

  it("returns heredoc delimiter-line arguments to the command", () => {
    const source = "cat <<EOF file.txt\nbody\nEOF";
    withTree(corrected, source, (program) => {
      const root = statement(program);
      expect(root.type).toBe("command");
      expect(types(root)).toEqual(["command_name", "heredoc_redirect", "word"]);
      expect(children(root)[2]!.text).toBe("file.txt");
      expect(types(children(root)[1]!)).toEqual(["<<", "heredoc_start", "heredoc_body", "heredoc_end"]);
    });
  });

  it("turns a heredoc pipeline tail into a pipeline", () => {
    const source = "cat <<EOF | grep x\nbody\nEOF";
    withTree(corrected, source, (program) => {
      const root = statement(program);
      expect(root.type).toBe("pipeline");
      expect(types(root)).toEqual(["redirected_statement", "|", "command"]);
      expect(commandNames(root)).toEqual(["cat", "grep"]);
      expect(collect(root, "heredoc_body")[0]!.text).toBe("body\n");
    });
  });

  it("turns a heredoc && tail into a list", () => {
    const source = "cat <<EOF && echo hi > out\nbody\nEOF";
    withTree(corrected, source, (program) => {
      const root = statement(program);
      expect(root.type).toBe("list");
      expect(types(root)).toEqual(["redirected_statement", "&&", "redirected_statement"]);
      expect(commandNames(root)).toEqual(["cat", "echo"]);
      expect(collect(root, "file_redirect")[0]!.text).toBe("> out");
    });
  });

  it("lifts a here-string tail out of the heredoc", () => {
    const source = "cat <<EOF <<< here\nbody\nEOF";
    withTree(corrected, source, (program) => {
      const root = statement(program);
      expect(root.type).toBe("redirected_statement");
      expect(types(root)).toEqual(["command", "heredoc_redirect", "herestring_redirect"]);
      expect(collect(root, "herestring_redirect")[0]!.text).toBe("<<< here");
    });
  });

  it("returns arguments from a redirect that precedes a heredoc list tail", () => {
    const source = "cat <<EOF > out file.txt && echo hi\nbody\nEOF";
    withTree(corrected, source, (program) => {
      const root = statement(program);
      expect(root.type).toBe("list");
      expect(types(root)).toEqual(["command", "&&", "command"]);
      expect(types(children(root)[0]!)).toEqual(["command_name", "heredoc_redirect", "file_redirect", "word"]);
      expect(children(root)[0]!.child(3)!.text).toBe("file.txt");
    });
  });

  it("keeps a heredoc tail inside a pipeline stage", () => {
    const source = "echo hi | cat <<EOF | grep x\nbody\nEOF";
    withTree(corrected, source, (program) => {
      const root = statement(program);
      expect(root.type).toBe("pipeline");
      expect(types(root)).toEqual(["redirected_statement", "|", "command"]);
      expect(commandNames(root)).toEqual(["echo", "cat", "grep"]);
    });
  });

  it("keeps an unresolved heredoc tail unchanged and recovers it by salvage", () => {
    const source = "cat <<EOF > out | grep x\nbody\nEOF";
    withTree(corrected, source, (root) => {
      expect(root.hasError).toBe(true);
      expect(applyParseView(root, source)).toBe(root);

      const result = withSalvagedRoots(root, { source, reparser: raw }, (roots) =>
        roots.map((entry) => ({ origin: entry.origin, names: commandNames(entry.root) })),
      );
      const heredocFree = result.find((entry) => entry.origin === "heredoc-free");
      expect(heredocFree).toBeDefined();
      expect(heredocFree!.names).toEqual(["cat", "grep"]);
    });
  });

  it("reports read-write and stranded-operator redirect risk", () => {
    withTree(corrected, "cat <> rw.txt", (root) => {
      const redirect = collect(root, "file_redirect")[0]!;
      expect(redirectMayWriteFile(redirect)).toBe(true);
      expect(analyzeRedirect(redirect).mayWriteFile).toBe(true);
    });

    withTree(corrected, "cat <> ~/rw.txt", (root) => {
      const redirect = collect(root, "file_redirect")[0]!;
      expect(redirectPositionUnresolved(redirect)).toBe(true);
      expect(redirectMayWriteFile(redirect)).toBe(true);
    });

    withTree(corrected, "cat <>&1", (root) => {
      const redirect = collect(root, "file_redirect")[0]!;
      expect(redirectPositionUnresolved(redirect)).toBe(true);
      expect(redirectMayWriteFile(redirect)).toBe(true);
    });
  });

  it("searches interpolated heredoc bodies but not quoted ones", () => {
    withTree(corrected, "cat <<EOF\n$(date)\nEOF", (root) => {
      const found = findNestedExecutions(root);
      expect(found.map((entry) => entry.node.text)).toEqual(["$(date)"]);
    });

    withTree(corrected, "cat <<'EOF'\n$(date)\nEOF", (root) => {
      expect(findNestedExecutions(root)).toHaveLength(0);
    });
  });

  it("keeps redirects that follow the heredoc at statement level", () => {
    const source = "cat <<EOF\nbody\nEOF 2>/dev/null";
    withTree(corrected, source, (program) => {
      const root = statement(program);
      expect(root.type).toBe("redirected_statement");
      expect(types(root)).toEqual(["command", "heredoc_redirect", "file_redirect"]);
    });
  });

  it("keeps a redirect after the last carrying redirect at statement level", () => {
    const source = "git push --force 2>/dev/null";
    withTree(corrected, source, (program) => {
      const root = statement(program);
      expect(root.type).toBe("redirected_statement");
      expect(types(root)).toEqual(["command", "file_redirect"]);
    });
  });

  it("does not rewrite the normal pipeline redirect shape", () => {
    const source = "a | b | c > out";
    withTree(corrected, source, (program) => {
      const root = statement(program);
      expect(root.type).toBe("redirected_statement");
      expect(types(root)).toEqual(["pipeline", "file_redirect"]);
      expect(commandNames(root)).toEqual(["a", "b", "c"]);
    });
  });

  it("recognizes here-strings without treating them as writes", () => {
    withTree(corrected, "echo a <<< here b", (program) => {
      const root = statement(program);
      expect(root.type).toBe("command");
      const redirect = collect(root, "herestring_redirect")[0]!;
      expect(analyzeRedirect(redirect).targetValue).toBe("here");
      expect(redirectMayWriteFile(redirect)).toBe(false);
    });
  });

  it("keeps the time command and its subshell", () => {
    withTree(corrected, "time (echo hi)", (program) => {
      const root = statement(program);
      expect(root.type).toBe("command");
      expect(collect(root, "command_name")[0]!.text).toBe("time");
      expect(types(root)).toContain("subshell");
    });
  });

  it("uses for_statement for select and while_statement for until", () => {
    withTree(raw, "select x in a; do echo $x; done", (program) => {
      expect(statement(program).type).toBe("for_statement");
    });
    withTree(raw, "until false; do echo hi; done", (program) => {
      expect(statement(program).type).toBe("while_statement");
    });
  });

  it("builds a heredoc-free candidate for a zero-descriptor heredoc", () => {
    const source = "0<<EOF\nx\nEOF";
    withTree(corrected, source, (root) => {
      const line = buildHeredocFreeLine(root, source);
      expect(line?.text).toBe("0");
    });
  });
});
