import { describe, expect, it } from "vitest";
import type { LocalReparser, SyntaxNode, SyntaxTree } from "#approve-core/utils/access-intent/bash/parser";
import { withSalvagedRoots } from "#approve-core/utils/access-intent/bash/unresolved-salvage";
import { syntax, token } from "./fake-syntax";

class FakeReparser implements LocalReparser {
  readonly calls: string[] = [];
  deleted = 0;

  constructor(private readonly respond: (text: string) => SyntaxNode | null) {}

  parse(text: string): SyntaxTree | null {
    this.calls.push(text);
    const root = this.respond(text);
    if (!root) return null;
    return { rootNode: root, delete: () => (this.deleted += 1) };
  }
}

function clean(text: string): SyntaxNode {
  return syntax("program", text, [syntax("command", text)]);
}

function broken(text: string): SyntaxNode {
  return syntax("program", text, [syntax("ERROR", text, [], { error: true })], { error: true });
}

function command(text: string): SyntaxNode {
  return syntax("command", text, [syntax("command_name", text, [syntax("word", text)])]);
}

function children(node: SyntaxNode): SyntaxNode[] {
  const result: SyntaxNode[] = [];
  for (let index = 0; index < node.childCount; index += 1) {
    const child = node.child(index);
    if (child) result.push(child);
  }
  return result;
}

describe("unresolved salvage", () => {
  it("reparses the innermost non-ERROR error region", () => {
    const brokenRedirect = syntax("file_redirect", "2>/dev/null ! push", [
      syntax("file_descriptor", "2"),
      token(">", ">"),
      syntax("word", "/dev/null"),
      syntax("ERROR", "!", [token("!", "!")], { error: true }),
      syntax("word", "push"),
    ]);
    const statement = syntax("redirected_statement", "git 2>/dev/null ! push", [
      command("git"),
      brokenRedirect,
    ]);
    const root = syntax("program", "git 2>/dev/null ! push", [statement], { error: true });
    const reparser = new FakeReparser((text) => (text === brokenRedirect.text ? clean(text) : null));

    const result = withSalvagedRoots(root, { source: root.text, reparser }, (roots) => roots);

    expect(result).toHaveLength(1);
    expect(result[0]?.origin).toBe("reparse");
    expect(result[0]?.uncertain).toBe(true);
    expect(result[0]?.region).toEqual({
      startIndex: brokenRedirect.startIndex,
      endIndex: brokenRedirect.endIndex,
    });
    expect(result[0]?.root.text).toBe(brokenRedirect.text);
  });

  it("rejects and releases a reparsed tree that still has errors", () => {
    const brokenRedirect = syntax("file_redirect", "> out !", [
      token(">", ">"),
      syntax("word", "out"),
      syntax("ERROR", "!", [token("!", "!")], { error: true }),
    ]);
    const root = syntax(
      "program",
      "git > out !",
      [syntax("redirected_statement", "git > out !", [command("git"), brokenRedirect])],
      { error: true },
    );
    const reparser = new FakeReparser((text) => broken(text));

    const result = withSalvagedRoots(root, { source: root.text, reparser }, (roots) => roots);

    expect(result).toHaveLength(0);
    expect(reparser.deleted).toBe(1);
  });

  it("does not descend into ERROR recovery structures", () => {
    const error = syntax(
      "ERROR",
      "! rm -rf /",
      [token("!", "!"), command("rm -rf /")],
      { error: true },
    );
    const root = syntax("program", "! rm -rf /", [error], { error: true });
    const reparser = new FakeReparser(() => clean("rm -rf /"));

    const result = withSalvagedRoots(root, { source: root.text, reparser }, (roots) => roots);

    expect(result).toHaveLength(0);
    expect(reparser.calls).toHaveLength(0);
  });

  it("falls back to a heredoc-free line when local reparse fails", () => {
    const brokenRedirect = syntax("file_redirect", "> out | grep x", [
      token(">", ">"),
      syntax("word", "out"),
      syntax("ERROR", "|", [token("|", "|")], { error: true }),
      syntax("word", "grep"),
      syntax("word", "x"),
    ]);
    const heredoc = syntax(
      "heredoc_redirect",
      "<<EOF > out | grep x\nbody\nEOF",
      [
        token("<<", "<<"),
        syntax("heredoc_start", "EOF"),
        brokenRedirect,
        syntax("heredoc_body", "body\n"),
        syntax("heredoc_end", "EOF"),
      ],
      { error: true },
    );
    const statement = syntax(
      "redirected_statement",
      "cat <<EOF > out | grep x\nbody\nEOF",
      [command("cat"), heredoc],
      { error: true },
    );
    const root = syntax("program", "cat <<EOF > out | grep x\nbody\nEOF", [statement], { error: true });
    const reparser = new FakeReparser((text) => {
      if (text === "> out | grep x") return broken(text);
      if (text === "cat > out | grep x") return clean(text);
      return null;
    });

    const result = withSalvagedRoots(root, { source: root.text, reparser }, (roots) => roots);

    expect(result).toHaveLength(1);
    expect(result[0]?.origin).toBe("heredoc-free");
    expect(result[0]?.root.text).toBe("cat > out | grep x");
    expect(result[0]?.region).toEqual({ startIndex: 0, endIndex: 24 });
    expect(reparser.calls).toEqual(["> out | grep x", "cat > out | grep x"]);
  });

  it("passes every accepted root to the callback and releases them afterwards", () => {
    const first = syntax("file_redirect", "> x !", [
      token(">", ">"),
      syntax("word", "x"),
      syntax("ERROR", "!", [token("!", "!")], { error: true }),
    ]);
    const second = syntax("file_redirect", "> y !", [
      token(">", ">"),
      syntax("word", "y"),
      syntax("ERROR", "!", [token("!", "!")], { error: true }),
    ]);
    const root = syntax(
      "program",
      "a > x ! ; b > y !",
      [
        syntax("redirected_statement", "a > x !", [command("a"), first]),
        token(";", ";"),
        syntax("redirected_statement", "b > y !", [command("b"), second]),
      ],
      { error: true },
    );
    const reparser = new FakeReparser((text) => clean(text));

    const result = withSalvagedRoots(root, { source: root.text, reparser }, (roots) => roots);

    expect(result.map((entry) => entry.root.text)).toEqual(["> x !", "> y !"]);
    expect(reparser.deleted).toBe(2);
  });

  it("applies the corrected view to accepted salvage trees", () => {
    const quirk = syntax("redirected_statement", "git 2>/dev/null push --force", [
      command("git"),
      syntax("file_redirect", "2>/dev/null push --force", [
        syntax("file_descriptor", "2"),
        token(">", ">"),
        syntax("word", "/dev/null"),
        syntax("word", "push"),
        syntax("word", "--force"),
      ]),
    ]);
    const brokenRedirect = syntax("file_redirect", "> x !", [
      token(">", ">"),
      syntax("word", "x"),
      syntax("ERROR", "!", [token("!", "!")], { error: true }),
    ]);
    const root = syntax(
      "program",
      "a > x !",
      [syntax("redirected_statement", "a > x !", [command("a"), brokenRedirect])],
      { error: true },
    );
    const reparser = new FakeReparser((text) => (text === "> x !" ? quirk : null));

    const result = withSalvagedRoots(root, { source: root.text, reparser }, (roots) => roots);

    expect(result[0]?.root.type).toBe("command");
    expect(children(result[0]!.root).map((child) => child.type)).toEqual([
      "command_name",
      "file_redirect",
      "word",
      "word",
    ]);
  });

  it("releases trees when the callback throws", () => {
    const brokenRedirect = syntax("file_redirect", "> x !", [
      token(">", ">"),
      syntax("word", "x"),
      syntax("ERROR", "!", [token("!", "!")], { error: true }),
    ]);
    const root = syntax(
      "program",
      "a > x !",
      [syntax("redirected_statement", "a > x !", [command("a"), brokenRedirect])],
      { error: true },
    );
    const reparser = new FakeReparser((text) => clean(text));

    expect(() =>
      withSalvagedRoots(root, { source: root.text, reparser }, () => {
        throw new Error("callback failed");
      }),
    ).toThrow("callback failed");
    expect(reparser.deleted).toBe(1);
  });

  it("keeps salvaged offsets local to the reparsed text", () => {
    const brokenRedirect = syntax("file_redirect", "> x !", [
      token(">", ">"),
      syntax("word", "x"),
      syntax("ERROR", "!", [token("!", "!")], { error: true }),
    ]);
    const root = syntax(
      "program",
      "a > x !",
      [syntax("redirected_statement", "a > x !", [command("a"), brokenRedirect])],
      { error: true },
    );
    const reparser = new FakeReparser((text) => clean(text));

    const result = withSalvagedRoots(root, { source: root.text, reparser }, (roots) => roots);

    expect(result[0]?.root.startIndex).toBe(0);
    expect(result[0]?.region.startIndex).toBeGreaterThan(0);
  });

  it("reports an empty result when there is no unresolved region", () => {
    const root = syntax("program", "echo hi", [command("echo hi")]);
    const reparser = new FakeReparser((text) => clean(text));

    const result = withSalvagedRoots(root, { source: root.text, reparser }, (roots) => roots);

    expect(result).toHaveLength(0);
    expect(reparser.calls).toHaveLength(0);
    expect(children(root)).toHaveLength(1);
  });
});
