import { describe, expect, it } from "vitest";
import { applyParseView } from "#approve-core/utils/access-intent/bash/parse-view";
import type { SyntaxNode } from "#approve-core/utils/access-intent/bash/parser";
import { syntax, token } from "./fake-syntax";

function command(text: string): SyntaxNode {
  const [name, ...args] = text.split(" ");
  return syntax("command", text, [
    syntax("command_name", name!, [syntax("word", name!)]),
    ...args.map((arg) => syntax("word", arg)),
  ]);
}

function fileRedirect(
  text: string,
  operator: string,
  descriptor: string | undefined,
  target: string | null,
  args: readonly string[] = [],
): SyntaxNode {
  const children: SyntaxNode[] = [];
  if (descriptor) children.push(syntax("file_descriptor", descriptor));
  children.push(token(operator, operator));
  if (target) children.push(syntax("word", target));
  for (const arg of args) children.push(syntax("word", arg));
  return syntax("file_redirect", text, children);
}

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

function texts(node: SyntaxNode): string[] {
  return children(node).map((child) => child.text);
}

describe("redirect argument return", () => {
  it("returns arguments stranded after a file redirect", () => {
    const root = syntax("redirected_statement", "git 2>/dev/null push --force", [
      command("git"),
      fileRedirect("2>/dev/null push --force", ">", "2", "/dev/null", ["push", "--force"]),
    ]);

    const corrected = applyParseView(root, root.text);

    expect(corrected.type).toBe("command");
    expect(types(corrected)).toEqual(["command_name", "file_redirect", "word", "word"]);
    expect(texts(corrected)).toEqual(["git", "2>/dev/null push --force", "push", "--force"]);
    expect(children(corrected)[1]!.childCount).toBe(3);
  });

  it("returns arguments after an existing command word", () => {
    const root = syntax("redirected_statement", "git push 2>/dev/null --force", [
      command("git push"),
      fileRedirect("2>/dev/null --force", ">", "2", "/dev/null", ["--force"]),
    ]);

    const corrected = applyParseView(root, root.text);

    expect(corrected.type).toBe("command");
    expect(texts(corrected)).toEqual(["git", "push", "2>/dev/null --force", "--force"]);
  });

  it("leaves a redirect after the last carrying redirect at statement level", () => {
    const root = syntax("redirected_statement", "git push --force 2>/dev/null", [
      command("git push --force"),
      fileRedirect("2>/dev/null", ">", "2", "/dev/null"),
    ]);

    expect(applyParseView(root, root.text)).toBe(root);
  });

  it("returns arguments from every redirect up to the last carrier", () => {
    const root = syntax("redirected_statement", "echo a 2>/dev/null b 2>/dev/null c", [
      command("echo a"),
      fileRedirect("2>/dev/null b", ">", "2", "/dev/null", ["b"]),
      fileRedirect("2>/dev/null c", ">", "2", "/dev/null", ["c"]),
    ]);

    const corrected = applyParseView(root, root.text);

    expect(corrected.type).toBe("command");
    expect(texts(corrected)).toEqual(["echo", "a", "2>/dev/null b", "b", "2>/dev/null c", "c"]);
  });

  it("sends arguments to the last command of a pipeline", () => {
    const root = syntax("redirected_statement", "a | b | c > out d", [
      syntax("pipeline", "a | b | c", [command("a"), token("|", "|"), command("b"), token("|", "|"), command("c")]),
      fileRedirect("> out d", ">", undefined, "out", ["d"]),
    ]);

    const corrected = applyParseView(root, root.text);

    expect(corrected.type).toBe("redirected_statement");
    expect(types(corrected)).toEqual(["pipeline"]);
    const pipeline = children(corrected)[0]!;
    expect(types(pipeline)).toEqual(["command", "|", "command", "|", "command"]);
    expect(texts(pipeline.child(4)!)).toEqual(["c", "> out d", "d"]);
  });

  it("returns heredoc delimiter-line arguments to the command", () => {
    const root = syntax("redirected_statement", "cat <<EOF file.txt\nbody\nEOF", [
      command("cat"),
      syntax("heredoc_redirect", "<<EOF file.txt\nbody\nEOF", [
        token("<<", "<<"),
        syntax("heredoc_start", "EOF"),
        syntax("word", "file.txt"),
        syntax("heredoc_body", "body\n"),
        syntax("heredoc_end", "EOF"),
      ]),
    ]);

    const corrected = applyParseView(root, root.text);

    expect(corrected.type).toBe("command");
    expect(types(corrected)).toEqual(["command_name", "heredoc_redirect", "word"]);
    expect(texts(corrected)).toEqual(["cat", "<<EOF file.txt\nbody\nEOF", "file.txt"]);
    expect(types(children(corrected)[1]!)).toEqual(["<<", "heredoc_start", "heredoc_body", "heredoc_end"]);
  });

  it("returns arguments nested in a heredoc redirect", () => {
    const root = syntax("redirected_statement", "cat <<EOF > out file.txt\nbody\nEOF", [
      command("cat"),
      syntax("heredoc_redirect", "<<EOF > out file.txt\nbody\nEOF", [
        token("<<", "<<"),
        syntax("heredoc_start", "EOF"),
        fileRedirect("> out file.txt", ">", undefined, "out", ["file.txt"]),
        syntax("heredoc_body", "body\n"),
        syntax("heredoc_end", "EOF"),
      ]),
    ]);

    const corrected = applyParseView(root, root.text);

    expect(corrected.type).toBe("command");
    expect(types(corrected)).toEqual(["command_name", "heredoc_redirect", "file_redirect", "word"]);
    expect(texts(corrected)).toEqual(["cat", "<<EOF > out file.txt\nbody\nEOF", "> out file.txt", "file.txt"]);
    expect(types(children(corrected)[1]!)).toEqual(["<<", "heredoc_start", "heredoc_body", "heredoc_end"]);
  });

  it("keeps redirects after the last carrier at statement level", () => {
    const root = syntax("redirected_statement", "echo a > out b 2>/dev/null", [
      command("echo a"),
      fileRedirect("> out b", ">", undefined, "out", ["b"]),
      fileRedirect("2>/dev/null", ">", "2", "/dev/null"),
    ]);

    const corrected = applyParseView(root, root.text);

    expect(corrected.type).toBe("redirected_statement");
    expect(types(corrected)).toEqual(["command", "file_redirect"]);
    expect(texts(children(corrected)[0]!)).toEqual(["echo", "a", "> out b", "b"]);
    expect(children(corrected)[1]!.text).toBe("2>/dev/null");
  });

  it("does not move arguments into a compound body", () => {
    const root = syntax("redirected_statement", "if true; then echo hi; fi 2>/dev/null x", [
      syntax("if_statement", "if true; then echo hi; fi", [syntax("command", "true")]),
      fileRedirect("2>/dev/null x", ">", "2", "/dev/null", ["x"]),
    ]);

    expect(applyParseView(root, root.text)).toBe(root);
  });

  it("does not correct an unresolved statement", () => {
    const root = syntax(
      "redirected_statement",
      "git 2>/dev/null push --force",
      [command("git"), fileRedirect("2>/dev/null push --force", ">", "2", "/dev/null", ["push", "--force"])],
      { error: true },
    );

    expect(applyParseView(root, root.text)).toBe(root);
  });

  it("returns arguments to the last command inside a list", () => {
    const inner = syntax("redirected_statement", "b > out d", [
      command("b"),
      fileRedirect("> out d", ">", undefined, "out", ["d"]),
    ]);
    const root = syntax("list", "a && b > out d", [command("a"), token("&&", "&&"), inner]);

    const corrected = applyParseView(root, root.text);

    expect(corrected.type).toBe("list");
    expect(types(corrected)).toEqual(["command", "&&", "command"]);
    expect(texts(children(corrected)[2]!)).toEqual(["b", "> out d", "d"]);
  });
});
