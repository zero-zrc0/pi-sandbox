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

function heredoc(text: string, children: readonly SyntaxNode[]): SyntaxNode {
  return syntax("heredoc_redirect", text, children);
}

function redirect(text: string): SyntaxNode {
  const descriptor = /^\d+/.exec(text)?.[0];
  const rest = descriptor ? text.slice(descriptor.length) : text;
  const operator = /^(>>|>&|>|<)/.exec(rest)![1]!;
  const target = rest.slice(operator.length).trim();
  const children: SyntaxNode[] = [];
  if (descriptor) children.push(syntax("file_descriptor", descriptor));
  children.push(token(operator, operator));
  if (target) children.push(/^\d+$/.test(target) ? syntax("number", target) : syntax("word", target));
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

function statement(text: string, heredocNode: SyntaxNode): SyntaxNode {
  return syntax("redirected_statement", text, [command("cat"), heredocNode]);
}

describe("heredoc tail lifting", () => {
  it("lifts a trailing file redirect out of the heredoc", () => {
    const heredocNode = heredoc("<<EOF > out\nbody\nEOF", [
      token("<<", "<<"),
      syntax("heredoc_start", "EOF"),
      redirect("> out"),
      syntax("heredoc_body", "body\n"),
      syntax("heredoc_end", "EOF"),
    ]);
    const root = statement("cat <<EOF > out\nbody\nEOF", heredocNode);

    const corrected = applyParseView(root, root.text);

    expect(corrected.type).toBe("redirected_statement");
    expect(types(corrected)).toEqual(["command", "heredoc_redirect", "file_redirect"]);
    expect(types(children(corrected)[1]!)).toEqual(["<<", "heredoc_start", "heredoc_body", "heredoc_end"]);
  });

  it("lifts multiple redirects in source order", () => {
    const heredocNode = heredoc("<<EOF 2>/dev/null > out\nbody\nEOF", [
      token("<<", "<<"),
      syntax("heredoc_start", "EOF"),
      redirect("2>/dev/null"),
      redirect("> out"),
      syntax("heredoc_body", "body\n"),
      syntax("heredoc_end", "EOF"),
    ]);
    const root = statement("cat <<EOF 2>/dev/null > out\nbody\nEOF", heredocNode);

    const corrected = applyParseView(root, root.text);

    expect(types(corrected)).toEqual(["command", "heredoc_redirect", "file_redirect", "file_redirect"]);
  });

  it("lifts a here-string tail out of the heredoc", () => {
    const heredocNode = heredoc("<<EOF <<< here\nbody\nEOF", [
      token("<<", "<<"),
      syntax("heredoc_start", "EOF"),
      syntax("herestring_redirect", "<<< here", [token("<<<", "<<<"), syntax("word", "here")]),
      syntax("heredoc_body", "body\n"),
      syntax("heredoc_end", "EOF"),
    ]);
    const root = statement("cat <<EOF <<< here\nbody\nEOF", heredocNode);

    const corrected = applyParseView(root, root.text);

    expect(corrected.type).toBe("redirected_statement");
    expect(types(corrected)).toEqual(["command", "heredoc_redirect", "herestring_redirect"]);
  });

  it("turns a pipeline tail into a pipeline around the statement", () => {
    const heredocNode = heredoc("<<EOF | grep x\nbody\nEOF", [
      token("<<", "<<"),
      syntax("heredoc_start", "EOF"),
      syntax("pipeline", "| grep x", [token("|", "|"), command("grep x")]),
      syntax("heredoc_body", "body\n"),
      syntax("heredoc_end", "EOF"),
    ]);
    const root = statement("cat <<EOF | grep x\nbody\nEOF", heredocNode);

    const corrected = applyParseView(root, root.text);

    expect(corrected.type).toBe("pipeline");
    expect(types(corrected)).toEqual(["redirected_statement", "|", "command"]);
    expect(types(children(corrected)[0]!)).toEqual(["command", "heredoc_redirect"]);
  });

  it("flattens the right-nested pipeline chain", () => {
    const heredocNode = heredoc("<<EOF | grep x | cat\nbody\nEOF", [
      token("<<", "<<"),
      syntax("heredoc_start", "EOF"),
      syntax("pipeline", "| grep x | cat", [
        token("|", "|"),
        syntax("pipeline", "grep x | cat", [command("grep x"), token("|", "|"), command("cat")]),
      ]),
      syntax("heredoc_body", "body\n"),
      syntax("heredoc_end", "EOF"),
    ]);
    const root = statement("cat <<EOF | grep x | cat\nbody\nEOF", heredocNode);

    const corrected = applyParseView(root, root.text);

    expect(corrected.type).toBe("pipeline");
    expect(types(corrected)).toEqual(["redirected_statement", "|", "command", "|", "command"]);
  });

  it("turns an && tail into a list around the statement", () => {
    const heredocNode = heredoc("<<EOF && echo hi\nbody\nEOF", [
      token("<<", "<<"),
      syntax("heredoc_start", "EOF"),
      token("&&", "&&"),
      command("echo hi"),
      syntax("heredoc_body", "body\n"),
      syntax("heredoc_end", "EOF"),
    ]);
    const root = statement("cat <<EOF && echo hi\nbody\nEOF", heredocNode);

    const corrected = applyParseView(root, root.text);

    expect(corrected.type).toBe("list");
    expect(types(corrected)).toEqual(["redirected_statement", "&&", "command"]);
  });

  it("folds a nested list tail left-associatively", () => {
    const heredocNode = heredoc("<<EOF && echo hi && echo bye\nbody\nEOF", [
      token("<<", "<<"),
      syntax("heredoc_start", "EOF"),
      token("&&", "&&"),
      syntax("list", "echo hi && echo bye", [command("echo hi"), token("&&", "&&"), command("echo bye")]),
      syntax("heredoc_body", "body\n"),
      syntax("heredoc_end", "EOF"),
    ]);
    const root = statement("cat <<EOF && echo hi && echo bye\nbody\nEOF", heredocNode);

    const corrected = applyParseView(root, root.text);

    expect(corrected.type).toBe("list");
    expect(types(corrected)).toEqual(["list", "&&", "command"]);
    expect(types(children(corrected)[0]!)).toEqual(["redirected_statement", "&&", "command"]);
  });

  it("handles || tails", () => {
    const heredocNode = heredoc("<<EOF || echo hi\nbody\nEOF", [
      token("<<", "<<"),
      syntax("heredoc_start", "EOF"),
      token("||", "||"),
      command("echo hi"),
      syntax("heredoc_body", "body\n"),
      syntax("heredoc_end", "EOF"),
    ]);
    const root = statement("cat <<EOF || echo hi\nbody\nEOF", heredocNode);

    const corrected = applyParseView(root, root.text);

    expect(corrected.type).toBe("list");
    expect(types(corrected)).toEqual(["redirected_statement", "||", "command"]);
  });

  it("lifts a redirect before a list connector", () => {
    const heredocNode = heredoc("<<EOF > out && echo hi\nbody\nEOF", [
      token("<<", "<<"),
      syntax("heredoc_start", "EOF"),
      redirect("> out"),
      token("&&", "&&"),
      command("echo hi"),
      syntax("heredoc_body", "body\n"),
      syntax("heredoc_end", "EOF"),
    ]);
    const root = statement("cat <<EOF > out && echo hi\nbody\nEOF", heredocNode);

    const corrected = applyParseView(root, root.text);

    expect(corrected.type).toBe("list");
    expect(types(corrected)).toEqual(["redirected_statement", "&&", "command"]);
    expect(types(children(corrected)[0]!)).toEqual(["command", "heredoc_redirect", "file_redirect"]);
  });

  it("does not guess when extra named nodes follow the connector", () => {
    const heredocNode = heredoc("<<EOF && echo hi extra\nbody\nEOF", [
      token("<<", "<<"),
      syntax("heredoc_start", "EOF"),
      token("&&", "&&"),
      command("echo hi"),
      syntax("word", "extra"),
      syntax("heredoc_body", "body\n"),
      syntax("heredoc_end", "EOF"),
    ]);
    const root = statement("cat <<EOF && echo hi extra\nbody\nEOF", heredocNode);

    expect(applyParseView(root, root.text)).toBe(root);
  });

  it("does not lift a connector after an unknown tail node", () => {
    const heredocNode = heredoc("<<EOF f() { :; } && echo hi\nbody\nEOF", [
      token("<<", "<<"),
      syntax("heredoc_start", "EOF"),
      syntax("function_definition", "f() { :; }", [command(":")]),
      token("&&", "&&"),
      command("echo hi"),
      syntax("heredoc_body", "body\n"),
      syntax("heredoc_end", "EOF"),
    ]);
    const root = statement("cat <<EOF f() { :; } && echo hi\nbody\nEOF", heredocNode);

    expect(applyParseView(root, root.text)).toBe(root);
  });

  it("skips an unresolved heredoc", () => {
    const heredocNode = heredoc("<<EOF > out\nbody\nEOF", [
      token("<<", "<<"),
      syntax("heredoc_start", "EOF"),
      syntax("file_redirect", "> out", [token(">", ">"), syntax("word", "out")], { error: true }),
      syntax("heredoc_body", "body\n"),
      syntax("heredoc_end", "EOF"),
    ]);
    const root = statement("cat <<EOF > out\nbody\nEOF", heredocNode);

    expect(applyParseView(root, root.text)).toBe(root);
  });

  it("leaves a redirect after the heredoc at statement level", () => {
    const heredocNode = heredoc("<<EOF\nbody\nEOF", [
      token("<<", "<<"),
      syntax("heredoc_start", "EOF"),
      syntax("heredoc_body", "body\n"),
      syntax("heredoc_end", "EOF"),
    ]);
    const root = syntax("redirected_statement", "cat <<EOF\nbody\nEOF > out", [
      command("cat"),
      heredocNode,
      redirect("> out"),
    ]);

    expect(applyParseView(root, root.text)).toBe(root);
  });
});
