import { describe, expect, it } from "vitest";
import { applyParseView, SyntaxTreeEditor } from "#approve-core/utils/access-intent/bash/parse-view";
import type { SyntaxNode } from "#approve-core/utils/access-intent/bash/parser";
import { syntax, token } from "./fake-syntax";

function command(text: string): SyntaxNode {
  const [name, ...args] = text.split(" ");
  return syntax("command", text, [
    syntax("command_name", name!, [syntax("word", name!)]),
    ...args.map((arg) => syntax("word", arg)),
  ]);
}

function children(node: SyntaxNode): SyntaxNode[] {
  const result: SyntaxNode[] = [];
  for (let index = 0; index < node.childCount; index += 1) {
    const child = node.child(index);
    if (child) result.push(child);
  }
  return result;
}

describe("corrected parse view", () => {
  it("returns the original root when nothing changes", () => {
    const root = syntax("redirected_statement", "cat < in > out", [
      command("cat"),
      syntax("file_redirect", "< in", [token("<", "<"), syntax("word", "in")]),
      syntax("file_redirect", "> out", [token(">", ">"), syntax("word", "out")]),
    ]);

    expect(applyParseView(root, root.text)).toBe(root);
  });

  it("applies heredoc tails before redirect arguments", () => {
    const root = syntax("redirected_statement", "cat <<EOF > out file.txt\nbody\nEOF", [
      command("cat"),
      syntax("heredoc_redirect", "<<EOF > out file.txt\nbody\nEOF", [
        token("<<", "<<"),
        syntax("heredoc_start", "EOF"),
        syntax("file_redirect", "> out file.txt", [
          token(">", ">"),
          syntax("word", "out"),
          syntax("word", "file.txt"),
        ]),
        syntax("heredoc_body", "body\n"),
        syntax("heredoc_end", "EOF"),
      ]),
    ]);

    const corrected = applyParseView(root, root.text);

    expect(corrected.type).toBe("command");
    expect(children(corrected).map((child) => child.type)).toEqual([
      "command_name",
      "heredoc_redirect",
      "file_redirect",
      "word",
    ]);
    expect(children(children(corrected)[1]!).map((child) => child.type)).toEqual([
      "<<",
      "heredoc_start",
      "heredoc_body",
      "heredoc_end",
    ]);
  });

  it("keeps moved node type, text and absolute offsets", () => {
    const redirect = syntax("file_redirect", "2>/dev/null push --force", [
      syntax("file_descriptor", "2"),
      token(">", ">"),
      syntax("word", "/dev/null"),
      syntax("word", "push"),
      syntax("word", "--force"),
    ]);
    const push = redirect.child(3)!;
    const force = redirect.child(4)!;
    const root = syntax("redirected_statement", "git 2>/dev/null push --force", [command("git"), redirect]);
    const pushSpan = { text: push.text, start: push.startIndex, end: push.endIndex, named: push.isNamed };
    const forceSpan = { text: force.text, start: force.startIndex, end: force.endIndex, named: force.isNamed };

    const corrected = applyParseView(root, root.text);
    const movedPush = children(corrected)[2]!;
    const movedForce = children(corrected)[3]!;

    expect(movedPush.type).toBe("word");
    expect(movedPush.text).toBe(pushSpan.text);
    expect(movedPush.startIndex).toBe(pushSpan.start);
    expect(movedPush.endIndex).toBe(pushSpan.end);
    expect(movedPush.isNamed).toBe(pushSpan.named);
    expect(movedForce.text).toBe(forceSpan.text);
    expect(movedForce.startIndex).toBe(forceSpan.start);
    expect(movedForce.endIndex).toBe(forceSpan.end);
  });

  it("reconnects previous-sibling links after moves", () => {
    const root = syntax("redirected_statement", "git 2>/dev/null push", [
      command("git"),
      syntax("file_redirect", "2>/dev/null push", [
        syntax("file_descriptor", "2"),
        token(">", ">"),
        syntax("word", "/dev/null"),
        syntax("word", "push"),
      ]),
    ]);

    const corrected = applyParseView(root, root.text);
    const [name, redirect, push] = children(corrected);

    expect(push!.previousSibling()).toBe(redirect);
    expect(redirect!.previousSibling()).toBe(name);
  });

  it("propagates child error state in the edited tree", () => {
    const error = syntax("ERROR", "<", [token("<", "<")], { error: true });
    const root = syntax("redirected_statement", "cat <> rw", [
      command("cat"),
      error,
      syntax("file_redirect", "> rw", [token(">", ">"), syntax("word", "rw")]),
    ]);
    const editor = new SyntaxTreeEditor(root, root.text);

    expect(editor.root.hasError).toBe(true);
    editor.remove(editor.childrenOf(editor.root)[1]!);
    expect(editor.root.hasError).toBe(false);
  });
});
