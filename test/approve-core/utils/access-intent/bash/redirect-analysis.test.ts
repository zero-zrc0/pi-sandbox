import { describe, expect, it } from "vitest";
import {
  analyzeRedirect,
  isRedirectNode,
  redirectMayWriteFile,
  staticRedirectTarget,
} from "#approve-core/utils/access-intent/bash/redirect-analysis";
import { syntax, token } from "./fake-syntax";

function redirect(type: string, text: string, children: ReturnType<typeof syntax>[]) {
  return syntax(type, text, children);
}

function word(text: string) {
  return syntax("word", text);
}

describe("redirect structure", () => {
  it("reads the operator, descriptor and target", () => {
    const facts = analyzeRedirect(
      redirect("file_redirect", "2>/dev/null", [
        syntax("file_descriptor", "2"),
        token(">", ">"),
        word("/dev/null"),
      ]),
    );

    expect(facts.operator).toBe(">");
    expect(facts.sourceDescriptor).toBe("2");
    expect(facts.targetText).toBe("/dev/null");
    expect(facts.targetValue).toBe("/dev/null");
    expect(facts.dynamicTarget).toBe(false);
    expect(facts.mayWriteFile).toBe(false);
  });

  it("recognizes descriptor duplication and descriptor close", () => {
    const duplicate = analyzeRedirect(
      redirect("file_redirect", "2>&1", [
        syntax("file_descriptor", "2"),
        token(">&", ">&"),
        syntax("number", "1"),
      ]),
    );
    const close = analyzeRedirect(
      redirect("file_redirect", "2>&-", [syntax("file_descriptor", "2"), token(">&-", ">&-")]),
    );

    expect(duplicate.duplicatesDescriptor).toBe(true);
    expect(duplicate.mayWriteFile).toBe(false);
    expect(close.duplicatesDescriptor).toBe(true);
    expect(close.targetText).toBeNull();
    expect(close.mayWriteFile).toBe(false);
  });

  it("treats read-only redirects as proven reads", () => {
    const input = redirect("file_redirect", "< in", [token("<", "<"), word("in")]);
    const heredoc = redirect("heredoc_redirect", "<<EOF", [
      token("<<", "<<"),
      syntax("heredoc_start", "EOF"),
      syntax("heredoc_body", "body\n"),
      syntax("heredoc_end", "EOF"),
    ]);
    const herestring = redirect("herestring_redirect", "<<< here", [token("<<<", "<<<"), word("here")]);

    expect(redirectMayWriteFile(input)).toBe(false);
    expect(redirectMayWriteFile(heredoc)).toBe(false);
    expect(redirectMayWriteFile(herestring)).toBe(false);
  });

  it("keeps write redirects conservative", () => {
    const plain = redirect("file_redirect", "> out", [token(">", ">"), word("out")]);
    const glob = redirect("file_redirect", "> *.txt", [token(">", ">"), word("*.txt")]);
    const dynamic = redirect("file_redirect", "> $out", [
      token(">", ">"),
      syntax("simple_expansion", "$out", [token("$", "$"), syntax("variable_name", "out")]),
    ]);
    const unknown = redirect("file_redirect", ">> out", [token(">>", ">>"), word("out")]);

    expect(redirectMayWriteFile(plain)).toBe(true);
    expect(redirectMayWriteFile(glob)).toBe(true);
    expect(redirectMayWriteFile(dynamic)).toBe(true);
    expect(redirectMayWriteFile(unknown)).toBe(true);
    expect(staticRedirectTarget(glob)).toBeNull();
    expect(staticRedirectTarget(dynamic)).toBeNull();
  });

  it("extracts static values from quoted targets only", () => {
    const double = redirect("file_redirect", '> "out file"', [
      token(">", ">"),
      syntax("string", '"out file"', [syntax("string_content", "out file")]),
    ]);
    const single = redirect("file_redirect", "> 'out file'", [token(">", ">"), syntax("raw_string", "'out file'")]);
    const expansion = redirect("file_redirect", '> "$out"', [
      token(">", ">"),
      syntax("string", '"$out"', [syntax("simple_expansion", "$out")]),
    ]);
    const ansi = redirect("file_redirect", "> $'out'", [token(">", ">"), syntax("ansi_c_string", "$'out'")]);
    const escaped = redirect("file_redirect", "> out\\ file", [token(">", ">"), word("out\\ file")]);

    expect(staticRedirectTarget(double)).toBe("out file");
    expect(staticRedirectTarget(single)).toBe("out file");
    expect(staticRedirectTarget(expansion)).toBeNull();
    expect(staticRedirectTarget(ansi)).toBeNull();
    expect(staticRedirectTarget(escaped)).toBeNull();
  });

  it("counts an unresolved previous sibling as a possible write", () => {
    const command = syntax("command", "cat", [syntax("command_name", "cat")]);
    const stranded = syntax("ERROR", "<", [token("<", "<")], { error: true });
    const redirect = syntax("file_redirect", ">&1", [token(">&", ">&"), syntax("number", "1")]);
    syntax("redirected_statement", "cat <>&1", [command, stranded, redirect]);

    expect(redirectMayWriteFile(redirect)).toBe(true);
  });

  it("does not treat a stranded read-write operator as a read", () => {
    const command = syntax("command", "cat", [syntax("command_name", "cat")]);
    const broken = syntax("file_redirect", "<> rw", [
      token("<", "<"),
      syntax("ERROR", ">", [token(">", ">")], { error: true }),
      word("rw"),
    ]);
    syntax("redirected_statement", "cat <> rw", [command, broken]);

    expect(redirectMayWriteFile(broken)).toBe(true);
  });

  it("identifies redirect node types", () => {
    expect(isRedirectNode(syntax("file_redirect", "> out"))).toBe(true);
    expect(isRedirectNode(syntax("heredoc_redirect", "<<EOF"))).toBe(true);
    expect(isRedirectNode(syntax("herestring_redirect", "<<< x"))).toBe(true);
    expect(isRedirectNode(syntax("command", "cat"))).toBe(false);
  });
});
