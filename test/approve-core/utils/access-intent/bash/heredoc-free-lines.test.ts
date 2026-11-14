import { describe, expect, it } from "vitest";
import { buildHeredocFreeLine } from "#approve-core/utils/access-intent/bash/heredoc-free-lines";
import { syntax, token } from "./fake-syntax";

function command(text: string) {
  return syntax("command", text, [syntax("command_name", text)]);
}

function heredoc(text: string, opener: "<<" | "<<-", delimiter: string, body = "body\n") {
  return syntax("heredoc_redirect", text, [
    token(opener, opener),
    syntax("heredoc_start", delimiter),
    syntax("heredoc_body", body),
    syntax("heredoc_end", "EOF"),
  ]);
}

describe("heredoc-free line candidates", () => {
  it("removes the opener, delimiter and preceding whitespace", () => {
    const statement = syntax("redirected_statement", "cat <<EOF > out | grep x\nbody\nEOF", [
      command("cat"),
      heredoc("<<EOF > out | grep x\nbody\nEOF", "<<", "EOF"),
    ]);

    const line = buildHeredocFreeLine(statement, statement.text);

    expect(line?.text).toBe("cat > out | grep x");
    expect(line?.removed).toEqual([{ startIndex: 3, endIndex: 9 }]);
  });

  it("removes an adjacent descriptor", () => {
    const statement = syntax("redirected_statement", "cat 0<<EOF\nbody\nEOF", [
      command("cat"),
      syntax("heredoc_redirect", "0<<EOF\nbody\nEOF", [
        syntax("file_descriptor", "0"),
        token("<<", "<<"),
        syntax("heredoc_start", "EOF"),
        syntax("heredoc_body", "body\n"),
        syntax("heredoc_end", "EOF"),
      ]),
    ]);

    expect(buildHeredocFreeLine(statement, statement.text)?.text).toBe("cat");
  });

  it("handles dash heredocs", () => {
    const statement = syntax("redirected_statement", "cat <<-A", [
      command("cat"),
      syntax("heredoc_redirect", "<<-A", [token("<<-", "<<-"), syntax("heredoc_start", "A")]),
    ]);

    expect(buildHeredocFreeLine(statement, statement.text)?.text).toBe("cat");
  });

  it("merges same-line deletion spans", () => {
    const statement = syntax("redirected_statement", "cat <<A <<B", [
      command("cat"),
      syntax("heredoc_redirect", "<<A", [token("<<", "<<"), syntax("heredoc_start", "A")]),
      syntax("heredoc_redirect", "<<B", [token("<<", "<<"), syntax("heredoc_start", "B")]),
    ]);

    expect(buildHeredocFreeLine(statement, statement.text)?.text).toBe("cat");
  });

  it("recovers a scanner-recognized heredoc inside an ERROR node", () => {
    const error = syntax(
      "ERROR",
      "<<EOF; echo hi\nbody\nEOF",
      [
        token("<<", "<<"),
        syntax("heredoc_start", "EOF;"),
        syntax("word", "echo"),
        syntax("word", "hi"),
        syntax("heredoc_body", "body\n"),
        syntax("word", "EOF"),
      ],
      { error: true },
    );
    const program = syntax("program", "cat <<EOF; echo hi\nbody\nEOF", [command("cat"), error]);

    expect(buildHeredocFreeLine(error, program.text)?.text).toBe("cat; echo hi");
  });

  it("does not treat a lone less-than as a heredoc opener", () => {
    const error = syntax("ERROR", "<", [token("<", "<")], { error: true });
    const program = syntax("program", "cat <> rw", [command("cat"), error]);

    expect(buildHeredocFreeLine(program, program.text)).toBeNull();
  });

  it("returns null when the host has no heredoc", () => {
    const statement = syntax("redirected_statement", "cat < in", [
      command("cat"),
      syntax("file_redirect", "< in", [token("<", "<"), syntax("word", "in")]),
    ]);

    expect(buildHeredocFreeLine(statement, statement.text)).toBeNull();
  });
});
