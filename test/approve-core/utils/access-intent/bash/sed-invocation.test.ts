import { describe, expect, it } from "vitest";
import { isReadOnlySed } from "#approve-core/utils/access-intent/bash/sed-invocation";
import type { CommandWord } from "#approve-core/utils/access-intent/bash/wrapper-analysis";

function words(...values: string[]): CommandWord[] {
  return values.map((value) => ({ value, computed: false, mayLeadWithDash: value.startsWith("-") }));
}

describe("sed read-only proof", () => {
  it("accepts a print script but rejects a write script", () => {
    expect(isReadOnlySed(words("-n", "p", "input"))).toBe(true);
    expect(isReadOnlySed(words("w output", "input"))).toBe(false);
  });

  it("withdraws proof for an option after the positional script", () => {
    expect(isReadOnlySed(words("p", "-i", "input"))).toBe(false);
  });

  it("accepts explicit print expressions without treating the file as a script", () => {
    expect(isReadOnlySed(words("-e", "p", "input"))).toBe(true);
    expect(isReadOnlySed(words("--expression=p", "input"))).toBe(true);
    expect(isReadOnlySed(words("-e", "w output", "input"))).toBe(false);
  });

  it("proves a basic substitution but rejects substitution write and execute flags", () => {
    expect(isReadOnlySed(words("s/foo/bar/g", "input"))).toBe(true);
    expect(isReadOnlySed(words("s/foo/bar/w output", "input"))).toBe(false);
    expect(isReadOnlySed(words("s/foo/bar/e", "input"))).toBe(false);
  });

  it("supports a numeric address range on a substitution", () => {
    expect(isReadOnlySed(words("1,5s/a/b/g", "input"))).toBe(true);
    expect(isReadOnlySed(words("1,5s/a/b/w output", "input"))).toBe(false);
  });

  it("supports a negated regex address on a substitution", () => {
    expect(isReadOnlySed(words("/skip/!s/a/b/g", "input"))).toBe(true);
    expect(isReadOnlySed(words("/skip/!s/a/b/e", "input"))).toBe(false);
  });

  it("accepts addressed read-only print and delete commands", () => {
    expect(isReadOnlySed(words("-n", "1,5p; 7d", "input"))).toBe(true);
    expect(isReadOnlySed(words("1,5p; 7w output", "input"))).toBe(false);
  });

  it("accepts non-writing quit, list and buffer-clear commands", () => {
    for (const script of ["q", "Q", "l", "z"]) expect(isReadOnlySed(words(script, "input"))).toBe(true);
    for (const script of ["a text", "i text", "c text", "r file", "e command"]) expect(isReadOnlySed(words(script, "input"))).toBe(false);
  });

  it("supports attached expressions and an option terminator", () => {
    expect(isReadOnlySed(words("-ep", "--", "input"))).toBe(true);
    expect(isReadOnlySed(words("--", "p", "input"))).toBe(true);
  });

  it("supports regex addresses while rejecting incomplete delimiters", () => {
    expect(isReadOnlySed(words("/hello/p", "input"))).toBe(true);
    expect(isReadOnlySed(words("/hello", "input"))).toBe(false);
  });

  it("supports a regex address range for a read-only command", () => {
    expect(isReadOnlySed(words("/start/,/end/p", "input"))).toBe(true);
    expect(isReadOnlySed(words("/start/,/end/w output", "input"))).toBe(false);
  });

  it("supports a numeric-to-regex address range without admitting writes", () => {
    expect(isReadOnlySed(words("1,/end/p", "input"))).toBe(true);
    expect(isReadOnlySed(words("1,/end/w output", "input"))).toBe(false);
  });

  it("accepts a read-only block and rejects a block containing file output", () => {
    expect(isReadOnlySed(words("{p;d}", "input"))).toBe(true);
    expect(isReadOnlySed(words("{p;w output}", "input"))).toBe(false);
    expect(isReadOnlySed(words("{p;d", "input"))).toBe(false);
  });

  it("accepts addressed blocks and does not hide writes inside them", () => {
    expect(isReadOnlySed(words("1,5{p;d}", "input"))).toBe(true);
    expect(isReadOnlySed(words("1,5{p;w output}", "input"))).toBe(false);
  });

  it("accepts complete transliteration and rejects incomplete scripts", () => {
    expect(isReadOnlySed(words("y/abc/ABC/", "input"))).toBe(true);
    expect(isReadOnlySed(words("y/abc/ABC", "input"))).toBe(false);
  });

  it("accepts non-writing regular-expression and quiet flags", () => {
    expect(isReadOnlySed(words("-E", "--quiet", "p", "input"))).toBe(true);
    expect(isReadOnlySed(words("--in-place", "p", "input"))).toBe(false);
  });

  it("accepts a trailing script comment without interpreting its text as commands", () => {
    expect(isReadOnlySed(words("p\n# w output", "input"))).toBe(true);
    expect(isReadOnlySed(words("p\nw output", "input"))).toBe(false);
  });

  it("parses a substitution followed by another command", () => {
    expect(isReadOnlySed(words("s/foo/bar/g;p", "input"))).toBe(true);
    expect(isReadOnlySed(words("s/foo/bar/g;w output", "input"))).toBe(false);
  });

  it("parses a substitution following a simple command", () => {
    expect(isReadOnlySed(words("p;s/foo/bar/", "input"))).toBe(true);
    expect(isReadOnlySed(words("p;s/foo/bar/w output", "input"))).toBe(false);
  });

  it("proves labels and branches when their syntax is unambiguous", () => {
    expect(isReadOnlySed(words(":again\ns/a/b/\nt again", "input"))).toBe(true);
    expect(isReadOnlySed(words(":again\ns/a/b/w output\nt again", "input"))).toBe(false);
  });

  it("handles a delimiter inside a POSIX bracket expression", () => {
    expect(isReadOnlySed(words("s#[[:alpha:]#]#x#g", "input"))).toBe(true);
    expect(isReadOnlySed(words("s#[[:alpha:]#]#x#w output", "input"))).toBe(false);
  });

  it("recognizes a delimiter inside an address character class", () => {
    expect(isReadOnlySed(words("/[[:alpha:]/]/p", "input"))).toBe(true);
    expect(isReadOnlySed(words("/[[:alpha:]/]/w output", "input"))).toBe(false);
  });

  it("does not treat escaped delimiters as the end of a regex or replacement", () => {
    expect(isReadOnlySed(words(String.raw`s/a\/b/c\/d/g`, "input"))).toBe(true);
    expect(isReadOnlySed(words(String.raw`s/a\/b/c\/d/w out`, "input"))).toBe(false);
  });
});
