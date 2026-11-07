import { describe, expect, it } from "vitest";
import {
  extractFrontmatter,
  normalizeLineEndings,
  parseSimpleFrontmatterMap,
  readFrontmatterMap,
} from "#config/yaml-frontmatter";

describe("normalizeLineEndings", () => {
  it("replaces every CRLF pair with LF", () => {
    expect(normalizeLineEndings("a\r\nb\r\nc")).toBe("a\nb\nc");
  });

  it("keeps a lone carriage return", () => {
    expect(normalizeLineEndings("a\rb\r\nc")).toBe("a\rb\nc");
  });

  it("returns LF documents unchanged", () => {
    expect(normalizeLineEndings("a\nb\n")).toBe("a\nb\n");
  });
});

describe("extractFrontmatter", () => {
  it("returns an empty string for an empty document", () => {
    expect(extractFrontmatter("")).toBe("");
  });

  it("requires the first line to start with ---", () => {
    expect(extractFrontmatter("# Title\ntext\n---\nkey: value\n---\n")).toBe("");
  });

  it("returns the text between the boundary lines", () => {
    expect(extractFrontmatter("---\ntitle: Hello\n---\nbody\n")).toBe("title: Hello");
  });

  it("keeps blank lines inside the frontmatter block", () => {
    expect(extractFrontmatter("---\na: 1\n\nb: 2\n---\n")).toBe("a: 1\n\nb: 2");
  });

  it("normalizes CRLF boundaries and content to LF", () => {
    expect(extractFrontmatter("---\r\na: 1\r\nb: 2\r\n---\r\nbody\r\n")).toBe("a: 1\nb: 2");
  });

  it("does not trim inner whitespace", () => {
    expect(extractFrontmatter("---\n  a: 1  \n---\n")).toBe("  a: 1  ");
  });

  it("returns an empty string when the terminator is missing", () => {
    expect(extractFrontmatter("---\nkey: value\n")).toBe("");
  });

  it("returns an empty string for an empty block", () => {
    expect(extractFrontmatter("---\n---\nbody\n")).toBe("");
  });

  it("accepts a terminator on the last line without a trailing newline", () => {
    expect(extractFrontmatter("---\na: 1\n---")).toBe("a: 1");
  });

  it("treats ---x and ---- fences like a standalone --- fence", () => {
    for (const fence of ["---", "---x", "----"]) {
      const document = `---\nkey: value\n${fence}\ntail\n`;
      expect(extractFrontmatter(document)).toBe("key: value");
    }
  });

  it("ignores --- in the middle of a content line", () => {
    expect(extractFrontmatter("---\ntitle: ---\nsub: a---b\n---\nbody\n")).toBe("title: ---\nsub: a---b");
  });

  it("ignores an indented --- line", () => {
    expect(extractFrontmatter("---\na: 1\n  ---\nb: 2\n---\nbody\n")).toBe("a: 1\n  ---\nb: 2");
  });

  it("accepts an opening line with any --- prefix", () => {
    expect(extractFrontmatter("---x\na: 1\n---\nbody\n")).toBe("a: 1");
  });
});

describe("parseSimpleFrontmatterMap", () => {
  it("returns an empty object for empty input", () => {
    expect(parseSimpleFrontmatterMap("")).toEqual({});
  });

  it("parses a flat map", () => {
    expect(parseSimpleFrontmatterMap("a: 1\nb: two")).toEqual({ a: "1", b: "two" });
  });

  it("skips empty and whitespace-only lines", () => {
    expect(parseSimpleFrontmatterMap("a: 1\n\n   \nb: 2\n")).toEqual({ a: "1", b: "2" });
  });

  it("skips comment lines, including indented ones", () => {
    expect(parseSimpleFrontmatterMap("# heading\na: 1\n  # note\nb: 2")).toEqual({ a: "1", b: "2" });
  });

  it("skips lines without a colon", () => {
    expect(parseSimpleFrontmatterMap("plain text\na: 1\n- item")).toEqual({ a: "1" });
  });

  it("skips lines with an empty key", () => {
    expect(parseSimpleFrontmatterMap(": value\na: 1")).toEqual({ a: "1" });
  });

  it("creates an object for an empty value", () => {
    expect(parseSimpleFrontmatterMap("a:\nb: 1")).toEqual({ a: {}, b: "1" });
  });

  it("nests two levels", () => {
    expect(parseSimpleFrontmatterMap("a:\n  b: c")).toEqual({ a: { b: "c" } });
  });

  it("nests three levels", () => {
    expect(parseSimpleFrontmatterMap("a:\n  b:\n    c: d")).toEqual({ a: { b: { c: "d" } } });
  });

  it("pops back to the parent on equal indentation", () => {
    expect(parseSimpleFrontmatterMap("a:\n  b:\n    c: 1\n  d: 2")).toEqual({ a: { b: { c: "1" }, d: "2" } });
  });

  it("creates sibling objects at the same indentation", () => {
    expect(parseSimpleFrontmatterMap("a:\n  b:\n  c:")).toEqual({ a: { b: {}, c: {} } });
  });

  it("returns to the root when a later key is less indented", () => {
    expect(parseSimpleFrontmatterMap("a:\n  b: c\nd: e")).toEqual({ a: { b: "c" }, d: "e" });
  });

  it("treats tabs as one indentation unit each", () => {
    expect(parseSimpleFrontmatterMap("\ta:\n\t\tb: c")).toEqual({ a: { b: "c" } });
  });

  it("counts mixed leading whitespace as one unit per character", () => {
    expect(parseSimpleFrontmatterMap("a:\n \tb: c")).toEqual({ a: { b: "c" } });
  });

  it("assigns a more-indented line to the current object when no child is open", () => {
    expect(parseSimpleFrontmatterMap("a: b\n  c: d")).toEqual({ a: "b", c: "d" });
  });

  it("strips one pair of matching quotes from keys", () => {
    expect(parseSimpleFrontmatterMap("'a b': c\n\"d\": e")).toEqual({ "a b": "c", d: "e" });
  });

  it("strips one pair of matching quotes from values", () => {
    expect(parseSimpleFrontmatterMap("a: 'x y'\nb: \"z\"")).toEqual({ a: "x y", b: "z" });
  });

  it("keeps unpaired quotes", () => {
    expect(parseSimpleFrontmatterMap("a: \"x\nb: x'\nc: \"y'")).toEqual({ a: "\"x", b: "x'", c: "\"y'" });
  });

  it("keeps quotes that are not at both ends", () => {
    expect(parseSimpleFrontmatterMap("a: x\"y\nb: \"x\"y\"")).toEqual({ a: "x\"y", b: "x\"y" });
  });

  it("keeps mismatched quote characters", () => {
    expect(parseSimpleFrontmatterMap("a: 'x\"")).toEqual({ a: "'x\"" });
  });

  it("turns an empty quoted value into an empty string, not an object", () => {
    expect(parseSimpleFrontmatterMap("a: \"\"\nb: ''")).toEqual({ a: "", b: "" });
  });

  it("trims surrounding whitespace from keys and values", () => {
    expect(parseSimpleFrontmatterMap("a :    padded   ")).toEqual({ a: "padded" });
  });

  it("treats a whitespace-only value as empty", () => {
    expect(parseSimpleFrontmatterMap("a:   \nb: 1")).toEqual({ a: {}, b: "1" });
  });

  it("splits only on the first colon", () => {
    expect(parseSimpleFrontmatterMap("url: https://example.com/a:b\nnote: b: c")).toEqual({
      url: "https://example.com/a:b",
      note: "b: c",
    });
  });

  it("keeps # inside values", () => {
    expect(parseSimpleFrontmatterMap("a: b # c")).toEqual({ a: "b # c" });
  });

  it("does not coerce scalars or parse flow arrays", () => {
    expect(parseSimpleFrontmatterMap("n: 123\nflag: true\nlist: [1, 2]\nempty: null")).toEqual({
      n: "123",
      flag: "true",
      list: "[1, 2]",
      empty: "null",
    });
  });

  it("skips dash sequence lines without closing the open object", () => {
    expect(parseSimpleFrontmatterMap("list:\n  - item\n  - two\nreal: ok")).toEqual({ list: {}, real: "ok" });
  });

  it("does not interpret escapes", () => {
    expect(parseSimpleFrontmatterMap("a: \"x\\n\"\nb: C:\\temp")).toEqual({ a: "x\\n", b: "C:\\temp" });
  });

  it("overwrites duplicate keys", () => {
    expect(parseSimpleFrontmatterMap("a: one\na: two")).toEqual({ a: "two" });
  });

  it("overwrites duplicate nested keys", () => {
    expect(parseSimpleFrontmatterMap("g:\n  a: one\n  a: two")).toEqual({ g: { a: "two" } });
  });

  it("closes nested objects when a top-level key follows", () => {
    expect(parseSimpleFrontmatterMap("a:\n  b: 1\nc:")).toEqual({ a: { b: "1" }, c: {} });
  });
});

describe("readFrontmatterMap", () => {
  it("composes extraction and parsing", () => {
    expect(readFrontmatterMap("---\ntitle: \"Hello\"\nnested:\n  flag: 'on'\n---\nbody\n")).toEqual({
      title: "Hello",
      nested: { flag: "on" },
    });
  });

  it("handles CRLF documents", () => {
    expect(readFrontmatterMap("---\r\nkey: value\r\n---\r\nbody\r\n")).toEqual({ key: "value" });
  });

  it("returns an empty object without frontmatter", () => {
    expect(readFrontmatterMap("# Title\nkey: value\n")).toEqual({});
  });

  it("returns an empty object when the block is unterminated", () => {
    expect(readFrontmatterMap("---\nkey: value\n")).toEqual({});
  });
});
