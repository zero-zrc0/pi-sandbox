import { describe, expect, it } from "vitest";
import {
  DEFAULT_PREVIEW_LIMITS,
  PREVIEW_ELLIPSIS,
  REDACTED_VALUE,
  collapseWhitespace,
  countLabel,
  countLines,
  inlinePreview,
  isSensitiveKey,
  jsonPreview,
  logJsonPreview,
  maskSensitiveKeys,
  resolvePreviewLimits,
  safeStringify,
  truncateWithEllipsis,
} from "#approve-core/nodes/human/tool-input-preview";

describe("preview limits", () => {
  it("ships the documented default caps as a frozen object", () => {
    expect(DEFAULT_PREVIEW_LIMITS).toEqual({
      promptInput: 200,
      textSummary: 80,
      mcpSummary: 160,
      mcpValue: 60,
    });
    expect(Object.isFrozen(DEFAULT_PREVIEW_LIMITS)).toBe(true);
  });

  it("returns the defaults when no override is supplied", () => {
    expect(resolvePreviewLimits()).toEqual(DEFAULT_PREVIEW_LIMITS);
    expect(resolvePreviewLimits(undefined)).toEqual(DEFAULT_PREVIEW_LIMITS);
  });

  it("applies independent positive integer overrides and freezes the result", () => {
    const limits = resolvePreviewLimits({ promptInput: 12, mcpValue: 4 });
    expect(limits).toEqual({ promptInput: 12, textSummary: 80, mcpSummary: 160, mcpValue: 4 });
    expect(Object.isFrozen(limits)).toBe(true);
  });

  it("ignores invalid overrides instead of failing", () => {
    const limits = resolvePreviewLimits({
      promptInput: 0,
      textSummary: -3,
      mcpSummary: Number.NaN,
      mcpValue: 12.5,
    });
    expect(limits).toEqual(DEFAULT_PREVIEW_LIMITS);
  });

  it("ignores infinite overrides", () => {
    expect(resolvePreviewLimits({ promptInput: Number.POSITIVE_INFINITY })).toEqual(DEFAULT_PREVIEW_LIMITS);
  });
});

describe("truncateWithEllipsis", () => {
  it("keeps text that fits unchanged", () => {
    expect(truncateWithEllipsis("abc", 3)).toBe("abc");
    expect(truncateWithEllipsis("", 10)).toBe("");
  });

  it("keeps the limit characters and appends the ellipsis", () => {
    expect(truncateWithEllipsis("abcdef", 3)).toBe(`abc${PREVIEW_ELLIPSIS}`);
    expect(truncateWithEllipsis("x".repeat(201), 200)).toBe(`x${"x".repeat(199)}${PREVIEW_ELLIPSIS}`);
  });

  it("does not truncate exactly at the limit", () => {
    expect(truncateWithEllipsis("x".repeat(200), 200)).toBe("x".repeat(200));
  });
});

describe("countLines", () => {
  it("reports zero lines for the empty string", () => {
    expect(countLines("")).toBe(0);
  });

  it("counts single and multi line text", () => {
    expect(countLines("one")).toBe(1);
    expect(countLines("one\ntwo")).toBe(2);
    expect(countLines("one\n")).toBe(2);
  });

  it("counts CRLF, CR and LF line endings", () => {
    expect(countLines("a\r\nb")).toBe(2);
    expect(countLines("a\rb")).toBe(2);
    expect(countLines("a\r\nb\rc\nd")).toBe(4);
    expect(countLines("\r\n\r\n")).toBe(3);
  });
});

describe("countLabel", () => {
  it("uses the singular only for exactly one", () => {
    expect(countLabel(0, "line", "lines")).toBe("0 lines");
    expect(countLabel(1, "line", "lines")).toBe("1 line");
    expect(countLabel(2, "line", "lines")).toBe("2 lines");
    expect(countLabel(-1, "line", "lines")).toBe("-1 lines");
  });
});

describe("collapseWhitespace and inlinePreview", () => {
  it("collapses all whitespace runs and trims", () => {
    expect(collapseWhitespace("  a \t\n b   c  ")).toBe("a b c");
    expect(collapseWhitespace("\r\n")).toBe("");
  });

  it("reports the empty text category for blank input", () => {
    expect(inlinePreview("", 80)).toBeUndefined();
    expect(inlinePreview("   \n\t ", 80)).toBeUndefined();
  });

  it("collapses then truncates at the injected limit", () => {
    expect(inlinePreview("  a\n b  ", 80)).toBe("a b");
    expect(inlinePreview("abcdef", 3)).toBe(`abc${PREVIEW_ELLIPSIS}`);
  });
});

describe("safeStringify and jsonPreview", () => {
  it("serializes a plain object", () => {
    expect(safeStringify({ a: 1 })).toBe('{"a":1}');
  });

  it("returns undefined for values JSON cannot represent", () => {
    expect(safeStringify(undefined)).toBeUndefined();
    expect(safeStringify(() => 1)).toBeUndefined();
    expect(safeStringify(Symbol("x"))).toBeUndefined();
  });

  it("returns undefined for circular values and BigInt instead of throwing", () => {
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    expect(safeStringify(circular)).toBeUndefined();
    expect(safeStringify({ big: 1n })).toBeUndefined();
  });

  it("produces no preview for null, empty objects and serialization failures", () => {
    expect(jsonPreview(null, 200)).toBeUndefined();
    expect(jsonPreview({}, 200)).toBeUndefined();
    expect(jsonPreview(Object.create(null), 200)).toBeUndefined();
    expect(jsonPreview(undefined, 200)).toBeUndefined();
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    expect(jsonPreview(circular, 200)).toBeUndefined();
  });

  it("keeps non-empty structures, empty arrays and collapse whitespace", () => {
    expect(jsonPreview({ a: 1 }, 200)).toBe('{"a":1}');
    expect(jsonPreview([], 200)).toBe("[]");
    expect(jsonPreview({ a: "  x   y  " }, 200)).toBe('{"a":" x y "}');
  });

  it("truncates the serialized preview at the limit", () => {
    const preview = jsonPreview({ a: "x".repeat(500) }, 20);
    expect(preview).toBeDefined();
    expect(preview!.length).toBe(21);
    expect(preview!.endsWith(PREVIEW_ELLIPSIS)).toBe(true);
  });
});

describe("isSensitiveKey", () => {
  it("recognizes credential style keys after normalizing separators and case", () => {
    for (const key of [
      "password",
      "passwd",
      "API_KEY",
      "api-key",
      "apiKey",
      "Authorization",
      "client_secret",
      "SESSION_KEY",
      "cookie",
      "privateKey",
      "credential",
      "token",
      "accessKey",
    ]) {
      expect(isSensitiveKey(key), key).toBe(true);
    }
  });

  it("does not flag ordinary input keys", () => {
    for (const key of ["path", "file_path", "content", "url", "username", "key", "offset", "limit"]) {
      expect(isSensitiveKey(key), key).toBe(false);
    }
  });

  it("treats non-string and blank keys as not sensitive", () => {
    expect(isSensitiveKey(undefined as never)).toBe(false);
    expect(isSensitiveKey("   ")).toBe(false);
  });
});

describe("maskSensitiveKeys", () => {
  it("replaces sensitive values without changing ordinary ones", () => {
    expect(maskSensitiveKeys({ password: "hunter2", name: "a" })).toEqual({
      password: REDACTED_VALUE,
      name: "a",
    });
  });

  it("masks nested objects and arrays", () => {
    const masked = maskSensitiveKeys({
      outer: { apiKey: "k", list: [{ token: "t", keep: 1 }] },
    });
    expect(masked).toEqual({
      outer: { apiKey: REDACTED_VALUE, list: [{ token: REDACTED_VALUE, keep: 1 }] },
    });
  });

  it("does not mutate the input", () => {
    const input = { secret: "s", nested: { password: "p" } };
    maskSensitiveKeys(input);
    expect(input).toEqual({ secret: "s", nested: { password: "p" } });
  });

  it("survives cycles and deep nesting without throwing", () => {
    const circular: Record<string, unknown> = { name: "a" };
    circular.self = circular;
    const masked = maskSensitiveKeys(circular) as Record<string, unknown>;
    expect(masked.name).toBe("a");
    expect(masked.self).toBe(REDACTED_VALUE);

    let deep: Record<string, unknown> = { leaf: "ok" };
    for (let index = 0; index < 15; index += 1) deep = { next: deep };
    expect(() => maskSensitiveKeys(deep)).not.toThrow();
  });

  it("leaves non-plain objects untouched", () => {
    const date = new Date(0);
    const masked = maskSensitiveKeys({ when: date }) as { when: unknown };
    expect(masked.when).toBe(date);
  });

  it("keeps primitives as they are", () => {
    expect(maskSensitiveKeys("plain")).toBe("plain");
    expect(maskSensitiveKeys(7)).toBe(7);
    expect(maskSensitiveKeys(null)).toBeNull();
  });
});

describe("logJsonPreview", () => {
  it("masks sensitive keys before serializing", () => {
    const preview = logJsonPreview({ path: "a.txt", password: "hunter2" }, 200);
    expect(preview).toBe(`{"path":"a.txt","password":"${REDACTED_VALUE}"}`);
    expect(preview).not.toContain("hunter2");
  });

  it("behaves like jsonPreview for values without sensitive keys", () => {
    expect(logJsonPreview({ a: 1 }, 200)).toBe('{"a":1}');
  });

  it("produces no preview for null and empty objects", () => {
    expect(logJsonPreview(null, 200)).toBeUndefined();
    expect(logJsonPreview({}, 200)).toBeUndefined();
  });

  it("serializes a masked cycle instead of failing", () => {
    const circular: Record<string, unknown> = { name: "a" };
    circular.self = circular;
    expect(logJsonPreview(circular, 200)).toBe(`{"name":"a","self":"${REDACTED_VALUE}"}`);
  });
});
