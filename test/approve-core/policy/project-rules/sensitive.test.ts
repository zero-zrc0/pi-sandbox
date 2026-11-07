import { describe, expect, it } from "vitest";
import {
  SENSITIVE_REASON_PLACEHOLDER,
  isSensitiveText,
  redactSensitiveReason,
  scanStructuredArguments,
} from "#approve-core/policy/project-rules/sensitive";

const MAX_DEPTH = 16;
const MAX_ENTRIES = 512;
const MAX_STRING_LENGTH = 4096;

const JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
const JWT_HEADER_SEGMENT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
const HIGH_ENTROPY = "q7Zr2mN8xK4pL9wQ1sT6vY3bC5dF0gH2jR8uE4aZ";

function nestedContainer(depth: number): unknown {
  let node: unknown = "leaf";
  for (let level = 0; level < depth; level += 1) node = { child: node };
  return node;
}

function objectWithEntries(count: number): Record<string, number> {
  const value: Record<string, number> = {};
  for (let index = 0; index < count; index += 1) value[`field${index}`] = index;
  return value;
}

const SENSITIVE_KEYS: Array<[string, string]> = [
  ["password", "password"],
  ["PASSWORD", "password"],
  ["passwd", "password"],
  ["api-key", "api-key"],
  ["API_KEY", "api-key"],
  ["apiKey", "api-key"],
  ["x-api-key", "api-key"],
  ["clientSecret", "client-secret"],
  ["client_secret", "client-secret"],
  ["private key", "private-key"],
  ["privateKey", "private-key"],
  ["access.token", "token"],
  ["session_key", "session-key"],
  ["accessKey", "access-key"],
  ["authorization", "authorization"],
  ["Authorization", "authorization"],
  ["cookie", "cookie"],
  ["bearer", "bearer"],
  ["credentials", "credential"],
  ["secretValue", "secret"],
  ["authToken", "token"],
  ["apiToken", "token"],
];

const SENSITIVE_SAMPLES: Array<[string, string, string]> = [
  ["authorization header", "Authorization: Bearer abcDEF123456xyz987", "authorization"],
  ["basic authorization header", "authorization: Basic dXNlcjpwYXNz", "authorization"],
  ["bearer token", "Bearer abcdefghijklmnopqrstuvwxyz", "bearer"],
  ["basic credentials", "Basic dXNlcjpwYXNz", "bearer"],
  ["cookie header", "Cookie: session=abc123; theme=dark", "cookie"],
  ["password option", "--password hunter2", "password"],
  ["password assignment", "PASSWORD=hunter2", "password"],
  ["token assignment", "TOKEN=abc123def456", "token"],
  ["token query parameter", "?token=abc123def456", "token"],
  ["url credentials", "https://admin:hunter2@example.com/repo.git", "url-credentials"],
  ["database url credentials", "postgres://user:secret@db.internal:5432/app", "url-credentials"],
  ["private key block", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA", "private-key"],
  ["jwt", JWT, "jwt"],
  ["jwt header segment in a path", `/work/${JWT_HEADER_SEGMENT}`, "jwt"],
  ["github token", "use token ghp_abcdefghijklmnopqrstuvwxyz012345", "service-token"],
  ["aws access key", "AKIAIOSFODNN7EXAMPLE", "service-token"],
  ["slack token", "xoxb-123456789012-123456789012-abcdefABCDEF", "service-token"],
  ["high entropy opaque value", HIGH_ENTROPY, "high-entropy"],
];

const NON_JSON_VALUES: Array<[string, unknown, string]> = [
  ["undefined", undefined, "non-json"],
  ["a property holding undefined", { value: undefined }, "non-json"],
  ["a function", () => 1, "non-json"],
  ["a property holding a function", { value: () => 1 }, "non-json"],
  ["a symbol", Symbol("token"), "non-json"],
  ["a bigint", 1n, "non-json"],
  ["NaN", { value: Number.NaN }, "non-json"],
  ["Infinity", { value: Number.POSITIVE_INFINITY }, "non-json"],
  ["a Date", { value: new Date(0) }, "non-json"],
  ["a Map", new Map(), "non-json"],
  ["a class instance", new (class Sample {})(), "non-json"],
  ["a symbol key", { [Symbol("x")]: 1 }, "non-json"],
];

const BENIGN_TEXTS: string[] = [
  "",
  "npm install",
  "git status --short",
  "Please run the test suite before merging.",
  "The tokenizer handles JSON strings.",
  "authorization is required for this endpoint",
  "Basic authentication is supported.",
  "https://example.com/docs?page=2",
  "https://user@example.com/repo.git",
  "C:\\Users\\dev\\project",
  "src/approve-core/policy/project-rules/sensitive.ts",
  "build-2026-11-01.log",
  "user@example.com",
  "this is a normal commit message",
  "always allow this",
  "rule revoked by the user",
  "definition-digest",
  "0123456789abcdef",
];

describe("scanStructuredArguments: plain arguments", () => {
  it("accepts a nested JSON argument object", () => {
    const value = {
      command: "npm run build",
      cwd: "E:\\Users\\dev\\project",
      timeoutMs: 5000,
      env: { NODE_ENV: "test" },
      args: ["--watch", "src/index.ts"],
      nested: { list: [1, null, true, "text"], emptyObject: {}, emptyArray: [] },
    };
    expect(scanStructuredArguments(value)).toEqual({ ok: true });
  });

  it("accepts empty containers and scalar roots", () => {
    expect(scanStructuredArguments({})).toEqual({ ok: true });
    expect(scanStructuredArguments([])).toEqual({ ok: true });
    expect(scanStructuredArguments("plain text")).toEqual({ ok: true });
    expect(scanStructuredArguments(42)).toEqual({ ok: true });
    expect(scanStructuredArguments(null)).toEqual({ ok: true });
    expect(scanStructuredArguments(true)).toEqual({ ok: true });
  });

  it("accepts the same object referenced twice without treating it as a cycle", () => {
    const shared = { command: "cat file.txt" };
    expect(scanStructuredArguments({ first: shared, second: shared })).toEqual({ ok: true });
  });
});

describe("scanStructuredArguments: sensitive arguments", () => {
  it.each(SENSITIVE_KEYS)("rejects the sensitive key %s", (key: string, category: string) => {
    expect(scanStructuredArguments({ outer: { [key]: "visible" } })).toEqual({
      ok: false,
      kind: "sensitive",
      category,
    });
  });

  it("rejects a sensitive key nested inside an array", () => {
    expect(scanStructuredArguments({ headers: [{ "api-key": "visible" }] })).toEqual({
      ok: false,
      kind: "sensitive",
      category: "api-key",
    });
  });

  it.each(SENSITIVE_SAMPLES)("rejects a %s string value", (_label: string, sample: string, category: string) => {
    expect(scanStructuredArguments({ args: { value: sample } })).toEqual({
      ok: false,
      kind: "sensitive",
      category,
    });
  });
});

describe("scanStructuredArguments: unlearnable arguments", () => {
  it.each(NON_JSON_VALUES)("rejects %s as non-json", (_label: string, value: unknown, reason: string) => {
    expect(scanStructuredArguments(value)).toEqual({ ok: false, kind: "unlearnable", reason });
  });

  it("rejects a cyclic reference", () => {
    const cyclic: Record<string, unknown> = { command: "cat file.txt" };
    cyclic.self = cyclic;
    expect(scanStructuredArguments(cyclic)).toEqual({ ok: false, kind: "unlearnable", reason: "non-json" });
  });
});

describe("scanStructuredArguments: structural limits", () => {
  it("accepts nesting at the depth limit", () => {
    expect(scanStructuredArguments(nestedContainer(MAX_DEPTH))).toEqual({ ok: true });
  });

  it("rejects nesting one level beyond the depth limit", () => {
    expect(scanStructuredArguments(nestedContainer(MAX_DEPTH + 1))).toEqual({
      ok: false,
      kind: "unlearnable",
      reason: "depth-limit",
    });
  });

  it("accepts an object with the maximum entries", () => {
    expect(scanStructuredArguments(objectWithEntries(MAX_ENTRIES))).toEqual({ ok: true });
  });

  it("rejects an object with one entry beyond the limit", () => {
    expect(scanStructuredArguments(objectWithEntries(MAX_ENTRIES + 1))).toEqual({
      ok: false,
      kind: "unlearnable",
      reason: "entry-limit",
    });
  });

  it("accepts an array with the maximum entries", () => {
    expect(scanStructuredArguments(Array.from({ length: MAX_ENTRIES }, (_, index) => index))).toEqual({ ok: true });
  });

  it("rejects an array with one entry beyond the limit", () => {
    expect(scanStructuredArguments(Array.from({ length: MAX_ENTRIES + 1 }, (_, index) => index))).toEqual({
      ok: false,
      kind: "unlearnable",
      reason: "entry-limit",
    });
  });

  it("accepts a string value at the length limit", () => {
    expect(scanStructuredArguments({ value: "a".repeat(MAX_STRING_LENGTH) })).toEqual({ ok: true });
  });

  it("rejects a string value one character beyond the limit", () => {
    expect(scanStructuredArguments({ value: "a".repeat(MAX_STRING_LENGTH + 1) })).toEqual({
      ok: false,
      kind: "unlearnable",
      reason: "string-length-limit",
    });
  });

  it("rejects a long nested string even when it resembles a credential", () => {
    expect(scanStructuredArguments({ args: { value: `Bearer ${"a".repeat(MAX_STRING_LENGTH)}` } })).toEqual({
      ok: false,
      kind: "unlearnable",
      reason: "string-length-limit",
    });
  });
});

describe("isSensitiveText", () => {
  it.each(SENSITIVE_SAMPLES)("flags a %s", (_label: string, sample: string, category: string) => {
    expect(isSensitiveText(sample)).toBe(true);
    expect(scanStructuredArguments({ value: sample })).toEqual({ ok: false, kind: "sensitive", category });
  });

  it.each(BENIGN_TEXTS)("does not flag benign text %s", (text: string) => {
    expect(isSensitiveText(text)).toBe(false);
  });
});

describe("redactSensitiveReason", () => {
  it("keeps the exported placeholder generic", () => {
    expect(SENSITIVE_REASON_PLACEHOLDER).toBe("[redacted: sensitive content]");
  });

  it("leaves an ordinary reason untouched", () => {
    expect(redactSensitiveReason("rule revoked by the user")).toBe("rule revoked by the user");
  });

  it("replaces a sensitive reason without copying the original text", () => {
    const reason = "Authorization: Bearer super-secret-token-123456";
    const redacted = redactSensitiveReason(reason);
    expect(redacted).toBe(SENSITIVE_REASON_PLACEHOLDER);
    expect(redacted).not.toContain("super-secret-token-123456");
  });

  it("does not treat the placeholder itself as sensitive", () => {
    expect(redactSensitiveReason(SENSITIVE_REASON_PLACEHOLDER)).toBe(SENSITIVE_REASON_PLACEHOLDER);
  });
});
