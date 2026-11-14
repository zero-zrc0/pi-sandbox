import { describe, expect, it } from "vitest";
import {
  commandPrefixArity,
  SESSION_PREFIX_ARITY,
} from "#approve-core/utils/access-intent/bash/bash-arity";

describe("command prefix arity", () => {
  it("keeps the semantic prefix of common tools", () => {
    expect(commandPrefixArity(["git", "status"])).toBe(2);
    expect(commandPrefixArity(["ls", "-la"])).toBe(1);
    expect(commandPrefixArity(["make", "all"])).toBe(1);
  });

  it("prefers multi-word keys", () => {
    expect(commandPrefixArity(["npm", "run", "test"])).toBe(3);
    expect(commandPrefixArity(["npm", "install", "x"])).toBe(2);
    expect(commandPrefixArity(["uv", "pip", "install", "pkg"])).toBe(3);
    expect(commandPrefixArity(["docker", "compose", "up", "-d"])).toBe(3);
    expect(commandPrefixArity(["gh", "pr", "list"])).toBe(3);
  });

  it("truncates arity beyond the actual token count", () => {
    expect(commandPrefixArity(["git"])).toBe(1);
    expect(commandPrefixArity(["gh", "repo"])).toBe(2);
  });

  it("defaults to the first token for unknown commands", () => {
    expect(commandPrefixArity(["mytool", "--flag", "x"])).toBe(1);
    expect(commandPrefixArity([])).toBe(1);
  });

  it("publishes the whole table for review", () => {
    expect(SESSION_PREFIX_ARITY["bun add"]).toBe(2);
    expect(SESSION_PREFIX_ARITY.aws).toBe(3);
  });
});
