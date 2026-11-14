import { describe, expect, it } from "vitest";
import { SessionRuleStore } from "#approve-core/policy/session-rules";
import { compileWildcard } from "#approve-core/policy/wildcard-matcher";
import { POSIX_PATH_FLAVOR as POSIX } from "#approve-core/utils/path/path-flavor";

function store(options: { maxRules?: number; onCompile?: () => void } = {}) {
  return new SessionRuleStore({
    flavor: POSIX,
    ...(options.maxRules === undefined ? {} : { maxRules: options.maxRules }),
    ...(options.onCompile === undefined ? {} : {
      compilePattern: (pattern, matchOptions) => {
        options.onCompile?.();
        return compileWildcard(pattern, matchOptions);
      },
    }),
  });
}

describe("approval targets", () => {
  it("grants one surface for ordinary and directional names", () => {
    const rules = store();
    rules.approve("bash", "git *");
    rules.approve("path_read", "/tmp/*");
    expect(rules.rules().map((rule) => [rule.surface, rule.pattern, rule.action, rule.origin])).toEqual([
      ["bash", "git *", "allow", "session"],
      ["path_read", "/tmp/*", "allow", "session"],
    ]);
    expect(rules.snapshot().evaluator.evaluate("bash", "git status").action).toBe("allow");
  });

  it("grants both directions for a bare path family", () => {
    const rules = store();
    rules.approve("path", "/work/*");
    expect(rules.rules().map((rule) => rule.surface)).toEqual(["path_read", "path_write"]);
  });
});

describe("stable views", () => {
  it("keeps the same view reference while nothing changes", () => {
    const rules = store();
    const before = rules.snapshot();
    expect(rules.snapshot()).toBe(before);
    rules.approve("bash", "git *");
    const after = rules.snapshot();
    expect(after).not.toBe(before);
    expect(after.version).toBe(before.version + 1);
    expect(rules.snapshot()).toBe(after);
  });

  it("does not rebuild the view for a duplicate approval", () => {
    const rules = store();
    const view = rules.approve("bash", "git *");
    expect(rules.approve("bash", "git *")).toBe(view);
    expect(rules.rules()).toHaveLength(1);
  });

  it("keeps old references valid after approve and clear", () => {
    const rules = store();
    rules.approve("bash", "git *");
    const old = rules.snapshot();
    rules.clear();
    expect(old.evaluator.evaluate("bash", "git status").action).toBe("allow");
    expect(rules.snapshot().evaluator.evaluate("bash", "git status").action).toBe("ask");
  });

  it("returns a defensive copy but compiles the stable array", () => {
    const rules = store();
    rules.approve("bash", "git *");
    const copy = rules.rules() as unknown as { push(value: unknown): void };
    copy.push({ surface: "bash", pattern: "rm *", action: "allow", origin: "session", layer: "session" });
    expect(rules.rules()).toHaveLength(1);
    expect(rules.snapshot().evaluator.evaluate("bash", "rm -rf /").action).toBe("ask");
  });

  it("compiles the session evaluator lazily, once per view", () => {
    let compiles = 0;
    const rules = store({ onCompile: () => { compiles += 1; } });
    rules.approve("bash", "git *");
    expect(compiles).toBe(0);
    rules.snapshot().evaluator.evaluate("bash", "git status");
    rules.snapshot().evaluator.evaluate("bash", "git push");
    expect(compiles).toBe(1);
  });
});

describe("clearing and bounds", () => {
  it("clears approvals and bumps the view", () => {
    const rules = store();
    const empty = rules.snapshot();
    rules.approve("bash", "git *");
    const cleared = rules.clear();
    expect(cleared.rules).toEqual([]);
    expect(cleared.version).toBe(empty.version + 2);
    expect(rules.clear()).toBe(cleared);
  });

  it("clears on shutdown", () => {
    const rules = store();
    rules.approve("bash", "git *");
    rules.shutdown();
    expect(rules.rules()).toEqual([]);
  });

  it("drops the oldest rules beyond the bound and reports it", () => {
    const rules = store({ maxRules: 2 });
    rules.approve("bash", "one");
    rules.approve("bash", "two");
    rules.approve("bash", "three");
    expect(rules.rules().map((rule) => rule.pattern)).toEqual(["two", "three"]);
    expect(rules.dropped).toBe(1);
  });
});
