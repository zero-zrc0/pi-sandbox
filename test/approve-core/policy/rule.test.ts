import { describe, expect, it } from "vitest";
import {
  createRuleEvaluator,
  representativeValueOf,
  type Rule,
  type RuleAction,
} from "#approve-core/policy/rule";
import { compileWildcard } from "#approve-core/policy/wildcard-matcher";
import {
  POSIX_PATH_FLAVOR as POSIX,
  WIN32_PATH_FLAVOR as WIN32,
} from "#approve-core/utils/path/path-flavor";

function rule(
  surface: string,
  pattern: string,
  action: RuleAction,
  extra: Partial<Rule> = {},
): Rule {
  return { surface, pattern, action, origin: "global", layer: "config", ...extra };
}

describe("rule order", () => {
  it("lets the last matching rule of a surface win", () => {
    const evaluator = createRuleEvaluator([
      rule("bash", "git *", "deny"),
      rule("bash", "git status", "allow"),
    ], POSIX);
    expect(evaluator.evaluate("bash", "git status").action).toBe("allow");
    expect(evaluator.evaluate("bash", "git push").action).toBe("deny");
  });

  it("never consults rules of another surface", () => {
    const evaluator = createRuleEvaluator([rule("tool", "*", "allow")], POSIX);
    expect(evaluator.evaluate("bash", "ls").origin).toBe("builtin");
  });

  it("matches the surface name exactly", () => {
    const evaluator = createRuleEvaluator([rule("Read", "*", "deny")], WIN32);
    expect(evaluator.evaluate("Read", "*").action).toBe("deny");
    expect(evaluator.evaluate("read", "*").action).toBe("ask");
  });
});

describe("candidate evaluation", () => {
  it("lets a later rule match an earlier candidate and reports that candidate", () => {
    const evaluator = createRuleEvaluator([
      rule("bash", "npm install", "deny"),
      rule("bash", "npm *", "allow"),
    ], POSIX);
    const match = evaluator.evaluateAnyValue("bash", ["npm install", "npm x"]);
    expect(match.rule.action).toBe("allow");
    expect(match.value).toBe("npm install");
  });

  it("reports the winning rule's first matching candidate, not the first candidate", () => {
    const evaluator = createRuleEvaluator([rule("bash", "git *", "deny")], POSIX);
    const match = evaluator.evaluateAnyValue("bash", ["ls", "git status"]);
    expect(match.value).toBe("git status");
  });

  it("falls back to * for an empty candidate list", () => {
    const evaluator = createRuleEvaluator([rule("bash", "*", "allow")], POSIX);
    const match = evaluator.evaluateAnyValue("bash", []);
    expect(match.value).toBe("*");
    expect(match.rule.action).toBe("allow");
  });
});

describe("no-match default", () => {
  it("synthesizes an ask default with builtin origin", () => {
    const evaluator = createRuleEvaluator([], POSIX);
    const ruleHit = evaluator.evaluate("bash", "ls");
    expect(ruleHit).toMatchObject({ action: "ask", origin: "builtin", layer: "default", pattern: "*" });
  });

  it("uses a provided default rule", () => {
    const evaluator = createRuleEvaluator([], POSIX, {
      defaultRule: rule("*", "*", "allow", { origin: "global", layer: "default" }),
    });
    expect(evaluator.evaluate("bash", "ls").action).toBe("allow");
  });
});

describe("compiled matcher reuse", () => {
  it("compiles each surface once and reuses matchers across calls", () => {
    const compiles: string[] = [];
    const evaluator = createRuleEvaluator([
      rule("bash", "git *", "deny"),
      rule("bash", "npm *", "allow"),
    ], POSIX, {
      compilePattern: (pattern, options) => {
        compiles.push(`${pattern}:${JSON.stringify(options)}`);
        return compileWildcard(pattern, options);
      },
    });
    evaluator.evaluate("bash", "git status");
    evaluator.evaluateAnyValue("bash", ["npm run"]);
    expect(compiles).toHaveLength(2);
  });

  it("keeps folded path matchers separate from plain text matchers", () => {
    const compiles: string[] = [];
    const evaluator = createRuleEvaluator([
      rule("path_read", "C:\\Temp\\*", "deny"),
      rule("bash", "git *", "allow"),
    ], WIN32, {
      compilePattern: (pattern, options) => {
        compiles.push(JSON.stringify(options));
        return compileWildcard(pattern, options);
      },
    });
    expect(evaluator.evaluate("path_read", "c:/temp/x").action).toBe("deny");
    expect(evaluator.evaluate("bash", "git x").action).toBe("allow");
    expect(compiles).toEqual([
      JSON.stringify(WIN32.wildcard),
      JSON.stringify({}),
    ]);
  });
});

describe("deny reachability probe", () => {
  it("is true only when every representative value is denied", () => {
    const fully = createRuleEvaluator([rule("path_read", "*", "deny")], POSIX);
    expect(fully.isSurfaceFullyDenied("path_read")).toBe(true);

    const withException = createRuleEvaluator([
      rule("path_read", "*", "deny"),
      rule("path_read", "/safe/*", "allow"),
    ], POSIX);
    expect(withException.isSurfaceFullyDenied("path_read")).toBe(false);
  });

  it("does not treat a partial deny pattern as full denial", () => {
    const evaluator = createRuleEvaluator([rule("path_read", "*.log", "deny")], POSIX);
    expect(evaluator.isSurfaceFullyDenied("path_read")).toBe(false);
  });

  it("reuses the compiled surface matchers for probing", () => {
    let compiles = 0;
    const evaluator = createRuleEvaluator([
      rule("path_read", "*", "deny"),
      rule("path_read", "/a/*", "deny"),
    ], POSIX, {
      compilePattern: (pattern, options) => {
        compiles += 1;
        return compileWildcard(pattern, options);
      },
    });
    evaluator.isSurfaceFullyDenied("path_read");
    evaluator.isSurfaceFullyDenied("path_read");
    expect(compiles).toBe(2);
  });

  it("derives a representative value that the pattern accepts", () => {
    expect(representativeValueOf("git *")).toBe("git x");
    expect(representativeValueOf("a?b")).toBe("axb");
  });
});
