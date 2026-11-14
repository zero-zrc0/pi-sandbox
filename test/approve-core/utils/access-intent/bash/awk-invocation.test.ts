import { describe, expect, it } from "vitest";
import { isReadOnlyAwk } from "#approve-core/utils/access-intent/bash/awk-invocation";
import type { CommandWord } from "#approve-core/utils/access-intent/bash/wrapper-analysis";

function words(...values: string[]): CommandWord[] {
  return values.map((value) => ({ value, computed: false, mayLeadWithDash: value.startsWith("-") }));
}

describe("awk read-only proof", () => {
  it("accepts a simple program and rejects possible output redirection", () => {
    expect(isReadOnlyAwk(words("{ print $1 }", "input"))).toBe(true);
    expect(isReadOnlyAwk(words('{ print $1 > "file" }', "input"))).toBe(false);
  });

  it("consumes field separator and variable options before the program", () => {
    expect(isReadOnlyAwk(words("-F", ":", "-v", "x=1", "{ print $1 }", "input"))).toBe(true);
    expect(isReadOnlyAwk(words("-F:", "-vx=1", "{ system(x) }"))).toBe(false);
  });

  it("rejects missing programs, unsupported options, and computed arguments", () => {
    expect(isReadOnlyAwk(words("-F", ":"))).toBe(false);
    expect(isReadOnlyAwk(words("-f", "script.awk", "input"))).toBe(false);
    expect(isReadOnlyAwk([{ value: "{print $1}", computed: true, mayLeadWithDash: false }])).toBe(false);
  });
});
