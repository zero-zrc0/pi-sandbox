import { describe, expect, it } from "vitest";
import { coreCommandEffect } from "#approve-core/utils/access-intent/bash/command-effects";
import type { CommandWord } from "#approve-core/utils/access-intent/bash/wrapper-analysis";

function words(...values: string[]): CommandWord[] {
  return values.map((value) => ({ value, computed: false, mayLeadWithDash: value.startsWith("-") }));
}

describe("core command effects", () => {
  it("proves bare readers but does not trust a path-qualified executable", () => {
    expect(coreCommandEffect(words("cat", "file"))).toBe("read");
    expect(coreCommandEffect(words("/tmp/cat", "file"))).toBeUndefined();
  });

  it("withdraws the proof when sort requests an output file", () => {
    expect(coreCommandEffect(words("sort", "--out=result", "input"))).toBe("unknown");
    expect(coreCommandEffect(words("sort", "input"))).toBe("read");
  });

  it("withdraws find and fd proofs for execution or file-writing options", () => {
    expect(coreCommandEffect(words("find", ".", "-exec", "rm", "{}", ";"))).toBe("unknown");
    expect(coreCommandEffect(words("find", ".", "-fprint0", "output"))).toBe("unknown");
    expect(coreCommandEffect(words("fd", "--exec-batch", "rm"))).toBe("unknown");
    expect(coreCommandEffect(words("fd", "pattern"))).toBe("read");
  });

  it("uses the awk program proof for core effects", () => {
    expect(coreCommandEffect(words("awk", "{print $1}", "input"))).toBe("read");
    expect(coreCommandEffect(words("awk", "{system(x)}", "input"))).toBe("unknown");
  });

  it("uses the sed program proof for core effects", () => {
    expect(coreCommandEffect(words("sed", "-n", "p", "input"))).toBe("read");
    expect(coreCommandEffect(words("sed", "w output", "input"))).toBe("unknown");
  });
});
