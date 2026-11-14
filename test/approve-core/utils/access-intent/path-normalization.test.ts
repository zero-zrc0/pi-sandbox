import { describe, expect, it } from "vitest";
import { cleanPolicyLiteral } from "#approve-core/utils/access-intent/path-normalization";

const HOME = "/home/user";

describe("cleanPolicyLiteral", () => {
  it("applies the fixed order: trim, unquote once per end, drop @, expand home", () => {
    expect(cleanPolicyLiteral("  /a  ", HOME)).toBe("/a");
    expect(cleanPolicyLiteral("\"/a/b\"", HOME)).toBe("/a/b");
    expect(cleanPolicyLiteral("'/a/b'", HOME)).toBe("/a/b");
    expect(cleanPolicyLiteral("\"/a/b'", HOME)).toBe("/a/b");
    expect(cleanPolicyLiteral("@/a", HOME)).toBe("/a");
    expect(cleanPolicyLiteral("@@/a", HOME)).toBe("@/a");
    expect(cleanPolicyLiteral("~/x", HOME)).toBe(`${HOME}/x`);
  });

  it("keeps mismatched and interior quotes", () => {
    expect(cleanPolicyLiteral("''x''", HOME)).toBe("'x'");
    expect(cleanPolicyLiteral("a\"b\"c", HOME)).toBe("a\"b\"c");
  });
});
