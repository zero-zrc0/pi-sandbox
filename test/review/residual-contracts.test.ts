import { describe, expect, it } from "vitest";
import { PermissionManager } from "#approve-core/policy/permission-manager";
import { PermissionResolver } from "#approve-core/policy/permission-resolver";
import { PermissionService } from "#approve-core/policy/permissions-service";
import { SessionRuleStore } from "#approve-core/policy/session-rules";
import { BashProgram } from "#approve-core/utils/access-intent/bash/program";
import type { BashCommand } from "#approve-core/utils/access-intent/bash/command-enumeration";
import { POSIX_PATH_FLAVOR } from "#approve-core/utils/path/path-flavor";
import { PathNormalizer } from "#approve-core/utils/path/path-normalizer";

describe("mixed advisory unit input", () => {
  it.each<readonly (BashCommand | string)[]>([
    [{ text: "printf first" }, "printf second"],
    ["printf first", { text: "printf second" }],
  ])("preserves a later explicit denial for units %j and %j", async (first, second) => {
    const session = new SessionRuleStore({ flavor: POSIX_PATH_FLAVOR });
    const manager = new PermissionManager({
      flavor: POSIX_PATH_FLAVOR,
      session,
      loadPolicy: () => ({
        stamp: "mixed-input",
        scopes: { global: { permission: { bash: { "*": "allow", "printf second": "deny" } } } },
      }),
    });
    const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/workspace");
    const resolver = new PermissionResolver({ manager, normalizer });
    const service = new PermissionService({
      manager, resolver, normalizer, session,
      bash: { units: () => [first, second] },
    });
    expect(service.checkBash("printf first; printf second")).toMatchObject({ state: "deny", bashAnalysis: "incomplete" });
    await BashProgram.parse("printf first; printf second", normalizer);
    expect(service.checkBash("printf first; printf second")).toMatchObject({ state: "deny", bashAnalysis: "incomplete" });
  });
});
