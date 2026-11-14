/**
 * The built-in chain in the order v4 §2 documents.
 *
 * Kept as one function so every caller sees the same order and the same kinds:
 * the host's decision node, the tests and (later) the user-handler loader all
 * start from this list and only insert their own links around it.
 */
import { createDangerIntentHandler } from "./handlers/danger-intent";
import { createExplicitRuleGrantHandler, createExplicitRuleRestrictionHandler } from "./handlers/explicit-rules";
import { createFallbackHandler } from "./handlers/fallback";
import { createModeBaseHandler } from "./handlers/mode-base";
import { createSensitivePathsHandler } from "./handlers/sensitive-paths";
import type { Handler } from "./run";

/**
 * Built-in links only. Optional links (assessment, session grants, the C2
 * sandbox default run) are appended by the host once their facts exist, because
 * they need capabilities a pure chain does not have.
 */
export function createDefaultChainHandlers(): readonly Handler[] {
  return [
    createModeBaseHandler(),
    createExplicitRuleRestrictionHandler(),
    createExplicitRuleGrantHandler(),
    createDangerIntentHandler(),
    createSensitivePathsHandler(),
    createFallbackHandler(),
  ];
}
