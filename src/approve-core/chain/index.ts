/**
 * The approval responsibility chain (v4 §1).
 *
 * Public surface: the contract types, the composition rules, the runner and the
 * built-in links. The chain is pure: it reads frozen facts and returns a verdict,
 * it never executes a tool, reads a file, or writes unit state.
 */
export {
  allowVerdict,
  askVerdict,
  composeVerdict,
  denyVerdict,
  isHandlerResult,
  isResolverEligible,
  NO_VERDICT,
  strongerAskTarget,
  strongestVerdict,
  unknownVerdict,
} from "./verdict";
export type {
  AskTarget,
  ComposeOutcome,
  Decision,
  HandlerKind,
  HandlerResult,
  Verdict,
  VerdictState,
} from "./verdict";

export type {
  ApprovalContext,
  ChainCallFacts,
  ChainChannel,
  ChainUnitFacts,
  SensitiveRef,
  SensitiveSurface,
  UnitAccessFact,
  UnitAccessKind,
  UnitRuleFact,
} from "./facts";

export { combineCall, orderHandlers, runChain } from "./run";
export type {
  CallVerdict,
  ChainFault,
  ChainOutcome,
  ChainStep,
  Handler,
  OrderHandlersFailure,
  OrderHandlersResult,
  UnitVerdict,
} from "./run";

export { decideCall } from "./decide";
export type { DecideOptions, DecideResult } from "./decide";

export { createDefaultChainHandlers } from "./defaults";

export { createDangerIntentHandler, DANGER_INTENT_PRIORITY } from "./handlers/danger-intent";
export {
  createExplicitRuleGrantHandler,
  createExplicitRuleRestrictionHandler,
  EXPLICIT_RULE_GRANT_PRIORITY,
  EXPLICIT_RULE_RESTRICTION_PRIORITY,
} from "./handlers/explicit-rules";
export { createFallbackHandler, FALLBACK_PRIORITY } from "./handlers/fallback";
export { createModeBaseHandler, MODE_BASE_PRIORITY } from "./handlers/mode-base";
export { createSensitivePathsHandler, SENSITIVE_PATHS_PRIORITY } from "./handlers/sensitive-paths";
