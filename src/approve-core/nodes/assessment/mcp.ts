import type { RegisteredToolFacts } from "../../../action";
import type { LocalAssessment } from "#approve-core/nodes/assessment/types";

/**
 * The MCP annotation facts, in their original three-state form (design §40.4).
 *
 * `true`, `false`, and `undefined` stay distinct: an undeclared hint is not a
 * `false` one, and no hint is ever filled in from a tool's name.
 */
export type McpAnnotations = RegisteredToolFacts["annotations"];

export interface McpAssessmentInput {
  readonly annotations?: McpAnnotations;
  /**
   * Host-known conflicts: argument or capability facts that contradict a
   * read-only claim (a publish, a bulk edit, an off-host send, a restricted
   * target). A non-empty list keeps the call in review.
   */
  readonly conflicts?: readonly string[];
}

/**
 * Apply design §40.4's annotation table to one MCP call.
 *
 * Order matters: `destructiveHint=true` prevails even beside
 * `readOnlyHint=true`; `idempotentHint` appears in no branch, so it can never
 * waive review nor authorize a retry. The result is only ever `run` or
 * `review` — a local annotation default is not a user authorization
 * (design §40.4).
 */
export function assessMcpAnnotations(
  input: McpAssessmentInput,
): LocalAssessment {
  if (input.conflicts !== undefined && input.conflicts.length > 0) {
    return {
      route: "review",
      cause: "mcp-conflict",
      reason: `mcp-conflict:${input.conflicts.join(",")}`,
      modelRequests: 0,
    };
  }

  const annotations = input.annotations;
  const destructive = annotations?.destructiveHint;
  const readOnly = annotations?.readOnlyHint;
  const openWorld = annotations?.openWorldHint;

  if (destructive === true) {
    return {
      route: "review",
      cause: "mcp-annotations",
      reason: "destructive-hint",
      modelRequests: 0,
    };
  }

  if (readOnly === true) {
    return {
      route: "run",
      cause: "mcp-annotations",
      reason: "read-only-hint",
      modelRequests: 0,
    };
  }

  if (destructive === false && openWorld === false) {
    return {
      route: "run",
      cause: "mcp-annotations",
      reason: "non-destructive-closed-hint",
      modelRequests: 0,
    };
  }

  return {
    route: "review",
    cause: "mcp-annotations",
    reason: "annotations-missing-or-unknown",
    modelRequests: 0,
  };
}
