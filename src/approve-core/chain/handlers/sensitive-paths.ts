/**
 * `sensitive-paths` — protected targets (v4 §2, priority 40).
 *
 * The sensitive families (`.git`, `.ssh`, `.aws`, `.env`, `*.pem`, cloud
 * credentials, database data directories) are restriction material: a write,
 * delete or upload of one is denied outright, because a human approval would
 * still hand the write to the same process the sandbox is trying to confine.
 *
 * A **read** of one is only an ask: reading `.env` to display it is different
 * from sending it somewhere, and the model resolver may approve that. Upload
 * counts as a write, not a read: it moves the secret out of the workspace.
 */
import type { ApprovalContext } from "../facts";
import type { Handler } from "../run";
import type { HandlerResult } from "../verdict";

export const SENSITIVE_PATHS_PRIORITY = 40;

export function createSensitivePathsHandler(): Handler {
  return Object.freeze({
    id: "builtin/sensitive-paths",
    priority: SENSITIVE_PATHS_PRIORITY,
    kind: "restriction" as const,
    evaluate: (context: ApprovalContext): HandlerResult => {
      const refs = context.unit.sensitive ?? [];
      if (refs.length === 0) return { action: "pass" };
      return sensitiveOpinion(refs);
    },
  });
}

function sensitiveOpinion(
  refs: NonNullable<ApprovalContext["unit"]["sensitive"]>,
): HandlerResult {
  const mutating = refs.find((ref) => ref.surface !== "read");
  if (mutating !== undefined) {
    return {
      action: "deny",
      reason: `sensitive:${mutating.category}:${mutating.surface}:${mutating.path}`,
    };
  }
  const first = refs[0];
  return {
    action: "ask",
    reason: `sensitive:${first.category}:read:${first.path}`,
  };
}
