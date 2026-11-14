/**
 * The local (first-stage) assessment contract: the side-effect-free result of
 * judging one bound tool call against explicit rules and the tool-specific
 * default policies in design §19/§35/§40.4.
 *
 * It is deliberately separate from the frozen shared `ToolAssessment` in
 * `../contracts.ts`: that contract still carries only run/review/block, so a
 * technical failure has nowhere to live in it. A local assessment can defer,
 * and this module says so with its own result type rather than by overloading
 * `block` with a timeout or a parser crash (design §40.1).
 */
import type {
  ToolExecutionBinding,
  ToolInvocationSeed,
} from "../../../invocation";

/**
 * What the local assessment decided.
 *
 * - `run` — every necessary scope is settled and execution may proceed under
 *   the already-bound scope, with no model decision.
 * - `review` — a decision (or the explicit rule that asked) still stands.
 * - `block` — current policy forbids the call.
 * - `defer` — the facts, or a capability the answer needs, could not be proven.
 *   Never an allow.
 */
export type AssessmentRoute = "run" | "review" | "block" | "defer";

/**
 * Why the local assessment reached its route. Named rather than a free string
 * so a caller can assert the kind of evidence behind a route without pinning
 * the whole reason text.
 */
export type AssessmentCause =
  | "all-gates-allow"
  | "explicit-rule"
  | "not-default-eligible"
  | "synthetic-floor"
  | "shell-default-policy"
  | "shell-risk"
  | "mcp-annotations"
  | "mcp-conflict"
  | "capability-unavailable"
  | "incomplete-facts"
  | "unknown-tool";

/**
 * One local assessment of one call.
 *
 * `modelRequests` is always `0`: this module never builds reviewer context nor
 * sends a model request (design §40.7's separate counters).
 */
export interface LocalAssessment {
  readonly route: AssessmentRoute;
  readonly cause: AssessmentCause;
  readonly reason: string;
  readonly modelRequests: 0;
}

/** The immutable invocation facts a host capability must bind its proof to. */
export interface AssessmentInvocationSnapshot {
  readonly invocation: ToolInvocationSeed;
  /** Digest of the full invocation plus the effective Shell interpretation. */
  readonly actionDigest: string;
  readonly shell?: {
    readonly language: "bash" | "unknown";
    readonly command: string;
    readonly workdir: string | null;
  };
}

export type BoundAssessmentExecution = Extract<
  ToolExecutionBinding,
  { readonly status: "bound" }
>;

/** Conflicts checked against a particular captured MCP registration/action. */
export interface McpConflictFacts {
  readonly actionDigest: string;
  readonly toolName: string;
  readonly registrationRevision: string;
  readonly conflicts: readonly string[];
}

/**
 * The host-probed facts a shell default policy needs before it may run.
 *
 * The plugin never asserts a sandbox exists: an absent or unsatisfied
 * capability turns a would-be `run` into `defer`, never into an allow
 * (design §35.1, §40.5).
 */
export interface ShellSandboxCapability {
  readonly available: boolean;
  /** True only when the sandbox can enforce every limit the call needs. */
  readonly enforcesAllLimits: boolean;
  /** A host-owned name for the boundary actually enforced. */
  readonly boundary: string;
  /** The exact immutable action and scope covered by this host proof. */
  readonly actionDigest: string;
  readonly executionBinding: BoundAssessmentExecution;
  readonly reason?: string;
}

/** The host's proof that this MCP call reaches the captured registered tool. */
export interface McpExecutionCapability {
  readonly actionDigest: string;
  readonly executionBinding: BoundAssessmentExecution;
}

/**
 * The capabilities a host exposes to local assessment.
 *
 * Supplying the object opts the host into local assessment. `preEvaluate`
 * requires an action-bound execution proof for each default-run path. Real
 * production wires none of this yet, so calls without a provider keep the
 * pre-existing conservative behavior.
 */
export interface AssessmentCapabilities {
  readonly shellSandbox?: ShellSandboxCapability;
  readonly mcpExecution?: McpExecutionCapability;
}
