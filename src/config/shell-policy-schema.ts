import { z } from "zod";
import { nonEmptyStringSchema, positiveIntegerSchema } from "#config/config-schema";
import { PERMISSION_MODES } from "#config/permission-mode";

export const SHELL_POLICY_NODES = [
  "builtin/powershell",
  "builtin/external-command",
] as const;

export const SHELL_LANGUAGES = ["bash", "powershell"] as const;

export const SHELL_EFFECTS = [
  "file.read",
  "file.create",
  "file.write",
  "file.delete",
  "network",
  "process.spawn",
  "system",
] as const;
type ShellEffect = (typeof SHELL_EFFECTS)[number];

const shellPolicyNodeSchema = z.enum(SHELL_POLICY_NODES);
const shellLanguageSchema = z.enum(SHELL_LANGUAGES);
const shellEffectSchema = z.enum(SHELL_EFFECTS);
const pathListSchema = z.array(nonEmptyStringSchema).min(1);
const stringListSchema = z.array(nonEmptyStringSchema).min(1);
const argumentListSchema = z.array(z.string()).min(1);
const modeListSchema = z.array(z.enum(PERMISSION_MODES)).min(1);
const reviewDecisionSchema = z.enum(["ask", "deny"]);
const fullAccessDecisionSchema = z.enum(["allow", "ask", "deny"]);

const targetConstraintSchema = z.strictObject({
  allWithin: pathListSchema.optional(),
  allOutside: pathListSchema.optional(),
}).refine((value) => value.allWithin !== undefined || value.allOutside !== undefined);

const networkDestinationSchema = z.strictObject({
  host: nonEmptyStringSchema,
  port: z.number().int().min(1).max(65535).optional(),
});

const networkConstraintSchema = z.strictObject({
  destinations: z.strictObject({ allIn: z.array(networkDestinationSchema).min(1) }),
});

const conditionLeafSchemas = {
  program: nonEmptyStringSchema.optional(),
  executable: z.strictObject({ path: nonEmptyStringSchema }).optional(),
  args: z.strictObject({
    exact: argumentListSchema.optional(),
    prefix: argumentListSchema.optional(),
    contains: argumentListSchema.optional(),
    excludes: argumentListSchema.optional(),
  }).refine((value) => Object.values(value).some((entry) => entry !== undefined)).optional(),
  options: z.strictObject({
    present: stringListSchema.optional(),
    absent: stringListSchema.optional(),
  }).refine((value) => Object.values(value).some((entry) => entry !== undefined)).optional(),
  effects: z.strictObject({
    only: z.array(shellEffectSchema).min(1).optional(),
    hasAny: z.array(shellEffectSchema).min(1).optional(),
  }).refine((value) => Object.values(value).some((entry) => entry !== undefined)).optional(),
  targets: z.strictObject({
    fileReads: targetConstraintSchema.optional(),
    fileWrites: targetConstraintSchema.optional(),
    fileDeletes: targetConstraintSchema.optional(),
  }).refine((value) => Object.values(value).some((entry) => entry !== undefined)).optional(),
  network: networkConstraintSchema.optional(),
  dynamicExecution: z.boolean().optional(),
  processSpawn: z.boolean().optional(),
} as const;

export interface ShellCondition {
  all?: ShellCondition[];
  any?: ShellCondition[];
  not?: ShellCondition;
  program?: string;
  executable?: { path: string };
  args?: { exact?: string[]; prefix?: string[]; contains?: string[]; excludes?: string[] };
  options?: { present?: string[]; absent?: string[] };
  effects?: { only?: (typeof SHELL_EFFECTS)[number][]; hasAny?: (typeof SHELL_EFFECTS)[number][] };
  targets?: {
    fileReads?: { allWithin?: string[]; allOutside?: string[] };
    fileWrites?: { allWithin?: string[]; allOutside?: string[] };
    fileDeletes?: { allWithin?: string[]; allOutside?: string[] };
  };
  network?: { destinations: { allIn: { host: string; port?: number }[] } };
  dynamicExecution?: boolean;
  processSpawn?: boolean;
}

export const shellConditionSchema: z.ZodType<ShellCondition> = z.lazy(() =>
  z.strictObject({
    all: z.array(shellConditionSchema).min(1).optional(),
    any: z.array(shellConditionSchema).min(1).optional(),
    not: shellConditionSchema.optional(),
    ...conditionLeafSchemas,
  }).refine((value) => Object.keys(value).length > 0) as z.ZodType<ShellCondition>,
);

const shellRuleScopeSchema = z.strictObject({
  tools: stringListSchema.optional(),
  shells: z.array(shellLanguageSchema).min(1).optional(),
  modes: modeListSchema.optional(),
  cwd: z.strictObject({ within: pathListSchema }),
}).partial();

export const shellPolicyRuleSchema = z.strictObject({
  id: nonEmptyStringSchema,
  node: shellPolicyNodeSchema,
  scope: shellRuleScopeSchema.optional(),
  when: shellConditionSchema,
  then: z.strictObject({
    decision: z.enum(["allow", "ask", "deny"]),
    reason: nonEmptyStringSchema.optional(),
  }),
});

const shellModeExceptionSchema = z.strictObject({
  ruleId: nonEmptyStringSchema,
  effects: z.array(shellEffectSchema).min(1),
});

const restrictedModePolicySchema = z.strictObject({
  unmatched: reviewDecisionSchema.optional(),
  uncertain: reviewDecisionSchema.optional(),
  /**
   * Approval default for ordinary sandbox calls: `ask` enables strict approval;
   * `sandbox-run` allows unresolved effects only with a valid sandbox receipt.
   * A project may tighten the trusted global value to `ask`.
   */
  defaultPolicy: z.enum(["ask", "sandbox-run"]).optional(),
});

const readOnlyModePolicySchema = z.strictObject({
  unmatched: reviewDecisionSchema.optional(),
  uncertain: reviewDecisionSchema.optional(),
  forbidEffects: z.array(shellEffectSchema).optional(),
  exceptions: z.array(shellModeExceptionSchema).optional(),
});

const fullAccessModePolicySchema = z.strictObject({
  unmatched: fullAccessDecisionSchema.optional(),
  uncertain: fullAccessDecisionSchema.optional(),
});

export const shellModePoliciesSchema = z.strictObject({
  "read-only": readOnlyModePolicySchema.optional(),
  default: restrictedModePolicySchema.optional(),
  "auto-review": restrictedModePolicySchema.optional(),
  "full-access": fullAccessModePolicySchema.optional(),
});

export const shellAnalysisLimitsSchema = z.strictObject({
  timeoutMs: positiveIntegerSchema.optional(),
  maxInputBytes: positiveIntegerSchema.optional(),
  maxOutputBytes: positiveIntegerSchema.optional(),
  maxAstNodes: positiveIntegerSchema.optional(),
  maxDepth: positiveIntegerSchema.optional(),
});

export type ShellAnalysisLimits = z.infer<typeof shellAnalysisLimitsSchema>;
export type ShellModePolicies = z.infer<typeof shellModePoliciesSchema>;

function hasGuaranteedCondition(
  condition: ShellCondition,
  matches: (condition: ShellCondition) => boolean,
): boolean {
  if (matches(condition)) return true;
  const guaranteedByAll = condition.all?.some((child) => hasGuaranteedCondition(child, matches)) ?? false;
  const guaranteedByAny = condition.any?.every((child) => hasGuaranteedCondition(child, matches)) ?? false;
  return guaranteedByAll || guaranteedByAny;
}

function isConcreteExceptionPath(path: string): boolean {
  if (/[?*]/u.test(path)) return false;
  return !path.includes("${") || /^\$\{(?:workspace|tempDir)\}(?:[\\/].*)?$/u.test(path);
}

function hasConcreteWithinTarget(
  condition: ShellCondition,
  key: "fileReads" | "fileWrites" | "fileDeletes",
): boolean {
  const roots = condition.targets?.[key]?.allWithin;
  return roots !== undefined && roots.length > 0 && roots.every(isConcreteExceptionPath);
}

function isScopedReadOnlyException(
  rule: z.infer<typeof shellPolicyRuleSchema>,
  effects: readonly ShellEffect[],
): boolean {
  if (rule.scope?.modes?.length !== 1 || rule.scope.modes[0] !== "read-only") return false;
  const effectBound = hasGuaranteedCondition(rule.when, (condition) => {
    const permitted = condition.effects?.only;
    return permitted !== undefined &&
      permitted.every((effect) => effects.includes(effect)) &&
      effects.every((effect) => permitted.includes(effect));
  });
  if (!effectBound) return false;

  const pathTarget: Partial<Record<ShellEffect, "fileReads" | "fileWrites" | "fileDeletes">> = {
    "file.read": "fileReads",
    "file.create": "fileWrites",
    "file.write": "fileWrites",
    "file.delete": "fileDeletes",
  };
  return effects.every((effect) => {
    if (effect === "network") {
      return hasGuaranteedCondition(rule.when, (condition) =>
        (condition.network?.destinations.allIn.length ?? 0) > 0);
    }
    const key = pathTarget[effect];
    return key !== undefined && hasGuaranteedCondition(rule.when, (condition) =>
      hasConcreteWithinTarget(condition, key));
  });
}

export const shellPolicySchema = z.strictObject({
  version: z.literal(1),
  analysis: shellAnalysisLimitsSchema.optional(),
  modes: shellModePoliciesSchema.optional(),
  rules: z.array(shellPolicyRuleSchema).default([]),
}).superRefine((policy, context) => {
  const rules = new Map<string, z.infer<typeof shellPolicyRuleSchema>>();
  policy.rules.forEach((rule, index) => {
    if (rules.has(rule.id)) {
      context.addIssue({
        code: "custom",
        path: ["rules", index, "id"],
        message: `duplicate shell policy rule id: ${rule.id}`,
      });
    } else {
      rules.set(rule.id, rule);
    }
  });

  const exceptions = policy.modes?.["read-only"]?.exceptions ?? [];
  const readOnlyForbid = new Set([
    "file.create", "file.write", "file.delete", "network",
    ...(policy.modes?.["read-only"]?.forbidEffects ?? []),
  ]);
  exceptions.forEach((exception, index) => {
    const rule = rules.get(exception.ruleId);
    if (rule === undefined || rule.then.decision !== "allow") {
      context.addIssue({
        code: "custom",
        path: ["modes", "read-only", "exceptions", index, "ruleId"],
        message: "read-only exceptions must reference an allow rule in this shell policy",
      });
      return;
    }
    if (exception.effects.some((effect) => !readOnlyForbid.has(effect)) ||
        !isScopedReadOnlyException(rule, exception.effects)) {
      context.addIssue({
        code: "custom",
        path: ["modes", "read-only", "exceptions", index],
        message: "read-only exceptions require a read-only-only allow rule with matching effects and concrete targets",
      });
    }
  });
});

export type ShellPolicy = z.infer<typeof shellPolicySchema>;
export type ShellPolicyRule = z.infer<typeof shellPolicyRuleSchema>;
