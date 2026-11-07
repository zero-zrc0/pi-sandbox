/**
 * Shared execution configuration (specs/config-schema.md §6).
 *
 * Built-in tools use the sandbox network ceiling. Experimental MCP sandboxing
 * uses the same ceiling only when explicitly enabled. Shell calls may declare
 * additional filesystem and network grants. The published JSON Schema is
 * derived from these declarations.
 */
import { z } from "zod";
import { nonEmptyStringSchema } from "./config-schema";

/** The two filesystem grant granularities. */
export const GRANT_GRANULARITIES = ["file", "directory"] as const;

/** One filesystem grant: an exact path and whether it names a file or a directory. */
export const filesystemGrantSchema = z.strictObject({
  path: nonEmptyStringSchema,
  granularity: z.enum(GRANT_GRANULARITIES),
});

/** Filesystem reach. Both directions are required and may be empty. */
export const executionFilesystemPermissionsSchema = z.strictObject({
  read: z.array(filesystemGrantSchema),
  write: z.array(filesystemGrantSchema),
});

/** Ports used when an allowlist destination omits its port. */
export const DEFAULT_NETWORK_PORTS = [80, 443] as const;

/** One allowed network destination. An omitted port means HTTP and HTTPS; "any" means every port. */
export const networkDestinationSchema = z.strictObject({
  host: nonEmptyStringSchema,
  port: z.union([z.number().int().min(1).max(65535), z.literal("any")]).optional(),
});

/** Network reach: none, everything, or an explicit allowlist. */
export const networkScopeSchema = z.discriminatedUnion("mode", [
  z.strictObject({ mode: z.literal("none") }),
  z.strictObject({ mode: z.literal("all") }),
  z.strictObject({
    mode: z.literal("allowlist"),
    allow: z.array(networkDestinationSchema).min(1),
  }),
]);

/** Additional filesystem and network permissions available to shell calls. */
export const shellExecutionPermissionsSchema = z.strictObject({
  filesystem: executionFilesystemPermissionsSchema,
  network: networkScopeSchema,
});

/** Shared execution network plus optional shell-specific grants. */
export const executionConfigSchema = z.strictObject({
  network: networkScopeSchema.optional(),
  shell: shellExecutionPermissionsSchema.optional(),
});

export type NetworkScope = z.infer<typeof networkScopeSchema>;
export type ExecutionConfig = z.infer<typeof executionConfigSchema>;
export type ShellExecutionPermissions = z.infer<typeof shellExecutionPermissionsSchema>;
