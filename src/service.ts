import type { PermissionCheckResult, PermissionState } from "./contracts";

export type { PermissionCheckResult, PermissionState } from "./contracts";
export type { ToolBindingDeclaration } from "#config/tool-binding-schema";

export type ToolInputFormatter = (input: unknown) => string | undefined;

export interface PermissionQuery {
  checkPermission(toolName: string, input?: unknown): PermissionCheckResult;
  getToolPermission(toolName: string): PermissionState;
}

export interface PermissionsService extends PermissionQuery {}

const registryKey = Symbol.for("pi-sandbox.permissions-service.v1");
const registryHost = globalThis as typeof globalThis & { [registryKey]?: Map<string, PermissionsService> };
const services = registryHost[registryKey] ??= new Map<string, PermissionsService>();

export function publishPermissionsService(sessionId: string, service: PermissionsService): void {
  services.set(sessionId, service);
}

export function unpublishPermissionsService(sessionId: string): void {
  services.delete(sessionId);
}

export function getPermissionsService(sessionId: string): PermissionsService | undefined {
  return services.get(sessionId);
}
