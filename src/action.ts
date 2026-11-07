import type { ToolAnnotations, ToolNamespace } from "@earendil-works/pi-coding-agent";
import type { PermissionState } from "#approve-core/policy/normalize";
import type { ToolAccessScopeAccess } from "#approve-core/utils/tool-access/assessment";

export interface PermissionScope {
  readonly id: string;
  readonly surface: string;
  readonly target: string;
  readonly access: ToolAccessScopeAccess;
  readonly state: PermissionState;
  readonly source?: string;
}

export interface RegisteredToolFacts {
  readonly name: string;
  readonly origin: string;
  readonly revision: string;
  readonly description: string;
  readonly parameters: Readonly<Record<string, unknown>>;
  readonly annotations?: ToolAnnotations;
  readonly namespace?: ToolNamespace;
}
