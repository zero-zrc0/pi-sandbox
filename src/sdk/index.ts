import type { PermissionState } from "../contracts";
import type { JsonObject } from "../json";
import type {
  EffectiveNode,
  EffectiveNodeConfiguration,
  NodeResult,
} from "#approve-core/contracts";
import type { NodeHost, StepContext } from "#approve-core/runtime";

export interface ApprovalPermissionQuery {
  checkPermission(toolName: string, command?: string): {
    readonly state: PermissionState;
    readonly origin: string;
  };
  getToolPermission(toolName: string): PermissionState;
}

export type ApprovalNodeConfigView = EffectiveNodeConfiguration;

export interface ApprovalNodeContext {
  readonly id: string;
  readonly options: JsonObject;
  readonly config: ApprovalNodeConfigView;
  readonly permissions: ApprovalPermissionQuery;
}

export interface ApprovalNode {
  readonly apiVersion: "1";
  readonly id: string;
  evaluate(context: StepContext, host: NodeHost): NodeResult | Promise<NodeResult>;
}

export interface ApprovalNodeModule {
  readonly apiVersion: "1";
  createNode(context: ApprovalNodeContext): ApprovalNode | Promise<ApprovalNode>;
  dispose?(): void | Promise<void>;
}

export interface ApprovalNodeLoadPlan {
  readonly effectiveNodes: readonly EffectiveNode[];
  readonly nodeConfig: ApprovalNodeConfigView;
  readonly configDigest: string;
  readonly globalConfigDir: string;
  readonly projectConfigDir: string;
  readonly projectTrusted: boolean;
}

export function defineApprovalNode<T extends ApprovalNodeModule>(module: T): T {
  return module;
}
