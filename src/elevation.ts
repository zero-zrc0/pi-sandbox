export interface ToolElevation {
  readonly tier: "default" | "host";
  readonly scope: readonly { readonly path: string; readonly access: "read" | "write" }[];
}

export interface ExecutionRequest {
  readonly reason: string;
  readonly elevation: ToolElevation;
}
