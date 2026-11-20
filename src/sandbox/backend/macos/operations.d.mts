import type { ExecutionOperation, ExecutionPlan, ExecutionStartParameters } from "../../types";

export interface MacValidatedStart {
  readonly cwd: string;
  readonly environment: Readonly<Record<string, string>>;
  readonly operation: ExecutionOperation;
}

export interface MacFileOperationResult {
  readonly exitCode: number;
  readonly errorCode?: string;
  readonly error?: string;
  readonly dataBase64?: string;
}

export function validatePlan(plan: ExecutionPlan, start: ExecutionStartParameters): MacValidatedStart;
export function performFileOperation(operation: ExecutionOperation): MacFileOperationResult;
