import type { SHELL_EFFECTS } from "#config/shell-policy-schema";

export type ShellLanguage = "bash" | "powershell";
export type ShellEffect = (typeof SHELL_EFFECTS)[number];

export type Knowledge<T> =
  | { readonly status: "known"; readonly value: T }
  | { readonly status: "unknown"; readonly reason: string };

export interface ExecutableIdentity {
  readonly name: string;
  readonly path: Knowledge<string>;
}

export interface SourceExtent {
  readonly start: number;
  readonly end: number;
}

export interface ProgramInvocation {
  readonly operationId: string;
  readonly unitId: string;
  readonly shell: ShellLanguage;
  readonly program: Knowledge<string>;
  readonly executable: Knowledge<ExecutableIdentity>;
  readonly argv: Knowledge<readonly string[]>;
  readonly cwd: Knowledge<string>;
  readonly extent: SourceExtent;
}

export interface FileTargetFact {
  readonly path: string;
  readonly effect: "file.read" | "file.create" | "file.write" | "file.delete";
}

export interface NetworkTargetFact {
  readonly host: string;
  readonly port?: number;
}

export interface ShellOperationFact {
  readonly operationId: string;
  readonly unitId: string;
  readonly owner: "powershell" | "external-command" | "shell";
  readonly effects: Knowledge<readonly ShellEffect[]>;
  readonly fileTargets: Knowledge<readonly FileTargetFact[]>;
  readonly networkTargets: Knowledge<readonly NetworkTargetFact[]>;
  readonly dynamicExecution?: Knowledge<boolean>;
  readonly processSpawn?: Knowledge<boolean>;
  readonly complete: boolean;
  readonly source: "powershell-parser" | "bash-parser" | "program-adapter" | "runtime" | "unknown";
}
