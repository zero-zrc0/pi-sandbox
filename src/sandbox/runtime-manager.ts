import { realpathSync } from "node:fs";
import { join } from "node:path";
import type { RuntimeCatalog, RuntimeResourceEntry } from "./runtime-catalog";
import { installRuntimeEntry } from "./runtime-installation";
import { scanInstalledRuntimes, validateInstalledRuntime, type ResolvedRuntimeFiles } from "./runtime-store";
import { compareRuntimeVersions, selectRuntime } from "./runtime-selection";
import type { RuntimeDownloadProgress } from "./runtime-download";
import { isPathWithin } from "./path";
import { basename, dirname } from "node:path";

export type SandboxRuntimeState =
  | { readonly status: "disabled" }
  | { readonly status: "preparing"; readonly progress?: RuntimeDownloadProgress }
  | { readonly status: "ready"; readonly runtime: ResolvedRuntimeFiles }
  | { readonly status: "unavailable"; readonly reason: string };

export interface RuntimeProbeResult {
  readonly available: boolean;
  readonly reason?: string;
}

export interface SandboxRuntimeManagerOptions {
  readonly pluginRoot: string;
  readonly catalog: RuntimeCatalog;
  readonly platform: string;
  readonly arch: string;
  readonly pluginVersion: string;
  readonly protocolVersion: number;
  readonly probe: (runtime: ResolvedRuntimeFiles, input: { readonly signal: AbortSignal; readonly workspaceRoot: string }) => Promise<RuntimeProbeResult>;
  readonly fetch?: typeof fetch;
}

export class SandboxRuntimeManager {
  private stateValue: SandboxRuntimeState = { status: "disabled" };
  private generation = 0;
  private controller: AbortController | undefined;
  private pending: Promise<SandboxRuntimeState> | undefined;

  constructor(private readonly options: SandboxRuntimeManagerOptions) {}

  state(): SandboxRuntimeState {
    return this.stateValue;
  }

  async disable(): Promise<SandboxRuntimeState> {
    const pending = this.pending;
    this.generation += 1;
    this.controller?.abort();
    this.controller = undefined;
    this.pending = undefined;
    this.stateValue = { status: "disabled" };
    await pending?.catch(() => undefined);
    return this.stateValue;
  }

  prepare(input: {
    readonly workspaceRoot: string;
    readonly signal?: AbortSignal;
    readonly confirmDownload?: (release: RuntimeResourceEntry) => Promise<boolean>;
    readonly onProgress?: (progress: RuntimeDownloadProgress) => void;
  }): Promise<SandboxRuntimeState> {
    if (this.pending) return this.pending;
    const generation = ++this.generation;
    const controller = new AbortController();
    this.controller = controller;
    const signal = input.signal === undefined
      ? controller.signal
      : AbortSignal.any([controller.signal, input.signal]);
    this.stateValue = { status: "preparing" };
    const run = async (): Promise<SandboxRuntimeState> => {
      try {
        if (this.options.platform !== "linux" && this.options.platform !== "win32") {
          throw new Error(`OS sandbox is unsupported on ${this.options.platform}`);
        }
        if (this.options.arch !== "x64" && this.options.arch !== "arm64") {
          throw new Error(`OS sandbox is unsupported on ${this.options.platform}/${this.options.arch}`);
        }
        const pluginRoot = realpathSync(this.options.pluginRoot);
        const workspaceRoot = realpathSync(input.workspaceRoot);
        if (isPathWithin(workspaceRoot, pluginRoot)) {
          throw new Error("trusted runtime installation is inside the restricted workspace");
        }
        const scan = scanInstalledRuntimes({
          pluginRoot,
          platform: this.options.platform,
          arch: this.options.arch,
          catalog: this.options.catalog,
        });
        const selected = selectRuntime({
          platform: this.options.platform,
          arch: this.options.arch,
          pluginVersion: this.options.pluginVersion,
          protocolVersion: this.options.protocolVersion,
          installed: scan.candidates,
          releases: this.options.catalog.runtimes,
        });
        let runtime: ResolvedRuntimeFiles;
        if (selected.kind === "unavailable") {
          const problem = scan.problems[0];
          throw new Error(problem
            ? `runtime directory ${problem.directory} is invalid: ${problem.reason}`
            : `${selected.reason}; manual runtime directory: ${join(pluginRoot, "runtimes", "<runtime-version>", `${this.options.platform}-${this.options.arch}`)}`);
        }
        const selectedVersion = selected.kind === "installed" ? selected.runtime.version : selected.release.version;
        const invalidNewerDirectory = scan.problems.find(problem => {
          const name = basename(problem.directory);
          const version = name === `${this.options.platform}-${this.options.arch}`
            ? basename(dirname(problem.directory))
            : name;
          const order = compareRuntimeVersions(version, selectedVersion);
          return order === undefined || order >= 0;
        });
        if (invalidNewerDirectory) {
          throw new Error(`runtime directory ${invalidNewerDirectory.directory} is invalid: ${invalidNewerDirectory.reason}`);
        }
        if (selected.kind === "installed") {
          runtime = await validateInstalledRuntime(selected.runtime);
        } else {
          if (input.confirmDownload && !(await input.confirmDownload(selected.release))) {
            throw new Error("runtime download was not confirmed");
          }
          runtime = await installRuntimeEntry({
            pluginRoot,
            entry: selected.release,
            ...(this.options.fetch === undefined ? {} : { fetch: this.options.fetch }),
            signal,
            onProgress: progress => {
              if (generation !== this.generation) return;
              this.stateValue = { status: "preparing", progress };
              input.onProgress?.(progress);
            },
          });
        }
        if (generation !== this.generation || signal.aborted) return this.stateValue;
        const probe = await this.options.probe(runtime, { signal, workspaceRoot: input.workspaceRoot });
        if (generation !== this.generation || signal.aborted) return this.stateValue;
        if (!probe.available) throw new Error(probe.reason ?? "runtime capability probe failed");
        this.stateValue = { status: "ready", runtime };
      } catch (error) {
        if (generation !== this.generation) return this.stateValue;
        const reason = error instanceof Error ? error.message : String(error);
        this.stateValue = { status: "unavailable", reason };
      } finally {
        if (generation === this.generation) {
          this.controller = undefined;
          this.pending = undefined;
        }
      }
      return this.stateValue;
    };
    this.pending = Promise.resolve().then(run);
    return this.pending;
  }
}
