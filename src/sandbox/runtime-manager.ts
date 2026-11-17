import { existsSync, lstatSync, mkdirSync, realpathSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import type { RuntimeCatalog, RuntimeResourceEntry } from "./runtime-catalog";
import { installRuntimeEntry } from "./runtime-installation";
import { scanInstalledRuntimes, validateInstalledRuntime, type ResolvedRuntimeFiles } from "./runtime-store";
import type { RuntimeManifest } from "./runtime-manifest";
import { selectRuntime } from "./runtime-selection";
import type { RuntimeDownloadProgress } from "./runtime-download";
import { isPathWithin } from "./path";

const MACOS_BACKEND_ID = "macos-seatbelt";
const MACOS_PLATFORM = "darwin";

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
  readonly agentDir?: string;
  readonly catalog: RuntimeCatalog;
  readonly platform: string;
  readonly arch: string;
  readonly pluginVersion: string;
  readonly protocolVersion: number;
  readonly probe: (runtime: ResolvedRuntimeFiles, input: { readonly signal: AbortSignal; readonly workspaceRoot: string }) => Promise<RuntimeProbeResult>;
  readonly fetch?: typeof fetch;
}

function ensureRuntimeStorageRoot(path: string, agentDir?: string): string {
  if (agentDir === undefined) {
    const metadata = lstatSync(path);
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) throw new Error("runtime storage root must be a real directory");
    return realpathSync(path);
  }

  mkdirSync(agentDir, { recursive: true });
  const agentRoot = realpathSync(agentDir);
  const configuredAgentDir = resolve(agentDir);
  const configuredRoot = resolve(path);
  const relativeRoot = relative(configuredAgentDir, configuredRoot);
  if (!relativeRoot || !isPathWithin(configuredAgentDir, configuredRoot)) {
    throw new Error("runtime storage root is outside the configured agent directory");
  }
  let current = agentRoot;
  for (const part of relativeRoot.split(/[\\/]/u).filter(Boolean)) {
    current = join(current, part);
    if (!existsSync(current)) {
      try { mkdirSync(current); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
    }
    const metadata = lstatSync(current);
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) throw new Error("runtime storage path contains a non-directory or link");
    current = realpathSync(current);
    if (!isPathWithin(agentRoot, current)) throw new Error("runtime storage root is outside the configured agent directory");
  }
  return current;
}

/**
 * macOS needs no downloaded runtime: `/usr/bin/sandbox-exec` is system-provided.
 * The ready state therefore carries a synthetic manifest whose backend id
 * selects the Seatbelt backend and an empty file set.
 */
function macOSSystemRuntime(
  options: SandboxRuntimeManagerOptions,
  arch: "x64" | "arm64",
): ResolvedRuntimeFiles {
  const manifest: RuntimeManifest = {
    schemaVersion: 1,
    version: options.pluginVersion,
    stable: true,
    platform: MACOS_PLATFORM,
    arch,
    protocolVersion: options.protocolVersion,
    minPluginVersion: "0.0.0",
    maxPluginVersionExclusive: "999999.999.999",
    backendId: MACOS_BACKEND_ID,
    files: [],
  };
  return {
    directory: join(options.pluginRoot, "runtimes", `${MACOS_PLATFORM}-${arch}`),
    storageRoot: options.pluginRoot,
    manifest,
    source: "manual",
    files: {},
  };
}

export class SandboxRuntimeManager {
  private stateValue: SandboxRuntimeState = { status: "disabled" };
  private preparedRuntime: ResolvedRuntimeFiles | undefined;
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
    if (this.preparedRuntime) {
      this.stateValue = { status: "ready", runtime: this.preparedRuntime };
      return Promise.resolve(this.stateValue);
    }
    if (this.stateValue.status === "ready") return Promise.resolve(this.stateValue);
    const generation = ++this.generation;
    const controller = new AbortController();
    this.controller = controller;
    const signal = input.signal === undefined
      ? controller.signal
      : AbortSignal.any([controller.signal, input.signal]);
    this.stateValue = { status: "preparing" };
    const run = async (): Promise<SandboxRuntimeState> => {
      try {
        if (this.options.platform !== "linux" && this.options.platform !== "win32" &&
            this.options.platform !== MACOS_PLATFORM) {
          throw new Error(`OS sandbox is unsupported on ${this.options.platform}`);
        }
        if (this.options.arch !== "x64" && this.options.arch !== "arm64") {
          throw new Error(`OS sandbox is unsupported on ${this.options.platform}/${this.options.arch}`);
        }
        if (this.options.platform === MACOS_PLATFORM) {
          // System runtime: no storage root, no catalog scan, no download lease.
          const runtime = macOSSystemRuntime(this.options, this.options.arch === "arm64" ? "arm64" : "x64");
          const probe = await this.options.probe(runtime, { signal, workspaceRoot: input.workspaceRoot });
          if (generation !== this.generation || signal.aborted) return this.stateValue;
          if (!probe.available) throw new Error(probe.reason ?? "runtime capability probe failed");
          this.preparedRuntime = runtime;
          this.stateValue = { status: "ready", runtime };
          return this.stateValue;
        }
        const pluginRoot = ensureRuntimeStorageRoot(this.options.pluginRoot, this.options.agentDir);
        const workspaceRoot = realpathSync(input.workspaceRoot);
        if (isPathWithin(workspaceRoot, pluginRoot) || isPathWithin(pluginRoot, workspaceRoot)) {
          throw new Error("runtime storage root overlaps the restricted workspace");
        }
        const scan = scanInstalledRuntimes({
          pluginRoot,
          platform: this.options.platform,
          arch: this.options.arch,
          catalog: this.options.catalog,
        });
        let selected = selectRuntime({
          platform: this.options.platform,
          arch: this.options.arch,
          pluginVersion: this.options.pluginVersion,
          protocolVersion: this.options.protocolVersion,
          installed: scan.candidates,
          releases: this.options.catalog.runtimes,
          matchesRelease: (installed, release) => installed.catalogEntry?.version === release.version &&
            installed.catalogEntry.archiveSha256 === release.archiveSha256,
        });
        let runtime: ResolvedRuntimeFiles | undefined;
        if (selected.kind === "unavailable") {
          const problem = scan.problems[0];
          throw new Error(problem
            ? `runtime directory ${problem.directory} is invalid: ${problem.reason}`
            : `${selected.reason}; manual runtime directory: ${join(pluginRoot, "runtimes", `${this.options.platform}-${this.options.arch}`)}`);
        }
        if (selected.kind === "installed") {
          try {
            runtime = await validateInstalledRuntime(selected.runtime);
          } catch (error) {
            if (!selected.runtime.catalogEntry) throw error;
            selected = { kind: "download", release: selected.runtime.catalogEntry };
          }
        }
        if (selected.kind === "download") {
          if (scan.candidates.length === 0 && scan.problems.length === 0 && input.confirmDownload &&
              !(await input.confirmDownload(selected.release))) {
            throw new Error("runtime download was not confirmed");
          }
          runtime = await installRuntimeEntry({
            pluginRoot,
            entry: selected.release,
            ...(this.options.fetch === undefined ? {} : { fetch: this.options.fetch }),
            signal,
            beforeCommit: async candidate => {
              const probe = await this.options.probe(candidate, { signal, workspaceRoot: input.workspaceRoot });
              if (!probe.available) throw new Error(probe.reason ?? "runtime capability probe failed");
              if (generation !== this.generation || signal.aborted) throw new Error("runtime preparation was cancelled");
            },
            onProgress: progress => {
              if (generation !== this.generation) return;
              this.stateValue = { status: "preparing", progress };
              input.onProgress?.(progress);
            },
          });
        }
        if (!runtime) throw new Error("runtime preparation did not produce validated files");
        if (generation !== this.generation || signal.aborted) return this.stateValue;
        if (selected.kind === "installed") {
          const probe = await this.options.probe(runtime, { signal, workspaceRoot: input.workspaceRoot });
          if (generation !== this.generation || signal.aborted) return this.stateValue;
          if (!probe.available) throw new Error(probe.reason ?? "runtime capability probe failed");
        }
        this.preparedRuntime = runtime;
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
