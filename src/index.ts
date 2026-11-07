import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import {
  DynamicBorder,
  getAgentDir,
  getSelectListTheme,
  type ExtensionAPI,
  type ExtensionContext,
} from "@earendil-works/pi-coding-agent";
import { Container, Input, SelectList, Spacer, Text } from "@earendil-works/pi-tui";
import { createPermissionExtension, type PermissionPublication, type PublicationFactoryInput } from "#approve-core/host/pi-extension";
import { getActiveAgentName } from "#approve-core/host/active-agent";
import { assembleModelNodes, type ApproverConfig } from "#approve-core/host/model-nodes";
import { reviewerThinking } from "#approve-core/host/reviewer-thinking";
import { createApprovalNodeHost, type PreparedApprovalNodePublication } from "#approve-core/node-loader/manager";
import { createBuiltinFrontBindings } from "#approve-core/nodes/mode/bindings";
import { createPowerShellApprovalNode, createExternalCommandApprovalNode } from "#approve-core/nodes/shell-policy";
import {
  analyzeStep,
  createBashProgramProvider,
  createPowerShellProgramProvider,
  type BashProgramProvider,
  type PowerShellProgramProvider,
} from "#approve-core/nodes/analysis";
import { PowerShellParser, type PowerShellParserLimits } from "#approve-core/utils/access-intent/powershell/parser";
import { createDefaultAssessmentResolver } from "#approve-core/nodes/assessment";
import { createLlmApproverNode } from "#approve-core/nodes/llm-approver";
import { createDecisionApproverNode } from "#approve-core/nodes/decision-approver";
import { PermissionManager } from "#approve-core/policy/permission-manager";
import { createRuleEvaluator, type RuleEvaluator } from "#approve-core/policy/rule";
import { PermissionResolver } from "#approve-core/policy/permission-resolver";
import { PermissionService } from "#approve-core/policy/permissions-service";
import { SessionRuleStore } from "#approve-core/policy/session-rules";
import { captureStep, describeNode, type StepCapture } from "#approve-core/contracts";
import { runStepChain } from "#approve-core/runtime";
import {
  createApprovalChainConfigOwner,
  type ApprovalChainConfigOwner,
  type ApprovalChainConfigSnapshot,
} from "#config/owner";
import { createPolicyLoader, type PolicyLoader } from "#config/policy-loader";
import { resolveConfigPaths } from "#config/config-paths";
import { createConfigIssueReporter } from "#config/config-issue-reporter";
import { createPolicyIssueReporter } from "#config/policy-issue-reporter";
import {
  applyChatEndpoint,
  listModelsJsonProviders,
} from "#config/models-json";
import { handlePermissionCommand, formatPermissionStatus, permissionArgumentCompletions } from "#config/command";
import { applyExperiments, type ExperimentJudge } from "#config/experiments";
import { pathFlavorForPlatform } from "#approve-core/utils/path/path-flavor";
import { PathNormalizer } from "#approve-core/utils/path/path-normalizer";
import { normalizeToolTargets } from "#approve-core/utils/access-intent/input-normalizer";
import { createControlledExecution } from "#sandbox/production";
import { createSandboxBypass, SANDBOX_BYPASS_TOOL_NAME } from "#sandbox/bypass";
import { createCodemodeHostToolExecutor } from "#sandbox/codemode/host-execution";
import { createManagedCodemodeExtension } from "#sandbox/codemode/tool-adapter";
import { CodemodeRuntimeSupervisor, createPiCodemodeRuntimeFactory } from "#sandbox/codemode/supervisor";
import { jsonDigest } from "./json";
import { publishPermissionsService, unpublishPermissionsService, type PermissionsService } from "./service";
import { createReviewDebugReporter, type ReviewDebugSink } from "./review-debug";
import type { ShellPolicy } from "#config/shell-policy-schema";
import type { ShellPolicyPathVariables } from "#approve-core/policy/shell-policy/evaluate";
import type { ShellExecutionPermissions } from "#config/execution-source-schema";

interface SessionRuntime {
  readonly id: string;
  readonly owner: ApprovalChainConfigOwner;
  readonly policyLoader: PolicyLoader;
  readonly manager: PermissionManager;
  readonly permissions: PermissionsService;
  readonly nodeHost: ReturnType<typeof createApprovalNodeHost>;
  readonly permissionService: PermissionService;
  readonly sessionRules: SessionRuleStore;
  readonly reportConfig: ReturnType<typeof createConfigIssueReporter>;
  readonly reportPolicy: ReturnType<typeof createPolicyIssueReporter>;
  ctx: ExtensionContext;
  disposed: boolean;
}

interface PublicationNodes {
  readonly rules: ReturnType<PermissionManager["configRules"]>;
  readonly defaultRule: ReturnType<PermissionManager["configDefaultRule"]>;
  readonly cwd: string;
  readonly modeSource: "default" | "global" | "project" | "session";
  readonly commandEffects: unknown;
  readonly shellAnalysis: Partial<PowerShellParserLimits> | undefined;
  readonly shellPolicy: ShellPolicy | undefined;
  readonly shellGrants: ShellExecutionPermissions | undefined;
  readonly shellPathVariables: ShellPolicyPathVariables;
  readonly enabledShellNodes: readonly string[];
  readonly mcpServerNames: readonly string[];
}

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));

function intentRevision(stamp: string): number {
  return Number.parseInt(jsonDigest(stamp).slice(0, 8), 16);
}

function notify(ctx: ExtensionContext, message: string, level: "info" | "warning" = "warning"): void {
  try {
    ctx.ui.notify(message, level);
  } catch {
    return;
  }
}

interface PermissionOption {
  readonly value: string;
  readonly label: string;
  readonly description?: string;
  /** Accent color for the label so action entries stand out from models. */
  readonly color?: "accent" | "warning" | "success" | "error";
}

function selectPermissionOption(
  ctx: ExtensionContext,
  title: string,
  options: readonly PermissionOption[],
  footer: readonly string[] = [],
  searchable = false,
  hint = "↑↓ move  Enter select  Esc cancel",
): Promise<string | undefined> {
  return ctx.ui.custom<string | undefined>((_tui, theme, keybindings, done) => {
    let settled = false;
    const finish = (value?: string): void => {
      if (settled) return;
      settled = true;
      done(value);
    };
    const listContainer = new Container();
    let list: SelectList | undefined;
    const updateList = (filter: string): void => {
      const query = filter.trim().toLocaleLowerCase();
      const matches = query.length === 0
        ? options
        : options.filter((option) => option.label.toLocaleLowerCase().includes(query));
      listContainer.clear();
      if (matches.length === 0) {
        list = undefined;
        listContainer.addChild(new Text(theme.fg("muted", "No matching models"), 1, 0));
        return;
      }
      list = new SelectList(
        matches.map(({ value, label, description, color }) => ({
          value,
          label: color === undefined ? label : theme.fg(color, label),
          ...(description === undefined ? {} : { description }),
        })),
        Math.min(8, matches.length),
        getSelectListTheme(),
      );
      list.onSelect = (option) => finish(option.value);
      list.onCancel = () => finish(undefined);
      listContainer.addChild(list);
    };
    updateList("");
    const search = searchable
      ? new Input({ prompt: "Search: ", placeholder: "Filter by provider or model" })
      : undefined;
    if (search !== undefined) search.focused = true;

    class PermissionOptionSelector extends Container {
      constructor() {
        super();
        this.addChild(new DynamicBorder());
        this.addChild(new Spacer(1));
        for (const line of title.split("\n")) this.addChild(new Text(theme.fg("text", line), 1, 0));
        this.addChild(new Spacer(1));
        if (search !== undefined) {
          this.addChild(search);
          this.addChild(new Spacer(1));
        }
        this.addChild(listContainer);
        if (footer.length > 0) this.addChild(new Spacer(1));
        for (const line of footer) this.addChild(new Text(theme.fg("muted", line), 1, 0));
        this.addChild(new Spacer(1));
        this.addChild(new Text(theme.fg("muted", hint), 1, 0));
        this.addChild(new Spacer(1));
        this.addChild(new DynamicBorder());
      }

      handleInput(keyData: string): void {
        if (keybindings.matches(keyData, "tui.select.cancel")) {
          finish(undefined);
          return;
        }
        const listKey = keybindings.matches(keyData, "tui.select.up") ||
          keybindings.matches(keyData, "tui.select.down") ||
          keybindings.matches(keyData, "tui.select.confirm");
        if (listKey || search === undefined) {
          list?.handleInput(keyData);
          return;
        }
        if (settled) return;
        search.handleInput(keyData);
        updateList(search.getValue());
      }
    }

    return new PermissionOptionSelector();
  });
}

/** Marker value for the "Add provider" entry in the approver-model pickers. */
const ADD_PROVIDER = "__add-provider__";

/** Single-line text prompt; Enter submits the line, Esc cancels. */
async function promptLine(
  ctx: ExtensionContext,
  prompt: string,
  placeholder: string,
): Promise<string | undefined> {
  return ctx.ui.custom((tui, theme, keybindings, done) => {
    let settled = false;
    const finish = (value: string | undefined): void => {
      if (settled) return;
      settled = true;
      done(value);
    };
    const input = new Input({ prompt, placeholder });
    input.focused = true;
    class LinePrompt extends Container {
      constructor() {
        super();
        this.addChild(new DynamicBorder());
        this.addChild(new Spacer(1));
        this.addChild(input);
        this.addChild(new Spacer(1));
        this.addChild(new Text(theme.fg("muted", "Enter submit  Esc cancel"), 1, 0));
        this.addChild(new Spacer(1));
        this.addChild(new DynamicBorder());
      }

      handleInput(keyData: string): void {
        if (keybindings.matches(keyData, "tui.select.cancel")) {
          finish(undefined);
          return;
        }
        if (keybindings.matches(keyData, "tui.select.confirm")) {
          finish(input.getValue());
          return;
        }
        if (settled) return;
        input.handleInput(keyData);
      }
    }
    return new LinePrompt();
  });
}

/**
 * Configure a custom classifier endpoint: pick one of the built-in
 * classifier providers, optionally override its base URL, and store a
 * literal API key in the agent-level models.json. Pi keeps the provider's
 * built-in classifier models and routes them through the new endpoint.
 */
/**
 * Configure a custom classifier endpoint: pick a provider that already
 * ships classifier models in the registry (built-ins or third-party
 * providers registered by an extension), optionally override its base URL,
 * and store a literal API key in the agent-level models.json. Pi keeps the
 * provider's classifier models and routes them through the new endpoint.
 * A manually entered provider id only takes effect for ids pi already
 * knows classifier models for; a brand-new id can only carry chat models
 * (models.json `models` entries never create classifier models).
 */
/**
 * Add a provider to the agent-level models.json with four sequential
 * prompts: provider id, model id, base URL, API key. A brand-new provider
 * is created with one OpenAI-compatible chat model; an existing one keeps
 * its models (the named model is appended) and only its endpoint is
 * re-pointed. Models defined this way are chat models, so they serve as
 * LLM approver models; a decision (classifier) judge still has to be a
 * classifier model shipped by the provider itself.
 *
 * Returns the provider id that was saved, or undefined when cancelled or
 * rejected.
 */
async function addProvider(ctx: ExtensionContext): Promise<string | undefined> {
  const providerId = (await promptLine(ctx, "Provider id: ", "e.g. opencode"))?.trim();
  if (providerId === undefined) return undefined;
  if (providerId === "") {
    notify(ctx, "Provider was not saved: a provider id is required.", "warning");
    return undefined;
  }
  const modelName = await promptLine(ctx, "Model id: ", "e.g. jev-1.13");
  if (modelName === undefined) return undefined;
  const baseUrl = await promptLine(ctx, "Base URL: ", "e.g. https://api.example.com/v1");
  if (baseUrl === undefined) return undefined;
  const apiKey = await promptLine(ctx, "API key: ", "Blank keeps the current credential");
  if (apiKey === undefined) return undefined;
  const result = applyChatEndpoint(join(getAgentDir(), "models.json"), {
    providerId,
    baseUrl,
    apiKey,
    ...(modelName.trim() === "" ? {} : { modelId: modelName.trim() }),
  });
  if (!result.ok) {
    notify(ctx, `Provider could not be saved: ${result.message}`);
    return undefined;
  }
  notify(
    ctx,
    "Provider saved to models.json. Open /model once to reload it, then pick the model in /permission settings.",
    "info",
  );
  return providerId;
}

/**
 * Decision (classifier) judge prompt shared by the Experiments dialog and
 * the decision-branch approver-model picker. Lists only classifier models
 * from providers already added to models.json (non-empty entries), with
 * the Add provider entry first; after adding, the picker is shown again so
 * the new provider's classifier models can be picked right away. Esc
 * cancels with no judge.
 */
const ADD_CUSTOM_JUDGE = "__add_custom_judge__";
const SELECT_CUSTOM_JUDGE = "__select_custom_judge__";

async function selectDecisionJudge(ctx: ExtensionContext, currentJudge?: { type?: string; baseUrl?: string; model?: string; apiKey?: string }): Promise<ExperimentJudge | undefined> {
  while (true) {
    const addedProviders = new Set(listModelsJsonProviders(join(getAgentDir(), "models.json")));
    const models = ctx.modelRegistry.getModelsOfType("classifier")
      .filter((item) => addedProviders.has(item.provider));
    const currentJudgeTyped = currentJudge as { type?: string; baseUrl?: string; model?: string; apiKey?: string } | undefined;
    const options: { value: string; label: string; color?: "accent" }[] = [
      { value: ADD_PROVIDER, label: "Add provider", color: "accent" as const },
      { value: ADD_CUSTOM_JUDGE, label: "Custom judge (enter endpoint)", color: "accent" as const },
    ];
    if (currentJudgeTyped?.type === "custom") {
      options.push({ value: SELECT_CUSTOM_JUDGE, label: `custom: ${currentJudgeTyped?.baseUrl}/${currentJudgeTyped?.model}` });
    }
    options.push(...models.map((item, index) => ({
      value: String(index),
      label: `${item.provider}/${item.id}`,
    })));
    const selected = await selectPermissionOption(
      ctx,
      "Decision classifier",
      options,
      models.length === 0 && currentJudgeTyped?.type !== "custom"
        ? ["No classifier models from added providers yet. Use Add provider or Custom judge."]
        : [],
      true,
    );
    if (selected === undefined) return undefined;
    if (selected === ADD_PROVIDER) {
      const providerId = await addProvider(ctx);
      if (providerId !== undefined && ctx.modelRegistry.getModelsOfType("classifier", providerId).length === 0) {
        notify(
          ctx,
          `Provider "${providerId}" ships no classifier models and cannot serve as a decision judge; use one of the built-in classifier providers (e.g. opencode, typesafe) with its own endpoint overridden.`,
          "warning",
        );
      }
      continue;
    }
    if (selected === ADD_CUSTOM_JUDGE) {
      const baseUrl = await promptLine(ctx, "Base URL: ", "https://...");
      if (baseUrl === undefined || baseUrl.trim() === "") continue;
      const model = await promptLine(ctx, "Model: ", "model id");
      if (model === undefined || model.trim() === "") continue;
      const apiKey = await promptLine(ctx, "API key: ", "optional");
      return {
        kind: "custom",
        baseUrl: baseUrl.trim(),
        model: model.trim(),
        ...(apiKey !== undefined && apiKey.trim() !== "" ? { apiKey: apiKey.trim() } : {}),
      };
    }
    if (selected === SELECT_CUSTOM_JUDGE && currentJudgeTyped?.type === "custom") {
      return {
        kind: "custom",
        baseUrl: currentJudgeTyped?.baseUrl as string,
        model: currentJudgeTyped?.model as string,
        ...(currentJudgeTyped?.apiKey === undefined ? {} : { apiKey: currentJudgeTyped.apiKey }),
      };
    }
    const chosen = models[Number(selected)];
    if (chosen === undefined) return undefined;
    return { provider: chosen.provider, model: chosen.id };
  }
}

/**
 * Read-only node list: each node shows its id and a description of what it
 * does; Enter opens a detail view, Esc returns to the settings menu.
 */
async function runApprovalNodes(
  ctx: ExtensionContext,
  nodes: readonly { readonly id: string; readonly description?: string }[],
): Promise<void> {
  while (true) {
    const picked = await selectPermissionOption(
      ctx,
      "Approval nodes",
      nodes.map((node) => ({ value: node.id, label: node.id, description: describeNode(node) })),
      nodes.length === 0 ? ["No effective approval nodes."] : [],
      false,
      "Enter details  Esc close",
    );
    if (picked === undefined) return;
    const node = nodes.find((candidate) => candidate.id === picked);
    if (node === undefined) continue;
    await showStatusView(ctx, [
      node.id,
      "",
      describeNode(node),
    ].join("\n"));
  }
}

/** Read-only status page; any key returns to the settings menu. */
function showStatusView(ctx: ExtensionContext, text: string): Promise<void> {
  return ctx.ui.custom<void>((_tui, theme, _keybindings, done) => {
    let settled = false;
    const finish = (): void => {
      if (settled) return;
      settled = true;
      done();
    };
    class StatusView extends Container {
      constructor() {
        super();
        this.addChild(new DynamicBorder());
        this.addChild(new Spacer(1));
        for (const line of text.split("\n")) this.addChild(new Text(theme.fg("text", line), 1, 0));
        this.addChild(new Spacer(1));
        this.addChild(new Text(theme.fg("muted", "Esc close"), 1, 0));
        this.addChild(new Spacer(1));
        this.addChild(new DynamicBorder());
      }

      handleInput(_keyData: string): void {
        finish();
      }
    }
    return new StatusView();
  });
}

interface ExperimentItem {
  readonly id: string;
  readonly label: string;
  readonly description: string;
}

/**
 * Checklist popup for experiments: Space toggles the highlighted item,
 * Enter confirms with the checked ids, Esc cancels without changes.
 */
function selectExperiments(
  ctx: ExtensionContext,
  title: string,
  items: readonly ExperimentItem[],
  initial: ReadonlySet<string>,
): Promise<ReadonlySet<string> | undefined> {
  return ctx.ui.custom<ReadonlySet<string> | undefined>((_tui, theme, keybindings, done) => {
    let settled = false;
    const finish = (value?: ReadonlySet<string>): void => {
      if (settled) return;
      settled = true;
      done(value);
    };
    const checked = new Set(initial);
    let index = 0;

    class ExperimentChecklist extends Container {
      private readonly listContainer = new Container();

      constructor() {
        super();
        this.addChild(new DynamicBorder());
        this.addChild(new Spacer(1));
        for (const line of title.split("\n")) this.addChild(new Text(theme.fg("text", line), 1, 0));
        this.addChild(new Spacer(1));
        this.addChild(this.listContainer);
        this.addChild(new Spacer(1));
        this.addChild(new Text(theme.fg("muted", "Space toggle  Enter apply  Esc cancel"), 1, 0));
        this.addChild(new Spacer(1));
        this.addChild(new DynamicBorder());
        this.rebuild();
      }

      private rebuild(): void {
        this.listContainer.clear();
        items.forEach((item, itemIndex) => {
          const cursor = itemIndex === index ? theme.fg("accent", "❯") : " ";
          const box = checked.has(item.id) ? "[x]" : "[ ]";
          const label = itemIndex === index ? theme.fg("accent", item.label) : theme.fg("text", item.label);
          this.listContainer.addChild(new Text(`${cursor} ${box} ${label}`, 1, 0));
        });
        const highlighted = items[index];
        if (highlighted !== undefined) {
          this.listContainer.addChild(new Spacer(1));
          this.listContainer.addChild(new Text(theme.fg("muted", highlighted.description), 1, 0));
        }
      }

      handleInput(keyData: string): void {
        if (keybindings.matches(keyData, "tui.select.cancel")) {
          finish(undefined);
          return;
        }
        if (keybindings.matches(keyData, "tui.select.up")) {
          index = (index - 1 + items.length) % items.length;
          this.rebuild();
          return;
        }
        if (keybindings.matches(keyData, "tui.select.down")) {
          index = (index + 1) % items.length;
          this.rebuild();
          return;
        }
        if (keybindings.matches(keyData, "tui.select.confirm")) {
          finish(new Set(checked));
          return;
        }
        if (keyData === " " && items[index] !== undefined) {
          const id = items[index]!.id;
          if (checked.has(id)) checked.delete(id);
          else checked.add(id);
          this.rebuild();
        }
      }
    }
    return new ExperimentChecklist();
  });
}

function modelApprover(config: ReturnType<ApprovalChainConfigOwner["snapshot"]>["config"]["approver"]): ApproverConfig {
  const judge = config.judge;
  return {
    provider: config.provider,
    modelId: config.model,
    instructions: config.instructions,
    timeoutMs: config.timeoutMs,
    queueTimeoutMs: config.queueTimeoutMs,
    decisionContextAcquisition: config.decisionContextAcquisition,
    ...(judge === undefined
      ? {}
      : judge.type === "custom"
        ? {
            judge: {
              kind: "custom" as const,
              baseUrl: judge.baseUrl,
              modelId: judge.model,
              apiKey: judge.apiKey,
              timeoutMs: judge.timeoutMs,
              contextBudgetTokens: judge.contextBudgetTokens,
              allowConfidenceThreshold: judge.allowThreshold,
              denyConfidenceThreshold: judge.denyThreshold,
            },
          }
        : judge.type === "pi-classifier"
          ? {
              judge: {
                kind: "pi-classifier" as const,
                provider: judge.provider,
                modelId: judge.model,
                timeoutMs: judge.timeoutMs,
                contextBudgetTokens: judge.contextBudgetTokens,
                allowConfidenceThreshold: judge.allowThreshold,
                denyConfidenceThreshold: judge.denyThreshold,
              },
            }
          : {
              judge: {
                kind: "pi-model" as const,
                provider: judge.provider,
                modelId: judge.model,
                timeoutMs: judge.timeoutMs,
              },
            }),
  };
}

function modeSourceForNode(source: PublicationNodes["modeSource"]): "user" | "project" | "session" | "default" {
  return source === "global" ? "user" : source;
}

export interface PermissionExtensionOptions {
  readonly reviewDebugSink?: ReviewDebugSink;
}

export default function registerPermissionExtension(
  api: ExtensionAPI,
  options: PermissionExtensionOptions = {},
): void {
  const reviewDebug = createReviewDebugReporter(options.reviewDebugSink);
  const runtimes = new Map<string, SessionRuntime>();
  const publicationNodes = new Map<string, PublicationNodes>();
  const providers = new WeakMap<StepCapture, BashProgramProvider>();
  const powerShellProviders = new WeakMap<StepCapture, PowerShellProgramProvider>();
  const powerShellParser = new PowerShellParser();

  function runtimeFor(ctx: ExtensionContext): SessionRuntime {
    const id = ctx.sessionManager.getSessionId();
    const existing = runtimes.get(id);
    if (existing !== undefined) {
      existing.ctx = ctx;
      return existing;
    }

    const agentDir = getAgentDir();
    const paths = resolveConfigPaths({
      agentDir,
      cwd: ctx.cwd,
      extensionRoot: packageRoot,
    });
    const owner = createApprovalChainConfigOwner({
      paths,
      cwd: ctx.cwd,
      projectTrusted: ctx.isProjectTrusted(),
      platform: process.platform,
      shellPathVariables: { workspace: ctx.cwd, tempDir: tmpdir() },
    });
    const snapshot = owner.snapshot({ sessionId: id });
    const policyLoader = createPolicyLoader({
      paths,
      cwd: ctx.cwd,
      projectTrusted: snapshot.projectTrusted,
      globalAgentsDir: join(agentDir, "agents"),
      mcpConfigFile: join(agentDir, "mcp.json"),
      projectMcpConfigFile: join(ctx.cwd, ".pi", "mcp.json"),
    });
    const flavor = pathFlavorForPlatform(process.platform);
    const sessionRules = new SessionRuleStore({ flavor });
    let runtime!: SessionRuntime;
    const manager = new PermissionManager({
      flavor,
      session: sessionRules,
      loadPolicy: () => policyLoader.load(getActiveAgentName(runtime.ctx)),
      shellTools: snapshot.config.shellTools,
    });
    const normalizer = new PathNormalizer(flavor, ctx.cwd, {
      infrastructureReadPaths: snapshot.config.piInfrastructureReadPaths,
    });
    const resolver = new PermissionResolver({
      manager,
      normalizer,
      shellTools: snapshot.config.shellTools,
      mcpConfigServers: () => policyLoader.load(getActiveAgentName(runtime.ctx)).mcpServerNames,
    });
    const permissionService = new PermissionService({
      manager, resolver, normalizer, session: sessionRules,
      commandEffects: () => ({ project: owner.snapshot({ sessionId: id }).config.commandEffects ?? {} }),
    });
    const permissions: PermissionsService = Object.freeze({
      checkPermission: (toolName: string, input?: unknown) => {
        const agent = getActiveAgentName(runtime.ctx);
        if ((toolName === "bash" || toolName === "shell") && typeof input === "string") {
          return permissionService.checkBash(input, agent);
        }
        if (toolName.startsWith("mcp__")) return permissionService.checkMcp(toolName, agent);
        return permissionService.checkTool(toolName, input ?? {}, agent);
      },
      getToolPermission: (toolName: string) => manager.toolState(toolName),
    });
    const nodeHost = createApprovalNodeHost({
      onWarning: (warning) => notify(runtime.ctx, warning.message),
    });
    const reportConfig = createConfigIssueReporter({
      readIssues: () => owner.snapshot({ sessionId: id }).issues,
      notify: (message) => notify(runtime.ctx, message),
    });
    const reportPolicy = createPolicyIssueReporter({
      readIssues: (agentName) => policyLoader.load(agentName || undefined).messages,
      notify: (message) => notify(runtime.ctx, message),
    });
    runtime = {
      id,
      owner,
      policyLoader,
      manager,
      permissions,
      nodeHost,
      permissionService,
      sessionRules,
      reportConfig,
      reportPolicy,
      ctx,
      disposed: false,
    };
    runtimes.set(id, runtime);
    publishPermissionsService(id, permissions);
    return runtime;
  }

  const stepEvaluators = new WeakMap<StepCapture, RuleEvaluator>();

  function providerFor(capture: StepCapture, cwd: string, generation: number): BashProgramProvider {
    let provider = providers.get(capture);
    if (provider === undefined) {
      const data = publicationNodes.get(`${capture.sessionId}\u0000${generation}`);
      const runtime = runtimes.get(capture.sessionId);
      if (data === undefined || runtime === undefined) throw new Error("publication unavailable");
      stepEvaluators.set(capture, createRuleEvaluator(
        [...data.rules, ...runtime.sessionRules.snapshot().rules], pathFlavorForPlatform(process.platform),
        { defaultRule: data.defaultRule },
      ));
      provider = createBashProgramProvider(capture.directCalls, { cwd, commandEffects: data.commandEffects });
      providers.set(capture, provider);
    }
    return provider;
  }

  function powerShellProviderFor(
    capture: StepCapture,
    generation: number,
    signal?: AbortSignal,
  ): PowerShellProgramProvider {
    let provider = powerShellProviders.get(capture);
    if (provider === undefined) {
      const data = publicationNodes.get(`${capture.sessionId}\u0000${generation}`);
      if (data === undefined) throw new Error("publication unavailable");
      provider = createPowerShellProgramProvider(capture.directCalls, {
        parser: powerShellParser,
        limits: data.shellAnalysis,
        signal,
      });
      powerShellProviders.set(capture, provider);
    }
    return provider;
  }

  const analysis = {
    analyze(capture: StepCapture, input: { readonly cwd: string; readonly generation: number; readonly signal?: AbortSignal }) {
      return analyzeStep(capture, {
        cwd: input.cwd,
        getBashProgram: providerFor(capture, input.cwd, input.generation),
        getPowerShellParse: powerShellProviderFor(capture, input.generation, input.signal),
      });
    },
    bashPrograms(capture: StepCapture, input: { readonly cwd: string; readonly generation: number }) {
      return providerFor(capture, input.cwd, input.generation);
    },
    powershellPrograms(capture: StepCapture, input: { readonly cwd: string; readonly generation: number; readonly signal?: AbortSignal }) {
      return powerShellProviderFor(capture, input.generation, input.signal);
    },
  };

  const execution = createControlledExecution({
    snapshot: (ctx) => runtimeFor(ctx).owner.snapshot({ sessionId: ctx.sessionManager.getSessionId() }),
    registrationPath: fileURLToPath(import.meta.url),
  });

  const codemodeSupervisor = new CodemodeRuntimeSupervisor({
    createRuntime: createPiCodemodeRuntimeFactory(),
  });
  const codemodeToolInfo = (name: string) => api.getAllTools().find((tool) => tool.name === name);
  const codemodeExecutor = createCodemodeHostToolExecutor({
    supervisor: codemodeSupervisor,
    resolveBackend: (ctx) => runtimeFor(ctx).owner.snapshot({
      sessionId: ctx.sessionManager.getSessionId(),
    }).config.mode === "full-access" ? "full-access" : "restricted",
    getToolNamespace: (name) => codemodeToolInfo(name)?.namespace,
    getToolGuidelines: (name) => codemodeToolInfo(name)?.promptGuidelines ?? [],
    appendEntry: (customType, data) => api.appendEntry(customType, data),
    captureValidityGuard: (ctx) => {
      const sessionId = ctx.sessionManager.getSessionId();
      const revision = execution.configurationRevision(ctx);
      return () => ctx.sessionManager.getSessionId() === sessionId &&
        execution.configurationRevision(ctx) === revision;
    },
    modelsEnabled: true,
  });

  const bypass = createSandboxBypass({
    mode: (ctx) => runtimeFor(ctx).owner.snapshot({ sessionId: ctx.sessionManager.getSessionId() }).config.mode,
    policyRevision: (ctx) => execution.configurationRevision(ctx),
    resolveHostTool: (name, schema) => execution.resolveHostTool(name, schema),
    recordExecution: (event) => {
      try {
        api.appendEntry("permission:execution", { executionMode: "host", ...event });
      } catch {
        return;
      }
    },
  });

  const publications = {
    prepareReload(ctx: ExtensionContext, sessionId: string) {
      const candidate = runtimeFor(ctx).owner.prepareReload({ sessionId });
      return { configuration: candidate.snapshot, commit: () => candidate.commit() };
    },
    didReload(ctx: ExtensionContext) {
      const runtime = runtimeFor(ctx);
      runtime.reportConfig.report();
      runtime.reportPolicy.report(getActiveAgentName(ctx) ?? "");
      bypass.clearSession(runtime.id);
    },
    async publish(input: PublicationFactoryInput): Promise<PermissionPublication> {
      const runtime = runtimeFor(input.ctx);
      const snapshot = input.configuration as ApprovalChainConfigSnapshot | undefined ??
        runtime.owner.snapshot({ sessionId: runtime.id });
      if (snapshot.source === "invalid") throw new Error("approval configuration is invalid");
      const agent = getActiveAgentName(input.ctx);
      const policy = runtime.policyLoader.load(agent);
      const policySnapshot = runtime.manager.configSnapshot(policy, agent);
      const rules = policySnapshot.rules;
      const modelNodes = assembleModelNodes({
        generation: input.generation,
        effectiveNodes: snapshot.nodeConfig.nodes,
        approver: modelApprover(snapshot.config.approver),
        registry: {
          find: (provider, modelId) => input.ctx.modelRegistry.find(provider, modelId),
          findClassifier: (provider, modelId) => input.ctx.modelRegistry.findOfType("classifier", provider, modelId),
        },
        context: input.session.context,
        resolveSession: input.session.resolveSession,
        verifyFacts: input.session.verifyFacts,
        ...(input.session.learning === undefined ? {} : { learning: input.session.learning }),
        complete: async (model, context, options) => {
          const reasoning = reviewerThinking(model);
          const reply = await input.ctx.modelRegistry.streamSimple(model, context, {
            ...options,
            ...(reasoning === undefined ? {} : { reasoning }),
          }).result();
          const usage = reply.usage;
          const inputTokens = usage.input + usage.cacheRead + usage.cacheWrite;
          reviewDebug({ event: "model_usage", provider: model.provider, model: model.id, thinking: reasoning ?? "off", usage,
            cacheHitRate: inputTokens > 0 ? usage.cacheRead / inputTokens : null });
          return reply;
        },
        classify: (model, context, options) => input.ctx.modelRegistry.classify(model, context, options),
        now: Date.now,
        createLlmNode: createLlmApproverNode,
        createDecisionNode: createDecisionApproverNode,
        ...(input.ctx.model === undefined
          ? {}
          : { currentModel: { provider: input.ctx.model.provider, modelId: input.ctx.model.id } }),
      });
      let nodeCandidate: PreparedApprovalNodePublication;
      try {
        nodeCandidate = await runtime.nodeHost.prepare({
          plan: {
            effectiveNodes: snapshot.nodeConfig.nodes,
            nodeConfig: snapshot.nodeConfig,
            configDigest: snapshot.nodeConfig.digest,
            globalConfigDir: snapshot.paths.globalConfigDir,
            projectConfigDir: snapshot.paths.projectConfigDir,
            projectTrusted: snapshot.projectTrusted,
          },
          permissions: runtime.permissions,
        });
      } catch (error) {
        modelNodes.dispose();
        throw error;
      }
      const loaded = nodeCandidate.publication;
      const key = `${runtime.id}\u0000${input.generation}`;
      publicationNodes.set(key, {
        rules,
        defaultRule: policySnapshot.defaultRule,
        cwd: input.ctx.cwd,
        modeSource: snapshot.modeSource,
        commandEffects: { project: snapshot.config.commandEffects ?? {} },
        shellAnalysis: snapshot.config.shellPolicy?.analysis,
        shellPolicy: snapshot.config.shellPolicy,
        shellGrants: snapshot.config.execution.shell,
        shellPathVariables: { workspace: input.ctx.cwd, tempDir: tmpdir() },
        enabledShellNodes: snapshot.nodeConfig.nodes
          .filter((node) => node.enabled &&
            (node.id === "builtin/powershell" || node.id === "builtin/external-command"))
          .map((node) => node.id),
        mcpServerNames: [...policy.mcpServerNames],
      });
      let disposed = false;
      let committed = false;
      return {
        generation: input.generation,
        nodes: [...loaded.bindings, ...modelNodes.nodes.map((binding) => {
          const node = binding.node;
          return { ...binding, timeoutMs: snapshot.config.approver.judge?.timeoutMs ?? snapshot.config.approver.timeoutMs,
            node: { ...node, evaluate: async (step: Parameters<typeof node.evaluate>[0], host: Parameters<typeof node.evaluate>[1]) => {
            const started = Date.now();
            const timeoutMs = snapshot.config.approver.judge?.timeoutMs ?? snapshot.config.approver.timeoutMs;
            const controller = new AbortController();
            const signal = AbortSignal.any([step.signal, controller.signal]);
            let timer: ReturnType<typeof setTimeout> | undefined;
            reviewDebug({ event: "review_start", node: node.id, step: step.capture.stepKey, timeoutMs });
            try {
              const timeout = new Promise<never>((_, reject) => {
                timer = setTimeout(() => { controller.abort(); reject(new Error("reviewer-timeout")); }, timeoutMs);
              });
              const result = await Promise.race([node.evaluate({ ...step, signal }, host), timeout]);
              reviewDebug({ event: "review_end", node: node.id, step: step.capture.stepKey,
                durationMs: Date.now() - started, decisions: result.decisions });
              return result;
            } catch (error) {
              reviewDebug({ event: "review_error", node: node.id, step: step.capture.stepKey,
                durationMs: Date.now() - started, error: error instanceof Error ? error.message : String(error) });
              throw error;
            } finally {
              if (timer !== undefined) clearTimeout(timer);
            }
          } } };
        })],
        mode: snapshot.config.mode,
        rulesRevision: snapshot.revision,
        intentRevision: intentRevision(policy.stamp),
        learningEnabled: snapshot.config.learning.enabled,
        commit() {
          committed = nodeCandidate.commit();
          return committed;
        },
        async dispose() {
          if (disposed) return;
          disposed = true;
          modelNodes.dispose();
          publicationNodes.delete(key);
          const warnings = committed
            ? await runtime.nodeHost.release(loaded.generation)
            : await nodeCandidate.dispose();
          for (const warning of warnings) notify(runtime.ctx, warning.message);
        },
      };
    },
  };

  const host = createPermissionExtension({
    publications,
    analysis,
    captureStep,
    ...(options.reviewDebugSink === undefined ? {} : { audit: { write: (event) => {
      if (event.kind === "chain-node" || event.kind === "step" || event.kind === "human" || event.kind === "error") {
        reviewDebug({ event: "approval_chain", ...event });
      }
    } } }),
    runChain: (input) => {
      const runtime = runtimes.get(input.capture.sessionId);
      const data = publicationNodes.get(`${input.capture.sessionId}\u0000${input.generation}`);
      if (runtime === undefined || data === undefined) {
        return Promise.resolve({ ok: false, reason: "invalid-input" });
      }
      const programProvider = providerFor(input.capture, data.cwd, input.generation);
      const evaluator = stepEvaluators.get(input.capture)!;
      const mode = input.mode ?? runtime.owner.snapshot({ sessionId: runtime.id }).config.mode;
      const mcpCandidates = new Map(input.capture.directCalls.map((call) => [call.toolCallId,
        normalizeToolTargets(call.toolName, call.arguments, { mcpConfigServers: data.mcpServerNames }).targets]));
      const mcpTargets = (call: { readonly toolCallId: string }) => mcpCandidates.get(call.toolCallId) ?? [];
      const front = createBuiltinFrontBindings({
        rules: {
          rules: data.rules,
          evaluator,
          mcpTargets,
          getBashProgram: programProvider,
        },
        assessment: {
          resolve: createDefaultAssessmentResolver({
            rules: data.rules,
            evaluator,
            mcpTargets,
            cwd: data.cwd,
            getBashProgram: programProvider,
          }),
        },
        powershell: data.enabledShellNodes.includes("builtin/powershell")
          ? createPowerShellApprovalNode({
            policy: data.shellPolicy,
            mode,
            pathVariables: data.shellPathVariables,
          })
          : undefined,
        externalCommand: data.enabledShellNodes.includes("builtin/external-command")
          ? createExternalCommandApprovalNode({
            policy: data.shellPolicy,
            mode,
            pathVariables: data.shellPathVariables,
          })
          : undefined,
        mode: {
          mode,
          modeSource: modeSourceForNode(data.modeSource),
          cwd: data.cwd,
          getBashProgram: programProvider,
          shellPolicy: data.shellPolicy,
          shellPathVariables: data.shellPathVariables,
          enabledShellNodes: data.enabledShellNodes,
          shellGrants: data.shellGrants,
        },
      });
      return runStepChain({
        ...input,
        mode,
        nodes: [...front, ...input.nodes],
      });
    },
    sandbox: execution,
    bypassToolName: SANDBOX_BYPASS_TOOL_NAME,
  });
  bypass.setReviewer(host.reviewSandboxBypass);

  api.on("session_start", (_event, ctx) => {
    const runtime = runtimeFor(ctx);
    runtime.reportConfig.report();
    runtime.reportPolicy.report(getActiveAgentName(ctx) ?? "");
    bypass.syncMode(runtime.owner.snapshot({ sessionId: runtime.id }).config.mode, runtime.id);
  });
  host.install(api);
  api.on("session_shutdown", () => powerShellParser.dispose());
  execution.install(api);
  createManagedCodemodeExtension({
    execute: codemodeExecutor,
    registerTool: (tool) => execution.registerManagedTool(tool, {
      cancelSession: codemodeExecutor.cancelSession,
    }),
  })(api);
  bypass.install(api);

  api.registerCommand("permission", {
    description: "Inspect permission settings and change the current approval mode.",
    getArgumentCompletions: permissionArgumentCompletions,
    handler: async (args, ctx) => {
      const runtime = runtimeFor(ctx);
      const trimmed = args.trim();
      if (trimmed === "settings") {
        if (!ctx.hasUI) {
          notify(ctx, "Permission settings require an interactive UI.");
          return;
        }
        while (true) {
          const snapshot = runtime.owner.snapshot({ sessionId: runtime.id });
          const decision = snapshot.nodeConfig.nodes.some(
            (node) => node.id === "builtin/decision-approver" && node.enabled,
          );
          const config = snapshot.config.approver;
          const mcpSandbox = snapshot.config.experimental.mcpSandbox;
          const mainOptions: PermissionOption[] = [
            { value: "approver-model", label: "Select approver model" },
            { value: "view-nodes", label: "Approval nodes" },
            { value: "view-status", label: "Status" },
            { value: "experiments", label: "Experiments" },
          ];
          const action = await selectPermissionOption(ctx, "Permission settings", mainOptions, [], false, "↑↓ move  Enter select  Esc close");
          if (action === undefined) return;

          try {
            if (action === "view-nodes") {
              await runApprovalNodes(ctx, snapshot.nodeConfig.nodes);
              continue;
            }
            if (action === "view-status") {
              await showStatusView(ctx, formatPermissionStatus(snapshot));
              continue;
            }

            let result: ReturnType<ApprovalChainConfigOwner["update"]>;
            if (action === "experiments") {
              const selection = await selectExperiments(ctx, "Experiments", [
                { id: "decision", label: "Decision reviewer", description: "Reviews requests with a local decision classifier instead of an LLM." },
                { id: "mcp-sandbox", label: "MCP sandbox", description: "Runs MCP servers inside the experimental sandbox." },
              ], new Set([
                ...(decision ? ["decision"] : []),
                ...(mcpSandbox ? ["mcp-sandbox"] : []),
              ]));
              if (selection === undefined) continue;
              const wantMcp = selection.has("mcp-sandbox");
              let appliedDecision = selection.has("decision");
              let judge: ExperimentJudge | undefined;
              if (appliedDecision && !decision && config.judge?.type !== "pi-classifier" && config.judge?.type !== "custom") {
                judge = await selectDecisionJudge(ctx, config.judge);
                if (judge === undefined) {
                  notify(ctx, "No classifier chosen; the Decision reviewer stays disabled.", "warning");
                  appliedDecision = false;
                }
              }
              if (appliedDecision === decision && wantMcp === mcpSandbox && judge === undefined) continue;
              result = runtime.owner.update(
                (current) => applyExperiments(current, { decision: appliedDecision, mcpSandbox: wantMcp }, judge),
                { sessionId: runtime.id },
              );
            } else if (decision) {
              // Approver model with the Decision reviewer active: pick the classifier (judge).
              const chosen = await selectDecisionJudge(ctx, config.judge);
              if (chosen === undefined) continue;
              result = runtime.owner.update(
                (current) => applyExperiments(
                  current,
                  { decision: true, mcpSandbox: current.experimental.mcpSandbox },
                  chosen,
                ),
                { sessionId: runtime.id },
              );
            } else {
              const models = ctx.modelRegistry.getAvailable();
              const options = [
                { value: ADD_PROVIDER, label: "Add provider", color: "accent" as const },
                { value: "session", label: "Current session model" },
                ...models.map((item, index) => ({
                  value: String(index),
                  label: `${item.provider}/${item.id}`,
                })),
              ];
              const selected = await selectPermissionOption(
                ctx,
                "LLM approval model",
                options,
                [],
                true,
              );
              if (selected === undefined) continue;
              if (selected === ADD_PROVIDER) {
                await addProvider(ctx);
                continue;
              }
              const chosen = selected === "session" ? undefined : models[Number(selected)];
              if (selected !== "session" && chosen === undefined) continue;
              result = runtime.owner.update((current) => {
                const { provider: _provider, model: _model, judge: _judge, ...rest } = current.approver;
                return {
                  ...current,
                  approver: {
                    ...rest,
                    ...(chosen ? { provider: chosen.provider, model: chosen.id } : {}),
                  },
                  approval: {
                    ...current.approval,
                    nodes: {
                      ...current.approval.nodes,
                      "builtin/llm-approver": { enabled: true },
                      "builtin/decision-approver": { enabled: false },
                    },
                  },
                };
              }, { sessionId: runtime.id });
            }

            if (!result.ok) {
              notify(ctx, `Permission settings could not be saved: ${result.messages.map((entry) => entry.message).join("\n")}`);
              continue;
            }
            if (!(await host.reload(ctx))) {
              // The candidate was not committed; resync the snapshot from
              // disk so later menu iterations read the persisted state
              // instead of stale pre-update state (which a later approver
              // model save would write back as decision disabled).
              runtime.owner.reload({ sessionId: runtime.id });
              notify(ctx, "Settings saved, but approval chain reload failed.", "warning");
            } else {
              notify(ctx, "Permission settings saved.", "info");
            }
          } catch (error) {
            notify(ctx, `Permission settings failed: ${error instanceof Error ? error.message : String(error)}`, "warning");
          }
        }
      }

      if (!trimmed && ctx.hasUI) {
        const current = runtime.owner.snapshot({ sessionId: runtime.id }).config.mode;
        const modes = [
          ["read-only", "Deny writes and network access"],
          ["default", "Ask about external writes and network access"],
          ["auto-review", "Use configured model reviewers for requests"],
          ["full-access", "Allow remaining requests without prompts"],
        ] as const;
        const choices = modes.map(([mode, description]) =>
          `${mode}${mode === current ? " (current)" : ""} - ${description}`);
        const selected = await ctx.ui.select("Permission mode", choices);
        if (selected === undefined) return;
        const index = choices.indexOf(selected);
        const mode = modes[index]?.[0];
        if (mode === undefined) return;
        runtime.owner.setSessionMode(runtime.id, mode);
        host.setSessionMode(runtime.id, mode);
        bypass.syncMode(mode, runtime.id);
        notify(ctx, `Approval mode set to "${mode}" for the current session only.`, "info");
        return;
      }

      handlePermissionCommand(args, {
        sessionId: runtime.id,
        snapshot: (sessionId) => runtime.owner.snapshot({ sessionId }),
        notify: (message) => notify(ctx, message, "info"),
      });
    },
  });

  api.on("session_shutdown", async (_event, ctx) => {
    const id = ctx.sessionManager.getSessionId();
    const runtime = runtimes.get(id);
    if (runtime === undefined || runtime.disposed) return;
    runtime.disposed = true;
    unpublishPermissionsService(id);
    runtime.sessionRules.shutdown();
    await runtime.nodeHost.dispose();
    runtimes.delete(id);
    bypass.clearSession(id);
  });
}
