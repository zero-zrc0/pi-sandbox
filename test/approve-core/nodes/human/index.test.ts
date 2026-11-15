import { describe, expect, it, vi } from "vitest";
import type { ExecutionRequest } from "../../../../src/elevation";
import type { HumanRequest, HumanResponse } from "#approve-core/runtime";
import {
  DEFAULT_HUMAN_REASON_PREFIX,
  DEFAULT_HUMAN_TIMEOUT_MS,
  HUMAN_APPROVE_OPTION,
  HUMAN_CANCEL_OPTION,
  HUMAN_DENY_OPTION,
  createHumanApprover,
  createHumanPrompt,
  createHumanSelectionPort,
  createHumanSelectorComponent,
  describeHumanRequest,
  formatToolInputPreview,
  createPromptToolInputFormatter,
  summarizeBuiltinToolInput,
  type HumanAuditEvent,
  type HumanPromptHost,
  type HumanPromptView,
} from "#approve-core/nodes/human";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

interface RequestOverrides {
  readonly toolName?: string;
  readonly arguments?: Record<string, unknown>;
  readonly askFor?: "allow" | "escalate";
  readonly reasons?: readonly string[];
  readonly hostExecutionRequest?: ExecutionRequest;
  readonly signal?: AbortSignal;
  readonly stepKey?: string;
  readonly toolCallId?: string;
}

function makeRequest(overrides: RequestOverrides = {}): HumanRequest {
  const toolCallId = overrides.toolCallId ?? "call-1";
  return {
    capture: { stepKey: overrides.stepKey ?? "step-1" } as never,
    call: {
      toolCallId,
      toolName: overrides.toolName ?? "write",
      arguments: overrides.arguments ?? { path: "a.txt", content: "hello" },
      ...(overrides.hostExecutionRequest === undefined
        ? {}
        : { hostExecutionRequest: overrides.hostExecutionRequest }),
    } as never,
    summary: {
      toolCallId,
      decision: "ask",
      ...(overrides.askFor === undefined ? {} : { askFor: overrides.askFor }),
      reasons: (overrides.reasons ?? ["outside the workspace"]).map((reason, index) => ({
        unitId: `unit-${index}`,
        decision: "ask",
        reason,
      })),
      pendingUnitIds: ["unit-0"],
    } as never,
    state: {} as never,
    signal: overrides.signal ?? new AbortController().signal,
  };
}

function deferred<T>(): {
  readonly promise: Promise<T>;
  readonly resolve: (value: T) => void;
  readonly reject: (error: unknown) => void;
} {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function sleep(ms = 0): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

interface TimerPort {
  readonly setTimer: (callback: () => void, ms: number) => unknown;
  readonly clearTimer: (handle: unknown) => void;
  readonly pendingMs: () => number[];
  readonly fireAll: () => void;
  readonly size: () => number;
}

function makeTimers(): TimerPort {
  let nextId = 1;
  const pending = new Map<number, { readonly callback: () => void; readonly ms: number }>();
  return {
    setTimer: (callback, ms) => {
      const id = nextId;
      nextId += 1;
      pending.set(id, { callback, ms });
      return id;
    },
    clearTimer: (handle) => {
      pending.delete(handle as number);
    },
    pendingMs: () => [...pending.values()].map((entry) => entry.ms),
    fireAll: () => {
      for (const [id, entry] of [...pending.entries()]) {
        pending.delete(id);
        entry.callback();
      }
    },
    size: () => pending.size,
  };
}

function makeAudit(): { readonly events: HumanAuditEvent[]; readonly port: { record: (event: HumanAuditEvent) => void } } {
  const events: HumanAuditEvent[] = [];
  return { events, port: { record: (event) => events.push(event) } };
}

function makeHost(select: HumanPromptHost["ui"]["select"], extra: Partial<HumanPromptHost> = {}): HumanPromptHost {
  return { hasUI: true, ui: { select }, ...extra };
}

// ---------------------------------------------------------------------------
// describeHumanRequest (§1 prompt facts)
// ---------------------------------------------------------------------------

describe("describeHumanRequest", () => {
  it("names the tool and the recorded reason for a normal request", () => {
    const facts = describeHumanRequest(makeRequest({ toolName: "write", reasons: ["outside the workspace"] }));
    expect(facts.escalation).toBe(false);
    expect(facts.askFor).toBe("allow");
    expect(facts.toolName).toBe("write");
    expect(facts.toolCallId).toBe("call-1");
    expect(facts.reason).toBe("outside the workspace");
    expect(facts.title).toBe("Approve write call? Reason: outside the workspace");
  });

  it("joins every recorded reason", () => {
    const facts = describeHumanRequest(makeRequest({ reasons: ["first", "second"] }));
    expect(facts.reason).toBe("first; second");
  });

  it("falls back when no reason was recorded", () => {
    expect(describeHumanRequest(makeRequest({ reasons: [] })).reason).toBe("no reason was recorded");
  });

  it("labels an ordinary escalation as unavailable for Host execution", () => {
    const facts = describeHumanRequest(makeRequest({ askFor: "escalate" }));
    expect(facts.escalation).toBe(true);
    expect(facts.askFor).toBe("escalate");
    expect(facts.title).toContain("Ordinary write call cannot receive Host execution");
    expect(facts.title).toContain("Reason: outside the workspace");
  });

  it("escalates when the call carries a host execution request", () => {
    const facts = describeHumanRequest(
      makeRequest({ hostExecutionRequest: {
        reason: "sandbox blocked it",
        elevation: { tier: "host", scope: [{ path: "/outside/target", access: "write" }] },
      } }),
    );
    expect(facts.escalation).toBe(true);
    expect(facts.askFor).toBe("escalate");
    expect(facts.title).toContain("Host execution request for write (outside the OS sandbox)");
  });

  it("uses the ordinary Host denial reason when no tier was requested", () => {
    const facts = describeHumanRequest(makeRequest({ askFor: "escalate", reasons: [] }));
    expect(facts.reason).toBe("ordinary approvals cannot grant Host execution");
  });

  it("never disguises a normal request as an escalation", () => {
    const facts = describeHumanRequest(makeRequest());
    expect(facts.escalation).toBe(false);
    expect(facts.title.toLowerCase()).not.toContain("host execution");
    expect(facts.title.toLowerCase()).not.toContain("escalat");
  });

  it("falls back to a generic tool name and exposes the fixed options", () => {
    const facts = describeHumanRequest(makeRequest({ toolName: "   " }));
    expect(facts.toolName).toBe("tool");
    expect(facts.options).toEqual([HUMAN_CANCEL_OPTION, HUMAN_APPROVE_OPTION, HUMAN_DENY_OPTION]);
    expect(facts.approveOption).toBe(HUMAN_APPROVE_OPTION);
    expect(facts.denyOption).toBe(HUMAN_DENY_OPTION);
    expect(facts.cancelOption).toBe(HUMAN_CANCEL_OPTION);
  });

  it("keeps the original arguments available for the prompt", () => {
    const args = { path: "b.txt", content: "x" };
    expect(describeHumanRequest(makeRequest({ arguments: args })).arguments).toEqual(args);
  });
});

// ---------------------------------------------------------------------------
// TUI selector component (§9: no initial highlight, confirm only after moving)
// ---------------------------------------------------------------------------

const DOWN = "\u001b[B";
const UP = "\u001b[A";
const ENTER = "\r";
const ESCAPE = "\u001b";
const CTRL_C = "\u0003";

function makeSelector(): {
  component: ReturnType<typeof createHumanSelectorComponent>;
  selected: string[];
  cancelled: () => number;
  render: () => string[];
} {
  const selected: string[] = [];
  let cancels = 0;
  const component = createHumanSelectorComponent({
    title: "Approve write call?",
    options: [HUMAN_CANCEL_OPTION, HUMAN_APPROVE_OPTION, HUMAN_DENY_OPTION],
    onSelect: (option) => selected.push(option),
    onCancel: () => {
      cancels += 1;
    },
  });
  return { component, selected, cancelled: () => cancels, render: () => component.render(120) };
}

describe("createHumanSelectorComponent", () => {
  it("renders the title and options without any initial highlight", () => {
    const { component, render } = makeSelector();
    const lines = render();
    expect(lines[0]).toContain("Approve write call?");
    expect(lines.join("\n")).toContain(HUMAN_APPROVE_OPTION);
    expect(component.selectedIndex).toBe(-1);
    expect(lines.join("\n")).not.toContain("→");
  });

  it("moves to the first option after the first down key", () => {
    const { component, render } = makeSelector();
    component.handleInput(DOWN);
    expect(component.selectedIndex).toBe(0);
    expect(render().join("\n")).toContain(`→ ${HUMAN_CANCEL_OPTION}`);
  });

  it("does not confirm with Enter while nothing is highlighted", () => {
    const { component, selected, cancelled } = makeSelector();
    component.handleInput(ENTER);
    expect(selected).toEqual([]);
    expect(cancelled()).toBe(0);
  });

  it("confirms the highlighted option with Enter", () => {
    const { component, selected } = makeSelector();
    component.handleInput(DOWN);
    component.handleInput(DOWN);
    component.handleInput(ENTER);
    expect(selected).toEqual([HUMAN_APPROVE_OPTION]);
  });

  it("clamps movement at both ends", () => {
    const { component } = makeSelector();
    component.handleInput(DOWN);
    component.handleInput(DOWN);
    component.handleInput(DOWN);
    component.handleInput(DOWN);
    expect(component.selectedIndex).toBe(2);
    component.handleInput(UP);
    component.handleInput(UP);
    component.handleInput(UP);
    expect(component.selectedIndex).toBe(0);
  });

  it("wraps to the last option when moving up from no selection", () => {
    const { component } = makeSelector();
    component.handleInput(UP);
    expect(component.selectedIndex).toBe(2);
  });

  it("cancels on Esc without selecting anything", () => {
    const { component, selected, cancelled } = makeSelector();
    component.handleInput(DOWN);
    component.handleInput(ESCAPE);
    expect(cancelled()).toBe(1);
    expect(selected).toEqual([]);
  });

  it("cancels on Ctrl+C", () => {
    const { component, cancelled } = makeSelector();
    component.handleInput(CTRL_C);
    expect(cancelled()).toBe(1);
  });

  it("ignores unrelated keys", () => {
    const { component } = makeSelector();
    component.handleInput("x");
    expect(component.selectedIndex).toBe(-1);
  });

  it("settles once: later keys are ignored", () => {
    const { component, selected, cancelled } = makeSelector();
    component.handleInput(DOWN);
    component.handleInput(ENTER);
    component.handleInput(DOWN);
    component.handleInput(ESCAPE);
    expect(selected).toEqual([HUMAN_CANCEL_OPTION]);
    expect(cancelled()).toBe(0);
    expect(component.selectedIndex).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Default prompt port (UI / RPC / TUI modes)
// ---------------------------------------------------------------------------

const SAMPLE_VIEW: HumanPromptView = {
  title: "Approve write call? Reason: outside the workspace",
  options: [HUMAN_CANCEL_OPTION, HUMAN_APPROVE_OPTION, HUMAN_DENY_OPTION],
  approveOption: HUMAN_APPROVE_OPTION,
  denyOption: HUMAN_DENY_OPTION,
  cancelOption: HUMAN_CANCEL_OPTION,
};

describe("createHumanPrompt", () => {
  it("returns no selection when the host has no UI and never prompts", async () => {
    const select = vi.fn(async () => HUMAN_APPROVE_OPTION);
    const prompt = createHumanPrompt({ hasUI: false, ui: { select } });
    expect(await prompt(SAMPLE_VIEW, makeRequest())).toBeUndefined();
    expect(select).not.toHaveBeenCalled();
  });

  it("uses the host selector outside TUI mode and forwards the abort signal", async () => {
    const select = vi.fn(async () => HUMAN_DENY_OPTION);
    const prompt = createHumanPrompt(makeHost(select, { mode: "rpc" }), { timeoutMs: 1_234 });
    const request = makeRequest();
    expect(await prompt(SAMPLE_VIEW, request)).toBe(HUMAN_DENY_OPTION);
    expect(select).toHaveBeenCalledTimes(1);
    const [title, options, opts] = select.mock.calls[0] as unknown as [string, string[], { signal?: AbortSignal; timeout?: number }];
    expect(title).toBe(SAMPLE_VIEW.title);
    expect(options).toEqual([...SAMPLE_VIEW.options]);
    expect(opts.signal).toBe(request.signal);
    expect(opts.timeout).toBe(1_234);
  });

  it("treats a throwing selector as no selection instead of failing", async () => {
    const prompt = createHumanPrompt(makeHost(async () => {
      throw new Error("ui exploded");
    }));
    expect(await prompt(SAMPLE_VIEW, makeRequest())).toBeUndefined();
  });

  it("uses the custom component in TUI mode and resolves its selection", async () => {
    const select = vi.fn(async () => HUMAN_APPROVE_OPTION);
    const custom = vi.fn(async (factory: (tui: unknown, theme: unknown, keys: unknown, done: (result: unknown) => void) => { handleInput(data: string): void }) => {
      const settled = deferred<unknown>();
      const component = factory(undefined, undefined, undefined, (result) => settled.resolve(result));
      component.handleInput(DOWN);
      component.handleInput(DOWN);
      component.handleInput(ENTER);
      return settled.promise;
    });
    const prompt = createHumanPrompt(makeHost(select, { mode: "tui", ui: { select, custom: custom as never } }));
    expect(await prompt(SAMPLE_VIEW, makeRequest())).toBe(HUMAN_APPROVE_OPTION);
    expect(custom).toHaveBeenCalledTimes(1);
    expect(select).not.toHaveBeenCalled();
  });

  it("cancels in TUI mode when the custom component is cancelled", async () => {
    const custom = vi.fn(async (factory: (tui: unknown, theme: unknown, keys: unknown, done: (result: unknown) => void) => { handleInput(data: string): void }) => {
      const settled = deferred<unknown>();
      const component = factory(undefined, undefined, undefined, (result) => settled.resolve(result));
      component.handleInput(ESCAPE);
      return settled.promise;
    });
    const prompt = createHumanPrompt(makeHost(async () => HUMAN_APPROVE_OPTION, { mode: "tui", ui: { select: async () => HUMAN_APPROVE_OPTION, custom: custom as never } }));
    expect(await prompt(SAMPLE_VIEW, makeRequest())).toBeUndefined();
  });

  it("falls back to the selector when TUI mode has no custom component", async () => {
    const select = vi.fn(async () => HUMAN_CANCEL_OPTION);
    const prompt = createHumanPrompt(makeHost(select, { mode: "tui" }));
    expect(await prompt(SAMPLE_VIEW, makeRequest())).toBe(HUMAN_CANCEL_OPTION);
  });

  it("treats a throwing custom component as no selection", async () => {
    const prompt = createHumanPrompt(makeHost(
      async () => HUMAN_APPROVE_OPTION,
      { mode: "tui", ui: { select: async () => HUMAN_APPROVE_OPTION, custom: async () => { throw new Error("no tui"); } } },
    ));
    expect(await prompt(SAMPLE_VIEW, makeRequest())).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// createHumanApprover: decision mapping
// ---------------------------------------------------------------------------

function makeApprover(options: Partial<Parameters<typeof createHumanApprover>[0]> = {}): ReturnType<typeof createHumanApprover> {
  return createHumanApprover({ prompt: async () => HUMAN_APPROVE_OPTION, generation: () => 3, ...options });
}

describe("createHumanApprover decision mapping", () => {
  it("maps the approve option to an approval", async () => {
    const response = await makeApprover()(makeRequest());
    expect(response).toEqual({ decision: "approve", reason: `${DEFAULT_HUMAN_REASON_PREFIX}:approved` });
  });

  it("maps the deny option to a denial", async () => {
    const response = await makeApprover({ prompt: async () => HUMAN_DENY_OPTION })(makeRequest());
    expect(response).toEqual({ decision: "deny", reason: `${DEFAULT_HUMAN_REASON_PREFIX}:denied` });
  });

  it("maps the cancel option to a cancellation", async () => {
    const response = await makeApprover({ prompt: async () => HUMAN_CANCEL_OPTION })(makeRequest());
    expect(response).toEqual({ decision: "cancel", reason: `${DEFAULT_HUMAN_REASON_PREFIX}:cancelled` });
  });

  it("maps no selection to an unavailable cancellation, never an approval", async () => {
    const response = await makeApprover({ prompt: async () => undefined })(makeRequest());
    expect(response).toEqual({ decision: "cancel", reason: `${DEFAULT_HUMAN_REASON_PREFIX}:unavailable` });
  });

  it("maps a thrown prompt to unavailable", async () => {
    const response = await makeApprover({ prompt: async () => { throw new Error("boom"); } })(makeRequest());
    expect(response.decision).toBe("cancel");
    expect(response.reason).toBe(`${DEFAULT_HUMAN_REASON_PREFIX}:unavailable`);
  });

  it("gives an unknown option its own invalid-selection diagnostic", async () => {
    const response = await makeApprover({ prompt: async () => "Something else" })(makeRequest());
    expect(response).toEqual({ decision: "cancel", reason: `${DEFAULT_HUMAN_REASON_PREFIX}:invalid-selection` });
  });

  it("gives a non-string selection its own invalid-selection diagnostic", async () => {
    const response = await makeApprover({ prompt: async () => 42 })(makeRequest());
    expect(response).toEqual({ decision: "cancel", reason: `${DEFAULT_HUMAN_REASON_PREFIX}:invalid-selection` });
  });

  it("applies a configured reason prefix to every outcome", async () => {
    const outcomes = [
      [HUMAN_APPROVE_OPTION, "approved"],
      [HUMAN_DENY_OPTION, "denied"],
      [HUMAN_CANCEL_OPTION, "cancelled"],
    ] as const;
    for (const [option, suffix] of outcomes) {
      const response = await makeApprover({ prompt: async () => option, reasonPrefix: "custom" })(makeRequest());
      expect(response.reason).toBe(`custom:${suffix}`);
    }
    const unavailable = await makeApprover({ prompt: async () => undefined, reasonPrefix: "custom" })(makeRequest());
    expect(unavailable.reason).toBe("custom:unavailable");
  });

  it("trims the configured reason prefix and falls back for a blank one", async () => {
    const trimmed = await makeApprover({ prompt: async () => HUMAN_APPROVE_OPTION, reasonPrefix: "  p: " })(makeRequest());
    expect(trimmed.reason).toBe("p::approved");
    const blank = await makeApprover({ prompt: async () => HUMAN_APPROVE_OPTION, reasonPrefix: "   " })(makeRequest());
    expect(blank.reason).toBe(`${DEFAULT_HUMAN_REASON_PREFIX}:approved`);
  });
});

// ---------------------------------------------------------------------------
// createHumanApprover: prompt composition
// ---------------------------------------------------------------------------

describe("createHumanApprover prompt composition", () => {
  it("appends the formatted tool input preview to the title", async () => {
    const views: HumanPromptView[] = [];
    const approver = makeApprover({
      prompt: async (view) => {
        views.push(view);
        return HUMAN_APPROVE_OPTION;
      },
    });
    await approver(makeRequest({ toolName: "read", arguments: { path: "src/a.ts" } }));
    expect(views[0]?.title).toBe("Approve read call? Reason: outside the workspace with input read src/a.ts");
  });

  it("lets the caller override the input formatter", async () => {
    const views: HumanPromptView[] = [];
    const approver = makeApprover({
      prompt: async (view) => {
        views.push(view);
        return HUMAN_APPROVE_OPTION;
      },
      formatInput: (toolName, input) => `${toolName}:${JSON.stringify(input)}`,
    });
    await approver(makeRequest({ toolName: "custom", arguments: { a: 1 } }));
    expect(views[0]?.title).toContain('with input custom:{"a":1}');
  });

  it("omits the input clause when the formatter has no preview", async () => {
    const views: HumanPromptView[] = [];
    const approver = makeApprover({
      prompt: async (view) => {
        views.push(view);
        return HUMAN_APPROVE_OPTION;
      },
      formatInput: () => undefined,
    });
    await approver(makeRequest());
    expect(views[0]?.title).toBe("Approve write call? Reason: outside the workspace");
    expect(views[0]?.title).not.toContain("with input");
  });

  it("protects the prompt when the formatter throws", async () => {
    const response = await makeApprover({
      prompt: async () => HUMAN_APPROVE_OPTION,
      formatInput: () => {
        throw new Error("formatter exploded");
      },
    })(makeRequest());
    expect(response.decision).toBe("approve");
  });

  it("uses a caller supplied describer instead of the default facts", async () => {
    const views: HumanPromptView[] = [];
    const approver = makeApprover({
      prompt: async (view) => {
        views.push(view);
        return HUMAN_APPROVE_OPTION;
      },
      describe: () => ({
        title: "Custom prompt",
        options: ["a", "b"],
        approveOption: "a",
        denyOption: "b",
        cancelOption: "c",
      }),
      formatInput: () => undefined,
    });
    await approver(makeRequest());
    expect(views[0]?.title).toBe("Custom prompt");
  });
});

// ---------------------------------------------------------------------------
// createHumanApprover: timeout, abort and cleanup
// ---------------------------------------------------------------------------

describe("createHumanApprover timeout", () => {
  it("uses the five minute local timeout by default", async () => {
    const timers = makeTimers();
    const gate = deferred<unknown>();
    const promise = createHumanApprover({
      prompt: () => gate.promise,
      generation: () => 1,
      setTimer: timers.setTimer,
      clearTimer: timers.clearTimer,
    })(makeRequest());
    await sleep();
    expect(timers.pendingMs()).toEqual([DEFAULT_HUMAN_TIMEOUT_MS]);
    timers.fireAll();
    expect(await promise).toEqual({ decision: "cancel", reason: `${DEFAULT_HUMAN_REASON_PREFIX}:timeout` });
  });

  it("honors a finite positive override", async () => {
    const timers = makeTimers();
    const promise = createHumanApprover({
      prompt: () => deferred<unknown>().promise,
      generation: () => 1,
      timeoutMs: 1_500,
      setTimer: timers.setTimer,
      clearTimer: timers.clearTimer,
    })(makeRequest());
    await sleep();
    expect(timers.pendingMs()).toEqual([1_500]);
    timers.fireAll();
    await promise;
  });

  it("ignores non-positive or non-finite overrides and keeps the default timeout", async () => {
    for (const timeoutMs of [0, -5, Number.NaN, Number.POSITIVE_INFINITY]) {
      const timers = makeTimers();
      const promise = createHumanApprover({
        prompt: () => deferred<unknown>().promise,
        generation: () => 1,
        timeoutMs,
        setTimer: timers.setTimer,
        clearTimer: timers.clearTimer,
      })(makeRequest());
      await sleep();
      expect(timers.pendingMs(), String(timeoutMs)).toEqual([DEFAULT_HUMAN_TIMEOUT_MS]);
      timers.fireAll();
      await promise;
    }
  });

  it("honors a finite fractional override as a finite positive number", async () => {
    const timers = makeTimers();
    const promise = createHumanApprover({
      prompt: () => deferred<unknown>().promise,
      generation: () => 1,
      timeoutMs: 1_500.5,
      setTimer: timers.setTimer,
      clearTimer: timers.clearTimer,
    })(makeRequest());
    await sleep();
    expect(timers.pendingMs()).toEqual([1_500.5]);
    timers.fireAll();
    await promise;
  });

  it("clears the timer once the prompt answers", async () => {
    const timers = makeTimers();
    const gate = deferred<unknown>();
    const promise = createHumanApprover({
      prompt: () => gate.promise,
      generation: () => 1,
      setTimer: timers.setTimer,
      clearTimer: timers.clearTimer,
    })(makeRequest());
    await sleep();
    gate.resolve(HUMAN_APPROVE_OPTION);
    expect((await promise).decision).toBe("approve");
    expect(timers.size()).toBe(0);
  });

  it("ignores a prompt answer that arrives after the timeout", async () => {
    const timers = makeTimers();
    const gate = deferred<unknown>();
    const audit = makeAudit();
    const promise = createHumanApprover({
      prompt: () => gate.promise,
      generation: () => 1,
      audit: audit.port,
      setTimer: timers.setTimer,
      clearTimer: timers.clearTimer,
    })(makeRequest());
    await sleep();
    timers.fireAll();
    gate.resolve(HUMAN_APPROVE_OPTION);
    expect((await promise).reason).toBe(`${DEFAULT_HUMAN_REASON_PREFIX}:timeout`);
    expect(audit.events.filter((event) => event.kind === "answered")).toHaveLength(0);
  });
});

describe("createHumanApprover abort", () => {
  it("cancels immediately when the request arrives already aborted", async () => {
    const controller = new AbortController();
    controller.abort();
    const prompt = vi.fn(async () => HUMAN_APPROVE_OPTION);
    const response = await createHumanApprover({ prompt, generation: () => 1 })(makeRequest({ signal: controller.signal }));
    expect(response).toEqual({ decision: "cancel", reason: `${DEFAULT_HUMAN_REASON_PREFIX}:aborted` });
    expect(prompt).not.toHaveBeenCalled();
  });

  it("does not wait behind the serial queue when the request arrives aborted", async () => {
    const gate = deferred<unknown>();
    const prompt = vi.fn(() => gate.promise);
    const approver = createHumanApprover({ prompt, generation: () => 1 });
    const first = approver(makeRequest({ toolName: "first" }));
    await sleep();
    expect(prompt).toHaveBeenCalledTimes(1);

    const controller = new AbortController();
    controller.abort();
    const aborted = await approver(makeRequest({ toolName: "second", signal: controller.signal }));
    expect(aborted.reason).toBe(`${DEFAULT_HUMAN_REASON_PREFIX}:aborted`);
    expect(prompt).toHaveBeenCalledTimes(1);

    gate.resolve(HUMAN_APPROVE_OPTION);
    expect((await first).decision).toBe("approve");
  });

  it("races the prompt against abort and removes the listener after settling", async () => {
    const controller = new AbortController();
    const removeSpy = vi.spyOn(controller.signal, "removeEventListener");
    const timers = makeTimers();
    const gate = deferred<unknown>();
    const promise = createHumanApprover({
      prompt: () => gate.promise,
      generation: () => 1,
      setTimer: timers.setTimer,
      clearTimer: timers.clearTimer,
    })(makeRequest({ signal: controller.signal }));
    await sleep();
    controller.abort();
    expect(await promise).toEqual({ decision: "cancel", reason: `${DEFAULT_HUMAN_REASON_PREFIX}:aborted` });
    expect(removeSpy).toHaveBeenCalledWith("abort", expect.any(Function));
    expect(timers.size()).toBe(0);
  });

  it("ignores a prompt answer after an abort", async () => {
    const controller = new AbortController();
    const gate = deferred<unknown>();
    const promise = createHumanApprover({ prompt: () => gate.promise, generation: () => 1 })(makeRequest({ signal: controller.signal }));
    await sleep();
    controller.abort();
    const response = await promise;
    gate.resolve(HUMAN_APPROVE_OPTION);
    expect(response.reason).toBe(`${DEFAULT_HUMAN_REASON_PREFIX}:aborted`);
  });

  it("clears the timer after an abort", async () => {
    const controller = new AbortController();
    const timers = makeTimers();
    const promise = createHumanApprover({
      prompt: () => deferred<unknown>().promise,
      generation: () => 1,
      setTimer: timers.setTimer,
      clearTimer: timers.clearTimer,
    })(makeRequest({ signal: controller.signal }));
    await sleep();
    controller.abort();
    await promise;
    expect(timers.size()).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// createHumanApprover: serial and parallel prompting
// ---------------------------------------------------------------------------

describe("createHumanApprover concurrency", () => {
  it("shows prompts serially by default and preserves order", async () => {
    const gates = [deferred<unknown>(), deferred<unknown>()];
    const seen: string[] = [];
    const prompt = (view: HumanPromptView) => {
      seen.push(view.title);
      return gates[seen.length - 1]!.promise;
    };
    const approver = createHumanApprover({ prompt, generation: () => 1 });
    const first = approver(makeRequest({ toolName: "first" }));
    await sleep();
    const second = approver(makeRequest({ toolName: "second" }));
    await sleep();
    expect(seen).toHaveLength(1);
    expect(seen[0]).toContain("first");
    gates[0]!.resolve(HUMAN_APPROVE_OPTION);
    expect((await first).decision).toBe("approve");
    await sleep();
    expect(seen).toHaveLength(2);
    expect(seen[1]).toContain("second");
    gates[1]!.resolve(HUMAN_DENY_OPTION);
    expect((await second).decision).toBe("deny");
  });

  it("keeps draining the serial queue after a prompt failure", async () => {
    const seen: string[] = [];
    const prompt = (view: HumanPromptView) => {
      seen.push(view.title);
      if (seen.length === 1) throw new Error("first prompt failed");
      return Promise.resolve(HUMAN_APPROVE_OPTION);
    };
    const approver = createHumanApprover({ prompt, generation: () => 1 });
    const first = approver(makeRequest({ toolName: "first" }));
    const second = approver(makeRequest({ toolName: "second" }));
    expect((await first).reason).toBe(`${DEFAULT_HUMAN_REASON_PREFIX}:unavailable`);
    expect((await second).decision).toBe("approve");
    expect(seen).toHaveLength(2);
  });

  it("keeps draining the serial queue after a timeout", async () => {
    const timers = makeTimers();
    const gates = [deferred<unknown>(), deferred<unknown>()];
    let calls = 0;
    const approver = createHumanApprover({
      prompt: () => {
        calls += 1;
        return calls === 1 ? gates[0]!.promise : gates[1]!.promise;
      },
      generation: () => 1,
      setTimer: timers.setTimer,
      clearTimer: timers.clearTimer,
    });
    const first = approver(makeRequest({ toolName: "first" }));
    const second = approver(makeRequest({ toolName: "second" }));
    await sleep();
    expect(calls).toBe(1);
    timers.fireAll();
    expect((await first).reason).toBe(`${DEFAULT_HUMAN_REASON_PREFIX}:timeout`);
    await sleep();
    expect(calls).toBe(2);
    gates[1]!.resolve(HUMAN_APPROVE_OPTION);
    expect((await second).decision).toBe("approve");
  });

  it("shows prompts in parallel when configured", async () => {
    const gates = [deferred<unknown>(), deferred<unknown>()];
    let calls = 0;
    const approver = createHumanApprover({
      prompt: () => {
        calls += 1;
        return gates[calls - 1]!.promise;
      },
      generation: () => 1,
      concurrency: "parallel",
    });
    const first = approver(makeRequest({ toolName: "first" }));
    const second = approver(makeRequest({ toolName: "second" }));
    await sleep();
    expect(calls).toBe(2);
    gates[1]!.resolve(HUMAN_DENY_OPTION);
    gates[0]!.resolve(HUMAN_APPROVE_OPTION);
    expect((await first).decision).toBe("approve");
    expect((await second).decision).toBe("deny");
  });
});

// ---------------------------------------------------------------------------
// createHumanApprover: audit
// ---------------------------------------------------------------------------

describe("createHumanApprover audit", () => {
  it("records the prompt and the answer with generation, step, tool and askFor", async () => {
    const audit = makeAudit();
    const approver = createHumanApprover({
      prompt: async () => HUMAN_APPROVE_OPTION,
      generation: () => 9,
      audit: audit.port,
    });
    await approver(makeRequest({ toolName: "bash", stepKey: "step-7", toolCallId: "call-9", askFor: "escalate" }));
    expect(audit.events).toHaveLength(2);
    expect(audit.events[0]).toMatchObject({
      kind: "prompt",
      generation: 9,
      stepKey: "step-7",
      toolCallId: "call-9",
      toolName: "bash",
      askFor: "escalate",
      escalation: true,
    });
    expect(audit.events[1]).toMatchObject({
      kind: "answered",
      generation: 9,
      stepKey: "step-7",
      toolCallId: "call-9",
      toolName: "bash",
      askFor: "escalate",
      escalation: true,
      decision: "approve",
      reason: `${DEFAULT_HUMAN_REASON_PREFIX}:approved`,
    });
  });

  it("records unavailable outcomes with the cancellation decision", async () => {
    const audit = makeAudit();
    const response = await createHumanApprover({
      prompt: async () => {
        throw new Error("no ui");
      },
      generation: () => 2,
      audit: audit.port,
    })(makeRequest());
    expect(response.decision).toBe("cancel");
    const unavailable = audit.events.find((event) => event.kind === "unavailable");
    expect(unavailable).toMatchObject({
      kind: "unavailable",
      generation: 2,
      decision: "cancel",
      reason: `${DEFAULT_HUMAN_REASON_PREFIX}:unavailable`,
    });
  });

  it("records the abort reason for an aborted request", async () => {
    const controller = new AbortController();
    controller.abort();
    const audit = makeAudit();
    await createHumanApprover({ prompt: async () => HUMAN_APPROVE_OPTION, generation: () => 1, audit: audit.port })(
      makeRequest({ signal: controller.signal }),
    );
    expect(audit.events).toEqual([
      expect.objectContaining({ kind: "unavailable", decision: "cancel", reason: `${DEFAULT_HUMAN_REASON_PREFIX}:aborted` }),
    ]);
  });

  it("keeps the decision when the audit sink throws", async () => {
    const prompt = vi.fn(async () => HUMAN_APPROVE_OPTION);
    const response = await createHumanApprover({
      prompt,
      generation: () => 1,
      audit: {
        record: () => {
          throw new Error("audit write failed");
        },
      },
    })(makeRequest());
    expect(response).toEqual({ decision: "approve", reason: `${DEFAULT_HUMAN_REASON_PREFIX}:approved` });
  });

  it("keeps the decision when the generation reader throws", async () => {
    const audit = makeAudit();
    const response = await createHumanApprover({
      prompt: async () => HUMAN_APPROVE_OPTION,
      generation: () => {
        throw new Error("no generation");
      },
      audit: audit.port,
    })(makeRequest());
    expect(response.decision).toBe("approve");
    expect(audit.events[0]).toMatchObject({ kind: "prompt", generation: 0 });
  });

  it("works without an audit sink", async () => {
    const response = await makeApprover()(makeRequest());
    expect(response.decision).toBe("approve");
  });
});

// ---------------------------------------------------------------------------
// Selection port bridge (Phase 12 HumanSelectionPort shape)
// ---------------------------------------------------------------------------

describe("createHumanSelectionPort", () => {
  it("maps the approve and deny options to responses", async () => {
    const approve = createHumanSelectionPort(makeHost(async () => HUMAN_APPROVE_OPTION));
    expect(await approve(makeRequest())).toEqual({ decision: "approve", reason: `${DEFAULT_HUMAN_REASON_PREFIX}:approved` });
    const deny = createHumanSelectionPort(makeHost(async () => HUMAN_DENY_OPTION));
    expect(await deny(makeRequest())).toEqual({ decision: "deny", reason: `${DEFAULT_HUMAN_REASON_PREFIX}:denied` });
  });

  it("maps the cancel option to a cancellation", async () => {
    const port = createHumanSelectionPort(makeHost(async () => HUMAN_CANCEL_OPTION));
    expect(await port(makeRequest())).toEqual({ decision: "cancel", reason: `${DEFAULT_HUMAN_REASON_PREFIX}:cancelled` });
  });

  it("returns no selection when the host has no UI or the answer is unknown", async () => {
    expect(await createHumanSelectionPort({ hasUI: false, ui: { select: async () => HUMAN_APPROVE_OPTION } })(makeRequest())).toBeUndefined();
    expect(await createHumanSelectionPort(makeHost(async () => "mystery"))(makeRequest())).toBeUndefined();
    expect(await createHumanSelectionPort(makeHost(async () => undefined))(makeRequest())).toBeUndefined();
  });

  it("times out to no selection with the injected timer", async () => {
    const timers = makeTimers();
    const port = createHumanSelectionPort(makeHost(() => deferred<string | undefined>().promise), {
      setTimer: timers.setTimer,
      clearTimer: timers.clearTimer,
    });
    const promise = port(makeRequest());
    await sleep();
    expect(timers.pendingMs()).toEqual([DEFAULT_HUMAN_TIMEOUT_MS]);
    timers.fireAll();
    expect(await promise).toBeUndefined();
  });

  it("returns no selection for an already aborted request", async () => {
    const controller = new AbortController();
    controller.abort();
    const port = createHumanSelectionPort(makeHost(async () => HUMAN_APPROVE_OPTION));
    expect(await port(makeRequest({ signal: controller.signal }))).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Module surface
// ---------------------------------------------------------------------------

describe("human module barrel", () => {
  it("re-exports the preview, summary, prompt and log formatter entry points", () => {
    expect(typeof summarizeBuiltinToolInput).toBe("function");
    expect(typeof createPromptToolInputFormatter).toBe("function");
    expect(typeof formatToolInputPreview).toBe("function");
    expect(typeof createHumanApprover).toBe("function");
  });
});
