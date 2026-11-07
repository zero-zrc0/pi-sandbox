import { describe, expect, it } from "vitest";
import {
  analyzeWrapper,
  wrapperKindOf,
  type CommandWord,
} from "#approve-core/utils/access-intent/bash/wrapper-analysis";

function words(...values: string[]): readonly CommandWord[] {
  return values.map((value) => ({
    value,
    text: value,
    computed: false,
    mayLeadWithDash: value.startsWith("-"),
  }));
}

function computed(value: string): CommandWord {
  return { value, text: value, computed: true, mayLeadWithDash: true };
}

function names(layers: readonly { commandName: string }[]): string[] {
  return layers.map((layer) => layer.commandName);
}

function actions(analysis: ReturnType<typeof analyzeWrapper>): string[] {
  return analysis.actions.map((action) => action.text);
}

describe("wrapper classification", () => {
  it("knows the fixed indirect wrapper roster", () => {
    expect(wrapperKindOf("sudo")).toBe("privilege");
    expect(wrapperKindOf("env")).toBe("environment");
    expect(wrapperKindOf("command")).toBe("command");
    expect(wrapperKindOf("xargs")).toBe("executor");
    expect(wrapperKindOf("time")).toBe("execution-modifier");
    expect(wrapperKindOf("watch")).toBe("watcher");
    expect(wrapperKindOf("flock")).toBe("lock");
    expect(wrapperKindOf("find", words("find", "-name", "x"))).toBeUndefined();
  });

  it("treats find and fd as wrappers only with an exec clause", () => {
    expect(wrapperKindOf("find", words("find", "-exec", "rm", "{}", ";"))).toBe("finder");
    expect(wrapperKindOf("fd", words("fd", "-x", "rm"))).toBe("finder");
    expect(wrapperKindOf("fd", words("fd", "--exec-batch", "rm"))).toBe("finder");
  });
});

describe("explicit option tables", () => {
  it("unwraps sudo with separated and attached option values", () => {
    const analysis = analyzeWrapper(words("sudo", "-u", "root", "rm", "x"));
    expect(names(analysis.layers)).toEqual(["sudo"]);
    expect(analysis.layers[0]!.wrapperKind).toBe("privilege");
    expect(actions(analysis)).toEqual(["rm x"]);
    expect(analysis.complete).toBe(true);
    expect(analysis.stopReason).toBe("complete");

    expect(actions(analyzeWrapper(words("sudo", "-uroot", "rm", "x")))).toEqual(["rm x"]);
  });

  it("accepts the option terminator before the command", () => {
    expect(actions(analyzeWrapper(words("sudo", "--", "rm", "x")))).toEqual(["rm x"]);
  });

  it("stops on an unlisted sudo option", () => {
    const analysis = analyzeWrapper(words("sudo", "-Z", "rm", "x"));
    expect(analysis.complete).toBe(false);
    expect(analysis.stopReason).toBe("unknown-option");
    expect(analysis.actions).toEqual([]);
  });

  it("stops when an option may be computed", () => {
    const analysis = analyzeWrapper([words("sudo")[0]!, computed("$opts"), words("rm")[0]!]);
    expect(analysis.complete).toBe(false);
    expect(analysis.stopReason).toBe("computed-option");
  });

  it("consumes env assignments before the command", () => {
    expect(actions(analyzeWrapper(words("env", "FOO=1", "rm", "x")))).toEqual(["rm x"]);
    expect(actions(analyzeWrapper(words("sudo", "FOO=1", "rm", "x")))).toEqual(["rm x"]);
  });

  it("treats bare env as a proven no-command form", () => {
    const analysis = analyzeWrapper(words("env"));
    expect(analysis.actions).toEqual([]);
    expect(analysis.complete).toBe(true);
    expect(analysis.stopReason).toBe("no-command");
    expect(analysis.floorExemption).toBe("no-command");
  });

  it("does not excuse bare xargs", () => {
    const analysis = analyzeWrapper(words("xargs"));
    expect(analysis.complete).toBe(false);
    expect(analysis.stopReason).toBe("no-command");
    expect(analysis.floorExemption).toBeUndefined();
  });

  it("unwraps xargs options with values", () => {
    expect(actions(analyzeWrapper(words("xargs", "-n", "1", "rm", "x")))).toEqual(["rm x"]);
    expect(actions(analyzeWrapper(words("xargs", "-n1", "rm", "x")))).toEqual(["rm x"]);
  });

  it("recognizes command query mode", () => {
    const analysis = analyzeWrapper(words("command", "-v", "rm"));
    expect(analysis.actions).toEqual([]);
    expect(analysis.complete).toBe(true);
    expect(analysis.stopReason).toBe("query-mode");
    expect(analysis.floorExemption).toBe("no-command");
  });

  it("unwraps command without options", () => {
    expect(actions(analyzeWrapper(words("command", "rm", "x")))).toEqual(["rm x"]);
  });

  it("stops on an ambiguous long option", () => {
    const analysis = analyzeWrapper(words("sudo", "--l", "rm"));
    // --login and --list share the --l prefix.
    expect(analysis.complete).toBe(false);
    expect(analysis.stopReason).toBe("ambiguous-option");
  });

  it("resolves a unique long option prefix", () => {
    expect(actions(analyzeWrapper(words("sudo", "--user=root", "rm", "x")))).toEqual(["rm x"]);
  });
});

describe("opaque payloads", () => {
  it("keeps eval opaque", () => {
    const analysis = analyzeWrapper(words("eval", "rm", "-rf", "/"));
    expect(analysis.complete).toBe(false);
    expect(analysis.stopReason).toBe("opaque-payload");
    expect(analysis.executedUnit).toBe("rm -rf /");
    expect(analysis.floorExemption).toBeUndefined();
  });

  it("treats a shell -c cluster as opaque", () => {
    const analysis = analyzeWrapper(words("bash", "-xc", "rm -rf /"));
    expect(analysis.layers[0]!.wrapperKind).toBe("opaque-payload");
    expect(analysis.executedUnit).toBe("rm -rf /");
    expect(analysis.complete).toBe(false);
  });

  it("does not treat a shell script file as an opaque -c payload", () => {
    expect(analyzeWrapper(words("bash", "script.sh")).layers).toEqual([]);
    expect(analyzeWrapper(words("bash", "--", "-c", "x")).layers).toEqual([]);
    expect(analyzeWrapper(words("bash", "script.sh", "-c", "x")).layers).toEqual([]);
  });

  it("skips a shell option value before finding -c", () => {
    const analysis = analyzeWrapper(words("bash", "-O", "extglob", "-c", "rm x"));
    expect(analysis.layers[0]!.wrapperKind).toBe("opaque-payload");
    expect(analysis.executedUnit).toBe("rm x");
  });

  it("treats sudo -h as a flag, not a missing option value", () => {
    const analysis = analyzeWrapper(words("sudo", "-h"));
    expect(analysis.stopReason).toBe("no-command");
  });
});

describe("execution modifiers", () => {
  it("unwraps timeout, nice, stdbuf and setsid", () => {
    expect(actions(analyzeWrapper(words("timeout", "-s", "KILL", "5", "rm", "x")))).toEqual(["rm x"]);
    expect(actions(analyzeWrapper(words("nice", "-n", "5", "rm", "x")))).toEqual(["rm x"]);
    expect(actions(analyzeWrapper(words("stdbuf", "-oL", "rm", "x")))).toEqual(["rm x"]);
    expect(actions(analyzeWrapper(words("setsid", "rm", "x")))).toEqual(["rm x"]);
  });

  it("grants execution-modifier exemption to a plain literal inner command", () => {
    expect(analyzeWrapper(words("time", "ls")).floorExemption).toBe("execution-modifier");
    expect(analyzeWrapper(words("timeout", "5", "ls")).floorExemption).toBe("execution-modifier");
    expect(analyzeWrapper(words("nice", "-n", "5", "ls")).floorExemption).toBe("execution-modifier");
  });

  it("does not grant it when time writes a file", () => {
    const analysis = analyzeWrapper(words("time", "-o", "out", "ls"));
    expect(analysis.actions.map((action) => action.text)).toEqual(["ls"]);
    expect(analysis.floorExemption).toBeUndefined();
  });

  it("does not grant it to a computed inner command", () => {
    const analysis = analyzeWrapper([words("time")[0]!, computed("$cmd")]);
    expect(analysis.floorExemption).toBeUndefined();
  });

  it("grants core-reader when a non-modifier wrapper remains in the chain", () => {
    expect(analyzeWrapper(words("time", "sudo", "ls")).floorExemption).toBe("core-reader");
  });

  it("reports no command when the duration has no command after it", () => {
    const analysis = analyzeWrapper(words("timeout", "5"));
    expect(analysis.actions).toEqual([]);
    expect(analysis.complete).toBe(false);
    expect(analysis.stopReason).toBe("no-command");
  });
});

describe("core-reader exemption", () => {
  it("does not exempt a wrapper around a sed script that writes", () => {
    expect(analyzeWrapper(words("sudo", "sed", "w output", "input")).floorExemption).toBeUndefined();
  });

  it("grants it to a wrapper around a pure reader", () => {
    expect(analyzeWrapper(words("sudo", "cat", "file")).floorExemption).toBe("core-reader");
    expect(analyzeWrapper(words("env", "cat", "file")).floorExemption).toBe("core-reader");
  });

  it("does not grant it to a path-qualified reader", () => {
    expect(analyzeWrapper(words("sudo", "/bin/cat", "file")).floorExemption).toBeUndefined();
  });

  it("does not grant it when a redirect writes a file", () => {
    expect(analyzeWrapper(words("sudo", "cat", "file"), { redirectsWrite: true }).floorExemption)
      .toBeUndefined();
  });

  it("does not grant it when a layer has a computed argument", () => {
    const analysis = analyzeWrapper([words("sudo")[0]!, computed("$target")]);
    expect(analysis.floorExemption).toBeUndefined();
  });

  it("does not grant it to watch or template rebuilders", () => {
    expect(analyzeWrapper(words("watch", "cat", "file")).floorExemption).toBeUndefined();
    expect(analyzeWrapper(words("parallel", "cat", "file")).floorExemption).toBeUndefined();
  });
});

describe("find and fd exec clauses", () => {
  it("collects every independent find exec payload", () => {
    const analysis = analyzeWrapper(words("find", ".", "-exec", "rm", "{}", ";", "-exec", "ls", "{}", "+"));
    expect(actions(analysis)).toEqual(["rm {}", "ls {}"]);
    expect(analysis.complete).toBe(true);
  });

  it("keeps each action's source words, including their offsets", () => {
    const argv: CommandWord[] = [
      { value: "sudo", text: "sudo", computed: false, mayLeadWithDash: false, startIndex: 0 },
      { value: "rm", text: "rm", computed: false, mayLeadWithDash: false, startIndex: 5 },
      { value: "x", text: "x", computed: false, mayLeadWithDash: false, startIndex: 8 },
    ];
    const analysis = analyzeWrapper(argv);
    expect(analysis.actions[0]!.words.map((word) => word.startIndex)).toEqual([5, 8]);
  });

  it("keeps escaped semicolon out of the inner command", () => {
    expect(actions(analyzeWrapper(words("find", ".", "-exec", "rm", "{}", "\\;")))).toEqual(["rm {}"]);
  });

  it("accepts find leading options before the search paths", () => {
    const analysis = analyzeWrapper(words("find", "-L", "-D", "search", ".", "-exec", "rm", "{}", "\\;"));
    expect(actions(analysis)).toEqual(["rm {}"]);
    expect(analysis.complete).toBe(true);
  });

  it("does not mistake a primary value for an exec operator", () => {
    const analysis = analyzeWrapper(words("find", ".", "-name", "-exec"));
    // -exec is -name's value, so find is an ordinary search, not a wrapper.
    expect(analysis.layers).toEqual([]);
    expect(analysis.actions.map((action) => action.text)).toEqual(["find . -name -exec"]);
    expect(analysis.complete).toBe(true);
  });

  it("marks an unknown primary incomplete", () => {
    const analysis = analyzeWrapper(words("find", ".", "-frobnicate", "-exec", "rm", "{}", ";"));
    expect(analysis.complete).toBe(false);
    expect(analysis.stopReason).toBe("unknown-primary");
  });

  it("unwraps fd exec forms", () => {
    expect(actions(analyzeWrapper(words("fd", "-x", "rm", "x")))).toEqual(["rm x"]);
    expect(actions(analyzeWrapper(words("fd", "--exec-batch", "rm", "x")))).toEqual(["rm x"]);
  });

  it("does not treat plain fd search as a wrapper", () => {
    expect(analyzeWrapper(words("fd", "pattern")).layers).toEqual([]);
  });

  it("follows a wrapper inside an exec payload", () => {
    const analysis = analyzeWrapper(words("find", ".", "-exec", "sudo", "rm", "{}", ";"));
    expect(names(analysis.layers)).toEqual(["find", "sudo"]);
    expect(actions(analysis)).toEqual(["rm {}"]);
  });
});

describe("template and lock layers", () => {
  it("marks watch without -x as a template rebuild", () => {
    const analysis = analyzeWrapper(words("watch", "ls", "|", "grep", "x"));
    expect(analysis.layers[0]!.wrapperKind).toBe("watcher");
    expect(analysis.complete).toBe(false);
    expect(analysis.stopReason).toBe("template-command");
  });

  it("unwraps flock with a lock operand", () => {
    expect(actions(analyzeWrapper(words("flock", "/tmp/lock", "rm", "x")))).toEqual(["rm x"]);
  });

  it("treats flock -c as an opaque payload", () => {
    const analysis = analyzeWrapper(words("flock", "-c", "rm x", "/tmp/lock"));
    expect(analysis.complete).toBe(false);
    expect(analysis.stopReason).toBe("opaque-payload");
    expect(analysis.executedUnit).toBe("rm x");
  });
});

describe("depth limit", () => {
  it("stops the fifth wrapper layer", () => {
    const analysis = analyzeWrapper(words("sudo", "env", "nice", "timeout", "5", "stdbuf", "rm", "x"));
    expect(names(analysis.layers)).toEqual(["sudo", "env", "nice", "timeout"]);
    expect(analysis.complete).toBe(false);
    expect(analysis.stopReason).toBe("depth-limit");
  });

  it("allows four layers", () => {
    const analysis = analyzeWrapper(words("sudo", "env", "nice", "timeout", "5", "rm", "x"));
    expect(names(analysis.layers)).toEqual(["sudo", "env", "nice", "timeout"]);
    expect(actions(analysis)).toEqual(["rm x"]);
    expect(analysis.complete).toBe(true);
  });
});
