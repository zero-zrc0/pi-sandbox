import { describe, expect, it } from "vitest";
import {
  COMPAT_PATH_NAMES,
  EXTENSION_PACKAGE_NAME,
  PI_PROJECT_DIR,
  joinPath,
  resolveConfigPaths,
  resolveDebugLogFile,
  samePath,
} from "#config/config-paths";

const POSIX_ROOTS = {
  agentDir: "/home/dev/.pi/agent",
  cwd: "/work/project",
  extensionRoot: "/opt/pi-sandbox",
};

const POSIX_PATHS = {
  globalConfigDir: "/home/dev/.pi/agent/extensions/pi-sandbox",
  globalConfigFile: "/home/dev/.pi/agent/extensions/pi-sandbox/config.json",
  projectConfigDir: "/work/project/.pi/extensions/pi-sandbox",
  projectConfigFile: "/work/project/.pi/extensions/pi-sandbox/config.json",
  logDir: "/home/dev/.pi/agent/logs",
  debugLogFile: "/home/dev/.pi/agent/logs/debug.jsonl",
  reviewLogFile: "/home/dev/.pi/agent/logs/review.jsonl",
  projectAgentsDir: "/work/project/.pi/agents",
  legacyGlobalPolicyFile: "/home/dev/.pi/agent/policy.json",
  legacyProjectPolicyFile: "/work/project/.pi/policy.json",
  legacyExtensionConfigFile: "/opt/pi-sandbox/config.json",
};

const WINDOWS_ROOTS = {
  agentDir: "C:\\Users\\dev\\.pi\\agent",
  cwd: "D:\\work\\project",
  extensionRoot: "C:\\Users\\dev\\.pi\\extensions\\pi-sandbox",
};

const WINDOWS_PATHS = {
  globalConfigDir: "C:\\Users\\dev\\.pi\\agent\\extensions\\pi-sandbox",
  globalConfigFile: "C:\\Users\\dev\\.pi\\agent\\extensions\\pi-sandbox\\config.json",
  projectConfigDir: "D:\\work\\project\\.pi\\extensions\\pi-sandbox",
  projectConfigFile: "D:\\work\\project\\.pi\\extensions\\pi-sandbox\\config.json",
  logDir: "C:\\Users\\dev\\.pi\\agent\\logs",
  debugLogFile: "C:\\Users\\dev\\.pi\\agent\\logs\\debug.jsonl",
  reviewLogFile: "C:\\Users\\dev\\.pi\\agent\\logs\\review.jsonl",
  projectAgentsDir: "D:\\work\\project\\.pi\\agents",
  legacyGlobalPolicyFile: "C:\\Users\\dev\\.pi\\agent\\policy.json",
  legacyProjectPolicyFile: "D:\\work\\project\\.pi\\policy.json",
  legacyExtensionConfigFile: "C:\\Users\\dev\\.pi\\extensions\\pi-sandbox\\config.json",
};

describe("path constants", () => {
  it("exports the project directory and extension package names", () => {
    expect(PI_PROJECT_DIR).toBe(".pi");
    expect(EXTENSION_PACKAGE_NAME).toBe("pi-sandbox");
  });

  it("freezes the compatibility file and directory names", () => {
    expect(COMPAT_PATH_NAMES).toEqual({
      extensionsDirName: "extensions",
      projectDirName: ".pi",
      configFileName: "config.json",
      logDirName: "logs",
      debugLogFileName: "debug.jsonl",
      reviewLogFileName: "review.jsonl",
      agentsDirName: "agents",
      legacyPolicyFileName: "policy.json",
      legacyExtensionConfigFileName: "config.json",
    });
    expect(Object.isFrozen(COMPAT_PATH_NAMES)).toBe(true);
  });

  it("keeps the project directory name in one place", () => {
    expect(COMPAT_PATH_NAMES.projectDirName).toBe(PI_PROJECT_DIR);
  });
});

describe("resolveConfigPaths", () => {
  it("resolves the full POSIX layout", () => {
    expect(resolveConfigPaths(POSIX_ROOTS)).toEqual(POSIX_PATHS);
  });

  it("resolves the full Windows layout", () => {
    expect(resolveConfigPaths(WINDOWS_ROOTS)).toEqual(WINDOWS_PATHS);
  });

  it("keeps the standalone debug log helper aligned with the resolved layout", () => {
    expect(resolveDebugLogFile(POSIX_ROOTS.agentDir)).toBe(POSIX_PATHS.debugLogFile);
    expect(resolveDebugLogFile(WINDOWS_ROOTS.agentDir)).toBe(WINDOWS_PATHS.debugLogFile);
  });

  it("does not double trailing separators on POSIX roots", () => {
    expect(
      resolveConfigPaths({
        agentDir: "/home/dev/.pi/agent/",
        cwd: "/work/project/",
        extensionRoot: "/opt/pi-sandbox/",
      }),
    ).toEqual(POSIX_PATHS);
  });

  it("does not double trailing separators on Windows roots", () => {
    expect(
      resolveConfigPaths({
        agentDir: "C:\\Users\\dev\\.pi\\agent\\",
        cwd: "D:\\work\\project\\",
        extensionRoot: "C:\\Users\\dev\\.pi\\extensions\\pi-sandbox\\",
      }),
    ).toEqual(WINDOWS_PATHS);
  });

  it("keeps all paths relative when the roots are empty", () => {
    expect(resolveConfigPaths({ agentDir: "", cwd: "", extensionRoot: "" })).toEqual({
      globalConfigDir: "extensions/pi-sandbox",
      globalConfigFile: "extensions/pi-sandbox/config.json",
      projectConfigDir: ".pi/extensions/pi-sandbox",
      projectConfigFile: ".pi/extensions/pi-sandbox/config.json",
      logDir: "logs",
      debugLogFile: "logs/debug.jsonl",
      reviewLogFile: "logs/review.jsonl",
      projectAgentsDir: ".pi/agents",
      legacyGlobalPolicyFile: "policy.json",
      legacyProjectPolicyFile: ".pi/policy.json",
      legacyExtensionConfigFile: "config.json",
    });
  });

  it("produces disjoint layouts for different explicit roots", () => {
    const first = resolveConfigPaths({ agentDir: "/first/agent", cwd: "/first/cwd", extensionRoot: "/first/ext" });
    const second = resolveConfigPaths({ agentDir: "/second/agent", cwd: "/second/cwd", extensionRoot: "/second/ext" });
    const firstValues = Object.values(first);
    for (const value of Object.values(second)) {
      expect(firstValues).not.toContain(value);
    }
  });
});

describe("joinPath", () => {
  it("joins with a POSIX separator for a slash base", () => {
    expect(joinPath("/srv/agent", "extensions", "pi-sandbox")).toBe("/srv/agent/extensions/pi-sandbox");
  });

  it("joins with a backslash for a drive-letter base", () => {
    expect(joinPath("C:\\Users\\dev", "extensions", "pi-sandbox")).toBe(
      "C:\\Users\\dev\\extensions\\pi-sandbox",
    );
  });

  it("joins with a backslash for a relative base containing a backslash", () => {
    expect(joinPath("a\\b", "c")).toBe("a\\b\\c");
  });

  it("chooses the separator from the base spelling, not the platform", () => {
    expect(joinPath("C:/Users/dev", "logs")).toBe("C:/Users/dev\\logs");
    expect(joinPath("/srv/agent", "logs")).toBe("/srv/agent/logs");
  });

  it("joins with / when the base is empty", () => {
    expect(joinPath("", "extensions", "pi-sandbox")).toBe("extensions/pi-sandbox");
    expect(joinPath("", "config.json")).toBe("config.json");
    expect(joinPath("")).toBe("");
  });

  it("does not double a trailing separator on the base", () => {
    expect(joinPath("/srv/agent/", "logs")).toBe("/srv/agent/logs");
    expect(joinPath("C:\\Users\\dev\\", "logs")).toBe("C:\\Users\\dev\\logs");
  });

  it("keeps a bare root separator", () => {
    expect(joinPath("/", "logs")).toBe("/logs");
    expect(joinPath("C:\\", "logs")).toBe("C:\\logs");
  });

  it("strips leading separators from segments", () => {
    expect(joinPath("/srv/agent", "/logs", "/debug.jsonl")).toBe("/srv/agent/logs/debug.jsonl");
    expect(joinPath("C:\\Users\\dev", "\\logs")).toBe("C:\\Users\\dev\\logs");
  });

  it("does not resolve dot segments", () => {
    expect(joinPath("/srv/agent", ".", "..", "logs")).toBe("/srv/agent/./../logs");
    expect(joinPath("C:\\Users\\dev", "..", "logs")).toBe("C:\\Users\\dev\\..\\logs");
  });

  it("does not read the working directory", () => {
    expect(joinPath("relative/base", "config.json")).toBe("relative/base/config.json");
  });
});

describe("samePath", () => {
  it("compares equal POSIX paths", () => {
    expect(samePath("/srv/agent/logs", "/srv/agent/logs")).toBe(true);
  });

  it("compares equal Windows paths", () => {
    expect(samePath("C:\\Users\\dev\\logs", "C:\\Users\\dev\\logs")).toBe(true);
  });

  it("ignores the separator spelling", () => {
    expect(samePath("/srv/agent/logs", "\\srv\\agent\\logs")).toBe(true);
    expect(samePath("C:\\Users\\dev", "C:/Users/dev")).toBe(true);
  });

  it("compares Windows paths case-insensitively", () => {
    expect(samePath("C:\\Users\\Dev\\Logs", "c:\\users\\dev\\logs")).toBe(true);
  });

  it("compares POSIX paths case-sensitively", () => {
    expect(samePath("/srv/Agent/logs", "/srv/agent/logs")).toBe(false);
  });

  it("ignores trailing separators but keeps a bare root", () => {
    expect(samePath("/srv/agent/logs/", "/srv/agent/logs")).toBe(true);
    expect(samePath("C:\\Users\\dev\\logs\\", "C:\\Users\\dev\\logs")).toBe(true);
    expect(samePath("/", "/")).toBe(true);
    expect(samePath("/", "")).toBe(false);
  });

  it("folds only ASCII letters on Windows paths", () => {
    expect(samePath("C:\\Users\\Ä", "c:\\users\\ä")).toBe(false);
  });

  it("does not resolve dot segments", () => {
    expect(samePath("/srv/agent/logs", "/srv/agent/./logs")).toBe(false);
    expect(samePath("C:\\Users\\dev", "C:\\Users\\dev\\..")).toBe(false);
  });

  it("rejects different paths", () => {
    expect(samePath("/srv/agent/logs", "/srv/agent/config")).toBe(false);
  });

  it("treats a backslash value as Windows-flavoured even against a slash path", () => {
    expect(samePath("/Srv/Agent", "\\srv\\agent")).toBe(true);
  });
});
