import { chmodSync, mkdtempSync, mkdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
  findSystemBubblewrap,
  resolveSystemBubblewrap,
  selectBubblewrapCandidate,
} from "../../src/sandbox/backend/linux/bwrap-selection.mjs";

describe("bubblewrap selection", () => {
  it.skipIf(process.platform !== "linux")("finds only an executable system binary outside the workspace", () => {
    const root = mkdtempSync(join(tmpdir(), "runtime-bwrap-selection-test-"));
    const workspace = join(root, "workspace");
    const systemDirectory = join(root, "home", ".local", "bin");
    const workspaceDirectory = join(workspace, "bin");
    mkdirSync(systemDirectory, { recursive: true });
    mkdirSync(workspaceDirectory, { recursive: true });
    const systemBinary = join(systemDirectory, "bwrap");
    const workspaceBinary = join(workspaceDirectory, "bwrap");
    writeFileSync(systemBinary, "system");
    writeFileSync(workspaceBinary, "workspace");
    chmodSync(systemBinary, 0o755);
    chmodSync(workspaceBinary, 0o755);

    try {
      expect(findSystemBubblewrap(systemDirectory, workspace)).toBe(realpathSync(systemBinary));
      expect(resolveSystemBubblewrap(workspaceBinary, workspace)).toBeUndefined();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("prefers a compatible system binary", () => {
    const probe = vi.fn((path: string) => path === "/usr/local/bin/bwrap" ? "0.10.0" : "0.12.0");

    expect(selectBubblewrapCandidate("/usr/local/bin/bwrap", { path: "/runtime/bwrap", version: "0.12.0" }, probe))
      .toEqual({ path: "/usr/local/bin/bwrap", version: "0.10.0" });
    expect(probe).toHaveBeenCalledTimes(1);
  });

  it("falls back to the bundled binary when the system binary is incompatible", () => {
    const probe = vi.fn((path: string, expectedVersion?: string) =>
      path === "/runtime/bwrap" && expectedVersion === "0.12.0" ? expectedVersion : undefined);

    expect(selectBubblewrapCandidate("/usr/bin/bwrap", { path: "/runtime/bwrap", version: "0.12.0" }, probe))
      .toEqual({ path: "/runtime/bwrap", version: "0.12.0" });
    expect(probe).toHaveBeenNthCalledWith(1, "/usr/bin/bwrap", undefined);
    expect(probe).toHaveBeenNthCalledWith(2, "/runtime/bwrap", "0.12.0");
  });

  it("reports unavailable when neither binary passes the probe", () => {
    const probe = vi.fn(() => undefined);

    expect(selectBubblewrapCandidate("/usr/bin/bwrap", undefined, probe)).toBeUndefined();
    expect(probe).toHaveBeenCalledOnce();
  });
});
