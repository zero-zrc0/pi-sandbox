import { describe, expect, it } from "vitest";
import { selectRuntime, type RuntimeCandidate } from "#sandbox/runtime-selection";

function candidate(overrides: Partial<RuntimeCandidate> = {}): RuntimeCandidate {
  return {
    version: "1.0.0",
    stable: true,
    platform: "linux",
    arch: "x64",
    protocolVersion: 2,
    minPluginVersion: "1.0.0",
    maxPluginVersionExclusive: "2.0.0",
    ...overrides,
  };
}

const request = {
  platform: "linux",
  arch: "x64",
  pluginVersion: "1.2.0",
  protocolVersion: 2,
};

describe("selectRuntime", () => {
  it("selects the highest stable compatible local version by semantic version", () => {
    const selected = selectRuntime({
      ...request,
      installed: [candidate({ version: "1.9.0" }), candidate({ version: "1.10.0" })],
      releases: [],
    });

    expect(selected).toEqual({ kind: "installed", runtime: candidate({ version: "1.10.0" }) });
  });

  it("uses a compatible local version without downloading a newer release", () => {
    const installed = candidate({ version: "1.4.0" });
    const selected = selectRuntime({
      ...request,
      installed: [installed],
      releases: [candidate({ version: "1.8.0" })],
    });

    expect(selected).toEqual({ kind: "installed", runtime: installed });
  });

  it("selects the newest trusted stable release when no local version is compatible", () => {
    const selected = selectRuntime({
      ...request,
      installed: [],
      releases: [candidate({ version: "1.9.0" }), candidate({ version: "1.10.0" })],
    });

    expect(selected).toEqual({ kind: "download", release: candidate({ version: "1.10.0" }) });
  });

  it("accepts a user-trusted manual version that is absent from the release catalog", () => {
    const manual = candidate({ version: "8.2.0", source: "manual" });
    const selected = selectRuntime({
      ...request,
      installed: [manual],
      releases: [],
    });

    expect(selected).toEqual({ kind: "installed", runtime: manual });
  });

  it("does not fall back across platform or architecture", () => {
    const selected = selectRuntime({
      ...request,
      installed: [],
      releases: [candidate({ platform: "linux", arch: "arm64" })],
    });

    expect(selected).toEqual({ kind: "unavailable", reason: expect.stringContaining("linux/x64") });
  });

  it("rejects incompatible protocol, plugin range, and unstable releases", () => {
    const selected = selectRuntime({
      ...request,
      installed: [],
      releases: [
        candidate({ version: "1.9.0", stable: false }),
        candidate({ version: "1.8.0", protocolVersion: 3 }),
        candidate({ version: "1.7.0", minPluginVersion: "2.0.0" }),
      ],
    });

    expect(selected).toEqual({ kind: "unavailable", reason: expect.stringContaining("linux/x64") });
  });
});
