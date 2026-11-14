import { describe, expect, it, vi } from "vitest";
import {
  getPermissionsService,
  publishPermissionsService,
  unpublishPermissionsService,
} from "../src/service";

describe("session permission service", () => {
  it("shares session publications between independently loaded module instances", async () => {
    vi.resetModules();
    const publisher = await import("../src/service");
    vi.resetModules();
    const consumer = await import("../src/service");
    const service = {
      checkPermission: () => ({ toolName: "read", state: "ask" as const, source: "default" as const, origin: "builtin" as const }),
      getToolPermission: () => "ask" as const,
    };
    publisher.publishPermissionsService("isolated-module-session", service);
    expect(consumer.getPermissionsService("isolated-module-session")).toBe(service);
    consumer.unpublishPermissionsService("isolated-module-session");
    expect(publisher.getPermissionsService("isolated-module-session")).toBeUndefined();
  });
  it("publishes and removes a service under its session id", () => {
    const sessionId = "service-registry-test";
    const service = {
      checkPermission: () => ({
        toolName: "bash",
        state: "ask" as const,
        source: "bash" as const,
        origin: "builtin" as const,
      }),
      getToolPermission: () => "ask" as const,
    };
    unpublishPermissionsService(sessionId);

    expect(getPermissionsService(sessionId)).toBeUndefined();
    publishPermissionsService(sessionId, service);
    expect(getPermissionsService(sessionId)).toBe(service);
    expect(getPermissionsService("another-session")).toBeUndefined();

    unpublishPermissionsService(sessionId);
    expect(getPermissionsService(sessionId)).toBeUndefined();
  });
});
