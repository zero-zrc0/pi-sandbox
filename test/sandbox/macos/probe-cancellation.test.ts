import { expect, it, vi } from "vitest";
import { createMacOSDirectBackend } from "#sandbox/backend/macos/direct";
import { probeDirectBackendOnce } from "#sandbox/backend/direct";

const probe = vi.hoisted(() => vi.fn(async (signal?: AbortSignal) => {
  await new Promise<void>(resolve => signal?.addEventListener("abort", () => resolve(), { once: true }));
  return { status: "unavailable" as const, reason: "cancelled" };
}));

vi.mock("#sandbox/backend/macos/seatbelt", async importOriginal => ({
  ...await importOriginal<typeof import("#sandbox/backend/macos/seatbelt")>(),
  probeMacOSSeatbelt: probe,
}));

it("passes cancellation to the active macOS capability probe", async () => {
  const backend = createMacOSDirectBackend({ installRoot: ".", hostEnvironment: {} });
  const controller = new AbortController();
  const pending = probeDirectBackendOnce(backend, controller.signal);
  await vi.waitFor(() => expect(probe).toHaveBeenCalledWith(controller.signal));
  controller.abort();
  expect(await pending).toMatchObject({ ok: false });
});
