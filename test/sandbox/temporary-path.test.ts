import { realpathSync } from "node:fs";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { resolveTemporaryToolPath } from "#sandbox/builtin-path";

const hostTemp = realpathSync(mkdtempSync(join(tmpdir(), "pi-sandbox-host-temp-")));
const sandboxTemp = join(realpathSync(mkdtempSync(join(tmpdir(), "pi-sandbox-sandbox-temp-"))), "tmp");
mkdirSync(sandboxTemp);
const host = { TMPDIR: hostTemp, TMP: hostTemp, TEMP: hostTemp, PATH: "/usr/bin" };

afterAll(() => {
  rmSync(hostTemp, { recursive: true, force: true });
  rmSync(join(sandboxTemp, ".."), { recursive: true, force: true });
});

describe("temporary tool path mapping", () => {
  it("maps a spelled temporary variable onto the applicable temporary root", () => {
    expect(resolveTemporaryToolPath("$TMPDIR/notes.txt", host, sandboxTemp)).toBe(join(sandboxTemp, "notes.txt"));
    expect(resolveTemporaryToolPath("${TMPDIR}/nested/notes.txt", host, sandboxTemp))
      .toBe(join(sandboxTemp, "nested", "notes.txt"));
    expect(resolveTemporaryToolPath("${TMP}/notes.txt", host, sandboxTemp)).toBe(join(sandboxTemp, "notes.txt"));
    expect(resolveTemporaryToolPath("$TMPDIR", host, sandboxTemp)).toBe(sandboxTemp);
    expect(resolveTemporaryToolPath("$TMPDIR/notes.txt", host, hostTemp)).toBe(join(hostTemp, "notes.txt"));
  });

  it("leaves absolute temporary paths to the approval chain", () => {
    expect(resolveTemporaryToolPath(join(hostTemp, "notes.txt"), host, sandboxTemp)).toBeUndefined();
    expect(resolveTemporaryToolPath(join(hostTemp, "..", "outside.txt"), host, sandboxTemp)).toBeUndefined();
  });

  it("does not rewrite non-temporary paths, relative paths or unrelated variables", () => {
    expect(resolveTemporaryToolPath("$HOME/notes.txt", host, sandboxTemp)).toBeUndefined();
    expect(resolveTemporaryToolPath("$TMPDIRX/notes.txt", host, sandboxTemp)).toBeUndefined();
    expect(resolveTemporaryToolPath("notes.txt", host, sandboxTemp)).toBeUndefined();
    expect(resolveTemporaryToolPath("/etc/hosts", host, sandboxTemp)).toBeUndefined();
  });

  it("stays inert without an absolute temporary root", () => {
    expect(resolveTemporaryToolPath("$TMPDIR/notes.txt", host, undefined)).toBeUndefined();
    expect(resolveTemporaryToolPath("$TMPDIR/notes.txt", host, "relative/tmp")).toBeUndefined();
    expect(resolveTemporaryToolPath("$TMPDIR/notes.txt", {}, sandboxTemp)).toBeUndefined();
  });
});
