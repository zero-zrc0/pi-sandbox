import { afterEach, describe, expect, it, vi } from "vitest";
import { resolveApprovalLanguage } from "#approve-core/host/approval-i18n";

afterEach(() => vi.unstubAllEnvs());

describe("approval startup language", () => {
  it.each(["zh", "zh-CN", "zh_TW.UTF-8", "zh-Hant-HK", "ZH-sg"])("uses Chinese for %s", locale => {
    expect(resolveApprovalLanguage(locale)).toBe("zh");
  });
  it.each(["en-US", "ja-JP", "fr-FR", "C", "POSIX", ""])("uses English for %s", locale => {
    expect(resolveApprovalLanguage(locale)).toBe("en");
  });
  it("reads the user's locale with LC_ALL taking precedence", () => {
    vi.stubEnv("LC_ALL", "zh_CN.UTF-8");
    vi.stubEnv("LANG", "en_US.UTF-8");
    expect(resolveApprovalLanguage()).toBe("zh");
    vi.stubEnv("LC_ALL", "ja_JP.UTF-8");
    expect(resolveApprovalLanguage()).toBe("en");
  });
  it("ignores empty locale overrides", () => {
    vi.stubEnv("LC_ALL", "");
    vi.stubEnv("LC_MESSAGES", "");
    vi.stubEnv("LANGUAGE", "");
    vi.stubEnv("LANG", "zh_TW.UTF-8");
    expect(resolveApprovalLanguage()).toBe("zh");
  });
});
