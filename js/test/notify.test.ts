import { describe, it, expect, vi } from "vitest";
import { Notifier } from "../src/notify.js";

describe("Notifier", () => {
  it("does not send when disabled", () => {
    const notifier = new Notifier(false);
    expect(notifier.notify("title", "msg")).toBe(false);
  });

  it("sends when enabled (returns true)", () => {
    const notifier = new Notifier(true, 0);
    // On any platform, notify should return true (either native or fallback)
    const result = notifier.notify("title", "msg");
    expect(result).toBe(true);
  });

  it("throttles rapid notifications", () => {
    const notifier = new Notifier(true, 60); // 60s interval

    const first = notifier.notify("title", "msg1");
    expect(first).toBe(true);

    const second = notifier.notify("title", "msg2");
    expect(second).toBe(false); // Throttled
  });

  it("notifyThreat returns true", () => {
    const notifier = new Notifier(true, 0);
    const result = notifier.notifyThreat("evil-skill", "Skill", "critical", "Data exfiltration");
    expect(result).toBe(true);
  });

  it("notifyThreat handles unknown severity", () => {
    const notifier = new Notifier(true, 0);
    const result = notifier.notifyThreat("test", "Type", "unknown-sev", "detail");
    expect(result).toBe(true);
  });

  it("enabled getter reflects constructor", () => {
    expect(new Notifier(true).enabled).toBe(true);
    expect(new Notifier(false).enabled).toBe(false);
  });

  it("fallback writes to stderr", () => {
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    // Force fallback by using the private method
    const notifier = new Notifier(true, 0);
    const sent = (notifier as any)._notifyFallback("Test Title", "Test Message");
    expect(sent).toBe(true);

    const output = (stderrSpy.mock.calls[0]?.[0] as string) ?? "";
    expect(output).toContain("Test Title");
    expect(output).toContain("Test Message");
    stderrSpy.mockRestore();
  });
});
