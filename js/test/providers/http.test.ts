import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fromEndpoint } from "../../src/providers/http.js";
import { ProviderError } from "../../src/errors.js";

describe("fromEndpoint", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("creates a ChatFn that POSTs to the endpoint", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ response: "Hi there!" }),
    }) as unknown as typeof fetch;

    const chatFn = fromEndpoint({ url: "http://localhost:8080" });
    const result = await chatFn("Hello");

    expect(result).toBe("Hi there!");
    expect(globalThis.fetch).toHaveBeenCalledWith("http://localhost:8080", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: "Hello" }),
    });
  });

  it("uses custom field names", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ output: "Result" }),
    }) as unknown as typeof fetch;

    const chatFn = fromEndpoint({
      url: "http://localhost:8080",
      messageField: "input",
      responseField: "output",
    });
    const result = await chatFn("Test");

    expect(result).toBe("Result");
    expect(globalThis.fetch).toHaveBeenCalledWith("http://localhost:8080", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input: "Test" }),
    });
  });

  it("throws ProviderError on HTTP error", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      statusText: "Internal Server Error",
    }) as unknown as typeof fetch;

    const chatFn = fromEndpoint({ url: "http://localhost:8080" });
    await expect(chatFn("Hello")).rejects.toThrow(ProviderError);
  });

  it("throws ProviderError when response field is missing", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ other_field: "data" }),
    }) as unknown as typeof fetch;

    const chatFn = fromEndpoint({ url: "http://localhost:8080" });
    await expect(chatFn("Hello")).rejects.toThrow(ProviderError);
  });
});
