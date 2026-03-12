import { describe, it, expect, vi } from "vitest";
import { fromOpenAI } from "../../src/providers/openai.js";

describe("fromOpenAI", () => {
  it("creates a ChatFn that calls the OpenAI client", async () => {
    const mockClient = {
      chat: {
        completions: {
          create: vi.fn().mockResolvedValue({
            choices: [{ message: { content: "Hello back!" } }],
          }),
        },
      },
    };

    const chatFn = fromOpenAI(mockClient, {
      model: "gpt-4o",
      systemPrompt: "You are helpful.",
    });

    const result = await chatFn("Hello");
    expect(result).toBe("Hello back!");
    expect(mockClient.chat.completions.create).toHaveBeenCalledWith({
      model: "gpt-4o",
      messages: [
        { role: "system", content: "You are helpful." },
        { role: "user", content: "Hello" },
      ],
    });
  });

  it("returns empty string when content is null", async () => {
    const mockClient = {
      chat: {
        completions: {
          create: vi.fn().mockResolvedValue({
            choices: [{ message: { content: null } }],
          }),
        },
      },
    };

    const chatFn = fromOpenAI(mockClient, {
      model: "gpt-4o",
      systemPrompt: "test",
    });

    const result = await chatFn("Hello");
    expect(result).toBe("");
  });
});
