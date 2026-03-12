// providers/anthropic.ts — Wraps Anthropic SDK client into a ChatFn

import type { ChatFn } from "../types.js";

interface AnthropicLike {
  messages: {
    create(params: {
      model: string;
      max_tokens: number;
      system: string;
      messages: { role: string; content: string }[];
    }): Promise<{ content: { text: string }[] }>;
  };
}

/** Create a ChatFn from an Anthropic client instance. */
export function fromAnthropic(
  client: AnthropicLike,
  opts: { model: string; systemPrompt: string },
): ChatFn {
  return async (message: string) => {
    const response = await client.messages.create({
      model: opts.model,
      max_tokens: 1024,
      system: opts.systemPrompt,
      messages: [{ role: "user", content: message }],
    });
    return response.content[0]?.text ?? "";
  };
}
