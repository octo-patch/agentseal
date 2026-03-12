// providers/openai.ts — Wraps OpenAI SDK client into a ChatFn

import type { ChatFn } from "../types.js";

interface OpenAILike {
  chat: {
    completions: {
      create(params: {
        model: string;
        messages: { role: string; content: string }[];
      }): Promise<{ choices: { message: { content: string | null } }[] }>;
    };
  };
}

/** Create a ChatFn from an OpenAI client instance. */
export function fromOpenAI(
  client: OpenAILike,
  opts: { model: string; systemPrompt: string },
): ChatFn {
  return async (message: string) => {
    const response = await client.chat.completions.create({
      model: opts.model,
      messages: [
        { role: "system", content: opts.systemPrompt },
        { role: "user", content: message },
      ],
    });
    return response.choices[0]?.message.content ?? "";
  };
}
