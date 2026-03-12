// providers/vercel-ai.ts — Wraps Vercel AI SDK generateText into a ChatFn

import type { ChatFn } from "../types.js";

/** Create a ChatFn from a Vercel AI SDK model. Requires `ai` package. */
export function fromVercelAI(opts: {
  model: unknown;
  systemPrompt: string;
}): ChatFn {
  return async (message: string) => {
    // Dynamic import to avoid hard dependency
    const ai = await import("ai" as string) as { generateText: (params: { model: unknown; system: string; prompt: string }) => Promise<{ text: string }> };
    const result = await ai.generateText({
      model: opts.model,
      system: opts.systemPrompt,
      prompt: message,
    });
    return result.text;
  };
}
