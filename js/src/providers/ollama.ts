// providers/ollama.ts — Ollama API provider

import type { ChatFn } from "../types.js";
import { ProviderError } from "../errors.js";

/** Create a ChatFn from an Ollama instance. */
export function fromOllama(opts: {
  model: string;
  systemPrompt: string;
  baseUrl?: string;
}): ChatFn {
  const baseUrl = (opts.baseUrl ?? "http://localhost:11434").replace(/\/$/, "");

  return async (message: string) => {
    const res = await fetch(`${baseUrl}/api/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: opts.model,
        messages: [
          { role: "system", content: opts.systemPrompt },
          { role: "user", content: message },
        ],
        stream: false,
      }),
    });

    if (!res.ok) {
      throw new ProviderError("ollama", `HTTP ${res.status}: ${res.statusText}`);
    }

    const data = await res.json() as { message?: { content?: string } };
    return data.message?.content ?? "";
  };
}
