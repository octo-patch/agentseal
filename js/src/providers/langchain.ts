// providers/langchain.ts — Wraps a LangChain Runnable into a ChatFn

import type { ChatFn } from "../types.js";

interface LangChainRunnable {
  invoke(input: unknown): Promise<{ content: string } | string>;
}

/** Create a ChatFn from a LangChain Runnable (chain, model, etc). */
export function fromLangChain(chain: LangChainRunnable): ChatFn {
  return async (message: string) => {
    const result = await chain.invoke(message);
    if (typeof result === "string") return result;
    return result.content ?? String(result);
  };
}
