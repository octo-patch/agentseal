import type { ChatFn } from "../types.js";
export type { ChatFn };

export interface ProviderConfig {
  model: string;
  systemPrompt: string;
  apiKey?: string;
}
