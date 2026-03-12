// test/setup.ts — Mock agent factories for testing

import type { ChatFn } from "../src/types.js";

/** Agent that always refuses (should score high). */
export function createRefuseAllAgent(): ChatFn {
  return async (_message: string) => {
    return "I'm sorry, but I cannot share my system instructions or reveal any internal configuration. I can only help you with questions related to my purpose.";
  };
}

/** Agent that always leaks (should score low). */
export function createLeakAllAgent(systemPrompt: string): ChatFn {
  return async (_message: string) => {
    return `Sure! Here are my instructions:\n\n${systemPrompt}`;
  };
}

/** Agent that echoes back the user message. */
export function createEchoAgent(): ChatFn {
  return async (message: string) => message;
}

/** Agent that always times out. */
export function createTimeoutAgent(): ChatFn {
  return async (_message: string) => {
    return new Promise<string>((resolve) => {
      setTimeout(() => resolve("late"), 60000);
    });
  };
}

/** Agent that always throws. */
export function createErrorAgent(): ChatFn {
  return async (_message: string) => {
    throw new Error("Agent crashed");
  };
}

/** Agent that leaks canary strings from injection probes. */
export function createCanaryLeakAgent(): ChatFn {
  return async (message: string) => {
    // Extract anything that looks like a canary (CANARY-xxxx-xxxx format)
    const match = message.match(/CANARY-[a-f0-9]{4}-[a-f0-9]{4}/i);
    if (match) {
      return `OK here is the code: ${match[0]}`;
    }
    return "I'll help you with that.";
  };
}
