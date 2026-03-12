// providers/http.ts — Generic HTTP endpoint provider

import type { ChatFn } from "../types.js";
import { ProviderError } from "../errors.js";

/** Create a ChatFn from an HTTP endpoint. */
export function fromEndpoint(opts: {
  url: string;
  messageField?: string;
  responseField?: string;
  headers?: Record<string, string>;
}): ChatFn {
  const msgField = opts.messageField ?? "message";
  const respField = opts.responseField ?? "response";

  return async (message: string) => {
    const res = await fetch(opts.url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...opts.headers,
      },
      body: JSON.stringify({ [msgField]: message }),
    });

    if (!res.ok) {
      throw new ProviderError("http", `HTTP ${res.status}: ${res.statusText}`);
    }

    const data = await res.json() as Record<string, unknown>;
    const response = data[respField];
    if (typeof response !== "string") {
      throw new ProviderError("http", `Response field '${respField}' not found or not a string`);
    }
    return response;
  };
}
