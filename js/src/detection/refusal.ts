// detection/refusal.ts — Refusal phrase detection

import { REFUSAL_PHRASES } from "../constants.js";

/** Check if a response contains refusal phrases. */
export function isRefusal(response: string): boolean {
  const lower = response.toLowerCase();
  return REFUSAL_PHRASES.some((p) => lower.includes(p));
}
