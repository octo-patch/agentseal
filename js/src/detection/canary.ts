// detection/canary.ts — Exact-match canary detection for injection probes

/** Check if the canary string appears in the response. */
export function detectCanary(response: string, canary: string): boolean {
  if (!canary) return false;
  return response.includes(canary);
}
