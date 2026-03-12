// mutations/generate.ts — Mutation probe generation

import type { ProbeResult, Probe, Severity } from "../types.js";
import { TRANSFORMS } from "./index.js";

const TRANSFORM_SETS = [
  ["base64_wrap", "unicode_homoglyphs", "prefix_padding"],
  ["rot13_wrap", "zero_width_inject", "leetspeak"],
  ["case_scramble", "reverse_embed", "base64_wrap"],
  ["unicode_homoglyphs", "leetspeak", "rot13_wrap"],
  ["prefix_padding", "case_scramble", "zero_width_inject"],
];

/**
 * Generate mutation probes from blocked extraction results.
 * Takes top 5 blocked results, applies 3 transforms each → up to 15 mutations.
 */
export function generateMutations(
  blockedResults: ProbeResult[],
  originalProbes: Probe[],
): Probe[] {
  // Build lookup from probe_id to original payload
  const probePayloads = new Map<string, string>();
  for (const p of originalProbes) {
    const payload = Array.isArray(p.payload) ? p.payload[p.payload.length - 1]! : p.payload;
    probePayloads.set(p.probe_id, payload);
  }

  const mutationProbes: Probe[] = [];
  const top = blockedResults.slice(0, 5);

  for (let i = 0; i < top.length; i++) {
    const result = top[i]!;
    const originalText = probePayloads.get(result.probe_id) ?? result.attack_text;
    const transformSet = TRANSFORM_SETS[i % TRANSFORM_SETS.length]!;

    for (const transformName of transformSet) {
      const transformFn = TRANSFORMS[transformName];
      if (!transformFn) continue;
      const mutatedText = transformFn(originalText);

      mutationProbes.push({
        probe_id: `mut_${result.probe_id}_${transformName}`,
        category: "mutation",
        technique: `Mutation: ${transformName} on ${result.technique}`,
        severity: result.severity as Severity,
        payload: mutatedText,
      });
    }
  }

  return mutationProbes;
}
