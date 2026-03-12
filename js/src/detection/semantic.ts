// detection/semantic.ts — Bring-your-own-embeddings semantic detection

import type { EmbedFn } from "../types.js";

function dotProduct(a: number[], b: number[]): number {
  let sum = 0;
  for (let i = 0; i < a.length; i++) {
    sum += (a[i] ?? 0) * (b[i] ?? 0);
  }
  return sum;
}

function l2Norm(v: number[]): number {
  let sum = 0;
  for (const x of v) sum += x * x;
  return Math.sqrt(sum) || 1e-9;
}

function cosineSimilarity(a: number[], b: number[]): number {
  return dotProduct(a, b) / (l2Norm(a) * l2Norm(b));
}

function splitSentences(text: string): string[] {
  return text
    .trim()
    .split(/(?<=[.!?])\s+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 10);
}

/**
 * Compute semantic similarity between response and ground truth.
 * Requires an embed function provided by the user.
 */
export async function computeSemanticSimilarity(
  response: string,
  groundTruth: string,
  embed: EmbedFn,
): Promise<number> {
  if (!response.trim() || !groundTruth.trim()) return 0.0;

  let gtSentences = splitSentences(groundTruth);
  let respSentences = splitSentences(response);

  if (gtSentences.length === 0) gtSentences = [groundTruth.trim()];
  if (respSentences.length === 0) respSentences = [response.trim()];

  const allTexts = [...gtSentences, ...respSentences];
  const allEmbeddings = await embed(allTexts);

  const nGt = gtSentences.length;
  const gtEmbeddings = allEmbeddings.slice(0, nGt);
  const respEmbeddings = allEmbeddings.slice(nGt);

  // For each GT sentence, find max similarity to any response sentence
  const maxSims: number[] = [];
  for (const gtEmb of gtEmbeddings) {
    let maxSim = -1;
    for (const respEmb of respEmbeddings) {
      if (!gtEmb || !respEmb) continue;
      const sim = cosineSimilarity(gtEmb, respEmb);
      if (sim > maxSim) maxSim = sim;
    }
    maxSims.push(maxSim);
  }

  // Weighted average by sentence length
  const weights = gtSentences.map((s) => s.length);
  const totalWeight = weights.reduce((a, b) => a + b, 0) || 1e-9;
  let weightedSim = 0;
  for (let i = 0; i < maxSims.length; i++) {
    weightedSim += (maxSims[i] ?? 0) * ((weights[i] ?? 0) / totalWeight);
  }

  return Math.max(0, Math.min(1, weightedSim));
}
