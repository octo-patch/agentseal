// compare.ts — Compare two scan reports

import type { ScanReport, CompareResult, ProbeResult } from "./types.js";
import { Verdict } from "./types.js";

/** Compare two scan reports and return a diff summary. */
export function compareReports(baseline: ScanReport, current: ScanReport): CompareResult {
  const scoreDelta = current.trust_score - baseline.trust_score;

  // Build lookup maps by probe_id
  const baselineMap = new Map<string, ProbeResult>();
  for (const r of baseline.results) baselineMap.set(r.probe_id, r);

  const currentMap = new Map<string, ProbeResult>();
  for (const r of current.results) currentMap.set(r.probe_id, r);

  const newLeaks: ProbeResult[] = [];
  const fixedLeaks: ProbeResult[] = [];
  const regressions: ProbeResult[] = [];
  const improvements: ProbeResult[] = [];

  // Check current results against baseline
  for (const r of current.results) {
    const base = baselineMap.get(r.probe_id);
    if (!base) {
      if (r.verdict === Verdict.LEAKED) newLeaks.push(r);
      continue;
    }
    if (base.verdict === Verdict.BLOCKED && r.verdict === Verdict.LEAKED) regressions.push(r);
    if (base.verdict === Verdict.BLOCKED && r.verdict === Verdict.PARTIAL) regressions.push(r);
    if (base.verdict === Verdict.LEAKED && r.verdict === Verdict.BLOCKED) improvements.push(r);
    if (base.verdict === Verdict.PARTIAL && r.verdict === Verdict.BLOCKED) improvements.push(r);
  }

  // Check for fixed leaks
  for (const r of baseline.results) {
    const cur = currentMap.get(r.probe_id);
    if (r.verdict === Verdict.LEAKED && cur && cur.verdict === Verdict.BLOCKED) {
      fixedLeaks.push(cur);
    }
  }

  const parts: string[] = [];
  if (scoreDelta > 0) parts.push(`Score improved by ${scoreDelta.toFixed(1)} points`);
  else if (scoreDelta < 0) parts.push(`Score decreased by ${Math.abs(scoreDelta).toFixed(1)} points`);
  else parts.push("Score unchanged");

  if (newLeaks.length > 0) parts.push(`${newLeaks.length} new leak(s)`);
  if (fixedLeaks.length > 0) parts.push(`${fixedLeaks.length} leak(s) fixed`);
  if (regressions.length > 0) parts.push(`${regressions.length} regression(s)`);
  if (improvements.length > 0) parts.push(`${improvements.length} improvement(s)`);

  return {
    score_delta: scoreDelta,
    new_leaks: newLeaks,
    fixed_leaks: fixedLeaks,
    regressions,
    improvements,
    summary: parts.join(". ") + ".",
  };
}
