/**
 * Attack chain detection from scan results.
 *
 * Analyzes existing ProbeResult data to identify complete attack paths.
 * Does NOT run new probes.
 *
 * Port of Python agentseal/chains.py.
 */

import { Severity, Verdict, type ProbeResult, type ScanReport } from "./types.js";

// ═══════════════════════════════════════════════════════════════════════
// DATA TYPES
// ═══════════════════════════════════════════════════════════════════════

export interface ChainStep {
  step_number: number;
  probe_id: string;
  category: string;
  technique: string;
  verdict: string;
  summary: string;
}

export interface AttackChain {
  chain_type: string; // "injection_extraction" | "injection_exfiltration" | "full_chain"
  severity: string;   // "critical" | "high"
  title: string;
  description: string;
  steps: ChainStep[];
  remediation: string;
}

// ═══════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════

const SEVERITY_RANK: Record<string, number> = {
  [Severity.CRITICAL]: 4,
  [Severity.HIGH]: 3,
  [Severity.MEDIUM]: 2,
  [Severity.LOW]: 1,
};

const STEP_ROLES: Record<number, string> = {
  1: "ENTRY POINT",
  2: "DATA ACCESS",
  3: "EXFILTRATION",
};

const EXFIL_CATEGORIES = new Set([
  "data_exfiltration",
  "markdown_exfiltration",
  "enhanced_markdown_exfil",
]);

const MAX_CHAINS = 5;

const CHAIN_META: Record<string, { title: string; description: string; remediation: string }> = {
  injection_extraction: {
    title: "Injection to extraction chain detected",
    description:
      "An attacker can inject a malicious prompt that alters the agent's " +
      "behaviour, then extract sensitive data through follow-up queries.",
    remediation:
      "Add input validation to reject injected instructions. " +
      "Restrict the agent's ability to return raw data from internal sources.",
  },
  injection_exfiltration: {
    title: "Injection to data exfiltration chain detected",
    description:
      "An attacker can inject a prompt that causes the agent to exfiltrate " +
      "data through covert channels such as markdown images or encoded URLs.",
    remediation:
      "Sanitise agent output to strip markdown images and external URLs. " +
      "Block outbound requests that embed user data in query parameters.",
  },
  full_chain: {
    title: "Complete data theft chain detected",
    description:
      "An attacker can hijack the agent via prompt injection, access " +
      "sensitive data through extraction, and exfiltrate it through a " +
      "covert channel — a complete end-to-end attack.",
    remediation:
      "Apply defence in depth: validate inputs against injection, restrict " +
      "data access scope, and sanitise outputs to prevent exfiltration.",
  },
};

// ═══════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════

function bestProbe(probes: ProbeResult[]): ProbeResult {
  return probes.reduce((best, p) => {
    const pRank = SEVERITY_RANK[p.severity] ?? 0;
    const bestRank = SEVERITY_RANK[best.severity] ?? 0;
    if (pRank > bestRank) return p;
    if (pRank === bestRank && p.confidence > best.confidence) return p;
    return best;
  });
}

function makeStep(stepNumber: number, probe: ProbeResult): ChainStep {
  const role = STEP_ROLES[stepNumber] ?? "STEP";
  return {
    step_number: stepNumber,
    probe_id: probe.probe_id,
    category: probe.category,
    technique: probe.technique,
    verdict: probe.verdict,
    summary: `${role}: ${probe.technique} via ${probe.category}`,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// CHAIN DETECTION
// ═══════════════════════════════════════════════════════════════════════

/** Analyze probe results to identify complete attack chains. */
export function detectChains(report: ScanReport): AttackChain[] {
  const results = report.results ?? [];

  const leakedInjections = results.filter(
    (p) => p.probe_type === "injection" && p.verdict === Verdict.LEAKED,
  );
  const leakedExtractions = results.filter(
    (p) =>
      p.probe_type === "extraction" &&
      (p.verdict === Verdict.LEAKED || p.verdict === Verdict.PARTIAL),
  );
  const exfilProbes = leakedInjections.filter((p) => EXFIL_CATEGORIES.has(p.category));

  const chains: AttackChain[] = [];
  let hasFull = false;

  // Full chain: injection + extraction + exfiltration
  if (leakedInjections.length > 0 && leakedExtractions.length > 0 && exfilProbes.length > 0) {
    hasFull = true;
    const meta = CHAIN_META.full_chain!;
    chains.push({
      chain_type: "full_chain",
      severity: "critical",
      title: meta.title,
      description: meta.description,
      steps: [
        makeStep(1, bestProbe(leakedInjections)),
        makeStep(2, bestProbe(leakedExtractions)),
        makeStep(3, bestProbe(exfilProbes)),
      ],
      remediation: meta.remediation,
    });
  }

  // Injection + extraction (only if no full chain)
  if (leakedInjections.length > 0 && leakedExtractions.length > 0 && !hasFull) {
    const meta = CHAIN_META.injection_extraction!;
    chains.push({
      chain_type: "injection_extraction",
      severity: "high",
      title: meta.title,
      description: meta.description,
      steps: [
        makeStep(1, bestProbe(leakedInjections)),
        makeStep(2, bestProbe(leakedExtractions)),
      ],
      remediation: meta.remediation,
    });
  }

  // Injection + exfiltration (only if no full chain)
  if (exfilProbes.length > 0 && !hasFull) {
    const meta = CHAIN_META.injection_exfiltration!;
    const nonExfilInjections = leakedInjections.filter((p) => !EXFIL_CATEGORIES.has(p.category));
    const bestInj =
      nonExfilInjections.length > 0 ? bestProbe(nonExfilInjections) : bestProbe(leakedInjections);
    chains.push({
      chain_type: "injection_exfiltration",
      severity: "critical",
      title: meta.title,
      description: meta.description,
      steps: [makeStep(1, bestInj), makeStep(2, bestProbe(exfilProbes))],
      remediation: meta.remediation,
    });
  }

  return chains.slice(0, MAX_CHAINS);
}
