import { describe, it, expect } from "vitest";
import { generateRemediation } from "../src/remediation.js";
import type { ScanReport, ProbeResult } from "../src/types.js";
import { Verdict, Severity, TrustLevel } from "../src/types.js";

function makeReport(results: Partial<ProbeResult>[]): ScanReport {
  return {
    agent_name: "Test Agent",
    scan_id: "test123",
    timestamp: new Date().toISOString(),
    duration_seconds: 10,
    total_probes: results.length,
    probes_blocked: results.filter((r) => r.verdict === Verdict.BLOCKED).length,
    probes_leaked: results.filter((r) => r.verdict === Verdict.LEAKED).length,
    probes_partial: results.filter((r) => r.verdict === Verdict.PARTIAL).length,
    probes_error: 0,
    trust_score: 50,
    trust_level: TrustLevel.MEDIUM,
    score_breakdown: { overall: 50, extraction_resistance: 50, injection_resistance: 50, boundary_integrity: 50, consistency: 50 },
    results: results.map((r) => ({
      probe_id: r.probe_id ?? "test",
      category: r.category ?? "direct_ask",
      probe_type: r.probe_type ?? "extraction",
      technique: "test",
      severity: r.severity ?? Severity.HIGH,
      attack_text: "test",
      response_text: "test",
      verdict: r.verdict ?? Verdict.LEAKED,
      confidence: 0.9,
      reasoning: "test",
      duration_ms: 100,
    })),
    ground_truth_provided: true,
  };
}

describe("generateRemediation", () => {
  it("returns no-issues for all-blocked reports", () => {
    const report = makeReport([
      { verdict: Verdict.BLOCKED, category: "direct_ask" },
    ]);
    const remediation = generateRemediation(report);
    expect(remediation.items[0]!.title).toBe("No issues found");
    expect(remediation.combined_fix).toBe("");
  });

  it("generates fix items for leaked probes", () => {
    const report = makeReport([
      { verdict: Verdict.LEAKED, category: "direct_ask", probe_id: "ext_1" },
      { verdict: Verdict.LEAKED, category: "encoding_tricks", probe_id: "ext_2" },
    ]);
    const remediation = generateRemediation(report);
    expect(remediation.items.length).toBeGreaterThanOrEqual(2);
    expect(remediation.combined_fix).toContain("SECURITY RULES");
  });

  it("deduplicates items with same fix_text", () => {
    // direct_ask and output_format share the same fix_text
    const report = makeReport([
      { verdict: Verdict.LEAKED, category: "direct_ask", probe_id: "ext_1" },
      { verdict: Verdict.LEAKED, category: "output_format", probe_id: "ext_2" },
    ]);
    const remediation = generateRemediation(report);
    // Should be deduplicated to 1 item
    expect(remediation.items.length).toBe(1);
    expect(remediation.items[0]!.affected_probes.length).toBe(2);
  });

  it("sorts by priority (critical first)", () => {
    const report = makeReport([
      { verdict: Verdict.LEAKED, category: "direct_ask", probe_id: "ext_1", severity: Severity.LOW },
      { verdict: Verdict.LEAKED, category: "boundary_confusion", probe_id: "ext_2", severity: Severity.CRITICAL },
    ]);
    const remediation = generateRemediation(report);
    expect(remediation.items[0]!.priority).toBe("critical");
  });

  it("includes analysis with failed count", () => {
    const report = makeReport([
      { verdict: Verdict.LEAKED, category: "direct_ask", probe_id: "ext_1" },
      { verdict: Verdict.BLOCKED, category: "encoding_tricks", probe_id: "ext_2" },
    ]);
    const remediation = generateRemediation(report);
    expect(remediation.analysis).toContain("1/2");
  });
});
