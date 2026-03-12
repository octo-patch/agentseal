import { describe, it, expect } from "vitest";
import {
  GuardVerdict,
  SEVERITY_ORDER,
  topSkillFinding,
  topMCPFinding,
  totalDangers,
  totalWarnings,
  totalSafe,
  hasCritical,
  allActions,
  type SkillFinding,
  type SkillResult,
  type MCPServerResult,
  type GuardReport,
} from "../src/guard-models.js";

// ═══════════════════════════════════════════════════════════════════════
// GUARD VERDICT
// ═══════════════════════════════════════════════════════════════════════

describe("GuardVerdict", () => {
  it("has correct values", () => {
    expect(GuardVerdict.SAFE).toBe("safe");
    expect(GuardVerdict.WARNING).toBe("warning");
    expect(GuardVerdict.DANGER).toBe("danger");
    expect(GuardVerdict.ERROR).toBe("error");
  });
});

describe("SEVERITY_ORDER", () => {
  it("critical < high < medium < low", () => {
    expect(SEVERITY_ORDER.critical).toBeLessThan(SEVERITY_ORDER.high);
    expect(SEVERITY_ORDER.high).toBeLessThan(SEVERITY_ORDER.medium);
    expect(SEVERITY_ORDER.medium).toBeLessThan(SEVERITY_ORDER.low);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// TOP FINDING HELPERS
// ═══════════════════════════════════════════════════════════════════════

describe("topSkillFinding", () => {
  it("returns undefined when no findings", () => {
    const result: SkillResult = {
      name: "test", path: "/test", verdict: GuardVerdict.SAFE,
      findings: [], blocklist_match: false, sha256: "",
    };
    expect(topSkillFinding(result)).toBeUndefined();
  });

  it("returns highest severity finding", () => {
    const result: SkillResult = {
      name: "test", path: "/test", verdict: GuardVerdict.DANGER,
      findings: [
        { code: "S1", title: "Low", description: "", severity: "low", evidence: "", remediation: "fix low" },
        { code: "S2", title: "Critical", description: "", severity: "critical", evidence: "", remediation: "fix crit" },
        { code: "S3", title: "Medium", description: "", severity: "medium", evidence: "", remediation: "fix med" },
      ],
      blocklist_match: false, sha256: "",
    };
    expect(topSkillFinding(result)!.severity).toBe("critical");
  });
});

describe("topMCPFinding", () => {
  it("returns undefined when no findings", () => {
    const result: MCPServerResult = {
      name: "test", command: "npx", source_file: "/test",
      verdict: GuardVerdict.SAFE, findings: [],
    };
    expect(topMCPFinding(result)).toBeUndefined();
  });

  it("returns highest severity finding", () => {
    const result: MCPServerResult = {
      name: "test", command: "npx", source_file: "/test",
      verdict: GuardVerdict.WARNING,
      findings: [
        { code: "M1", title: "Med", description: "", severity: "medium", remediation: "" },
        { code: "M2", title: "High", description: "", severity: "high", remediation: "" },
      ],
    };
    expect(topMCPFinding(result)!.severity).toBe("high");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// GUARD REPORT HELPERS
// ═══════════════════════════════════════════════════════════════════════

function makeReport(overrides: Partial<GuardReport> = {}): GuardReport {
  return {
    timestamp: "2024-01-01T00:00:00Z",
    duration_seconds: 1.0,
    agents_found: [],
    skill_results: [],
    mcp_results: [],
    mcp_runtime_results: [],
    toxic_flows: [],
    baseline_changes: [],
    llm_tokens_used: 0,
    ...overrides,
  };
}

describe("totalDangers", () => {
  it("returns 0 for empty report", () => {
    expect(totalDangers(makeReport())).toBe(0);
  });

  it("counts dangers across all result types", () => {
    const report = makeReport({
      skill_results: [
        { name: "a", path: "", verdict: GuardVerdict.DANGER, findings: [], blocklist_match: false, sha256: "" },
        { name: "b", path: "", verdict: GuardVerdict.SAFE, findings: [], blocklist_match: false, sha256: "" },
      ],
      mcp_results: [
        { name: "c", command: "", source_file: "", verdict: GuardVerdict.DANGER, findings: [] },
      ],
      mcp_runtime_results: [
        { server_name: "d", tools_found: 0, findings: [], verdict: GuardVerdict.DANGER, connection_status: "connected" },
      ],
    });
    expect(totalDangers(report)).toBe(3);
  });
});

describe("totalWarnings", () => {
  it("counts warnings", () => {
    const report = makeReport({
      skill_results: [
        { name: "a", path: "", verdict: GuardVerdict.WARNING, findings: [], blocklist_match: false, sha256: "" },
      ],
    });
    expect(totalWarnings(report)).toBe(1);
  });
});

describe("totalSafe", () => {
  it("counts safe items", () => {
    const report = makeReport({
      skill_results: [
        { name: "a", path: "", verdict: GuardVerdict.SAFE, findings: [], blocklist_match: false, sha256: "" },
        { name: "b", path: "", verdict: GuardVerdict.SAFE, findings: [], blocklist_match: false, sha256: "" },
      ],
    });
    expect(totalSafe(report)).toBe(2);
  });
});

describe("hasCritical", () => {
  it("false for clean report", () => {
    expect(hasCritical(makeReport())).toBe(false);
  });

  it("true when any danger exists", () => {
    const report = makeReport({
      skill_results: [
        { name: "a", path: "", verdict: GuardVerdict.DANGER, findings: [], blocklist_match: false, sha256: "" },
      ],
    });
    expect(hasCritical(report)).toBe(true);
  });
});

describe("allActions", () => {
  it("returns empty for clean report", () => {
    expect(allActions(makeReport())).toEqual([]);
  });

  it("collects and sorts remediation actions by severity", () => {
    const report = makeReport({
      skill_results: [
        {
          name: "a", path: "", verdict: GuardVerdict.DANGER, blocklist_match: false, sha256: "",
          findings: [
            { code: "S1", title: "", description: "", severity: "medium", evidence: "", remediation: "fix medium" },
            { code: "S2", title: "", description: "", severity: "critical", evidence: "", remediation: "fix critical" },
          ],
        },
      ],
      mcp_results: [
        {
          name: "b", command: "", source_file: "", verdict: GuardVerdict.WARNING,
          findings: [
            { code: "M1", title: "", description: "", severity: "low", remediation: "fix low" },
          ],
        },
      ],
    });
    const actions = allActions(report);
    expect(actions).toEqual(["fix critical", "fix medium", "fix low"]);
  });
});
