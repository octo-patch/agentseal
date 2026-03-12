/**
 * Data models for the guard command — machine-level security scanning.
 *
 * Port of Python agentseal/guard_models.py — same structure, TypeScript interfaces.
 */

// ═══════════════════════════════════════════════════════════════════════
// GUARD VERDICT
// ═══════════════════════════════════════════════════════════════════════

export const GuardVerdict = {
  SAFE: "safe",
  WARNING: "warning",
  DANGER: "danger",
  ERROR: "error",
} as const;
export type GuardVerdict = (typeof GuardVerdict)[keyof typeof GuardVerdict];

export const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

// ═══════════════════════════════════════════════════════════════════════
// SKILL SCANNING MODELS
// ═══════════════════════════════════════════════════════════════════════

export interface SkillFinding {
  code: string;         // e.g. "SKILL-001"
  title: string;        // Human-readable: "Credential theft pattern"
  description: string;  // Plain English: "This skill reads ~/.ssh/..."
  severity: string;     // "critical", "high", "medium", "low"
  evidence: string;     // The suspicious line or pattern found
  remediation: string;  // "Remove this skill and rotate API keys"
}

export interface SkillResult {
  name: string;
  path: string;
  verdict: GuardVerdict;
  findings: SkillFinding[];
  blocklist_match: boolean;
  sha256: string;
}

/** Return the highest-severity finding from a SkillResult, or undefined. */
export function topSkillFinding(result: SkillResult): SkillFinding | undefined {
  if (result.findings.length === 0) return undefined;
  return result.findings.reduce((best, f) =>
    (SEVERITY_ORDER[f.severity] ?? 99) < (SEVERITY_ORDER[best.severity] ?? 99) ? f : best
  );
}

// ═══════════════════════════════════════════════════════════════════════
// MCP CONFIG SCANNING MODELS
// ═══════════════════════════════════════════════════════════════════════

export interface MCPFinding {
  code: string;         // e.g. "MCP-001"
  title: string;
  description: string;
  severity: string;
  remediation: string;
}

export interface MCPServerResult {
  name: string;
  command: string;
  source_file: string;
  verdict: GuardVerdict;
  findings: MCPFinding[];
}

/** Return the highest-severity finding from an MCPServerResult, or undefined. */
export function topMCPFinding(result: MCPServerResult): MCPFinding | undefined {
  if (result.findings.length === 0) return undefined;
  return result.findings.reduce((best, f) =>
    (SEVERITY_ORDER[f.severity] ?? 99) < (SEVERITY_ORDER[best.severity] ?? 99) ? f : best
  );
}

// ═══════════════════════════════════════════════════════════════════════
// AGENT DISCOVERY MODELS
// ═══════════════════════════════════════════════════════════════════════

export interface AgentConfigResult {
  name: string;          // "Claude Desktop", "Cursor", etc.
  config_path: string;
  agent_type: string;    // "claude-desktop", "cursor", "vscode", etc.
  mcp_servers: number;
  skills_count: number;
  status: string;        // "found", "not_installed", "error"
}

// ═══════════════════════════════════════════════════════════════════════
// MCP RUNTIME ANALYSIS MODELS
// ═══════════════════════════════════════════════════════════════════════

export interface MCPRuntimeFinding {
  code: string;          // e.g. "MCPR-101"
  title: string;
  description: string;
  severity: string;
  evidence: string;
  remediation: string;
  tool_name: string;     // "" for server-level
  server_name: string;
}

export interface MCPRuntimeResult {
  server_name: string;
  tools_found: number;
  findings: MCPRuntimeFinding[];
  verdict: GuardVerdict;
  connection_status: string; // "connected", "timeout", "auth_failed", "error"
}

// ═══════════════════════════════════════════════════════════════════════
// TOXIC FLOW MODELS
// ═══════════════════════════════════════════════════════════════════════

export interface ToxicFlowResult {
  risk_level: string;     // "high", "medium"
  risk_type: string;      // "data_exfiltration", "remote_code_execution", etc.
  title: string;
  description: string;
  servers_involved: string[];
  remediation: string;
  tools_involved: string[];    // e.g. ["server:read_file", "server:send_msg"]
  labels_involved: string[];   // e.g. ["private_data", "public_sink"]
}

// ═══════════════════════════════════════════════════════════════════════
// BASELINE CHANGE MODELS
// ═══════════════════════════════════════════════════════════════════════

export interface BaselineChangeResult {
  server_name: string;
  agent_type: string;
  change_type: string;   // "config_changed", "binary_changed"
  detail: string;
}

// ═══════════════════════════════════════════════════════════════════════
// GUARD REPORT (top-level result)
// ═══════════════════════════════════════════════════════════════════════

export interface GuardReport {
  timestamp: string;
  duration_seconds: number;
  agents_found: AgentConfigResult[];
  skill_results: SkillResult[];
  mcp_results: MCPServerResult[];
  mcp_runtime_results: MCPRuntimeResult[];
  toxic_flows: ToxicFlowResult[];
  baseline_changes: BaselineChangeResult[];
  llm_tokens_used: number;
}

/** Count items with a given verdict across results. */
function countVerdict(
  skills: SkillResult[],
  mcp: MCPServerResult[],
  runtime: MCPRuntimeResult[],
  verdict: GuardVerdict,
): number {
  return (
    skills.filter((s) => s.verdict === verdict).length +
    mcp.filter((m) => m.verdict === verdict).length +
    runtime.filter((r) => r.verdict === verdict).length
  );
}

export function totalDangers(report: GuardReport): number {
  return countVerdict(report.skill_results, report.mcp_results, report.mcp_runtime_results, GuardVerdict.DANGER);
}

export function totalWarnings(report: GuardReport): number {
  return countVerdict(report.skill_results, report.mcp_results, report.mcp_runtime_results, GuardVerdict.WARNING);
}

export function totalSafe(report: GuardReport): number {
  return countVerdict(report.skill_results, report.mcp_results, report.mcp_runtime_results, GuardVerdict.SAFE);
}

export function hasCritical(report: GuardReport): boolean {
  return totalDangers(report) > 0;
}

/** Collect all remediation actions, sorted by severity. */
export function allActions(report: GuardReport): string[] {
  const all: Array<{ severity: string; remediation: string }> = [];

  for (const s of report.skill_results) {
    for (const f of s.findings) all.push({ severity: f.severity, remediation: f.remediation });
  }
  for (const m of report.mcp_results) {
    for (const f of m.findings) all.push({ severity: f.severity, remediation: f.remediation });
  }
  for (const r of report.mcp_runtime_results) {
    for (const f of r.findings) all.push({ severity: f.severity, remediation: f.remediation });
  }

  all.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99));
  return all.map((x) => x.remediation);
}
