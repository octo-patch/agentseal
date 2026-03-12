/**
 * Guard — one-command machine security scan.
 *
 * Chains machine discovery, skill scanning, blocklist, and deobfuscation
 * into a single zero-config experience.
 *
 * Port of Python agentseal/guard.py + agentseal/skill_scanner.py.
 */

import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { basename, extname } from "node:path";

import { BaselineStore } from "./baselines.js";
import { Blocklist } from "./blocklist.js";
import { deobfuscate } from "./deobfuscate.js";
import {
  GuardVerdict,
  type GuardReport,
  type SkillFinding,
  type SkillResult,
} from "./guard-models.js";
import { scanDirectory, scanMachine, type DiscoveryResult } from "./machine-discovery.js";
import { MCPConfigChecker } from "./mcp-checker.js";
import { SkillScanner } from "./skill-scanner.js";
import { analyzeToxicFlows } from "./toxic-flows.js";

// ═══════════════════════════════════════════════════════════════════════
// PROGRESS CALLBACK
// ═══════════════════════════════════════════════════════════════════════

export type GuardProgressFn = (phase: string, detail: string) => void;

// ═══════════════════════════════════════════════════════════════════════
// GUARD OPTIONS
// ═══════════════════════════════════════════════════════════════════════

export interface GuardOptions {
  /** Enable semantic analysis (requires embedFn). Default: false */
  semantic?: boolean;
  /** Verbose output. Default: false */
  verbose?: boolean;
  /** Progress callback. */
  onProgress?: GuardProgressFn;
  /** Embedding function for semantic analysis. */
  embedFn?: (texts: string[]) => Promise<number[][]>;
  /** Scan a specific directory instead of the whole machine. */
  scanPath?: string;
}

// ═══════════════════════════════════════════════════════════════════════
// SKILL FILE SCANNER
// ═══════════════════════════════════════════════════════════════════════

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB

/** Extract a human-readable name from a skill file path. */
function extractSkillName(filePath: string): string {
  const name = basename(filePath);
  if (name.toLowerCase() === "skill.md") {
    // Use parent directory name
    const parts = filePath.split("/");
    return parts[parts.length - 2] ?? name;
  }
  // Remove extension
  const ext = extname(name);
  return ext ? name.slice(0, -ext.length) : name;
}

/** Determine verdict from findings. Worst severity wins. */
function computeVerdict(findings: SkillFinding[]): GuardVerdict {
  if (findings.length === 0) return GuardVerdict.SAFE;
  if (findings.some((f) => f.severity === "critical")) return GuardVerdict.DANGER;
  if (findings.some((f) => f.severity === "high" || f.severity === "medium")) return GuardVerdict.WARNING;
  return GuardVerdict.SAFE;
}

/** Scan a single skill file through all detection layers. */
function scanSkillFile(
  filePath: string,
  scanner: SkillScanner,
  blocklist: Blocklist,
): SkillResult {
  const name = extractSkillName(filePath);

  // Read file
  let content: string;
  let sha256: string;
  try {
    const stat = statSync(filePath);
    if (stat.size > MAX_FILE_SIZE) {
      return {
        name,
        path: filePath,
        verdict: GuardVerdict.ERROR,
        findings: [{
          code: "SKILL-ERR",
          title: "File too large",
          description: `File is ${Math.floor(stat.size / 1024 / 1024)}MB, max is 10MB.`,
          severity: "low",
          evidence: "",
          remediation: "Skill files should be small text files.",
        }],
        blocklist_match: false,
        sha256: "",
      };
    }

    const raw = readFileSync(filePath);
    sha256 = createHash("sha256").update(raw).digest("hex");
    content = raw.toString("utf-8");
  } catch (err) {
    return {
      name,
      path: filePath,
      verdict: GuardVerdict.ERROR,
      findings: [{
        code: "SKILL-ERR",
        title: "Could not read file",
        description: String(err),
        severity: "low",
        evidence: "",
        remediation: "Check file permissions.",
      }],
      blocklist_match: false,
      sha256: "",
    };
  }

  if (!content.trim()) {
    return { name, path: filePath, verdict: GuardVerdict.SAFE, findings: [], blocklist_match: false, sha256 };
  }

  // Layer 1: Blocklist check
  if (blocklist.isBlocked(sha256)) {
    return {
      name,
      path: filePath,
      verdict: GuardVerdict.DANGER,
      findings: [{
        code: "SKILL-000",
        title: "Known malicious skill",
        description: "This skill matches a known malware hash in the AgentSeal threat database.",
        severity: "critical",
        evidence: `SHA256: ${sha256}`,
        remediation: "Remove this skill immediately and rotate all credentials.",
      }],
      blocklist_match: true,
      sha256,
    };
  }

  // Layer 2: Static pattern matching (on original + deobfuscated content)
  const findings = scanner.scanPatterns(content);
  const deobfuscated = deobfuscate(content);
  if (deobfuscated !== content) {
    const deobFindings = scanner.scanPatterns(deobfuscated);
    const existing = new Set(findings.map((f) => `${f.code}::${f.evidence}`));
    for (const f of deobFindings) {
      if (!existing.has(`${f.code}::${f.evidence}`)) {
        findings.push(f);
      }
    }
  }

  const verdict = computeVerdict(findings);

  return { name, path: filePath, verdict, findings, blocklist_match: false, sha256 };
}

// ═══════════════════════════════════════════════════════════════════════
// GUARD CLASS
// ═══════════════════════════════════════════════════════════════════════

export class Guard {
  private readonly _options: Required<GuardOptions>;

  constructor(options: GuardOptions = {}) {
    this._options = {
      semantic: options.semantic ?? false,
      verbose: options.verbose ?? false,
      onProgress: options.onProgress ?? (() => {}),
      embedFn: options.embedFn ?? (undefined as any),
      scanPath: options.scanPath ?? "",
    };
  }

  /** Execute full guard scan. Returns a GuardReport with all findings. */
  run(): GuardReport {
    const start = performance.now();
    const progress = this._options.onProgress;

    // Phase 1: Discover
    let discovery: DiscoveryResult;
    if (this._options.scanPath) {
      progress("discover", `Scanning directory: ${this._options.scanPath}`);
      discovery = scanDirectory(this._options.scanPath);
    } else {
      progress("discover", "Scanning for AI agents, skills, and MCP servers...");
      discovery = scanMachine();
    }

    const installedCount = discovery.agents.filter(
      (a) => a.status === "found" || a.status === "installed_no_config",
    ).length;
    progress(
      "discover",
      `Found ${installedCount} agents, ${discovery.skillPaths.length} skills, ` +
        `${discovery.mcpServers.length} MCP servers`,
    );

    // Phase 2: Scan skills
    progress("skills", `Scanning ${discovery.skillPaths.length} skills for threats...`);
    const scanner = new SkillScanner();
    const blocklist = new Blocklist();
    const skillResults: SkillResult[] = [];
    for (let i = 0; i < discovery.skillPaths.length; i++) {
      const path = discovery.skillPaths[i]!;
      progress("skills", `[${i + 1}/${discovery.skillPaths.length}] ${basename(path)}`);
      skillResults.push(scanSkillFile(path, scanner, blocklist));
    }

    // Phase 3: Check MCP configs
    progress("mcp", `Checking ${discovery.mcpServers.length} MCP server configurations...`);
    const mcpChecker = new MCPConfigChecker();
    const mcpResults = mcpChecker.checkAll(discovery.mcpServers);

    // Phase 4: Toxic flow analysis
    const toxicFlows = discovery.mcpServers.length >= 2
      ? analyzeToxicFlows(discovery.mcpServers)
      : [];
    if (toxicFlows.length > 0) {
      progress("flows", `Found ${toxicFlows.length} toxic flow(s)`);
    }

    // Phase 5: Baseline check (rug pull detection)
    const baselineStore = new BaselineStore();
    const baselineChanges = discovery.mcpServers.length > 0
      ? baselineStore.checkAll(discovery.mcpServers).map((c) => ({
          server_name: c.server_name,
          agent_type: c.agent_type,
          change_type: c.change_type,
          detail: c.detail,
        }))
      : [];
    if (baselineChanges.length > 0) {
      progress("baselines", `${baselineChanges.length} baseline change(s) detected`);
    }

    const duration = (performance.now() - start) / 1000;

    return {
      timestamp: new Date().toISOString(),
      duration_seconds: Math.round(duration * 100) / 100,
      agents_found: discovery.agents,
      skill_results: skillResults,
      mcp_results: mcpResults,
      mcp_runtime_results: [],
      toxic_flows: toxicFlows,
      baseline_changes: baselineChanges,
      llm_tokens_used: 0,
    };
  }
}

// Re-export for convenience
export { scanSkillFile, extractSkillName, computeVerdict };
