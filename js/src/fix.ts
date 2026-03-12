/**
 * Fix engine — skill quarantine + report loading.
 *
 * Provides core logic for the `agentseal fix` command:
 *   - Quarantine dangerous skills (move to ~/.agentseal/quarantine/)
 *   - Restore quarantined skills
 *   - Load/save guard and scan reports
 *   - Extract fixable skills from guard reports
 *
 * Port of Python agentseal/fix.py.
 */

import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, extname, join, resolve } from "node:path";

// ═══════════════════════════════════════════════════════════════════════
// DEFAULT PATHS
// ═══════════════════════════════════════════════════════════════════════

export const QUARANTINE_DIR = join(homedir(), ".agentseal", "quarantine");
export const REPORTS_DIR = join(homedir(), ".agentseal", "reports");
export const BACKUPS_DIR = join(homedir(), ".agentseal", "backups");

// ═══════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════

export interface QuarantineEntry {
  original_path: string;
  quarantine_path: string;
  reason: string;
  timestamp: string;
  skill_name: string;
}

export interface FixResult {
  action: string; // "quarantined" | "hardened" | "skipped" | "error"
  target: string;
  detail: string;
  before: string | null;
  after: string | null;
}

// ═══════════════════════════════════════════════════════════════════════
// MANIFEST HELPERS
// ═══════════════════════════════════════════════════════════════════════

function manifestPath(quarantineDir: string): string {
  return join(quarantineDir, "manifest.json");
}

function rglob(dir: string): string[] {
  const results: string[] = [];
  const walk = (d: string) => {
    try {
      for (const entry of readdirSync(d, { withFileTypes: true })) {
        const full = join(d, entry.name);
        if (entry.isDirectory()) walk(full);
        else if (entry.isFile()) results.push(full);
      }
    } catch { /* ignore */ }
  };
  walk(dir);
  return results;
}

function loadManifest(quarantineDir: string): Array<Record<string, any>> {
  const mp = manifestPath(quarantineDir);
  if (!existsSync(mp)) return [];
  try {
    const data = JSON.parse(readFileSync(mp, "utf-8"));
    if (Array.isArray(data)) return data;
  } catch {
    // Fall through to best-effort rebuild
  }

  // Best-effort rebuild from directory listing
  const entries: Array<Record<string, any>> = [];
  for (const f of rglob(quarantineDir)) {
    if (basename(f) === "manifest.json") continue;
    const stem = basename(f, extname(f));
    entries.push({
      original_path: "",
      quarantine_path: f,
      reason: "recovered from corrupted manifest",
      timestamp: new Date().toISOString(),
      skill_name: stem,
    });
  }
  return entries;
}

function saveManifest(quarantineDir: string, entries: Array<Record<string, any>>): void {
  mkdirSync(quarantineDir, { recursive: true });
  writeFileSync(manifestPath(quarantineDir), JSON.stringify(entries, null, 2), "utf-8");
}

// ═══════════════════════════════════════════════════════════════════════
// QUARANTINE
// ═══════════════════════════════════════════════════════════════════════

/**
 * Move a dangerous skill to quarantine.
 *
 * Preserves relative directory structure under the quarantine dir.
 * Handles duplicate filenames by adding _1, _2, etc. suffixes.
 */
export function quarantineSkill(
  skillPath: string,
  reason = "",
  quarantineDir?: string,
): QuarantineEntry {
  const qdir = quarantineDir ?? QUARANTINE_DIR;
  const resolvedSkill = resolve(skillPath);

  if (!existsSync(resolvedSkill)) {
    throw new Error(`Skill not found: ${resolvedSkill}`);
  }

  // Build destination preserving parent/filename context
  const parts = resolvedSkill.split("/").filter(Boolean);
  const relative = parts.length >= 2
    ? join(parts[parts.length - 2]!, parts[parts.length - 1]!)
    : basename(resolvedSkill);
  let dest = join(qdir, relative);

  // Handle duplicates
  if (existsSync(dest)) {
    const stem = basename(dest, extname(dest));
    const suffix = extname(dest);
    const parent = dirname(dest);
    let counter = 1;
    while (existsSync(dest)) {
      dest = join(parent, `${stem}_${counter}${suffix}`);
      counter++;
    }
  }

  mkdirSync(dirname(dest), { recursive: true });
  renameSync(resolvedSkill, dest);

  const entry: QuarantineEntry = {
    original_path: resolvedSkill,
    quarantine_path: dest,
    reason,
    timestamp: new Date().toISOString(),
    skill_name: basename(resolvedSkill, extname(resolvedSkill)),
  };

  const manifest = loadManifest(qdir);
  manifest.push(entry);
  saveManifest(qdir, manifest);

  return entry;
}

/**
 * Restore a quarantined skill to its original location.
 *
 * @throws Error if skill not in quarantine, original path occupied, or file missing.
 */
export function restoreSkill(skillName: string, quarantineDir?: string): string {
  const qdir = quarantineDir ?? QUARANTINE_DIR;
  const manifest = loadManifest(qdir);

  let idx = -1;
  for (let i = 0; i < manifest.length; i++) {
    if (manifest[i]!.skill_name === skillName) {
      idx = i;
      break;
    }
  }

  if (idx === -1) {
    throw new Error(`Skill '${skillName}' not found in quarantine`);
  }

  const entry = manifest[idx]!;
  if (!entry.original_path) {
    throw new Error(
      `Cannot restore '${skillName}': original path is empty ` +
      `(recovered from corrupted manifest). Re-quarantine or move manually.`,
    );
  }

  const original = resolve(entry.original_path);
  const quarantined = resolve(entry.quarantine_path);
  const qdirResolved = resolve(qdir);

  // Validate: quarantined file must be inside quarantine dir
  if (!quarantined.startsWith(qdirResolved)) {
    throw new Error(
      `Cannot restore '${skillName}': quarantine path ${quarantined} ` +
      `is outside quarantine directory. Manifest may be tampered.`,
    );
  }

  if (existsSync(original)) {
    throw new Error(`Cannot restore: original path already occupied: ${original}`);
  }

  if (!existsSync(quarantined)) {
    throw new Error(`Quarantined file missing: ${quarantined}`);
  }

  mkdirSync(dirname(original), { recursive: true });
  renameSync(quarantined, original);

  manifest.splice(idx, 1);
  saveManifest(qdir, manifest);

  return original;
}

/** List all quarantined skills from manifest. */
export function listQuarantine(quarantineDir?: string): QuarantineEntry[] {
  const qdir = quarantineDir ?? QUARANTINE_DIR;
  const manifest = loadManifest(qdir);
  const required = ["original_path", "quarantine_path", "reason", "timestamp", "skill_name"];
  return manifest
    .filter((e) => required.every((k) => k in e))
    .map((e) => ({
      original_path: e.original_path,
      quarantine_path: e.quarantine_path,
      reason: e.reason,
      timestamp: e.timestamp,
      skill_name: e.skill_name,
    }));
}

// ═══════════════════════════════════════════════════════════════════════
// REPORT I/O
// ═══════════════════════════════════════════════════════════════════════

/** Load guard report from file or latest from reportsDir. */
export function loadGuardReport(path?: string, reportsDir?: string): Record<string, any> {
  const target = path ?? join(reportsDir ?? REPORTS_DIR, "guard-latest.json");
  if (!existsSync(target)) {
    throw new Error(
      `Guard report not found: ${target}\nRun 'agentseal guard' first to generate a report.`,
    );
  }
  return JSON.parse(readFileSync(target, "utf-8"));
}

/** Load scan report from file or latest from reportsDir. */
export function loadScanReport(path?: string, reportsDir?: string): Record<string, any> {
  const target = path ?? join(reportsDir ?? REPORTS_DIR, "scan-latest.json");
  if (!existsSync(target)) {
    throw new Error(
      `Scan report not found: ${target}\nRun 'agentseal scan' first to generate a report.`,
    );
  }
  return JSON.parse(readFileSync(target, "utf-8"));
}

/** Save report to reportsDir/{type}-latest.json. Creates dir if needed. */
export function saveReport(
  reportDict: Record<string, any>,
  reportType: string,
  reportsDir?: string,
): string {
  if (reportType.includes("/") || reportType.includes("..") || reportType.includes("\\")) {
    throw new Error("Invalid report type");
  }
  const dir = reportsDir ?? REPORTS_DIR;
  mkdirSync(dir, { recursive: true });
  const target = join(dir, `${reportType}-latest.json`);
  writeFileSync(target, JSON.stringify(reportDict, null, 2), "utf-8");
  return target;
}

// ═══════════════════════════════════════════════════════════════════════
// FIXABLE SKILLS EXTRACTION
// ═══════════════════════════════════════════════════════════════════════

/** Extract skills with DANGER verdict from guard report. */
export function getFixableSkills(guardReport: Record<string, any>): Array<Record<string, any>> {
  const results: Array<Record<string, any>> = [];
  for (const skill of guardReport.skill_results ?? []) {
    if (skill.verdict === "danger") {
      results.push({
        name: skill.name ?? "",
        path: skill.path ?? "",
        findings: skill.findings ?? [],
        verdict: skill.verdict ?? "",
      });
    }
  }
  return results;
}

// Re-export manifest helpers for testing
export { manifestPath, loadManifest, saveManifest };
