import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import {
  quarantineSkill,
  restoreSkill,
  listQuarantine,
  loadGuardReport,
  loadScanReport,
  saveReport,
  getFixableSkills,
  manifestPath,
  type QuarantineEntry,
} from "../src/fix.js";

// ═══════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════

function makeSkill(tmpDir: string, relPath = "rules/bad.md", content = "evil stuff"): string {
  const p = join(tmpDir, "skills", relPath);
  mkdirSync(join(p, ".."), { recursive: true });
  writeFileSync(p, content);
  return p;
}

function makeGuardReport(skills: Array<Record<string, any>> = []): Record<string, any> {
  return {
    timestamp: "2026-01-01T00:00:00Z",
    duration_seconds: 1.0,
    agents_found: [],
    skill_results: skills,
    mcp_results: [],
  };
}

// ═══════════════════════════════════════════════════════════════════════
// QUARANTINE
// ═══════════════════════════════════════════════════════════════════════

describe("quarantineSkill", () => {
  it("moves file to quarantine", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "fix-q-"));
    const skill = makeSkill(tmpDir);
    const qdir = join(tmpDir, "quarantine");

    const entry = quarantineSkill(skill, "dangerous", qdir);

    expect(existsSync(skill)).toBe(false);
    expect(existsSync(entry.quarantine_path)).toBe(true);
    expect(entry.reason).toBe("dangerous");
    expect(entry.skill_name).toBe("bad");

    // Manifest should be updated
    const manifest = JSON.parse(readFileSync(manifestPath(qdir), "utf-8"));
    expect(manifest).toHaveLength(1);
    expect(manifest[0].skill_name).toBe("bad");
  });

  it("preserves directory structure", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "fix-q-"));
    const skill = makeSkill(tmpDir, "cursor/rules/risky.md");
    const qdir = join(tmpDir, "quarantine");

    const entry = quarantineSkill(skill, "", qdir);
    expect(entry.quarantine_path).toContain("rules");
    expect(entry.quarantine_path).toContain("risky.md");
  });

  it("handles duplicate filenames", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "fix-q-"));
    const qdir = join(tmpDir, "quarantine");

    const skill1 = makeSkill(tmpDir, "a/rules/bad.md", "v1");
    const entry1 = quarantineSkill(skill1, "", qdir);

    const skill2 = makeSkill(tmpDir, "a/rules/bad.md", "v2");
    const entry2 = quarantineSkill(skill2, "", qdir);

    expect(entry1.quarantine_path).not.toBe(entry2.quarantine_path);
    expect(existsSync(entry1.quarantine_path)).toBe(true);
    expect(existsSync(entry2.quarantine_path)).toBe(true);
    expect(entry2.quarantine_path).toContain("_1");
  });

  it("creates manifest file", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "fix-q-"));
    const skill = makeSkill(tmpDir);
    const qdir = join(tmpDir, "quarantine");

    expect(existsSync(manifestPath(qdir))).toBe(false);
    quarantineSkill(skill, "", qdir);
    expect(existsSync(manifestPath(qdir))).toBe(true);
  });

  it("throws for nonexistent file", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "fix-q-"));
    expect(() => quarantineSkill(join(tmpDir, "ghost.md"), "", tmpDir)).toThrow(/not found/);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// RESTORE
// ═══════════════════════════════════════════════════════════════════════

describe("restoreSkill", () => {
  it("moves file back to original location", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "fix-r-"));
    const skill = makeSkill(tmpDir, "rules/bad.md", "my content");
    const originalPath = resolve(skill);
    const qdir = join(tmpDir, "quarantine");

    quarantineSkill(skill, "", qdir);
    expect(existsSync(originalPath)).toBe(false);

    const restored = restoreSkill("bad", qdir);
    expect(restored).toBe(originalPath);
    expect(existsSync(restored)).toBe(true);
    expect(readFileSync(restored, "utf-8")).toBe("my content");
  });

  it("updates manifest after restore", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "fix-r-"));
    const skill = makeSkill(tmpDir);
    const qdir = join(tmpDir, "quarantine");

    quarantineSkill(skill, "", qdir);
    const before = JSON.parse(readFileSync(manifestPath(qdir), "utf-8"));
    expect(before).toHaveLength(1);

    restoreSkill("bad", qdir);
    const after = JSON.parse(readFileSync(manifestPath(qdir), "utf-8"));
    expect(after).toHaveLength(0);
  });

  it("throws for unknown skill", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "fix-r-"));
    const qdir = join(tmpDir, "quarantine");
    mkdirSync(qdir, { recursive: true });

    expect(() => restoreSkill("nonexistent", qdir)).toThrow(/not found in quarantine/);
  });

  it("throws when original path is occupied", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "fix-r-"));
    const skill = makeSkill(tmpDir, "rules/bad.md", "original");
    const qdir = join(tmpDir, "quarantine");

    quarantineSkill(skill, "", qdir);
    makeSkill(tmpDir, "rules/bad.md", "new occupant");

    expect(() => restoreSkill("bad", qdir)).toThrow(/already occupied/);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// LIST QUARANTINE
// ═══════════════════════════════════════════════════════════════════════

describe("listQuarantine", () => {
  it("returns empty for no quarantine", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "fix-l-"));
    const result = listQuarantine(join(tmpDir, "quarantine"));
    expect(result).toEqual([]);
  });

  it("returns all quarantined entries", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "fix-l-"));
    const qdir = join(tmpDir, "quarantine");

    const skill1 = makeSkill(tmpDir, "a/one.md");
    const skill2 = makeSkill(tmpDir, "b/two.md");

    quarantineSkill(skill1, "bad1", qdir);
    quarantineSkill(skill2, "bad2", qdir);

    const entries = listQuarantine(qdir);
    expect(entries).toHaveLength(2);
    const names = new Set(entries.map((e) => e.skill_name));
    expect(names).toEqual(new Set(["one", "two"]));
  });
});

// ═══════════════════════════════════════════════════════════════════════
// REPORT I/O
// ═══════════════════════════════════════════════════════════════════════

describe("report I/O", () => {
  it("save and load guard report", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "fix-rpt-"));
    const report = makeGuardReport();
    saveReport(report, "guard", tmpDir);
    const loaded = loadGuardReport(undefined, tmpDir);
    expect(loaded.timestamp).toBe(report.timestamp);
    expect(loaded.skill_results).toEqual([]);
  });

  it("save and load scan report", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "fix-rpt-"));
    const report = { agent_name: "test", scan_id: "test-001" };
    saveReport(report, "scan", tmpDir);
    const loaded = loadScanReport(undefined, tmpDir);
    expect(loaded.agent_name).toBe("test");
  });

  it("throws on missing guard report", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "fix-rpt-"));
    expect(() => loadGuardReport(join(tmpDir, "nope.json"))).toThrow(/not found/);
  });

  it("throws on missing scan report", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "fix-rpt-"));
    expect(() => loadScanReport(join(tmpDir, "nope.json"))).toThrow(/not found/);
  });

  it("rejects invalid report type", () => {
    expect(() => saveReport({}, "../../evil")).toThrow(/Invalid report type/);
    expect(() => saveReport({}, "path/traversal")).toThrow(/Invalid report type/);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// FIXABLE SKILLS
// ═══════════════════════════════════════════════════════════════════════

describe("getFixableSkills", () => {
  it("filters only danger skills", () => {
    const report = makeGuardReport([
      { name: "bad_skill", path: "/tmp/bad.md", verdict: "danger", findings: [{ code: "SKILL-001" }], sha256: "" },
      { name: "safe_skill", path: "/tmp/safe.md", verdict: "safe", findings: [], sha256: "" },
      { name: "warn_skill", path: "/tmp/warn.md", verdict: "warning", findings: [], sha256: "" },
    ]);

    const fixable = getFixableSkills(report);
    expect(fixable).toHaveLength(1);
    expect(fixable[0]!.name).toBe("bad_skill");
    expect(fixable[0]!.verdict).toBe("danger");
  });

  it("returns empty for all-safe report", () => {
    const report = makeGuardReport([
      { name: "good1", path: "/tmp/g1.md", verdict: "safe", findings: [], sha256: "" },
      { name: "good2", path: "/tmp/g2.md", verdict: "safe", findings: [], sha256: "" },
    ]);

    expect(getFixableSkills(report)).toEqual([]);
  });
});
