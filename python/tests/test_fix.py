# tests/test_fix.py
"""Tests for agentseal.fix — quarantine, restore, report I/O, fixable extraction."""

import json
from pathlib import Path

import pytest

from agentseal.fix import (
    QuarantineEntry,
    quarantine_skill,
    restore_skill,
    list_quarantine,
    load_guard_report,
    load_scan_report,
    save_report,
    get_fixable_skills,
    _manifest_path,
)


# ═══════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _make_skill(tmp_path: Path, rel_path: str = "rules/bad.md",
                content: str = "evil stuff") -> Path:
    """Create a fake skill file and return its path."""
    p = tmp_path / "skills" / rel_path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def _make_guard_report(skills: list[dict] | None = None) -> dict:
    """Build a minimal guard report dict."""
    if skills is None:
        skills = []
    return {
        "timestamp": "2026-01-01T00:00:00Z",
        "duration_seconds": 1.0,
        "agents_found": [],
        "skill_results": skills,
        "mcp_results": [],
        "summary": {"total_dangers": 0, "total_warnings": 0, "total_safe": 0},
    }


def _make_scan_report(results: list[dict] | None = None) -> dict:
    """Build a minimal scan report dict."""
    if results is None:
        results = []
    return {
        "agent_name": "test",
        "scan_id": "test-001",
        "timestamp": "2026-01-01T00:00:00Z",
        "duration_seconds": 1.0,
        "total_probes": len(results),
        "probes_blocked": 0,
        "probes_leaked": len(results),
        "probes_partial": 0,
        "probes_error": 0,
        "trust_score": 50.0,
        "trust_level": "medium",
        "score_breakdown": {},
        "results": results,
        "ground_truth_provided": False,
    }


# ═══════════════════════════════════════════════════════════════════════
# QUARANTINE TESTS
# ═══════════════════════════════════════════════════════════════════════

def test_quarantine_skill_moves_file(tmp_path):
    skill = _make_skill(tmp_path)
    qdir = tmp_path / "quarantine"

    entry = quarantine_skill(skill, reason="dangerous", quarantine_dir=qdir)

    assert not skill.exists(), "Original file should be removed"
    assert Path(entry.quarantine_path).exists(), "File should be in quarantine"
    assert entry.reason == "dangerous"
    assert entry.skill_name == "bad"

    # Manifest should be updated
    manifest = json.loads(_manifest_path(qdir).read_text(encoding="utf-8"))
    assert len(manifest) == 1
    assert manifest[0]["skill_name"] == "bad"


def test_quarantine_preserves_directory_structure(tmp_path):
    skill = _make_skill(tmp_path, rel_path="cursor/rules/risky.md")
    qdir = tmp_path / "quarantine"

    entry = quarantine_skill(skill, quarantine_dir=qdir)

    qpath = Path(entry.quarantine_path)
    # Should preserve at least parent/filename structure
    assert "rules" in str(qpath)
    assert qpath.name == "risky.md"


def test_quarantine_handles_duplicate_filename(tmp_path):
    qdir = tmp_path / "quarantine"

    skill1 = _make_skill(tmp_path, rel_path="a/rules/bad.md", content="v1")
    entry1 = quarantine_skill(skill1, quarantine_dir=qdir)

    # Create another file with the same relative structure
    skill2 = _make_skill(tmp_path, rel_path="a/rules/bad.md", content="v2")
    entry2 = quarantine_skill(skill2, quarantine_dir=qdir)

    assert entry1.quarantine_path != entry2.quarantine_path
    assert Path(entry1.quarantine_path).exists()
    assert Path(entry2.quarantine_path).exists()
    # The duplicate should have a suffix like _1
    assert "_1" in Path(entry2.quarantine_path).stem


def test_quarantine_creates_manifest(tmp_path):
    skill = _make_skill(tmp_path)
    qdir = tmp_path / "quarantine"

    assert not _manifest_path(qdir).exists()
    quarantine_skill(skill, quarantine_dir=qdir)
    assert _manifest_path(qdir).exists()


# ═══════════════════════════════════════════════════════════════════════
# RESTORE TESTS
# ═══════════════════════════════════════════════════════════════════════

def test_restore_skill_moves_back(tmp_path):
    skill = _make_skill(tmp_path, content="my content")
    original_path = Path(str(skill))
    qdir = tmp_path / "quarantine"

    quarantine_skill(skill, quarantine_dir=qdir)
    assert not original_path.exists()

    restored = restore_skill("bad", quarantine_dir=qdir)
    assert restored == original_path
    assert restored.exists()
    assert restored.read_text(encoding="utf-8") == "my content"


def test_restore_updates_manifest(tmp_path):
    skill = _make_skill(tmp_path)
    qdir = tmp_path / "quarantine"

    quarantine_skill(skill, quarantine_dir=qdir)
    manifest_before = json.loads(_manifest_path(qdir).read_text(encoding="utf-8"))
    assert len(manifest_before) == 1

    restore_skill("bad", quarantine_dir=qdir)
    manifest_after = json.loads(_manifest_path(qdir).read_text(encoding="utf-8"))
    assert len(manifest_after) == 0


def test_restore_nonexistent_raises_file_not_found(tmp_path):
    qdir = tmp_path / "quarantine"
    qdir.mkdir(parents=True)

    with pytest.raises(FileNotFoundError, match="not found in quarantine"):
        restore_skill("nonexistent", quarantine_dir=qdir)


def test_restore_occupied_path_raises_file_exists(tmp_path):
    skill = _make_skill(tmp_path, content="original")
    qdir = tmp_path / "quarantine"

    quarantine_skill(skill, quarantine_dir=qdir)

    # Re-create file at original location
    _make_skill(tmp_path, content="new occupant")

    with pytest.raises(FileExistsError, match="already occupied"):
        restore_skill("bad", quarantine_dir=qdir)


# ═══════════════════════════════════════════════════════════════════════
# LIST QUARANTINE TESTS
# ═══════════════════════════════════════════════════════════════════════

def test_list_quarantine_empty(tmp_path):
    qdir = tmp_path / "quarantine"
    result = list_quarantine(quarantine_dir=qdir)
    assert result == []


def test_list_quarantine_populated(tmp_path):
    qdir = tmp_path / "quarantine"
    skill1 = _make_skill(tmp_path, rel_path="a/one.md")
    skill2 = _make_skill(tmp_path, rel_path="b/two.md")

    quarantine_skill(skill1, reason="bad1", quarantine_dir=qdir)
    quarantine_skill(skill2, reason="bad2", quarantine_dir=qdir)

    entries = list_quarantine(quarantine_dir=qdir)
    assert len(entries) == 2
    names = {e.skill_name for e in entries}
    assert names == {"one", "two"}
    assert all(isinstance(e, QuarantineEntry) for e in entries)


# ═══════════════════════════════════════════════════════════════════════
# REPORT I/O TESTS
# ═══════════════════════════════════════════════════════════════════════

def test_save_and_load_guard_report(tmp_path, monkeypatch):
    monkeypatch.setattr("agentseal.fix.REPORTS_DIR", tmp_path / "reports")

    report = _make_guard_report()
    from agentseal.fix import save_report as _save, load_guard_report as _load
    _save(report, "guard")
    loaded = _load()

    assert loaded["timestamp"] == report["timestamp"]
    assert loaded["skill_results"] == []


def test_save_and_load_scan_report(tmp_path, monkeypatch):
    monkeypatch.setattr("agentseal.fix.REPORTS_DIR", tmp_path / "reports")

    report = _make_scan_report()
    from agentseal.fix import save_report as _save, load_scan_report as _load
    _save(report, "scan")
    loaded = _load()

    assert loaded["agent_name"] == "test"
    assert loaded["scan_id"] == "test-001"


def test_load_report_not_found_raises(tmp_path):
    with pytest.raises(FileNotFoundError, match="not found"):
        load_guard_report(path=tmp_path / "nonexistent.json")

    with pytest.raises(FileNotFoundError, match="not found"):
        load_scan_report(path=tmp_path / "nonexistent.json")


# ═══════════════════════════════════════════════════════════════════════
# FIXABLE SKILLS TESTS
# ═══════════════════════════════════════════════════════════════════════

def test_get_fixable_skills_filters_danger():
    report = _make_guard_report(skills=[
        {"name": "bad_skill", "path": "/tmp/bad.md", "verdict": "danger",
         "findings": [{"code": "SKILL-001", "title": "Bad"}], "sha256": ""},
        {"name": "safe_skill", "path": "/tmp/safe.md", "verdict": "safe",
         "findings": [], "sha256": ""},
        {"name": "warn_skill", "path": "/tmp/warn.md", "verdict": "warning",
         "findings": [], "sha256": ""},
    ])

    fixable = get_fixable_skills(report)
    assert len(fixable) == 1
    assert fixable[0]["name"] == "bad_skill"
    assert fixable[0]["verdict"] == "danger"


def test_get_fixable_skills_skips_safe():
    report = _make_guard_report(skills=[
        {"name": "good1", "path": "/tmp/g1.md", "verdict": "safe",
         "findings": [], "sha256": ""},
        {"name": "good2", "path": "/tmp/g2.md", "verdict": "safe",
         "findings": [], "sha256": ""},
    ])

    fixable = get_fixable_skills(report)
    assert fixable == []
