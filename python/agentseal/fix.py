# agentseal/fix.py
"""Fix engine — skill quarantine + prompt hardening + report loading.

Provides the core logic for the `agentseal fix` command:
  - Quarantine dangerous skills (move to ~/.agentseal/quarantine/)
  - Restore quarantined skills
  - Load/save guard and scan reports
  - Extract fixable skills from guard reports
  - Generate hardened prompts from scan reports
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .remediation import generate_remediation
from .schemas import ScanReport


# ═══════════════════════════════════════════════════════════════════════
# PATHS
# ═══════════════════════════════════════════════════════════════════════

QUARANTINE_DIR = Path.home() / ".agentseal" / "quarantine"
REPORTS_DIR = Path.home() / ".agentseal" / "reports"
BACKUPS_DIR = Path.home() / ".agentseal" / "backups"


# ═══════════════════════════════════════════════════════════════════════
# DATACLASSES
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class QuarantineEntry:
    original_path: str
    quarantine_path: str
    reason: str
    timestamp: str
    skill_name: str


@dataclass
class FixResult:
    action: str           # "quarantined", "hardened", "skipped", "error"
    target: str           # file path or skill name
    detail: str           # what was done
    before: str | None    # content before (for diffs)
    after: str | None     # content after (for diffs)


# ═══════════════════════════════════════════════════════════════════════
# MANIFEST HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _manifest_path(quarantine_dir: Path) -> Path:
    return quarantine_dir / "manifest.json"


def _load_manifest(quarantine_dir: Path) -> list[dict]:
    mp = _manifest_path(quarantine_dir)
    if not mp.exists():
        return []
    try:
        data = json.loads(mp.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return data
    except (json.JSONDecodeError, OSError):
        pass
    # Best-effort rebuild from directory listing
    entries = []
    for f in quarantine_dir.rglob("*"):
        if f.is_file() and f.name != "manifest.json":
            entries.append({
                "original_path": "",
                "quarantine_path": str(f),
                "reason": "recovered from corrupted manifest",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "skill_name": f.stem,
            })
    return entries


def _save_manifest(quarantine_dir: Path, entries: list[dict]) -> None:
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    _manifest_path(quarantine_dir).write_text(
        json.dumps(entries, indent=2), encoding="utf-8"
    )


# ═══════════════════════════════════════════════════════════════════════
# QUARANTINE
# ═══════════════════════════════════════════════════════════════════════

def quarantine_skill(
    skill_path: Path,
    reason: str = "",
    quarantine_dir: Path | None = None,
) -> QuarantineEntry:
    """Move a dangerous skill to quarantine.

    Preserves relative directory structure under the quarantine dir.
    Handles duplicate filenames by adding _1, _2, etc. suffixes.
    Updates manifest.json with the new entry.
    """
    qdir = quarantine_dir or QUARANTINE_DIR
    skill_path = Path(skill_path).resolve()

    if not skill_path.exists():
        raise FileNotFoundError(f"Skill not found: {skill_path}")

    # Build destination preserving some structure from the original path.
    # Use the last two path components (parent/filename) to keep context.
    parts = skill_path.parts
    relative = Path(*parts[-2:]) if len(parts) >= 2 else Path(skill_path.name)
    dest = qdir / relative

    # Handle duplicates
    if dest.exists():
        stem = dest.stem
        suffix = dest.suffix
        parent = dest.parent
        counter = 1
        while dest.exists():
            dest = parent / f"{stem}_{counter}{suffix}"
            counter += 1

    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(skill_path), str(dest))

    entry = QuarantineEntry(
        original_path=str(skill_path),
        quarantine_path=str(dest),
        reason=reason,
        timestamp=datetime.now(timezone.utc).isoformat(),
        skill_name=skill_path.stem,
    )

    manifest = _load_manifest(qdir)
    manifest.append(asdict(entry))
    _save_manifest(qdir, manifest)

    return entry


def restore_skill(
    skill_name: str,
    quarantine_dir: Path | None = None,
) -> Path:
    """Restore a quarantined skill to its original location.

    Raises FileNotFoundError if skill not in quarantine.
    Raises FileExistsError if original path is already occupied.
    """
    qdir = quarantine_dir or QUARANTINE_DIR
    manifest = _load_manifest(qdir)

    idx = None
    for i, entry in enumerate(manifest):
        if entry.get("skill_name") == skill_name:
            idx = i
            break

    if idx is None:
        raise FileNotFoundError(f"Skill '{skill_name}' not found in quarantine")

    entry = manifest[idx]
    if not entry.get("original_path"):
        raise ValueError(
            f"Cannot restore '{skill_name}': original path is empty "
            f"(recovered from corrupted manifest). Re-quarantine or move manually."
        )
    original = Path(entry["original_path"]).resolve()
    quarantined = Path(entry["quarantine_path"]).resolve()

    # Validate paths: quarantined file must be inside the quarantine dir
    qdir_resolved = qdir.resolve()
    if not str(quarantined).startswith(str(qdir_resolved)):
        raise ValueError(
            f"Cannot restore '{skill_name}': quarantine path {quarantined} "
            f"is outside quarantine directory. Manifest may be tampered."
        )

    if original.exists():
        raise FileExistsError(
            f"Cannot restore: original path already occupied: {original}"
        )

    if not quarantined.exists():
        raise FileNotFoundError(
            f"Quarantined file missing: {quarantined}"
        )

    original.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(quarantined), str(original))

    manifest.pop(idx)
    _save_manifest(qdir, manifest)

    return original


def list_quarantine(
    quarantine_dir: Path | None = None,
) -> list[QuarantineEntry]:
    """List all quarantined skills from manifest."""
    qdir = quarantine_dir or QUARANTINE_DIR
    manifest = _load_manifest(qdir)
    return [
        QuarantineEntry(**e)
        for e in manifest
        if all(k in e for k in ("original_path", "quarantine_path",
                                 "reason", "timestamp", "skill_name"))
    ]


# ═══════════════════════════════════════════════════════════════════════
# REPORT I/O
# ═══════════════════════════════════════════════════════════════════════

def load_guard_report(path: Path | None = None) -> dict:
    """Load guard report from file or latest from REPORTS_DIR."""
    target = path or REPORTS_DIR / "guard-latest.json"
    target = Path(target)
    if not target.exists():
        raise FileNotFoundError(
            f"Guard report not found: {target}\n"
            f"Run 'agentseal guard' first to generate a report."
        )
    return json.loads(target.read_text(encoding="utf-8"))


def load_scan_report(path: Path | None = None) -> dict:
    """Load scan report from file or latest from REPORTS_DIR."""
    target = path or REPORTS_DIR / "scan-latest.json"
    target = Path(target)
    if not target.exists():
        raise FileNotFoundError(
            f"Scan report not found: {target}\n"
            f"Run 'agentseal scan' first to generate a report."
        )
    return json.loads(target.read_text(encoding="utf-8"))


def save_report(report_dict: dict, report_type: str) -> Path:
    """Save report to REPORTS_DIR/{type}-latest.json. Creates dir if needed."""
    if "/" in report_type or ".." in report_type or "\\" in report_type:
        raise ValueError("Invalid report type")
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    target = REPORTS_DIR / f"{report_type}-latest.json"
    target.write_text(json.dumps(report_dict, indent=2), encoding="utf-8")
    return target


# ═══════════════════════════════════════════════════════════════════════
# FIXABLE SKILLS EXTRACTION
# ═══════════════════════════════════════════════════════════════════════

def get_fixable_skills(guard_report: dict) -> list[dict]:
    """Extract skills with DANGER verdict from guard report.

    Returns list of dicts with keys: name, path, findings, verdict.
    """
    results = []
    for skill in guard_report.get("skill_results", []):
        if skill.get("verdict") == "danger":
            results.append({
                "name": skill.get("name", ""),
                "path": skill.get("path", ""),
                "findings": skill.get("findings", []),
                "verdict": skill.get("verdict", ""),
            })
    return results


# ═══════════════════════════════════════════════════════════════════════
# PROMPT HARDENING
# ═══════════════════════════════════════════════════════════════════════

def generate_hardened_prompt_from_report(
    scan_report: dict,
    original_prompt: str,
) -> str | None:
    """Generate hardened prompt from scan report using the remediation engine.

    Returns hardened prompt string, or None if no changes needed.
    """
    # Reconstruct a minimal ScanReport for the remediation engine
    from .schemas import ProbeResult, Verdict, Severity, TrustLevel

    probe_results = []
    for r in scan_report.get("results", []):
        verdict_val = r.get("verdict", "blocked")
        severity_val = r.get("severity", "low")
        try:
            verdict = Verdict(verdict_val)
        except ValueError:
            verdict = Verdict.BLOCKED
        try:
            severity = Severity(severity_val)
        except ValueError:
            severity = Severity.LOW

        probe_results.append(ProbeResult(
            probe_id=r.get("probe_id", ""),
            category=r.get("category", ""),
            probe_type=r.get("probe_type", "extraction"),
            technique=r.get("technique", ""),
            severity=severity,
            attack_text=r.get("attack_text", ""),
            response_text=r.get("response_text", ""),
            verdict=verdict,
            confidence=r.get("confidence", 1.0),
            reasoning=r.get("reasoning", ""),
            duration_ms=r.get("duration_ms", 0.0),
        ))

    # Check if there are any failures
    has_failures = any(
        r.verdict in (Verdict.LEAKED, Verdict.PARTIAL)
        for r in probe_results
    )
    if not has_failures:
        return None

    trust_score = scan_report.get("trust_score", 50.0)
    report = ScanReport(
        agent_name=scan_report.get("agent_name", ""),
        scan_id=scan_report.get("scan_id", ""),
        timestamp=scan_report.get("timestamp", ""),
        duration_seconds=scan_report.get("duration_seconds", 0.0),
        total_probes=len(probe_results),
        probes_blocked=sum(1 for r in probe_results if r.verdict == Verdict.BLOCKED),
        probes_leaked=sum(1 for r in probe_results if r.verdict == Verdict.LEAKED),
        probes_partial=sum(1 for r in probe_results if r.verdict == Verdict.PARTIAL),
        probes_error=sum(1 for r in probe_results if r.verdict == Verdict.ERROR),
        trust_score=trust_score,
        trust_level=TrustLevel.from_score(trust_score),
        score_breakdown=scan_report.get("score_breakdown", {}),
        results=probe_results,
        ground_truth_provided=scan_report.get("ground_truth_provided", False),
    )

    remediation = generate_remediation(report)

    if not remediation.combined_fix:
        return None

    return f"{original_prompt}\n\n{remediation.combined_fix}"
