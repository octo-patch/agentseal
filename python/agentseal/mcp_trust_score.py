# agentseal/mcp_trust_score.py
"""
MCP Server Trust Scoring — 0-100 score per server.

Consumes MCPRuntimeResult (findings from tool analysis) plus optional
baseline and snapshot context to produce a single trust score.

Scoring formula:
  Base: 100
  Deductions per finding severity (capped per tier):
    CRITICAL: -25 each (max -50)
    HIGH:     -15 each (max -30)
    MEDIUM:   -10 each (max -20)
    LOW:       -5 each (max -10)
  Bonuses:
    +5 if all tools declare readOnlyHint
    +5 if zero runtime findings
    +5 if baseline unchanged (returning server, no rug pull)
  Floor: 0, Ceiling: 100

Trust levels:
    0-19:  CRITICAL
   20-39:  LOW
   40-59:  MEDIUM
   60-79:  HIGH
   80-100: EXCELLENT
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from agentseal.guard_models import MCPRuntimeResult


# ═══════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════

_BASE_SCORE = 100

# (points_per_finding, max_deduction)
_SEVERITY_DEDUCTIONS: dict[str, tuple[int, int]] = {
    "critical": (25, 50),
    "high":     (15, 30),
    "medium":   (10, 20),
    "low":       (5, 10),
}

_BONUS_READONLY_ALL = 5
_BONUS_NO_FINDINGS = 5
_BONUS_BASELINE_UNCHANGED = 5

_TRUST_LEVELS: list[tuple[int, str]] = [
    (20, "critical"),   # 0-19
    (40, "low"),        # 20-39
    (60, "medium"),     # 40-59
    (80, "high"),       # 60-79
    (101, "excellent"), # 80-100
]


# ═══════════════════════════════════════════════════════════════════════
# OUTPUT MODEL
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class MCPTrustScore:
    """Trust score for one MCP server."""
    server_name: str
    score: int              # 0-100
    level: str              # "critical" | "low" | "medium" | "high" | "excellent"
    deductions: list[dict] = field(default_factory=list)  # [{finding_code, points, reason}]
    bonuses: list[dict] = field(default_factory=list)     # [{reason, points}]

    def to_dict(self) -> dict:
        return {
            "server_name": self.server_name,
            "score": self.score,
            "level": self.level,
            "deductions": self.deductions,
            "bonuses": self.bonuses,
        }


# ═══════════════════════════════════════════════════════════════════════
# SCORING ENGINE
# ═══════════════════════════════════════════════════════════════════════

def _score_to_level(score: int) -> str:
    """Map a 0-100 score to a trust level string."""
    for threshold, level in _TRUST_LEVELS:
        if score < threshold:
            return level
    return "excellent"  # Fallback (shouldn't reach here)


def compute_trust_score(
    runtime_result: MCPRuntimeResult,
    *,
    tools: Optional[list] = None,
    baseline_changed: bool = False,
) -> MCPTrustScore:
    """Compute a 0-100 trust score for one MCP server.

    Args:
        runtime_result: Analysis result containing findings.
        tools: Optional list of MCPToolSnapshot objects (for readOnlyHint bonus).
        baseline_changed: True if baseline changes were detected (rug pull).

    Returns:
        MCPTrustScore with score, level, deductions, and bonuses.
    """
    deductions: list[dict] = []
    bonuses: list[dict] = []

    # ── Deductions ──────────────────────────────────────────────────
    # Group findings by severity, apply per-finding deduction with cap
    severity_counts: dict[str, int] = {}
    for finding in runtime_result.findings:
        sev = finding.severity.lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    total_deduction = 0
    for severity, count in sorted(severity_counts.items()):
        if severity not in _SEVERITY_DEDUCTIONS:
            continue
        per_finding, max_ded = _SEVERITY_DEDUCTIONS[severity]
        raw = per_finding * count
        capped = min(raw, max_ded)
        total_deduction += capped
        deductions.append({
            "finding_code": f"{count}x {severity}",
            "points": -capped,
            "reason": f"{count} {severity} finding(s): -{per_finding} each, capped at -{max_ded}",
        })

    # ── Bonuses ─────────────────────────────────────────────────────
    # Bonus: all tools declare readOnlyHint
    if tools is not None and len(tools) > 0:
        all_readonly = all(
            t.annotations.get("readOnlyHint", False) is True
            for t in tools
        )
        if all_readonly:
            bonuses.append({
                "reason": "All tools declare readOnlyHint",
                "points": _BONUS_READONLY_ALL,
            })

    # Bonus: no runtime findings
    if len(runtime_result.findings) == 0:
        bonuses.append({
            "reason": "No runtime findings detected",
            "points": _BONUS_NO_FINDINGS,
        })

    # Bonus: baseline unchanged (returning server with stable tools)
    if not baseline_changed:
        bonuses.append({
            "reason": "Baseline unchanged (returning server)",
            "points": _BONUS_BASELINE_UNCHANGED,
        })

    # ── Final score ─────────────────────────────────────────────────
    total_bonus = sum(b["points"] for b in bonuses)
    raw_score = _BASE_SCORE - total_deduction + total_bonus
    score = max(0, min(100, raw_score))
    level = _score_to_level(score)

    return MCPTrustScore(
        server_name=runtime_result.server_name,
        score=score,
        level=level,
        deductions=deductions,
        bonuses=bonuses,
    )
