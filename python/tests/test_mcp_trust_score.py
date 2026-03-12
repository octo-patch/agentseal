# tests/test_mcp_trust_score.py
"""
Tests for MCP server trust scoring (0-100).
"""

import pytest

from agentseal.guard_models import GuardVerdict, MCPRuntimeFinding, MCPRuntimeResult
from agentseal.mcp_runtime import MCPToolSnapshot
from agentseal.mcp_trust_score import (
    MCPTrustScore,
    _score_to_level,
    compute_trust_score,
)


def _make_finding(
    severity: str = "medium",
    code: str = "MCPR-101",
    tool_name: str = "test_tool",
) -> MCPRuntimeFinding:
    return MCPRuntimeFinding(
        code=code,
        title="Test finding",
        description="Test",
        severity=severity,
        evidence="test evidence",
        remediation="Fix it",
        tool_name=tool_name,
        server_name="test-server",
    )


def _make_result(
    findings: list[MCPRuntimeFinding] | None = None,
    server_name: str = "test-server",
    tools_found: int = 3,
) -> MCPRuntimeResult:
    return MCPRuntimeResult(
        server_name=server_name,
        tools_found=tools_found,
        findings=findings or [],
        verdict=GuardVerdict.DANGER if findings else GuardVerdict.SAFE,
    )


def _make_tool(name: str, readonly: bool = False) -> MCPToolSnapshot:
    annotations = {"readOnlyHint": True} if readonly else {}
    return MCPToolSnapshot(
        name=name,
        description="Test tool",
        input_schema={},
        annotations=annotations,
        signature_hash="",
    )


# ═══════════════════════════════════════════════════════════════════════
# TRUST LEVEL MAPPING
# ═══════════════════════════════════════════════════════════════════════


class TestScoreToLevel:
    def test_critical_range(self):
        assert _score_to_level(0) == "critical"
        assert _score_to_level(19) == "critical"

    def test_low_range(self):
        assert _score_to_level(20) == "low"
        assert _score_to_level(39) == "low"

    def test_medium_range(self):
        assert _score_to_level(40) == "medium"
        assert _score_to_level(59) == "medium"

    def test_high_range(self):
        assert _score_to_level(60) == "high"
        assert _score_to_level(79) == "high"

    def test_excellent_range(self):
        assert _score_to_level(80) == "excellent"
        assert _score_to_level(100) == "excellent"


# ═══════════════════════════════════════════════════════════════════════
# PERFECT SCORE (NO FINDINGS)
# ═══════════════════════════════════════════════════════════════════════


class TestPerfectScore:
    def test_no_findings_baseline_unchanged(self):
        """Clean server with stable baseline gets max score (capped at 100)."""
        result = _make_result()
        score = compute_trust_score(result, baseline_changed=False)
        assert score.score == 100  # 100 - 0 + 5 (no findings) + 5 (baseline) = 110 → capped
        assert score.level == "excellent"
        assert len(score.deductions) == 0
        assert len(score.bonuses) == 2

    def test_no_findings_with_readonly_tools(self):
        """All bonuses applied → still capped at 100."""
        tools = [_make_tool("read", readonly=True), _make_tool("list", readonly=True)]
        result = _make_result()
        score = compute_trust_score(result, tools=tools, baseline_changed=False)
        assert score.score == 100  # 100 + 5 + 5 + 5 = 115 → 100
        assert len(score.bonuses) == 3


# ═══════════════════════════════════════════════════════════════════════
# DEDUCTIONS
# ═══════════════════════════════════════════════════════════════════════


class TestDeductions:
    def test_single_critical_finding(self):
        result = _make_result([_make_finding("critical")])
        score = compute_trust_score(result, baseline_changed=False)
        # 100 - 25 + 5 (baseline) = 80
        assert score.score == 80
        assert score.level == "excellent"
        assert len(score.deductions) == 1
        assert score.deductions[0]["points"] == -25

    def test_critical_capped_at_50(self):
        """3 critical findings: 3×25=75 but capped at 50."""
        findings = [_make_finding("critical") for _ in range(3)]
        result = _make_result(findings)
        score = compute_trust_score(result, baseline_changed=False)
        # 100 - 50 + 5 (baseline) = 55
        assert score.score == 55
        assert score.level == "medium"

    def test_single_high_finding(self):
        result = _make_result([_make_finding("high")])
        score = compute_trust_score(result, baseline_changed=False)
        # 100 - 15 + 5 (baseline) = 90
        assert score.score == 90

    def test_high_capped_at_30(self):
        findings = [_make_finding("high") for _ in range(3)]
        result = _make_result(findings)
        score = compute_trust_score(result, baseline_changed=False)
        # 100 - 30 + 5 (baseline) = 75
        assert score.score == 75

    def test_single_medium_finding(self):
        result = _make_result([_make_finding("medium")])
        score = compute_trust_score(result, baseline_changed=False)
        # 100 - 10 + 5 (baseline) = 95
        assert score.score == 95

    def test_medium_capped_at_20(self):
        findings = [_make_finding("medium") for _ in range(5)]
        result = _make_result(findings)
        score = compute_trust_score(result, baseline_changed=False)
        # 100 - 20 + 5 (baseline) = 85
        assert score.score == 85

    def test_single_low_finding(self):
        result = _make_result([_make_finding("low")])
        score = compute_trust_score(result, baseline_changed=False)
        # 100 - 5 + 5 (baseline) = 100
        assert score.score == 100

    def test_low_capped_at_10(self):
        findings = [_make_finding("low") for _ in range(5)]
        result = _make_result(findings)
        score = compute_trust_score(result, baseline_changed=False)
        # 100 - 10 + 5 (baseline) = 95
        assert score.score == 95

    def test_mixed_severities(self):
        """2 critical + 1 high + 1 medium: -50 + -15 + -10 = -75."""
        findings = [
            _make_finding("critical"),
            _make_finding("critical"),
            _make_finding("high"),
            _make_finding("medium"),
        ]
        result = _make_result(findings)
        score = compute_trust_score(result, baseline_changed=False)
        # 100 - (2×25=50) - 15 - 10 + 5 (baseline) = 30
        assert score.score == 30
        assert score.level == "low"

    def test_floor_at_zero(self):
        """Massive deductions don't go below 0."""
        findings = (
            [_make_finding("critical")] * 3 +  # capped at -50
            [_make_finding("high")] * 3 +       # capped at -30
            [_make_finding("medium")] * 3 +     # capped at -20
            [_make_finding("low")] * 3           # capped at -10
        )
        result = _make_result(findings)
        score = compute_trust_score(result, baseline_changed=True)
        # 100 - 50 - 30 - 20 - 10 = -10 → 0
        assert score.score == 0
        assert score.level == "critical"


# ═══════════════════════════════════════════════════════════════════════
# BONUSES
# ═══════════════════════════════════════════════════════════════════════


class TestBonuses:
    def test_readonly_bonus_all_tools(self):
        tools = [_make_tool("a", readonly=True), _make_tool("b", readonly=True)]
        result = _make_result()
        score = compute_trust_score(result, tools=tools, baseline_changed=False)
        bonus_reasons = [b["reason"] for b in score.bonuses]
        assert "All tools declare readOnlyHint" in bonus_reasons

    def test_readonly_bonus_not_all(self):
        """If any tool is NOT readonly, no bonus."""
        tools = [_make_tool("a", readonly=True), _make_tool("b", readonly=False)]
        result = _make_result()
        score = compute_trust_score(result, tools=tools, baseline_changed=False)
        bonus_reasons = [b["reason"] for b in score.bonuses]
        assert "All tools declare readOnlyHint" not in bonus_reasons

    def test_readonly_bonus_no_tools_provided(self):
        """If tools=None, no readonly bonus (can't verify)."""
        result = _make_result()
        score = compute_trust_score(result, tools=None, baseline_changed=False)
        bonus_reasons = [b["reason"] for b in score.bonuses]
        assert "All tools declare readOnlyHint" not in bonus_reasons

    def test_readonly_bonus_empty_tools_list(self):
        """Empty tools list — no bonus (nothing to verify)."""
        result = _make_result()
        score = compute_trust_score(result, tools=[], baseline_changed=False)
        bonus_reasons = [b["reason"] for b in score.bonuses]
        assert "All tools declare readOnlyHint" not in bonus_reasons

    def test_no_findings_bonus(self):
        result = _make_result()
        score = compute_trust_score(result)
        bonus_reasons = [b["reason"] for b in score.bonuses]
        assert "No runtime findings detected" in bonus_reasons

    def test_no_findings_bonus_absent_when_findings_exist(self):
        result = _make_result([_make_finding("low")])
        score = compute_trust_score(result)
        bonus_reasons = [b["reason"] for b in score.bonuses]
        assert "No runtime findings detected" not in bonus_reasons

    def test_baseline_unchanged_bonus(self):
        result = _make_result()
        score = compute_trust_score(result, baseline_changed=False)
        bonus_reasons = [b["reason"] for b in score.bonuses]
        assert "Baseline unchanged (returning server)" in bonus_reasons

    def test_baseline_changed_no_bonus(self):
        result = _make_result()
        score = compute_trust_score(result, baseline_changed=True)
        bonus_reasons = [b["reason"] for b in score.bonuses]
        assert "Baseline unchanged (returning server)" not in bonus_reasons


# ═══════════════════════════════════════════════════════════════════════
# OUTPUT MODEL
# ═══════════════════════════════════════════════════════════════════════


class TestMCPTrustScoreModel:
    def test_to_dict(self):
        score = MCPTrustScore(
            server_name="srv",
            score=75,
            level="high",
            deductions=[{"finding_code": "1x critical", "points": -25, "reason": "test"}],
            bonuses=[{"reason": "clean", "points": 5}],
        )
        d = score.to_dict()
        assert d["server_name"] == "srv"
        assert d["score"] == 75
        assert d["level"] == "high"
        assert len(d["deductions"]) == 1
        assert len(d["bonuses"]) == 1

    def test_server_name_propagated(self):
        result = _make_result(server_name="my-server")
        score = compute_trust_score(result)
        assert score.server_name == "my-server"


# ═══════════════════════════════════════════════════════════════════════
# EDGE CASES
# ═══════════════════════════════════════════════════════════════════════


class TestEdgeCases:
    def test_unknown_severity_ignored(self):
        """Findings with unrecognized severity are silently skipped in deductions."""
        finding = _make_finding("unknown_severity")
        result = _make_result([finding])
        score = compute_trust_score(result, baseline_changed=False)
        # No deduction for unknown severity, but no "no findings" bonus either
        assert len(score.deductions) == 0
        # Still baseline bonus
        assert score.score == 100  # 100 + 5 baseline = 105 → 100

    def test_connection_error_server(self):
        """Server that failed to connect still gets scored (based on findings)."""
        result = MCPRuntimeResult(
            server_name="dead",
            tools_found=0,
            findings=[],
            verdict=GuardVerdict.ERROR,
            connection_status="timeout",
        )
        score = compute_trust_score(result, baseline_changed=False)
        # No findings → bonuses apply
        assert score.score == 100

    def test_exactly_at_boundary_scores(self):
        """Verify boundary values map correctly."""
        assert _score_to_level(0) == "critical"
        assert _score_to_level(19) == "critical"
        assert _score_to_level(20) == "low"
        assert _score_to_level(79) == "high"
        assert _score_to_level(80) == "excellent"
        assert _score_to_level(100) == "excellent"
