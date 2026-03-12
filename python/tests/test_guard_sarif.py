# tests/test_guard_sarif.py
"""Tests for SARIF output (GAP 7)."""

import json
from unittest.mock import patch

from agentseal.guard_models import (
    GuardReport,
    GuardVerdict,
    MCPFinding,
    MCPServerResult,
    SkillFinding,
    SkillResult,
)


def _make_report(**kwargs) -> GuardReport:
    defaults = {
        "timestamp": "2026-03-10T00:00:00Z",
        "duration_seconds": 1.0,
        "agents_found": [],
        "skill_results": [],
        "mcp_results": [],
    }
    defaults.update(kwargs)
    return GuardReport(**defaults)


class TestSARIFOutput:

    def test_empty_report(self):
        report = _make_report()
        sarif = report.to_sarif()
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["results"] == []

    def test_skill_finding_in_sarif(self):
        report = _make_report(skill_results=[
            SkillResult(
                name="evil-skill",
                path="/tmp/evil.md",
                verdict=GuardVerdict.DANGER,
                findings=[SkillFinding(
                    code="SKILL-001",
                    title="Credential access",
                    description="Accesses ~/.ssh",
                    severity="critical",
                    evidence="~/.ssh/id_rsa",
                    remediation="Remove this skill.",
                )],
            )
        ])
        sarif = report.to_sarif()
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "SKILL-001"
        assert results[0]["level"] == "error"
        assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "/tmp/evil.md"

    def test_mcp_finding_in_sarif(self):
        report = _make_report(mcp_results=[
            MCPServerResult(
                name="filesystem",
                command="node",
                source_file="/home/user/.cursor/mcp.json",
                verdict=GuardVerdict.WARNING,
                findings=[MCPFinding(
                    code="MCP-005",
                    title="Insecure HTTP",
                    description="Uses HTTP",
                    severity="medium",
                    remediation="Use HTTPS",
                )],
            )
        ])
        sarif = report.to_sarif()
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "MCP-005"
        assert results[0]["level"] == "warning"

    def test_severity_mapping(self):
        report = _make_report(skill_results=[
            SkillResult(
                name="test",
                path="/tmp/test.md",
                verdict=GuardVerdict.WARNING,
                findings=[
                    SkillFinding(code="A", title="T", description="D", severity="critical",
                                 evidence="", remediation=""),
                    SkillFinding(code="B", title="T", description="D", severity="high",
                                 evidence="", remediation=""),
                    SkillFinding(code="C", title="T", description="D", severity="medium",
                                 evidence="", remediation=""),
                    SkillFinding(code="D", title="T", description="D", severity="low",
                                 evidence="", remediation=""),
                ],
            )
        ])
        sarif = report.to_sarif()
        levels = [r["level"] for r in sarif["runs"][0]["results"]]
        assert levels == ["error", "error", "warning", "note"]

    def test_sarif_is_valid_json(self):
        report = _make_report(mcp_results=[
            MCPServerResult(
                name="test",
                command="node",
                source_file="",
                verdict=GuardVerdict.SAFE,
                findings=[],
            )
        ])
        sarif = report.to_sarif()
        # Should be JSON-serializable
        json_str = json.dumps(sarif)
        parsed = json.loads(json_str)
        assert parsed["version"] == "2.1.0"

    def test_rules_array_deduplicates(self):
        report = _make_report(skill_results=[
            SkillResult(
                name="s1", path="/a", verdict=GuardVerdict.DANGER,
                findings=[
                    SkillFinding(code="SKILL-001", title="Cred", description="D",
                                 severity="critical", evidence="", remediation=""),
                ],
            ),
            SkillResult(
                name="s2", path="/b", verdict=GuardVerdict.DANGER,
                findings=[
                    SkillFinding(code="SKILL-001", title="Cred", description="D2",
                                 severity="critical", evidence="", remediation=""),
                ],
            ),
        ])
        sarif = report.to_sarif()
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1  # Same code = one rule
        assert len(sarif["runs"][0]["results"]) == 2  # But two results
