# tests/test_guard_models.py
"""Tests for guard data models."""

import json
import pytest
from agentseal.guard_models import (
    GuardVerdict,
    SkillFinding,
    SkillResult,
    MCPFinding,
    MCPServerResult,
    AgentConfigResult,
    GuardReport,
)


class TestGuardVerdict:
    def test_values(self):
        assert GuardVerdict.SAFE == "safe"
        assert GuardVerdict.WARNING == "warning"
        assert GuardVerdict.DANGER == "danger"
        assert GuardVerdict.ERROR == "error"

    def test_serializes_to_string(self):
        assert str(GuardVerdict.SAFE) == "GuardVerdict.SAFE"
        assert GuardVerdict.SAFE.value == "safe"


class TestSkillResult:
    def test_safe_result(self):
        r = SkillResult(name="test", path="/tmp/test", verdict=GuardVerdict.SAFE)
        assert r.top_finding is None
        assert r.to_dict()["verdict"] == "safe"

    def test_danger_result_top_finding(self):
        findings = [
            SkillFinding("SKILL-007", "Low issue", "desc", "medium", "ev", "fix"),
            SkillFinding("SKILL-001", "Critical issue", "desc", "critical", "ev", "fix"),
        ]
        r = SkillResult(name="test", path="/tmp/test", verdict=GuardVerdict.DANGER, findings=findings)
        assert r.top_finding.code == "SKILL-001"

    def test_to_dict(self):
        r = SkillResult(name="test", path="/tmp/test", verdict=GuardVerdict.SAFE, sha256="abc123")
        d = r.to_dict()
        assert d["name"] == "test"
        assert d["verdict"] == "safe"
        assert d["sha256"] == "abc123"


class TestMCPServerResult:
    def test_safe_server(self):
        r = MCPServerResult(name="brave", command="npx brave", source_file="/tmp/c.json",
                            verdict=GuardVerdict.SAFE)
        assert r.top_finding is None
        assert r.to_dict()["verdict"] == "safe"

    def test_danger_server(self):
        findings = [MCPFinding("MCP-001", "SSH access", "desc", "critical", "fix")]
        r = MCPServerResult(name="fs", command="npx fs", source_file="/tmp/c.json",
                            verdict=GuardVerdict.DANGER, findings=findings)
        assert r.top_finding.code == "MCP-001"


class TestGuardReport:
    def _make_report(self):
        return GuardReport(
            timestamp="2026-03-09T00:00:00Z",
            duration_seconds=1.5,
            agents_found=[
                AgentConfigResult("Claude Desktop", "/tmp/c.json", "claude-desktop", 2, 0, "found"),
            ],
            skill_results=[
                SkillResult("safe-skill", "/tmp/s1", GuardVerdict.SAFE),
                SkillResult("bad-skill", "/tmp/s2", GuardVerdict.DANGER, findings=[
                    SkillFinding("SKILL-001", "Cred theft", "desc", "critical", "ev", "Remove it"),
                ]),
                SkillResult("sus-skill", "/tmp/s3", GuardVerdict.WARNING, findings=[
                    SkillFinding("SKILL-007", "URL", "desc", "medium", "ev", "Check URL"),
                ]),
            ],
            mcp_results=[
                MCPServerResult("brave", "npx brave", "/tmp/c.json", GuardVerdict.SAFE),
                MCPServerResult("fs", "npx fs", "/tmp/c.json", GuardVerdict.DANGER, findings=[
                    MCPFinding("MCP-001", "SSH", "desc", "critical", "Fix it"),
                ]),
            ],
        )

    def test_total_dangers(self):
        r = self._make_report()
        assert r.total_dangers == 2  # bad-skill + fs

    def test_total_warnings(self):
        r = self._make_report()
        assert r.total_warnings == 1  # sus-skill

    def test_total_safe(self):
        r = self._make_report()
        assert r.total_safe == 2  # safe-skill + brave

    def test_has_critical(self):
        r = self._make_report()
        assert r.has_critical is True

    def test_no_critical(self):
        r = GuardReport("ts", 0.5, [], [], [])
        assert r.has_critical is False

    def test_all_actions(self):
        r = self._make_report()
        actions = r.all_actions
        assert len(actions) >= 2
        # Critical actions should come first
        assert "Remove it" in actions[0] or "Fix it" in actions[0]

    def test_to_dict_roundtrip(self):
        r = self._make_report()
        d = r.to_dict()
        j = json.dumps(d)
        parsed = json.loads(j)
        assert parsed["summary"]["total_dangers"] == 2
        assert len(parsed["skill_results"]) == 3
        assert len(parsed["mcp_results"]) == 2

    def test_to_json(self):
        r = self._make_report()
        j = r.to_json()
        parsed = json.loads(j)
        assert parsed["timestamp"] == "2026-03-09T00:00:00Z"
