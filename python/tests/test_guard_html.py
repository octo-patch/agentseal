# tests/test_guard_html.py
"""Tests for HTML output (GAP 12)."""

from agentseal.guard_models import (
    GuardReport,
    GuardVerdict,
    MCPFinding,
    MCPServerResult,
    SkillFinding,
    SkillResult,
    ToxicFlowResult,
    BaselineChangeResult,
)

# Import the HTML generator from cli
import importlib
cli = importlib.import_module("agentseal.cli")
_guard_to_html = cli._guard_to_html


def _make_report(**kwargs) -> GuardReport:
    defaults = {
        "timestamp": "2026-03-10T00:00:00Z",
        "duration_seconds": 1.5,
        "agents_found": [],
        "skill_results": [],
        "mcp_results": [],
    }
    defaults.update(kwargs)
    return GuardReport(**defaults)


class TestHTMLOutput:

    def test_empty_report_valid_html(self):
        report = _make_report()
        html = _guard_to_html(report)
        assert "<!DOCTYPE html>" in html
        assert "AgentSeal Guard Report" in html
        assert "Clean" in html

    def test_danger_status(self):
        report = _make_report(skill_results=[
            SkillResult(
                name="evil",
                path="/tmp/evil.md",
                verdict=GuardVerdict.DANGER,
                findings=[SkillFinding(
                    code="SKILL-001", title="Credential access",
                    description="Bad", severity="critical",
                    evidence="~/.ssh", remediation="Remove it.",
                )],
            )
        ])
        html = _guard_to_html(report)
        assert "Critical Threat" in html
        assert "evil" in html
        assert "DANGER" in html

    def test_mcp_servers_section(self):
        report = _make_report(mcp_results=[
            MCPServerResult(
                name="filesystem",
                command="node",
                source_file="/config.json",
                verdict=GuardVerdict.WARNING,
                findings=[MCPFinding(
                    code="MCP-005", title="Insecure HTTP",
                    description="Uses HTTP", severity="medium",
                    remediation="Use HTTPS",
                )],
            )
        ])
        html = _guard_to_html(report)
        assert "MCP Servers" in html
        assert "filesystem" in html
        assert "WARNING" in html

    def test_toxic_flows_section(self):
        report = _make_report(toxic_flows=[
            ToxicFlowResult(
                risk_level="high",
                risk_type="data_exfiltration",
                title="Read+Send combo",
                description="Can read files and send data",
                servers_involved=["fs-server", "slack-server"],
                remediation="Remove one server",
            )
        ])
        html = _guard_to_html(report)
        assert "Toxic Flows" in html
        assert "Read+Send combo" in html

    def test_baseline_changes_section(self):
        report = _make_report(baseline_changes=[
            BaselineChangeResult(
                server_name="test-server",
                agent_type="cursor",
                change_type="config_changed",
                detail="Args changed",
            )
        ])
        html = _guard_to_html(report)
        assert "Baseline Changes" in html
        assert "test-server" in html

    def test_html_escaping(self):
        report = _make_report(skill_results=[
            SkillResult(
                name="<script>alert(1)</script>",
                path="/tmp/test.md",
                verdict=GuardVerdict.SAFE,
                findings=[],
            )
        ])
        html = _guard_to_html(report)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_self_contained(self):
        """HTML should be self-contained — no external JS or CSS."""
        report = _make_report()
        html = _guard_to_html(report)
        assert "<style>" in html
        assert "<script" not in html  # No JS
        assert "http" not in html.split("<style>")[1].split("</style>")[0]  # No external CSS
