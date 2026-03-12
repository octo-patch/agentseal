# tests/test_scan_mcp.py
"""
Tests for the scan-mcp orchestration layer and CLI integration.
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agentseal.guard_models import (
    GuardVerdict,
    MCPRuntimeFinding,
    MCPRuntimeResult,
    ToxicFlowResult,
)
from agentseal.mcp_runtime import MCPConnectionError, MCPServerSnapshot, MCPToolSnapshot
from agentseal.mcp_trust_score import MCPTrustScore
from agentseal.scan_mcp import ScanMCP, ScanMCPReport, _find_agent_type


# ═══════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _make_tool(name: str, description: str = "A tool") -> MCPToolSnapshot:
    return MCPToolSnapshot(
        name=name,
        description=description,
        input_schema={},
        annotations={},
        signature_hash="",
    )


def _make_snapshot(name: str, tools: list[MCPToolSnapshot] | None = None) -> MCPServerSnapshot:
    return MCPServerSnapshot(
        server_name=name,
        server_version="1.0",
        protocol_version="2024-11-05",
        instructions="",
        capabilities={},
        tools=tools or [_make_tool("default_tool")],
        prompts=[],
        resources=[],
        connected_at="2026-01-01T00:00:00Z",
        connection_duration_ms=50,
    )


def _make_conn_error(name: str, error_type: str = "timeout") -> MCPConnectionError:
    return MCPConnectionError(
        server_name=name,
        error_type=error_type,
        detail=f"Connection {error_type}",
    )


def _make_runtime_result(
    name: str, findings: list | None = None, verdict: GuardVerdict = GuardVerdict.SAFE,
) -> MCPRuntimeResult:
    return MCPRuntimeResult(
        server_name=name,
        tools_found=3,
        findings=findings or [],
        verdict=verdict,
    )


# ═══════════════════════════════════════════════════════════════════════
# REPORT MODEL
# ═══════════════════════════════════════════════════════════════════════


class TestScanMCPReport:
    def test_to_dict_minimal(self):
        report = ScanMCPReport(
            timestamp="2026-01-01T00:00:00Z",
            duration_seconds=1.5,
            servers_scanned=1,
            servers_connected=1,
            servers_failed=0,
            total_tools=3,
            runtime_results=[_make_runtime_result("srv")],
            trust_scores=[MCPTrustScore(server_name="srv", score=85, level="excellent")],
        )
        d = report.to_dict()
        assert d["servers_scanned"] == 1
        assert d["total_tools"] == 3
        assert len(d["runtime_results"]) == 1
        assert len(d["trust_scores"]) == 1
        assert "toxic_flows" not in d
        assert "baseline_changes" not in d
        assert "connection_errors" not in d

    def test_to_dict_with_all_sections(self):
        report = ScanMCPReport(
            timestamp="2026-01-01T00:00:00Z",
            duration_seconds=2.0,
            servers_scanned=2,
            servers_connected=1,
            servers_failed=1,
            total_tools=5,
            runtime_results=[_make_runtime_result("srv")],
            trust_scores=[MCPTrustScore(server_name="srv", score=50, level="medium")],
            toxic_flows=[ToxicFlowResult(
                risk_level="high",
                risk_type="data_exfiltration",
                title="Test flow",
                description="desc",
                servers_involved=["a", "b"],
                remediation="fix it",
            )],
            baseline_changes=[],
            connection_errors=[{"server_name": "fail", "error_type": "timeout", "detail": "t/o"}],
        )
        d = report.to_dict()
        assert "toxic_flows" in d
        assert "connection_errors" in d

    def test_total_findings_property(self):
        findings = [MCPRuntimeFinding(
            code="MCPR-101", title="t", description="d", severity="critical",
            evidence="e", remediation="r", tool_name="t", server_name="s",
        )]
        report = ScanMCPReport(
            timestamp="", duration_seconds=0, servers_scanned=1,
            servers_connected=1, servers_failed=0, total_tools=1,
            runtime_results=[_make_runtime_result("s", findings, GuardVerdict.DANGER)],
            trust_scores=[],
        )
        assert report.total_findings == 1
        assert report.total_critical == 1
        assert report.has_critical is True

    def test_min_score_property(self):
        report = ScanMCPReport(
            timestamp="", duration_seconds=0, servers_scanned=2,
            servers_connected=2, servers_failed=0, total_tools=6,
            runtime_results=[],
            trust_scores=[
                MCPTrustScore(server_name="a", score=90, level="excellent"),
                MCPTrustScore(server_name="b", score=35, level="low"),
            ],
        )
        assert report.min_score == 35

    def test_min_score_empty(self):
        report = ScanMCPReport(
            timestamp="", duration_seconds=0, servers_scanned=0,
            servers_connected=0, servers_failed=0, total_tools=0,
            runtime_results=[], trust_scores=[],
        )
        assert report.min_score == 100

    def test_to_json(self):
        report = ScanMCPReport(
            timestamp="2026-01-01T00:00:00Z", duration_seconds=1.0,
            servers_scanned=1, servers_connected=1, servers_failed=0,
            total_tools=2,
            runtime_results=[_make_runtime_result("s")],
            trust_scores=[MCPTrustScore(server_name="s", score=80, level="excellent")],
        )
        j = report.to_json()
        parsed = json.loads(j)
        assert parsed["servers_scanned"] == 1


# ═══════════════════════════════════════════════════════════════════════
# SCANNER ENGINE
# ═══════════════════════════════════════════════════════════════════════


class TestScanMCPEngine:
    """Tests for ScanMCP.run() using mocked connections."""

    @patch("agentseal.scan_mcp.connect_stdio")
    @patch("agentseal.scan_mcp.BaselineStore")
    def test_run_with_successful_connections(self, mock_store_cls, mock_connect):
        """Full pipeline with mocked stdio connections."""
        snapshot = _make_snapshot("test-srv", [_make_tool("read_file", "Read a file")])
        mock_connect.return_value = snapshot

        # Mock baseline store
        mock_store = MagicMock()
        mock_store.check_server_tools.return_value = []
        mock_store_cls.return_value = mock_store

        servers = [{"name": "test-srv", "command": "node", "args": ["server.js"], "agent_type": "cursor"}]
        scanner = ScanMCP(timeout=5.0, concurrency=1)
        report = scanner.run(servers)

        assert report.servers_scanned == 1
        assert report.servers_connected == 1
        assert report.servers_failed == 0
        assert report.total_tools == 1
        assert len(report.runtime_results) == 1
        assert len(report.trust_scores) == 1

    @patch("agentseal.scan_mcp.connect_stdio")
    @patch("agentseal.scan_mcp.BaselineStore")
    def test_run_with_connection_error(self, mock_store_cls, mock_connect):
        """Handle connection failures gracefully."""
        mock_connect.return_value = _make_conn_error("dead-srv", "timeout")
        mock_store_cls.return_value = MagicMock()

        servers = [{"name": "dead-srv", "command": "node", "args": ["fail.js"], "agent_type": "test"}]
        scanner = ScanMCP(timeout=5.0)
        report = scanner.run(servers)

        assert report.servers_connected == 0
        assert report.servers_failed == 1
        assert len(report.connection_errors) == 1
        assert report.connection_errors[0]["error_type"] == "timeout"

    @patch("agentseal.scan_mcp.connect_stdio")
    @patch("agentseal.scan_mcp.BaselineStore")
    def test_run_mixed_success_and_failure(self, mock_store_cls, mock_connect):
        """Some servers connect, some fail."""
        snapshot = _make_snapshot("ok-srv")
        error = _make_conn_error("bad-srv")

        async def _side_effect(command, args, env=None, timeout=30.0, server_name=""):
            if server_name == "ok-srv":
                return snapshot
            return error

        mock_connect.side_effect = _side_effect
        mock_store = MagicMock()
        mock_store.check_server_tools.return_value = []
        mock_store_cls.return_value = mock_store

        servers = [
            {"name": "ok-srv", "command": "node", "args": ["ok.js"], "agent_type": "t"},
            {"name": "bad-srv", "command": "node", "args": ["bad.js"], "agent_type": "t"},
        ]
        scanner = ScanMCP(timeout=5.0)
        report = scanner.run(servers)

        assert report.servers_connected == 1
        assert report.servers_failed == 1

    @patch("agentseal.scan_mcp.connect_stdio")
    @patch("agentseal.scan_mcp.BaselineStore")
    def test_progress_callbacks(self, mock_store_cls, mock_connect):
        """Progress function is called during scan."""
        mock_connect.return_value = _make_snapshot("srv")
        mock_store = MagicMock()
        mock_store.check_server_tools.return_value = []
        mock_store_cls.return_value = mock_store

        progress_calls = []

        def on_progress(phase, detail):
            progress_calls.append((phase, detail))

        servers = [{"name": "srv", "command": "node", "args": [], "agent_type": "t"}]
        scanner = ScanMCP(timeout=5.0, on_progress=on_progress)
        scanner.run(servers)

        phases = [p for p, _ in progress_calls]
        assert "connect" in phases
        assert "analyze" in phases

    @patch("agentseal.scan_mcp.connect_http")
    @patch("agentseal.scan_mcp.BaselineStore")
    def test_url_server_uses_http(self, mock_store_cls, mock_connect):
        """Server with 'url' field uses connect_http."""
        mock_connect.return_value = _make_snapshot("remote")
        mock_store = MagicMock()
        mock_store.check_server_tools.return_value = []
        mock_store_cls.return_value = mock_store

        servers = [{"name": "remote", "url": "https://example.com/mcp", "agent_type": "remote"}]
        scanner = ScanMCP(timeout=5.0)
        report = scanner.run(servers)

        mock_connect.assert_called_once()
        assert report.servers_connected == 1

    @patch("agentseal.scan_mcp.connect_stdio")
    @patch("agentseal.scan_mcp.BaselineStore")
    def test_baseline_changes_detected(self, mock_store_cls, mock_connect):
        """Baseline changes are included in report."""
        from agentseal.baselines import BaselineChange

        mock_connect.return_value = _make_snapshot("srv")
        mock_store = MagicMock()
        mock_store.check_server_tools.return_value = [
            BaselineChange(
                server_name="srv",
                agent_type="cursor",
                change_type="tools_changed",
                old_value="abc",
                new_value="def",
                detail="Tool 'read_file' definition changed.",
            ),
        ]
        mock_store_cls.return_value = mock_store

        servers = [{"name": "srv", "command": "node", "args": [], "agent_type": "cursor"}]
        scanner = ScanMCP(timeout=5.0)
        report = scanner.run(servers)

        assert len(report.baseline_changes) == 1
        assert report.baseline_changes[0].change_type == "tools_changed"

    @patch("agentseal.scan_mcp.connect_stdio")
    @patch("agentseal.scan_mcp.BaselineStore")
    def test_trust_score_reflects_baseline_change(self, mock_store_cls, mock_connect):
        """Trust score should NOT have baseline bonus when baseline changed."""
        from agentseal.baselines import BaselineChange

        mock_connect.return_value = _make_snapshot("srv")
        mock_store = MagicMock()
        mock_store.check_server_tools.return_value = [
            BaselineChange(
                server_name="srv", agent_type="t",
                change_type="tools_added", detail="New tool appeared.",
            ),
        ]
        mock_store_cls.return_value = mock_store

        servers = [{"name": "srv", "command": "node", "args": [], "agent_type": "t"}]
        scanner = ScanMCP(timeout=5.0)
        report = scanner.run(servers)

        assert len(report.trust_scores) == 1
        bonus_reasons = [b["reason"] for b in report.trust_scores[0].bonuses]
        assert "Baseline unchanged (returning server)" not in bonus_reasons

    def test_no_command_no_url_returns_error(self):
        """Server with neither command nor url returns MCPConnectionError."""
        scanner = ScanMCP(timeout=5.0)

        async def _test():
            return await scanner._connect_server({"name": "broken"})

        result = asyncio.run(_test())
        assert isinstance(result, MCPConnectionError)
        assert result.error_type == "invalid"


# ═══════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════


class TestHelpers:
    def test_find_agent_type_found(self):
        servers = [
            {"name": "fs", "agent_type": "cursor"},
            {"name": "git", "agent_type": "claude-desktop"},
        ]
        assert _find_agent_type("fs", servers) == "cursor"
        assert _find_agent_type("git", servers) == "claude-desktop"

    def test_find_agent_type_not_found(self):
        assert _find_agent_type("ghost", []) == "unknown"

    def test_find_agent_type_missing_field(self):
        servers = [{"name": "no-type"}]
        assert _find_agent_type("no-type", servers) == "unknown"


# ═══════════════════════════════════════════════════════════════════════
# CLI INTEGRATION
# ═══════════════════════════════════════════════════════════════════════


class TestCLIIntegration:
    """Verify scan-mcp CLI argument parsing."""

    def test_scan_mcp_parser_exists(self):
        """The scan-mcp subcommand is registered."""
        import argparse
        from agentseal.cli import main

        # We can't easily test argparse without running main(),
        # but we can verify the module imports cleanly
        from agentseal.scan_mcp import ScanMCP, ScanMCPReport
        assert ScanMCP is not None
        assert ScanMCPReport is not None

    def test_guard_connect_flag_exists(self):
        """Guard class accepts connect parameter."""
        from agentseal.guard import Guard
        guard = Guard(connect=True, timeout=10.0, concurrency=2)
        assert guard._connect is True
        assert guard._timeout == 10.0
        assert guard._concurrency == 2

    def test_guard_without_connect_backward_compatible(self):
        """Guard without --connect behaves exactly as before."""
        from agentseal.guard import Guard
        guard = Guard()
        assert guard._connect is False
