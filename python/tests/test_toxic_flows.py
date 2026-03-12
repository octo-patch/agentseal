# tests/test_toxic_flows.py
"""
Tests for lightweight toxic flow detection.
"""

import pytest

from agentseal.toxic_flows import (
    LABEL_DESTRUCTIVE,
    LABEL_PRIVATE,
    LABEL_PUBLIC_SINK,
    LABEL_UNTRUSTED,
    ToxicFlow,
    analyze_toxic_flows,
    classify_server,
)


# ═══════════════════════════════════════════════════════════════════════
# Server Classification
# ═══════════════════════════════════════════════════════════════════════

class TestClassifyServer:
    def test_known_filesystem(self):
        labels = classify_server({"name": "filesystem", "command": "npx", "args": []})
        assert LABEL_PRIVATE in labels
        assert LABEL_DESTRUCTIVE in labels

    def test_known_slack(self):
        labels = classify_server({"name": "slack", "command": "npx", "args": []})
        assert LABEL_PUBLIC_SINK in labels

    def test_known_github(self):
        labels = classify_server({"name": "github", "command": "npx", "args": []})
        assert LABEL_PUBLIC_SINK in labels
        assert LABEL_PRIVATE in labels

    def test_known_fetch(self):
        labels = classify_server({"name": "fetch", "command": "npx", "args": []})
        assert LABEL_UNTRUSTED in labels

    def test_known_postgres(self):
        labels = classify_server({"name": "postgres", "command": "npx", "args": []})
        assert LABEL_PRIVATE in labels
        assert LABEL_DESTRUCTIVE in labels

    def test_known_shell(self):
        labels = classify_server({"name": "shell", "command": "npx", "args": []})
        assert LABEL_DESTRUCTIVE in labels

    def test_partial_name_match(self):
        """Server name containing a known name should match."""
        labels = classify_server({"name": "my-filesystem-server", "command": "npx", "args": []})
        assert LABEL_PRIVATE in labels

    def test_command_match(self):
        """Known name in command/args should match."""
        labels = classify_server({
            "name": "custom",
            "command": "npx",
            "args": ["@org/slack-server"],
        })
        assert LABEL_PUBLIC_SINK in labels

    def test_heuristic_file(self):
        labels = classify_server({"name": "my-file-manager", "command": "custom", "args": []})
        assert LABEL_PRIVATE in labels

    def test_heuristic_email(self):
        labels = classify_server({"name": "email-sender", "command": "custom", "args": []})
        assert LABEL_PUBLIC_SINK in labels

    def test_heuristic_http(self):
        labels = classify_server({"name": "http-fetcher", "command": "custom", "args": []})
        assert LABEL_UNTRUSTED in labels

    def test_heuristic_database(self):
        labels = classify_server({"name": "my-sql-connector", "command": "custom", "args": []})
        assert LABEL_PRIVATE in labels

    def test_heuristic_exec(self):
        labels = classify_server({"name": "code-runner", "command": "custom", "args": []})
        assert LABEL_DESTRUCTIVE in labels

    def test_unknown_server_empty_labels(self):
        labels = classify_server({"name": "foobar-xyz", "command": "foobar", "args": []})
        assert len(labels) == 0

    def test_case_insensitive(self):
        labels = classify_server({"name": "Filesystem", "command": "npx", "args": []})
        assert LABEL_PRIVATE in labels


# ═══════════════════════════════════════════════════════════════════════
# Toxic Flow Detection
# ═══════════════════════════════════════════════════════════════════════

class TestAnalyzeToxicFlows:
    def test_single_server_no_flows(self):
        """Need at least 2 servers for cross-server flows."""
        servers = [
            {"name": "filesystem", "command": "npx", "args": ["/tmp"]},
        ]
        flows = analyze_toxic_flows(servers)
        assert len(flows) == 0

    def test_safe_combination(self):
        """Two servers with no dangerous combo."""
        servers = [
            {"name": "memory", "command": "npx", "args": []},
            {"name": "my-custom-tool", "command": "npx", "args": []},
        ]
        flows = analyze_toxic_flows(servers)
        assert len(flows) == 0

    def test_data_exfiltration(self):
        """private_data + public_sink = exfiltration risk."""
        servers = [
            {"name": "filesystem", "command": "npx", "args": ["/home"]},
            {"name": "slack", "command": "npx", "args": []},
        ]
        flows = analyze_toxic_flows(servers)
        assert len(flows) >= 1
        assert any(f.risk_type == "data_exfiltration" for f in flows)
        exfil = next(f for f in flows if f.risk_type == "data_exfiltration")
        assert exfil.risk_level == "high"
        assert "filesystem" in exfil.servers_involved
        assert "slack" in exfil.servers_involved

    def test_remote_code_execution(self):
        """untrusted_content + destructive = RCE risk."""
        servers = [
            {"name": "fetch", "command": "npx", "args": []},
            {"name": "shell", "command": "npx", "args": []},
        ]
        flows = analyze_toxic_flows(servers)
        assert len(flows) >= 1
        assert any(f.risk_type == "remote_code_execution" for f in flows)

    def test_full_chain(self):
        """untrusted + private + sink = full chain (subsumes individual combos)."""
        servers = [
            {"name": "fetch", "command": "npx", "args": []},
            {"name": "filesystem", "command": "npx", "args": ["/home"]},
            {"name": "slack", "command": "npx", "args": []},
        ]
        flows = analyze_toxic_flows(servers)
        assert len(flows) == 1  # Full chain subsumes others
        assert flows[0].risk_type == "full_chain"
        assert flows[0].risk_level == "high"

    def test_data_destruction_cross_server(self):
        """private from one server + destructive from another."""
        servers = [
            {"name": "sentry", "command": "npx", "args": []},     # private only
            {"name": "docker", "command": "npx", "args": []},     # destructive only
        ]
        flows = analyze_toxic_flows(servers)
        assert any(f.risk_type == "data_destruction" for f in flows)

    def test_same_server_private_destructive_no_destruction_flow(self):
        """A single server with both labels shouldn't trigger cross-server destruction."""
        servers = [
            {"name": "filesystem", "command": "npx", "args": ["/tmp"]},  # private + destructive
            {"name": "my-safe-tool", "command": "npx", "args": []},      # no labels
        ]
        flows = analyze_toxic_flows(servers)
        # filesystem has both private and destructive, but they're the same server
        assert not any(f.risk_type == "data_destruction" for f in flows)

    def test_flows_have_remediation(self):
        servers = [
            {"name": "filesystem", "command": "npx", "args": ["/"]},
            {"name": "slack", "command": "npx", "args": []},
        ]
        flows = analyze_toxic_flows(servers)
        for flow in flows:
            assert flow.remediation
            assert len(flow.remediation) > 10

    def test_empty_servers(self):
        assert analyze_toxic_flows([]) == []

    def test_all_unknown_servers(self):
        servers = [
            {"name": "xyz-123", "command": "custom1", "args": []},
            {"name": "abc-456", "command": "custom2", "args": []},
        ]
        flows = analyze_toxic_flows(servers)
        assert len(flows) == 0

    def test_real_world_setup(self):
        """Common real-world agent setup: filesystem + github + puppeteer."""
        servers = [
            {"name": "filesystem", "command": "npx", "args": ["/Users/dev/projects"]},
            {"name": "github", "command": "npx", "args": ["@modelcontextprotocol/server-github"]},
            {"name": "puppeteer", "command": "npx", "args": ["@modelcontextprotocol/server-puppeteer"]},
        ]
        flows = analyze_toxic_flows(servers)
        # filesystem (private+destructive) + github (sink+private) + puppeteer (untrusted)
        # Should detect full chain
        assert len(flows) >= 1
        assert any(f.risk_type == "full_chain" for f in flows)
