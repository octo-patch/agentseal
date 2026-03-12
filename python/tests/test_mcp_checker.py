# tests/test_mcp_checker.py
"""Tests for MCP config checker."""

import pytest
from agentseal.mcp_checker import MCPConfigChecker
from agentseal.guard_models import GuardVerdict


class TestSensitivePaths:
    def setup_method(self):
        self.checker = MCPConfigChecker()

    def test_ssh_access_detected(self):
        server = {"name": "fs", "command": "npx fs", "args": ["/Users/me/.ssh"], "env": {}}
        result = self.checker.check(server)
        assert result.verdict == GuardVerdict.DANGER
        assert any(f.code == "MCP-001" for f in result.findings)

    def test_aws_access_detected(self):
        server = {"name": "fs", "command": "npx fs", "args": ["/home/user/.aws"], "env": {}}
        result = self.checker.check(server)
        assert any(f.code == "MCP-001" for f in result.findings)

    def test_safe_path_no_finding(self):
        server = {"name": "fs", "command": "npx fs", "args": ["/home/user/projects/myapp"], "env": {}}
        result = self.checker.check(server)
        mcp001 = [f for f in result.findings if f.code == "MCP-001"]
        assert len(mcp001) == 0


class TestEnvCredentials:
    def setup_method(self):
        self.checker = MCPConfigChecker()

    def test_openai_key_detected(self):
        server = {"name": "api", "command": "npx api", "args": [],
                  "env": {"OPENAI_API_KEY": "sk-proj-abc123def456ghi789jkl012mno345"}}
        result = self.checker.check(server)
        assert any(f.code == "MCP-002" for f in result.findings)

    def test_aws_key_detected(self):
        server = {"name": "aws", "command": "npx aws", "args": [],
                  "env": {"AWS_KEY": "AKIAIOSFODNN7EXAMPLE"}}
        result = self.checker.check(server)
        assert any(f.code == "MCP-002" for f in result.findings)

    def test_env_var_reference_not_flagged(self):
        server = {"name": "api", "command": "npx api", "args": [],
                  "env": {"API_KEY": "${OPENAI_API_KEY}"}}
        result = self.checker.check(server)
        mcp002 = [f for f in result.findings if f.code == "MCP-002"]
        assert len(mcp002) == 0

    def test_safe_env_no_finding(self):
        server = {"name": "api", "command": "npx api", "args": [],
                  "env": {"NODE_ENV": "production"}}
        result = self.checker.check(server)
        mcp002 = [f for f in result.findings if f.code == "MCP-002"]
        assert len(mcp002) == 0


class TestBroadAccess:
    def setup_method(self):
        self.checker = MCPConfigChecker()

    def test_root_access_detected(self):
        server = {"name": "fs", "command": "npx fs", "args": ["/"], "env": {}}
        result = self.checker.check(server)
        assert any(f.code == "MCP-003" for f in result.findings)

    def test_home_dir_access_detected(self):
        server = {"name": "fs", "command": "npx fs", "args": ["~"], "env": {}}
        result = self.checker.check(server)
        assert any(f.code == "MCP-003" for f in result.findings)

    def test_project_dir_no_finding(self):
        server = {"name": "fs", "command": "npx fs",
                  "args": ["/home/user/projects/myapp"], "env": {}}
        result = self.checker.check(server)
        mcp003 = [f for f in result.findings if f.code == "MCP-003"]
        assert len(mcp003) == 0


class TestInsecureUrls:
    def setup_method(self):
        self.checker = MCPConfigChecker()

    def test_http_url_detected(self):
        server = {"name": "api", "command": "npx api",
                  "args": ["http://remote-server.com:8080"], "env": {}}
        result = self.checker.check(server)
        assert any(f.code == "MCP-005" for f in result.findings)

    def test_localhost_exempted(self):
        server = {"name": "local", "command": "npx local",
                  "args": ["http://localhost:3000"], "env": {}}
        result = self.checker.check(server)
        mcp005 = [f for f in result.findings if f.code == "MCP-005"]
        assert len(mcp005) == 0

    def test_127_exempted(self):
        server = {"name": "local", "command": "npx local",
                  "args": ["http://127.0.0.1:3000"], "env": {}}
        result = self.checker.check(server)
        mcp005 = [f for f in result.findings if f.code == "MCP-005"]
        assert len(mcp005) == 0


class TestMCPConfigChecker:
    def setup_method(self):
        self.checker = MCPConfigChecker()

    def test_clean_server(self):
        server = {"name": "brave-search", "command": "npx @anthropic/brave-search",
                  "args": [], "env": {"BRAVE_API_KEY": "${BRAVE_KEY}"}}
        result = self.checker.check(server)
        assert result.verdict == GuardVerdict.SAFE

    def test_dangerous_server(self):
        server = {"name": "filesystem", "command": "npx @modelcontextprotocol/server-filesystem",
                  "args": ["/Users/me/.ssh", "/Users/me/.aws"],
                  "env": {"GITHUB_TOKEN": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"}}
        result = self.checker.check(server)
        assert result.verdict == GuardVerdict.DANGER
        assert len(result.findings) >= 2

    def test_check_all(self):
        servers = [
            {"name": "safe", "command": "npx safe", "args": [], "env": {}},
            {"name": "dangerous", "command": "npx fs",
             "args": ["/Users/me/.ssh"], "env": {}},
        ]
        results = self.checker.check_all(servers)
        assert len(results) == 2
        assert results[0].verdict == GuardVerdict.SAFE
        assert results[1].verdict == GuardVerdict.DANGER
