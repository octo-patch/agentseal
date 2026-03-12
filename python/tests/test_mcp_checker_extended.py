# tests/test_mcp_checker_extended.py
"""Tests for extended MCP checker: OWASP MCP-007 to MCP-012, CVE checks,
expanded credential patterns, entropy detection, and file permissions (GAPs 3, 4, 5, 8)."""

import os
import stat
import tempfile

from agentseal.mcp_checker import MCPConfigChecker, _shannon_entropy


class TestSupplyChain:
    """MCP-007: Supply chain checks."""

    def setup_method(self):
        self.checker = MCPConfigChecker()

    def test_unpinned_npx(self):
        server = {"name": "test", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"], "env": {}}
        result = self.checker.check(server)
        codes = [f.code for f in result.findings]
        assert "MCP-007" in codes

    def test_pinned_npx_no_warning(self):
        server = {"name": "test", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@1.2.3"], "env": {}}
        result = self.checker.check(server)
        codes = [f.code for f in result.findings]
        assert "MCP-007" not in codes

    def test_unpinned_uvx(self):
        server = {"name": "test", "command": "uvx", "args": ["mcp-server-git"], "env": {}}
        result = self.checker.check(server)
        codes = [f.code for f in result.findings]
        assert "MCP-007" in codes

    def test_known_malicious_package(self):
        server = {"name": "test", "command": "npx", "args": ["-y", "crossenv"], "env": {}}
        result = self.checker.check(server)
        mcp007 = [f for f in result.findings if f.code == "MCP-007"]
        assert any(f.severity == "critical" for f in mcp007)


class TestCommandInjection:
    """MCP-008: Command injection checks."""

    def setup_method(self):
        self.checker = MCPConfigChecker()

    def test_bash_as_command(self):
        server = {"name": "test", "command": "bash", "args": ["-c", "echo hello"], "env": {}}
        result = self.checker.check(server)
        codes = [f.code for f in result.findings]
        assert "MCP-008" in codes

    def test_shell_metacharacters(self):
        server = {"name": "test", "command": "node", "args": ["server.js; rm -rf /"], "env": {}}
        result = self.checker.check(server)
        mcp008 = [f for f in result.findings if f.code == "MCP-008"]
        assert len(mcp008) >= 1

    def test_safe_command(self):
        server = {"name": "test", "command": "node", "args": ["server.js"], "env": {}}
        result = self.checker.check(server)
        codes = [f.code for f in result.findings]
        assert "MCP-008" not in codes


class TestMissingAuth:
    """MCP-009: Missing authentication."""

    def setup_method(self):
        self.checker = MCPConfigChecker()

    def test_remote_no_auth(self):
        server = {"name": "test", "command": "", "args": [], "env": {},
                   "url": "https://remote-server.com/mcp"}
        result = self.checker.check(server)
        codes = [f.code for f in result.findings]
        assert "MCP-009" in codes

    def test_remote_with_api_key(self):
        server = {"name": "test", "command": "", "args": [], "env": {},
                   "url": "https://remote-server.com/mcp", "apiKey": "${API_KEY}"}
        result = self.checker.check(server)
        codes = [f.code for f in result.findings]
        assert "MCP-009" not in codes

    def test_localhost_no_auth_ok(self):
        server = {"name": "test", "command": "", "args": [], "env": {},
                   "url": "http://localhost:3000/mcp"}
        result = self.checker.check(server)
        codes = [f.code for f in result.findings]
        assert "MCP-009" not in codes


class TestContextOversharing:
    """MCP-010: Context oversharing."""

    def setup_method(self):
        self.checker = MCPConfigChecker()

    def test_broad_access(self):
        server = {"name": "fs", "command": "node", "args": ["/"], "env": {}}
        result = self.checker.check(server)
        codes = [f.code for f in result.findings]
        # MCP-003 (broad access) should fire; MCP-010 too since / implies read+write
        assert "MCP-003" in codes


class TestKnownCVEs:
    """MCP-CVE: CVE-specific checks."""

    def setup_method(self):
        self.checker = MCPConfigChecker()

    def test_path_traversal(self):
        server = {"name": "test", "command": "node", "args": ["--dir", "../../etc/passwd"], "env": {}}
        result = self.checker.check(server)
        cve = [f for f in result.findings if f.code == "MCP-CVE"]
        assert any("Path traversal" in f.title for f in cve)

    def test_unrestricted_git(self):
        server = {"name": "git", "command": "mcp-server-git", "args": [], "env": {}}
        result = self.checker.check(server)
        cve = [f for f in result.findings if f.code == "MCP-CVE"]
        assert any("git" in f.title.lower() for f in cve)

    def test_project_mcp_json(self):
        server = {"name": "test", "command": "node", "args": [], "env": {},
                   "source_file": "/project/.mcp.json"}
        result = self.checker.check(server)
        cve = [f for f in result.findings if f.code == "MCP-CVE"]
        assert any("Project-level" in f.title for f in cve)

    def test_mcp_remote(self):
        server = {"name": "test", "command": "npx", "args": ["-y", "mcp-remote", "https://example.com"], "env": {}}
        result = self.checker.check(server)
        cve = [f for f in result.findings if f.code == "MCP-CVE"]
        assert any("mcp-remote" in f.title for f in cve)


class TestExtendedCredentialPatterns:
    """GAP 4: Extended credential pattern detection."""

    def setup_method(self):
        self.checker = MCPConfigChecker()

    def test_anthropic_key(self):
        server = {"name": "test", "command": "node", "args": [], "env": {
            "ANTHROPIC_API_KEY": "sk-ant-api03-" + "A" * 95
        }}
        result = self.checker.check(server)
        assert any("Anthropic" in f.title for f in result.findings)

    def test_google_key(self):
        server = {"name": "test", "command": "node", "args": [], "env": {
            "GOOGLE_KEY": "AIza" + "A" * 35
        }}
        result = self.checker.check(server)
        assert any("Google" in f.title for f in result.findings)

    def test_huggingface_token(self):
        server = {"name": "test", "command": "node", "args": [], "env": {
            "HF_TOKEN": "hf_" + "A" * 25
        }}
        result = self.checker.check(server)
        assert any("HuggingFace" in f.title for f in result.findings)

    def test_pem_key(self):
        server = {"name": "test", "command": "node", "args": [], "env": {
            "KEY": "-----BEGIN PRIVATE KEY-----\nMIIE..."
        }}
        result = self.checker.check(server)
        assert any("PEM" in f.title or "PRIVATE" in f.title for f in result.findings)

    def test_env_var_reference_skipped(self):
        server = {"name": "test", "command": "node", "args": [], "env": {
            "API_KEY": "${MY_SECRET}"
        }}
        result = self.checker.check(server)
        assert not any(f.code == "MCP-002" for f in result.findings)


class TestShannonEntropy:
    """GAP 4: Entropy-based secret detection."""

    def test_high_entropy_string(self):
        assert _shannon_entropy("aB3cD4eF5gH6iJ7kL8mN9") > 4.0

    def test_low_entropy_string(self):
        assert _shannon_entropy("aaaaaaaaaa") < 1.0

    def test_empty_string(self):
        assert _shannon_entropy("") == 0.0

    def test_high_entropy_env_detected(self):
        checker = MCPConfigChecker()
        # A random-looking string that won't match any specific pattern
        random_key = "xQ9mR2pL7nK4vB8cZ1wY6hT3jF5gD0sA"
        server = {"name": "test", "command": "node", "args": [], "env": {
            "CUSTOM_SECRET": random_key
        }}
        result = checker.check(server)
        # Should detect via entropy
        entropy_findings = [f for f in result.findings if "entropy" in f.title.lower() or "entropy" in f.description.lower()]
        assert len(entropy_findings) >= 1


class TestFilePermissions:
    """MCP-011: File permissions check (GAP 8)."""

    def setup_method(self):
        self.checker = MCPConfigChecker()

    def test_world_readable_config(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('{"mcpServers": {}}')
            f.flush()
            os.chmod(f.name, 0o644)  # world-readable
            server = {"name": "test", "command": "node", "args": [], "env": {},
                       "source_file": f.name}
            result = self.checker.check(server)
            codes = [f.code for f in result.findings]
            assert "MCP-011" in codes
            os.unlink(f.name)

    def test_owner_only_config(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('{"mcpServers": {}}')
            f.flush()
            os.chmod(f.name, 0o600)  # owner only
            server = {"name": "test", "command": "node", "args": [], "env": {},
                       "source_file": f.name}
            result = self.checker.check(server)
            codes = [f.code for f in result.findings]
            assert "MCP-011" not in codes
            os.unlink(f.name)
