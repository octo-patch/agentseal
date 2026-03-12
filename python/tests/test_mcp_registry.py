# tests/test_mcp_registry.py
"""Tests for MCP server registry."""

import json
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from agentseal.mcp_registry import MCPRegistry, ServerInfo, _CORE_REGISTRY


class TestMCPRegistryCore:
    def test_core_servers_loaded(self):
        registry = MCPRegistry()
        assert registry.core_count == len(_CORE_REGISTRY)
        assert registry.count >= len(_CORE_REGISTRY)

    def test_lookup_by_name(self):
        registry = MCPRegistry()
        info = registry.lookup("filesystem")
        assert info is not None
        assert info.risk_level == "critical"

    def test_lookup_by_package(self):
        registry = MCPRegistry()
        info = registry.lookup("@modelcontextprotocol/server-filesystem")
        assert info is not None
        assert info.name == "filesystem"

    def test_lookup_fuzzy_dashes(self):
        registry = MCPRegistry()
        info = registry.lookup("brave_search")
        assert info is not None
        assert info.name == "brave-search"

    def test_lookup_by_args(self):
        registry = MCPRegistry()
        info = registry.lookup("unknown_name", args=["@modelcontextprotocol/server-filesystem"])
        assert info is not None
        assert info.name == "filesystem"

    def test_lookup_unknown(self):
        registry = MCPRegistry()
        info = registry.lookup("nonexistent_server_xyz")
        assert info is None

    def test_lookup_all(self):
        registry = MCPRegistry()
        servers = [
            {"name": "filesystem", "command": "npx", "args": []},
            {"name": "unknown_xyz", "command": "npx", "args": []},
        ]
        results = registry.lookup_all(servers)
        assert "filesystem" in results
        assert "unknown_xyz" not in results

    def test_export_core(self):
        registry = MCPRegistry()
        exported = registry.export_core()
        assert len(exported) == len(_CORE_REGISTRY)
        assert all(isinstance(e, dict) for e in exported)


class TestRegistrySecurity:
    """Core registry entries must NEVER be overwritten by API data."""

    def test_local_cache_cannot_overwrite_core(self, tmp_path):
        """Locally cached API data should not change core risk levels."""
        cache_file = tmp_path / "mcp_registry.json"
        # Attacker tries to downgrade filesystem from critical to low
        poisoned = {"servers": [
            {"name": "filesystem", "package": "@modelcontextprotocol/server-filesystem",
             "risk_level": "low", "risk_reason": "Totally safe trust me"},
        ]}
        cache_file.write_text(json.dumps(poisoned))

        with patch("agentseal.mcp_registry._REGISTRY_FILE", cache_file):
            registry = MCPRegistry()

        info = registry.lookup("filesystem")
        assert info.risk_level == "critical"  # Must remain critical

    def test_update_from_api_cannot_overwrite_core(self, tmp_path):
        """API response should not overwrite core entries."""
        cache_file = tmp_path / "mcp_registry.json"
        cache_dir = tmp_path

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"servers": [
            {"name": "filesystem", "risk_level": "low", "risk_reason": "Downgraded"},
            {"name": "new-server", "risk_level": "medium", "description": "A new server"},
        ]}

        with patch("agentseal.mcp_registry._REGISTRY_FILE", cache_file), \
             patch("agentseal.mcp_registry._REGISTRY_DIR", cache_dir), \
             patch("httpx.get", return_value=mock_response), \
             patch("agentseal.config.config_get", return_value=None):
            registry = MCPRegistry()
            count, msg = registry.update_from_api()

        # filesystem must stay critical
        info = registry.lookup("filesystem")
        assert info.risk_level == "critical"
        # new-server should be added
        new_info = registry.lookup("new-server")
        assert new_info is not None
        assert new_info.risk_level == "medium"
        # Only 1 new server added (filesystem was skipped)
        assert count == 1

    def test_api_validates_response_structure(self, tmp_path):
        """Invalid API responses should be rejected."""
        cache_file = tmp_path / "mcp_registry.json"
        cache_dir = tmp_path

        # Not a dict
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = ["not", "a", "dict"]

        with patch("agentseal.mcp_registry._REGISTRY_FILE", cache_file), \
             patch("agentseal.mcp_registry._REGISTRY_DIR", cache_dir), \
             patch("httpx.get", return_value=mock_response), \
             patch("agentseal.config.config_get", return_value=None):
            registry = MCPRegistry()
            count, msg = registry.update_from_api()

        assert count == 0
        assert "Invalid" in msg

    def test_api_sanitizes_invalid_risk_level(self, tmp_path):
        """Invalid risk levels from API should be normalized to 'unknown'."""
        cache_file = tmp_path / "mcp_registry.json"
        cache_dir = tmp_path

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"servers": [
            {"name": "sketchy-server", "risk_level": "totally_safe_lol"},
        ]}

        with patch("agentseal.mcp_registry._REGISTRY_FILE", cache_file), \
             patch("agentseal.mcp_registry._REGISTRY_DIR", cache_dir), \
             patch("httpx.get", return_value=mock_response), \
             patch("agentseal.config.config_get", return_value=None):
            registry = MCPRegistry()
            count, msg = registry.update_from_api()

        info = registry.lookup("sketchy-server")
        assert info is not None
        assert info.risk_level == "unknown"  # Sanitized

    def test_api_rejects_entries_without_name(self, tmp_path):
        """Entries without a name should be skipped."""
        cache_file = tmp_path / "mcp_registry.json"
        cache_dir = tmp_path

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"servers": [
            {"risk_level": "high"},  # No name
            {"name": "", "risk_level": "high"},  # Empty name
            {"name": "valid-server", "risk_level": "low"},
        ]}

        with patch("agentseal.mcp_registry._REGISTRY_FILE", cache_file), \
             patch("agentseal.mcp_registry._REGISTRY_DIR", cache_dir), \
             patch("httpx.get", return_value=mock_response), \
             patch("agentseal.config.config_get", return_value=None):
            registry = MCPRegistry()
            count, msg = registry.update_from_api()

        assert count == 1  # Only valid-server added
