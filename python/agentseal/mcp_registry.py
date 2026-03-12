# agentseal/mcp_registry.py
"""
MCP Server Registry — known server database with risk assessments.

Ships with a core set of ~50 most common/dangerous MCP servers baked in.
Users can fetch the full registry (~300+ servers) from the AgentSeal API
using `agentseal registry update`.

Usage:
    from agentseal.mcp_registry import MCPRegistry

    registry = MCPRegistry()
    info = registry.lookup("filesystem")
    # -> ServerInfo(name="filesystem", risk_level="critical", ...)
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


# ═══════════════════════════════════════════════════════════════════════
# DATA MODEL
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class ServerInfo:
    """Known MCP server metadata."""

    name: str
    package: str = ""
    description: str = ""
    category: str = ""
    capabilities: list[str] = field(default_factory=list)
    risk_level: str = "unknown"  # critical, high, medium, low, unknown
    risk_reason: str = ""


# ═══════════════════════════════════════════════════════════════════════
# CORE REGISTRY — Top 50 most common/dangerous servers (baked in)
# ═══════════════════════════════════════════════════════════════════════

_CORE_REGISTRY: list[dict] = [
    # ── Filesystem & Shell (CRITICAL) ──
    {"name": "filesystem", "package": "@modelcontextprotocol/server-filesystem", "description": "Local file system read/write access", "category": "filesystem", "capabilities": ["read", "write", "execute"], "risk_level": "critical", "risk_reason": "Full filesystem access — can read/write/delete any allowed files"},
    {"name": "desktop-commander", "package": "desktop-commander", "description": "Terminal command execution and file management", "category": "filesystem", "capabilities": ["read", "write", "execute"], "risk_level": "critical", "risk_reason": "Arbitrary command execution capability"},
    {"name": "filestash", "package": "filestash", "description": "Remote storage access (SFTP, S3, FTP, SMB)", "category": "filesystem", "capabilities": ["read", "write", "network"], "risk_level": "critical", "risk_reason": "Access to remote storage systems with credentials"},

    # ── Version Control (HIGH) ──
    {"name": "github", "package": "@modelcontextprotocol/server-github", "description": "GitHub repository management, PRs, issues", "category": "version_control", "capabilities": ["read", "write", "network"], "risk_level": "high", "risk_reason": "Can modify repos, create PRs, manage issues"},
    {"name": "github-official", "package": "@github/mcp-server", "description": "Official GitHub MCP with 80+ tools", "category": "version_control", "capabilities": ["read", "write", "network"], "risk_level": "high", "risk_reason": "Extensive GitHub API access"},
    {"name": "gitlab", "package": "@modelcontextprotocol/server-gitlab", "description": "GitLab API for projects, CI/CD, merge requests", "category": "version_control", "capabilities": ["read", "write", "network"], "risk_level": "high", "risk_reason": "Can modify projects, pipelines, merge requests"},
    {"name": "git", "package": "@modelcontextprotocol/server-git", "description": "Git repository operations", "category": "version_control", "capabilities": ["read", "write"], "risk_level": "medium", "risk_reason": "Can modify git repos, commit history"},

    # ── Databases (HIGH) ──
    {"name": "postgres", "package": "@modelcontextprotocol/server-postgres", "description": "PostgreSQL database access", "category": "database", "capabilities": ["read", "network"], "risk_level": "high", "risk_reason": "Database access — may expose sensitive data"},
    {"name": "sqlite", "package": "@modelcontextprotocol/server-sqlite", "description": "SQLite database interaction", "category": "database", "capabilities": ["read", "write"], "risk_level": "high", "risk_reason": "Full database read/write"},
    {"name": "mysql", "package": "mysql-mcp-server", "description": "MySQL database integration", "category": "database", "capabilities": ["read", "write", "network"], "risk_level": "high", "risk_reason": "Database access with write operations"},
    {"name": "mongodb", "package": "@mongodb/mcp-server", "description": "MongoDB collection querying", "category": "database", "capabilities": ["read", "write", "network"], "risk_level": "high", "risk_reason": "NoSQL database access"},
    {"name": "redis", "package": "@redis/mcp-server", "description": "Redis data management", "category": "database", "capabilities": ["read", "write", "network"], "risk_level": "high", "risk_reason": "Key-value store access"},
    {"name": "supabase", "package": "@supabase/mcp-server", "description": "Supabase platform (database, auth, functions)", "category": "database", "capabilities": ["read", "write", "network"], "risk_level": "critical", "risk_reason": "Full platform access including auth and functions"},
    {"name": "firebase-mcp", "package": "firebase-mcp", "description": "Firebase services (Auth, Firestore, Storage)", "category": "database", "capabilities": ["read", "write", "network"], "risk_level": "critical", "risk_reason": "Full Firebase platform access including auth"},
    {"name": "neo4j", "package": "neo4j-contrib/mcp-neo4j", "description": "Neo4j graph database", "category": "database", "capabilities": ["read", "write", "network"], "risk_level": "high", "risk_reason": "Graph database with write access"},
    {"name": "snowflake", "package": "@snowflake-labs/mcp", "description": "Snowflake data warehouse", "category": "database", "capabilities": ["read", "write", "network"], "risk_level": "high", "risk_reason": "Cloud data warehouse access"},

    # ── Communication (HIGH) ──
    {"name": "slack", "package": "@modelcontextprotocol/server-slack", "description": "Slack messaging and channel management", "category": "communication", "capabilities": ["read", "write", "network"], "risk_level": "high", "risk_reason": "Can send messages, access channels, read history"},
    {"name": "gmail", "package": "gmail-mcp-server", "description": "Gmail email management", "category": "communication", "capabilities": ["read", "write", "network"], "risk_level": "critical", "risk_reason": "Full email access — send, read, delete"},
    {"name": "discord", "package": "discord-mcp", "description": "Discord messaging and server management", "category": "communication", "capabilities": ["read", "write", "network"], "risk_level": "high", "risk_reason": "Can send messages in any accessible channel"},
    {"name": "twilio", "package": "twilio-mcp", "description": "SMS and voice communications via Twilio", "category": "communication", "capabilities": ["write", "network"], "risk_level": "critical", "risk_reason": "Can send SMS/calls — potential for abuse and costs"},

    # ── Cloud Platforms (CRITICAL) ──
    {"name": "aws", "package": "aws-mcp", "description": "AWS services interaction", "category": "cloud_platform", "capabilities": ["read", "write", "network"], "risk_level": "critical", "risk_reason": "AWS infrastructure management — potential for data loss and costs"},
    {"name": "gcp", "package": "gcp-mcp", "description": "Google Cloud Platform services", "category": "cloud_platform", "capabilities": ["read", "write", "network"], "risk_level": "critical", "risk_reason": "GCP infrastructure access"},
    {"name": "azure", "package": "azure-mcp", "description": "Microsoft Azure services", "category": "cloud_platform", "capabilities": ["read", "write", "network"], "risk_level": "critical", "risk_reason": "Azure infrastructure access"},
    {"name": "cloudflare", "package": "@cloudflare/mcp-server-cloudflare", "description": "Cloudflare Workers, KV, R2, D1 management", "category": "cloud_platform", "capabilities": ["read", "write", "network"], "risk_level": "high", "risk_reason": "Edge infrastructure management"},
    {"name": "vercel", "package": "@vercel/mcp", "description": "Vercel deployment and project management", "category": "cloud_platform", "capabilities": ["read", "write", "network"], "risk_level": "high", "risk_reason": "Deployment management — can deploy code"},

    # ── Browser & Web (HIGH) ──
    {"name": "puppeteer", "package": "@modelcontextprotocol/server-puppeteer", "description": "Browser automation via Puppeteer", "category": "browser_automation", "capabilities": ["read", "write", "network"], "risk_level": "high", "risk_reason": "Full browser control — can navigate, click, fill forms"},
    {"name": "playwright", "package": "@anthropic/mcp-playwright", "description": "Browser automation via Playwright", "category": "browser_automation", "capabilities": ["read", "write", "network"], "risk_level": "high", "risk_reason": "Full browser control across Chromium, Firefox, WebKit"},
    {"name": "browserbase", "package": "@browserbasehq/mcp-server", "description": "Cloud browser sessions for web automation", "category": "browser_automation", "capabilities": ["read", "write", "network"], "risk_level": "high", "risk_reason": "Cloud browser access for web scraping/automation"},
    {"name": "fetch", "package": "@modelcontextprotocol/server-fetch", "description": "Web content fetching and conversion", "category": "browser_automation", "capabilities": ["network", "read"], "risk_level": "medium", "risk_reason": "Can fetch arbitrary URLs, potential SSRF"},

    # ── Search (LOW-MEDIUM) ──
    {"name": "brave-search", "package": "@modelcontextprotocol/server-brave-search", "description": "Web and local search via Brave Search API", "category": "search", "capabilities": ["network", "read"], "risk_level": "low", "risk_reason": "Read-only web search"},
    {"name": "tavily", "package": "tavily-mcp", "description": "AI-powered web search and research", "category": "search", "capabilities": ["network", "read"], "risk_level": "low", "risk_reason": "Read-only search"},
    {"name": "exa", "package": "@anthropic/mcp-exa", "description": "AI search engine for web content", "category": "search", "capabilities": ["network", "read"], "risk_level": "low", "risk_reason": "Read-only search"},

    # ── Code Execution (CRITICAL) ──
    {"name": "e2b", "package": "@e2b/mcp-server", "description": "Cloud code execution environments", "category": "sandbox", "capabilities": ["execute", "network"], "risk_level": "medium", "risk_reason": "Sandboxed but arbitrary code execution"},
    {"name": "docker", "package": "docker-mcp", "description": "Docker container management", "category": "sandbox", "capabilities": ["execute", "network"], "risk_level": "high", "risk_reason": "Container management can expose host system"},

    # ── Finance & Payments (CRITICAL) ──
    {"name": "stripe", "package": "@stripe/mcp", "description": "Stripe payment processing", "category": "finance", "capabilities": ["read", "write", "network"], "risk_level": "critical", "risk_reason": "Payment processing — potential for financial loss"},
    {"name": "paypal", "package": "paypal-mcp", "description": "PayPal payment management", "category": "finance", "capabilities": ["read", "write", "network"], "risk_level": "critical", "risk_reason": "Payment processing — potential for financial loss"},
    {"name": "plaid", "package": "plaid-mcp", "description": "Bank account and transaction access via Plaid", "category": "finance", "capabilities": ["read", "network"], "risk_level": "critical", "risk_reason": "Bank account data access"},

    # ── DevOps & CI/CD (HIGH) ──
    {"name": "kubernetes", "package": "kubernetes-mcp", "description": "Kubernetes cluster management", "category": "devops", "capabilities": ["read", "write", "network"], "risk_level": "critical", "risk_reason": "Cluster management — can create/delete pods, services"},
    {"name": "terraform", "package": "terraform-mcp", "description": "Terraform infrastructure management", "category": "devops", "capabilities": ["read", "write", "execute"], "risk_level": "critical", "risk_reason": "Infrastructure as code — can provision/destroy resources"},
    {"name": "sentry", "package": "@sentry/mcp-server", "description": "Sentry error tracking and monitoring", "category": "monitoring", "capabilities": ["read", "network"], "risk_level": "medium", "risk_reason": "Error data may contain sensitive information"},

    # ── Productivity (MEDIUM) ──
    {"name": "notion", "package": "notion-mcp", "description": "Notion workspace management", "category": "productivity", "capabilities": ["read", "write", "network"], "risk_level": "medium", "risk_reason": "Workspace data access"},
    {"name": "linear", "package": "@anthropic/mcp-linear", "description": "Linear project management", "category": "productivity", "capabilities": ["read", "write", "network"], "risk_level": "medium", "risk_reason": "Project management access"},
    {"name": "google-drive", "package": "google-drive-mcp", "description": "Google Drive file management", "category": "productivity", "capabilities": ["read", "write", "network"], "risk_level": "high", "risk_reason": "Cloud file access — can read/modify documents"},

    # ── Identity & Auth (CRITICAL) ──
    {"name": "auth0", "package": "auth0-mcp", "description": "Auth0 identity management", "category": "identity", "capabilities": ["read", "write", "network"], "risk_level": "critical", "risk_reason": "Identity provider — can modify user accounts, roles"},
    {"name": "vault", "package": "vault-mcp", "description": "HashiCorp Vault secrets management", "category": "identity", "capabilities": ["read", "write", "network"], "risk_level": "critical", "risk_reason": "Secrets management — access to all stored credentials"},

    # ── Aggregators (HIGH — multiplied attack surface) ──
    {"name": "zapier", "package": "zapier-mcp", "description": "Zapier automation — access to 5000+ apps", "category": "aggregator", "capabilities": ["read", "write", "network"], "risk_level": "critical", "risk_reason": "Aggregator — single server grants access to thousands of APIs"},
    {"name": "pipedream", "package": "pipedream-mcp", "description": "Pipedream workflow automation", "category": "aggregator", "capabilities": ["read", "write", "network"], "risk_level": "critical", "risk_reason": "Aggregator with broad API access"},

    # ── Reference / Safe (LOW) ──
    {"name": "memory", "package": "@modelcontextprotocol/server-memory", "description": "Knowledge graph persistent memory", "category": "reference", "capabilities": ["read", "write"], "risk_level": "low", "risk_reason": "Local knowledge graph storage"},
    {"name": "sequential-thinking", "package": "@modelcontextprotocol/server-sequential-thinking", "description": "Problem-solving through thought sequences", "category": "reference", "capabilities": ["read"], "risk_level": "low", "risk_reason": "Reasoning only, no external access"},
    {"name": "time", "package": "@modelcontextprotocol/server-time", "description": "Time and timezone conversion", "category": "reference", "capabilities": ["read"], "risk_level": "low", "risk_reason": "Read-only time data"},
    {"name": "everything", "package": "@modelcontextprotocol/server-everything", "description": "Reference/test server", "category": "reference", "capabilities": ["read"], "risk_level": "low", "risk_reason": "Test server only"},
]


# ═══════════════════════════════════════════════════════════════════════
# REGISTRY CLASS
# ═══════════════════════════════════════════════════════════════════════

_REGISTRY_DIR = Path.home() / ".agentseal"
_REGISTRY_FILE = _REGISTRY_DIR / "mcp_registry.json"
_REGISTRY_API_URL = "https://api.agentseal.org/v1/registry/mcp-servers"


class MCPRegistry:
    """Known MCP server database with risk assessments."""

    def __init__(self) -> None:
        self._servers: dict[str, ServerInfo] = {}
        self._core_names: set[str] = set()  # Names protected from API overwrite
        self._load_core()
        self._load_local()

    def _load_core(self) -> None:
        """Load the baked-in core registry."""
        for entry in _CORE_REGISTRY:
            info = ServerInfo(**entry)
            self._servers[info.name] = info
            self._core_names.add(info.name)
            # Also index by package name for matching
            if info.package:
                self._servers[info.package] = info
                self._core_names.add(info.package)

    def _load_local(self) -> None:
        """Load locally cached extended registry (from API fetch).

        Core entries are never overwritten — API can only ADD new servers,
        not change risk levels of baked-in servers.
        """
        if not _REGISTRY_FILE.is_file():
            return
        try:
            data = json.loads(_REGISTRY_FILE.read_text(encoding="utf-8"))
            for entry in data.get("servers", []):
                info = ServerInfo(**{k: v for k, v in entry.items()
                                     if k in ServerInfo.__dataclass_fields__})
                # Never let API data overwrite core registry entries
                if info.name in self._core_names:
                    continue
                if info.package and info.package in self._core_names:
                    continue
                self._servers[info.name] = info
                if info.package:
                    self._servers[info.package] = info
        except Exception:
            pass  # Corrupt cache — ignore, core registry still works

    def lookup(self, name: str, args: list | None = None) -> Optional[ServerInfo]:
        """Look up a server by name, command, or package in args.

        Tries multiple matching strategies:
        1. Exact name match
        2. Package name in args (e.g., npx -y @modelcontextprotocol/server-filesystem)
        3. Fuzzy name match (e.g., "brave_search" matches "brave-search")
        """
        # 1. Exact name match
        if name in self._servers:
            return self._servers[name]

        # 2. Check args for package names
        for arg in (args or []):
            if isinstance(arg, str) and arg in self._servers:
                return self._servers[arg]

        # 3. Fuzzy: normalize dashes/underscores
        normalized = name.replace("_", "-").replace(" ", "-").lower()
        if normalized in self._servers:
            return self._servers[normalized]

        # 4. Try matching against all known names
        for key, info in self._servers.items():
            if key.replace("_", "-").lower() == normalized:
                return info

        return None

    def lookup_all(self, servers: list[dict]) -> dict[str, ServerInfo]:
        """Look up all servers from a scan result. Returns {server_name: ServerInfo}."""
        results = {}
        for srv in servers:
            name = srv.get("name", "")
            args = srv.get("args", [])
            info = self.lookup(name, args=args)
            if info:
                results[name] = info
        return results

    @property
    def count(self) -> int:
        """Number of unique servers (deduplicated by name)."""
        return len({v.name for v in self._servers.values()})

    @property
    def core_count(self) -> int:
        """Number of baked-in core servers."""
        return len(_CORE_REGISTRY)

    def update_from_api(self, api_url: str | None = None, timeout: float = 15.0) -> tuple[int, str]:
        """Fetch extended registry from AgentSeal API.

        Core entries are protected — API can only add new servers, never
        overwrite baked-in risk levels.

        Returns:
            (count, message): Number of new servers added and status message.
        """
        import httpx

        # Allow user-configured URL, env var, or default
        from agentseal.config import config_get
        url = api_url or config_get("registry-url") or os.environ.get("AGENTSEAL_REGISTRY_URL") or _REGISTRY_API_URL

        try:
            resp = httpx.get(url, timeout=timeout, follow_redirects=True)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            return 0, f"Failed to fetch registry: {e}"

        # Validate response structure
        if not isinstance(data, dict):
            return 0, "Invalid response: expected JSON object"
        servers = data.get("servers", [])
        if not isinstance(servers, list):
            return 0, "Invalid response: 'servers' must be a list"
        if not servers:
            return 0, "No servers in response"

        # Validate and filter entries
        _VALID_RISK_LEVELS = {"critical", "high", "medium", "low", "unknown"}
        valid_entries = []
        for entry in servers:
            if not isinstance(entry, dict):
                continue
            if not entry.get("name") or not isinstance(entry.get("name"), str):
                continue
            # Sanitize risk_level
            if entry.get("risk_level") and entry["risk_level"] not in _VALID_RISK_LEVELS:
                entry["risk_level"] = "unknown"
            valid_entries.append(entry)

        if not valid_entries:
            return 0, "No valid server entries in response"

        # Save to local cache
        _REGISTRY_DIR.mkdir(parents=True, exist_ok=True)
        cache_data = {"servers": valid_entries}
        _REGISTRY_FILE.write_text(json.dumps(cache_data, indent=2), encoding="utf-8")

        # Load new entries (never overwrite core)
        added = 0
        for entry in valid_entries:
            info = ServerInfo(**{k: v for k, v in entry.items()
                                 if k in ServerInfo.__dataclass_fields__})
            if info.name in self._core_names:
                continue
            if info.package and info.package in self._core_names:
                continue
            self._servers[info.name] = info
            if info.package:
                self._servers[info.package] = info
            added += 1

        return added, f"Registry updated: {added} new servers added ({len(valid_entries)} total in cache)"

    def export_core(self) -> list[dict]:
        """Export core registry as list of dicts."""
        return [dict(e) for e in _CORE_REGISTRY]
