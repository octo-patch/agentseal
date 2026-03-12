# agentseal/upload.py
"""
Upload AgentSeal scan results to the AgentSeal dashboard.

Privacy: Only a SHA-256 hash of the prompt is sent - never the prompt itself.
"""

import hashlib
import json
import os
from pathlib import Path
from typing import Optional

import httpx

CONFIG_DIR = Path.home() / ".agentseal"
CONFIG_FILE = CONFIG_DIR / "config.json"

DEFAULT_API_URL = "http://localhost:8100/api/v1"


def load_config() -> dict:
    """Load stored credentials from ~/.agentseal/config.json."""
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def save_config(config: dict) -> None:
    """Save credentials to ~/.agentseal/config.json."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))
    try:
        CONFIG_FILE.chmod(0o600)
    except OSError:
        pass  # chmod not supported on Windows


def get_credentials(
    api_url: Optional[str] = None,
    api_key: Optional[str] = None,
) -> tuple[str, str]:
    """Resolve API URL and key from args → env → config file.

    Returns (api_url, api_key).
    Raises ValueError if no credentials can be found.
    """
    config = load_config()

    url = (
        api_url
        or os.environ.get("AGENTSEAL_API_URL")
        or config.get("api_url")
        or DEFAULT_API_URL
    )
    key = (
        api_key
        or os.environ.get("AGENTSEAL_API_KEY")
        or config.get("api_key")
        or ""
    )

    return url, key


def upload_report(
    report_dict: dict,
    api_url: str,
    api_key: str,
    content_hash: str,
    agent_name: str,
    model_used: Optional[str] = None,
) -> dict:
    """Upload a scan report to the AgentSeal dashboard.

    Parameters
    ----------
    report_dict : dict
        Output of ScanReport.to_dict().
    api_url : str
        Dashboard API base URL (e.g. http://localhost:8100/api/v1).
    api_key : str
        API key or JWT token for authentication.
    content_hash : str
        SHA-256 hex digest of the system prompt.
    agent_name : str
        Name of the agent that was scanned.
    model_used : str, optional
        Model identifier used for the scan.

    Returns
    -------
    dict
        The JSON response from the dashboard.
    """
    payload = {
        "report": report_dict,
        "agent_name": agent_name,
        "content_hash": content_hash,
        "model_used": model_used,
    }

    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    url = f"{api_url.rstrip('/')}/scans/import"

    with httpx.Client(timeout=30) as client:
        response = client.post(url, json=payload, headers=headers)
        response.raise_for_status()
        return response.json()


def compute_content_hash(prompt: str) -> str:
    """Compute SHA-256 hash of a system prompt."""
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()
