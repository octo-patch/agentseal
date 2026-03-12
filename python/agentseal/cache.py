# agentseal/cache.py
"""
Local result caching - store and retrieve scan results by content hash.

Layer 5: imports from schemas.
"""

import hashlib
import json
from pathlib import Path
from typing import Optional


_CACHE_DIR = Path.home() / ".agentseal" / "cache"


def cache_key(system_prompt: str, model: str = "") -> str:
    """Generate a deterministic cache key from the prompt and model."""
    content = f"{model}::{system_prompt}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def get_cached(key: str) -> Optional[dict]:
    """Retrieve a cached scan report by key.

    Returns None if no cached result exists.
    """
    path = _CACHE_DIR / f"{key}.json"
    if path.exists():
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return None
    return None


def store_cache(key: str, report_dict: dict) -> Path:
    """Store a scan report dict in the local cache.

    Returns the path to the cached file.
    """
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = _CACHE_DIR / f"{key}.json"
    path.write_text(json.dumps(report_dict, indent=2))
    return path


def clear_cache() -> int:
    """Remove all cached results. Returns number of files removed."""
    if not _CACHE_DIR.exists():
        return 0
    count = 0
    for f in _CACHE_DIR.glob("*.json"):
        f.unlink()
        count += 1
    return count
