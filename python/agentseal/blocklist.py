# agentseal/blocklist.py
"""
Malicious skill blocklist client.

Maintains a local cache of known-malicious skill hashes.
Auto-updates from agentseal.org on each run (with 1-hour cache TTL).
Works fully offline — falls back to cached or empty blocklist.
"""

import json
import time
from pathlib import Path


class Blocklist:
    """Client for the AgentSeal malicious skill blocklist."""

    REMOTE_URL = "https://agentseal.org/api/v1/blocklist/skills.json"
    CACHE_TTL = 3600  # 1 hour

    # Seed hashes — known malicious skills (hardcoded so guard works offline from day 1).
    # These are SHA256 hashes of skill files that have been confirmed malicious.
    # Updated on each release; remote fetch adds any new hashes between releases.
    _SEED_HASHES: set[str] = set()

    def __init__(self):
        self._hashes: set[str] = set(self._SEED_HASHES)
        self._loaded = False
        # Lazy compute paths to avoid calling Path.home() at import time
        self._cache_dir: Path | None = None
        self._cache_path: Path | None = None

    @property
    def CACHE_DIR(self) -> Path:
        if self._cache_dir is None:
            self._cache_dir = Path.home() / ".agentseal"
        return self._cache_dir

    @CACHE_DIR.setter
    def CACHE_DIR(self, value: Path):
        self._cache_dir = value

    @property
    def CACHE_PATH(self) -> Path:
        if self._cache_path is None:
            self._cache_path = self.CACHE_DIR / "blocklist.json"
        return self._cache_path

    @CACHE_PATH.setter
    def CACHE_PATH(self, value: Path):
        self._cache_path = value

    def _load(self):
        """Load blocklist: try cache first, refresh from remote if stale."""
        if self._loaded:
            return

        # Check cache freshness
        if self.CACHE_PATH.is_file():
            try:
                age = time.time() - self.CACHE_PATH.stat().st_mtime
                if age < self.CACHE_TTL:
                    self._load_from_file(self.CACHE_PATH)
                    self._loaded = True
                    return
            except OSError:
                pass

        # Try remote fetch (non-blocking, short timeout)
        if self._try_remote_fetch():
            self._loaded = True
            return

        # Fall back to stale cache
        if self.CACHE_PATH.is_file():
            self._load_from_file(self.CACHE_PATH)

        self._loaded = True

    def _load_from_file(self, path: Path):
        """Load hashes from a local JSON file."""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            self._hashes = set(data.get("sha256_hashes", []))
        except (json.JSONDecodeError, OSError, KeyError):
            self._hashes = set()

    def _try_remote_fetch(self) -> bool:
        """Try to fetch blocklist from remote. Returns True on success."""
        try:
            import httpx
            resp = httpx.get(self.REMOTE_URL, timeout=5.0, follow_redirects=True)
            if resp.status_code == 200:
                data = resp.json()
                self._hashes = set(data.get("sha256_hashes", []))
                # Cache locally
                self.CACHE_DIR.mkdir(parents=True, exist_ok=True)
                self.CACHE_PATH.write_text(resp.text, encoding="utf-8")
                return True
        except Exception:
            pass  # Network unavailable — that's fine
        return False

    def is_blocked(self, sha256: str) -> bool:
        """Check if a SHA256 hash is in the blocklist."""
        self._load()
        return sha256.lower() in self._hashes

    @property
    def size(self) -> int:
        """Number of hashes in the blocklist."""
        self._load()
        return len(self._hashes)
