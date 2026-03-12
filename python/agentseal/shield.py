# agentseal/shield.py
"""
Shield - continuous filesystem monitoring for AI agent security.

Watches skill directories, MCP config files, and agent config dirs.
When a file changes, triggers an incremental scan and optionally sends
desktop notifications.

Usage:
    agentseal shield          # foreground, Ctrl+C to stop
    agentseal shield --quiet  # suppress terminal output, notifications only
"""

import signal
import sys
import time
from collections import defaultdict
from pathlib import Path
from threading import Timer
from typing import Callable, Optional

from agentseal.baselines import BaselineStore
from agentseal.guard_models import GuardVerdict
from agentseal.machine_discovery import _get_well_known_configs, _home, _SKILL_DIRS, _SKILL_FILES
from agentseal.mcp_checker import MCPConfigChecker
from agentseal.notify import Notifier
from agentseal.skill_scanner import SkillScanner
from agentseal.toxic_flows import analyze_toxic_flows

try:
    from watchdog.events import FileSystemEvent, FileSystemEventHandler
    from watchdog.observers import Observer

    _WATCHDOG_AVAILABLE = True
except ImportError:
    _WATCHDOG_AVAILABLE = False
    # Provide a stub base class so the module can be imported without watchdog
    FileSystemEventHandler = object  # type: ignore[misc,assignment]


# Colors for terminal output
_R = "\033[91m"
_Y = "\033[93m"
_G = "\033[92m"
_D = "\033[90m"
_B = "\033[1m"
_C = "\033[96m"
_RST = "\033[0m"


# Callback type: (event_type, path, result_summary) -> None
ShieldCallback = Callable[[str, str, str], None]


def check_watchdog_available() -> None:
    """Raise ImportError with install instructions if watchdog is missing."""
    if not _WATCHDOG_AVAILABLE:
        raise ImportError(
            "agentseal shield requires the 'watchdog' package.\n"
            "Install with: pip install agentseal[shield]"
        )


class _DebouncedHandler(FileSystemEventHandler):
    """Filesystem event handler with per-path debouncing.

    Accumulates events and fires the callback only after a quiet period
    (no new events for the same path). This prevents redundant scans when
    editors save multiple times or git operations touch many files.
    """

    def __init__(
        self,
        on_change: Callable[[Path], None],
        debounce_seconds: float = 2.0,
    ):
        super().__init__()
        self._on_change = on_change
        self._debounce = debounce_seconds
        self._timers: dict[str, Timer] = {}

    def on_any_event(self, event: "FileSystemEvent") -> None:
        # Skip directory events - we only care about file changes
        if event.is_directory:
            return
        # Skip temporary/swap files from editors
        src = event.src_path
        if src.endswith(("~", ".swp", ".swx", ".tmp", ".DS_Store")):
            return

        path_key = src
        # Cancel any pending timer for this path
        existing = self._timers.pop(path_key, None)
        if existing is not None:
            existing.cancel()

        # Schedule a new scan after the debounce period
        t = Timer(self._debounce, self._fire, args=(path_key,))
        t.daemon = True
        t.start()
        self._timers[path_key] = t

    def _fire(self, path_key: str) -> None:
        self._timers.pop(path_key, None)
        self._on_change(Path(path_key))

    def cancel_all(self) -> None:
        """Cancel all pending timers."""
        for t in self._timers.values():
            t.cancel()
        self._timers.clear()


def _collect_watch_paths() -> tuple[list[Path], list[Path]]:
    """Collect all paths that shield should monitor.

    Returns:
        watch_dirs: Directories to watch recursively (skill dirs)
        watch_files: Individual files to watch (MCP configs, single skill files)
    """
    import platform as _platform

    home = _home()
    system = _platform.system()
    configs = _get_well_known_configs()

    watch_dirs: list[Path] = []
    watch_files: list[Path] = []
    seen: set[str] = set()

    def _add_dir(p: Path) -> None:
        resolved = str(p.resolve())
        if resolved not in seen and p.is_dir() and not p.is_symlink():
            seen.add(resolved)
            watch_dirs.append(p)

    def _add_file(p: Path) -> None:
        resolved = str(p.resolve())
        if resolved not in seen and p.exists():
            seen.add(resolved)
            watch_files.append(p)

    # MCP config files from all known agents
    for cfg in configs:
        path = cfg["paths"].get(system) or cfg["paths"].get("all")
        if path is None:
            continue
        path = Path(path).expanduser()
        # Watch the parent directory (so we catch file creation too)
        if path.parent.is_dir():
            _add_dir(path.parent)

    # Skill directories
    for skill_dir_rel in _SKILL_DIRS:
        skill_dir = home / skill_dir_rel
        _add_dir(skill_dir)

    # Single skill files - watch their parent dirs
    for skill_file_rel in _SKILL_FILES:
        skill_file = home / skill_file_rel
        if skill_file.parent.is_dir():
            _add_dir(skill_file.parent)

    # Current working directory skill files
    try:
        cwd = Path.cwd()
        for name in [".cursorrules", "CLAUDE.md", ".github"]:
            candidate = cwd / name
            if candidate.exists():
                if candidate.is_dir():
                    _add_dir(candidate)
                else:
                    _add_file(candidate)
    except OSError:
        pass

    return watch_dirs, watch_files


def _classify_path(path: Path) -> str:
    """Classify a changed file as 'skill', 'mcp_config', or 'unknown'."""
    name = path.name.lower()
    suffix = path.suffix.lower()

    # MCP config files
    mcp_names = {
        "claude_desktop_config.json",
        "mcp.json",
        "mcp_config.json",
        "cline_mcp_settings.json",
    }
    if name in mcp_names:
        return "mcp_config"

    # Agent settings that may contain MCP config
    if name in ("settings.json", "config.json") and any(
        part in str(path).lower()
        for part in (".claude", ".cursor", ".gemini", ".codex", ".kiro", ".opencode",
                     ".continue", ".aider", ".roo", ".amp", "windsurf", "zed")
    ):
        return "mcp_config"

    # Skill files
    if suffix in (".md", ".txt", ".yaml", ".yml"):
        return "skill"
    if name in (".cursorrules",):
        return "skill"

    return "unknown"


class Shield:
    """Continuous filesystem monitor for AI agent security.

    Watches skill directories and MCP config files for changes.
    When a change is detected, runs an incremental scan on just the
    changed file and optionally sends a desktop notification.
    """

    def __init__(
        self,
        semantic: bool = True,
        notify: bool = True,
        debounce_seconds: float = 2.0,
        on_event: Optional[ShieldCallback] = None,
        llm_judge=None,
    ):
        check_watchdog_available()
        self._semantic = semantic
        self._debounce = debounce_seconds
        self._on_event = on_event or (lambda *a: None)
        self._notifier = Notifier(enabled=notify, min_interval=30.0)
        self._scanner = SkillScanner(semantic=semantic, llm_judge=llm_judge)
        self._mcp_checker = MCPConfigChecker()
        self._baseline_store = BaselineStore()
        self._observer: Optional["Observer"] = None
        self._running = False
        self._scan_count = 0
        self._threat_count = 0

    @property
    def scan_count(self) -> int:
        return self._scan_count

    @property
    def threat_count(self) -> int:
        return self._threat_count

    def _handle_change(self, path: Path) -> None:
        """Handle a single file change event."""
        if not path.is_file():
            return

        file_type = _classify_path(path)
        self._scan_count += 1

        if file_type == "skill":
            self._scan_skill(path)
        elif file_type == "mcp_config":
            self._scan_mcp_config(path)
        else:
            # Unknown file type in a watched directory - try skill scan
            if path.suffix.lower() in (".md", ".txt", ".yaml", ".yml"):
                self._scan_skill(path)

    def _scan_skill(self, path: Path) -> None:
        """Run incremental skill scan on a single file."""
        try:
            result = self._scanner.scan_file(path)
        except Exception:
            self._on_event("error", str(path), "Failed to scan file")
            return

        if result.verdict == GuardVerdict.DANGER:
            self._threat_count += 1
            detail = result.top_finding.title if result.top_finding else "Threat detected"
            self._on_event("threat", str(path), f"DANGER - {detail}")
            self._notifier.notify_threat(
                item_name=result.name,
                item_type="Skill",
                severity=result.top_finding.severity if result.top_finding else "high",
                detail=detail,
            )
        elif result.verdict == GuardVerdict.WARNING:
            detail = result.top_finding.title if result.top_finding else "Warning"
            self._on_event("warning", str(path), f"WARNING - {detail}")
        else:
            self._on_event("clean", str(path), "CLEAN")

    def _scan_mcp_config(self, path: Path) -> None:
        """Re-check MCP servers when a config file changes."""
        import json
        from agentseal.machine_discovery import _strip_json_comments

        try:
            raw = path.read_text(encoding="utf-8")
            data = json.loads(_strip_json_comments(raw))
        except (json.JSONDecodeError, OSError):
            self._on_event("error", str(path), "Failed to parse config")
            return

        # Try common MCP keys
        servers: dict = {}
        for key in ("mcpServers", "servers", "context_servers"):
            if key in data and isinstance(data[key], dict):
                servers = data[key]
                break

        if not servers:
            self._on_event("clean", str(path), "No MCP servers in config")
            return

        has_threat = False
        server_dicts = []
        for srv_name, srv_cfg in servers.items():
            if not isinstance(srv_cfg, dict):
                continue
            server_dict = {"name": srv_name, "source_file": str(path), **srv_cfg}
            server_dicts.append(server_dict)

            # MCP config check
            result = self._mcp_checker.check(server_dict)
            if result.verdict == GuardVerdict.DANGER:
                has_threat = True
                self._threat_count += 1
                detail = result.top_finding.title if result.top_finding else "Threat detected"
                self._on_event("threat", str(path), f"MCP '{srv_name}': DANGER - {detail}")
                self._notifier.notify_threat(
                    item_name=srv_name,
                    item_type="MCP Server",
                    severity=result.top_finding.severity if result.top_finding else "high",
                    detail=detail,
                )
            elif result.verdict == GuardVerdict.WARNING:
                detail = result.top_finding.title if result.top_finding else "Warning"
                self._on_event("warning", str(path), f"MCP '{srv_name}': WARNING - {detail}")

            # Baseline check (rug pull detection)
            change = self._baseline_store.check_server(server_dict)
            if change and change.change_type in ("config_changed", "binary_changed"):
                self._threat_count += 1
                self._on_event("warning", str(path), f"BASELINE: {change.detail}")
                self._notifier.notify_threat(
                    item_name=srv_name,
                    item_type="MCP Baseline",
                    severity="high",
                    detail=change.detail,
                )

        # Toxic flow analysis across all servers in this config
        if len(server_dicts) >= 2:
            flows = analyze_toxic_flows(server_dicts)
            for flow in flows:
                self._on_event("warning", str(path), f"TOXIC FLOW: {flow.title}")

        if not has_threat:
            self._on_event("clean", str(path), f"MCP config OK ({len(servers)} servers)")

    def start(self) -> tuple[int, int]:
        """Start watching. Returns (dirs_watched, files_watched).

        This sets up the observer but does NOT block. Call run_forever()
        or use start()/stop() for manual control.
        """
        check_watchdog_available()

        watch_dirs, watch_files = _collect_watch_paths()
        handler = _DebouncedHandler(
            on_change=self._handle_change,
            debounce_seconds=self._debounce,
        )
        self._handler = handler

        self._observer = Observer()

        watched_count = 0
        for d in watch_dirs:
            try:
                self._observer.schedule(handler, str(d), recursive=True)
                watched_count += 1
            except OSError:
                pass  # Permission denied or path disappeared

        # For individual files, watch their parent directory
        file_parents: set[str] = set()
        for f in watch_files:
            parent = str(f.parent)
            if parent not in file_parents:
                file_parents.add(parent)
                try:
                    self._observer.schedule(handler, parent, recursive=False)
                    watched_count += 1
                except OSError:
                    pass

        self._observer.start()
        self._running = True
        return watched_count, len(watch_files)

    def stop(self) -> None:
        """Stop the filesystem observer."""
        self._running = False
        if hasattr(self, "_handler"):
            self._handler.cancel_all()
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None

    def run_forever(self) -> None:
        """Block until interrupted (Ctrl+C or SIGTERM)."""
        stop_requested = False

        def _signal_handler(signum, frame):
            nonlocal stop_requested
            stop_requested = True

        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)

        try:
            while not stop_requested and self._running:
                time.sleep(0.5)
        finally:
            self.stop()
