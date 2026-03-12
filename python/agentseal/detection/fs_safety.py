# agentseal/detection/fs_safety.py
"""
Filesystem safety checks — case-sensitivity detection.

macOS APFS defaults to case-insensitive, which means path-based access
controls can be bypassed by changing case (e.g., /Users → /users).
"""

from __future__ import annotations

import functools
import os
import tempfile
from pathlib import Path


@functools.lru_cache(maxsize=16)
def is_case_insensitive(directory: str = "/tmp") -> bool:
    """Detect if a filesystem is case-insensitive (macOS APFS default).

    Creates a temporary file and checks if the uppercase version resolves
    to the same inode. Result is cached per directory.
    """
    try:
        dir_path = Path(directory)
        if not dir_path.is_dir():
            dir_path = Path(tempfile.gettempdir())

        # Create a temp file with lowercase name
        probe = dir_path / "_agentseal_case_probe_abc"
        probe_upper = dir_path / "_agentseal_case_probe_ABC"

        try:
            probe.write_text("probe", encoding="utf-8")
            # If the uppercase version also exists, the FS is case-insensitive
            result = probe_upper.exists()
            return result
        finally:
            try:
                probe.unlink()
            except OSError:
                pass
    except OSError:
        return False


def check_case_sensitivity_risk(allowed_paths: list[str]) -> str | None:
    """Check if path restrictions are on a case-insensitive filesystem.

    Returns a warning message if so, None if safe.
    """
    for path_str in allowed_paths:
        if not path_str or path_str.startswith("http"):
            continue
        expanded = os.path.expanduser(path_str)
        # Check the parent directory (the path itself may not exist yet)
        check_dir = expanded
        if not os.path.isdir(check_dir):
            check_dir = os.path.dirname(check_dir)
        if not check_dir or not os.path.isdir(check_dir):
            continue

        if is_case_insensitive(check_dir):
            return (
                f"Path '{path_str}' is on a case-insensitive filesystem. "
                f"Path-based access controls can be bypassed by changing case "
                f"(e.g., /Users/foo → /users/FOO)."
            )
    return None
