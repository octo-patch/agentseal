# tests/test_fs_safety.py
"""Tests for filesystem case-sensitivity detection (GAP 9)."""

import platform
import tempfile
from pathlib import Path

from agentseal.detection.fs_safety import check_case_sensitivity_risk, is_case_insensitive


class TestCaseInsensitiveDetection:

    def test_returns_bool(self):
        result = is_case_insensitive()
        assert isinstance(result, bool)

    def test_tmp_directory(self):
        # Just verifies it doesn't crash
        result = is_case_insensitive(tempfile.gettempdir())
        assert isinstance(result, bool)

    def test_nonexistent_directory_falls_back(self):
        result = is_case_insensitive("/nonexistent/path/12345")
        assert isinstance(result, bool)

    def test_caching(self):
        # Call twice — should use cache
        r1 = is_case_insensitive()
        r2 = is_case_insensitive()
        assert r1 == r2


class TestCaseSensitivityRisk:

    def test_no_paths(self):
        assert check_case_sensitivity_risk([]) is None

    def test_http_paths_skipped(self):
        assert check_case_sensitivity_risk(["https://example.com"]) is None

    def test_real_path_returns_something(self):
        # On macOS this should return a warning; on Linux it should return None
        result = check_case_sensitivity_risk(["/tmp"])
        if platform.system() == "Darwin":
            assert result is not None
            assert "case-insensitive" in result
        else:
            # Linux is typically case-sensitive
            assert result is None or "case-insensitive" in result
