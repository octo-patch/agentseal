# agentseal/detection/dataflow.py
"""
AST-based source→sink taint analysis for Python files.

Traces credential access (env vars, file reads, keyring calls) flowing to
network sends (requests.post, fetch, socket.send) through variable assignments,
function calls, and string formatting.

Stdlib only — uses ast module. ~50-100ms per script.
For JS/TS: regex-based fallback (not full AST).
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class DataflowFinding:
    """A detected source→sink data flow."""
    source_type: str      # "env_access", "file_read", "credential_access"
    source_line: int
    source_code: str
    sink_type: str        # "http_send", "exec_call", "socket_send"
    sink_line: int
    sink_code: str
    taint_chain: list[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════
# SOURCE PATTERNS — where sensitive data enters
# ═══════════════════════════════════════════════════════════════════════

_ENV_FUNCS = {
    ("os", "getenv"),
    ("os", "environ"),
    ("os.environ", "get"),
}

_SENSITIVE_FILE_PATTERNS = re.compile(
    r"\.ssh|\.aws|\.env|\.gnupg|\.npmrc|\.pypirc|\.docker|\.kube|"
    r"\.netrc|credentials|id_rsa|id_ed25519|wallet\.dat|"
    r"/etc/passwd|/etc/shadow|private.key"
)

_CREDENTIAL_FUNCS = {
    ("keyring", "get_password"),
    ("keyring", "get_credential"),
}

# ═══════════════════════════════════════════════════════════════════════
# SINK PATTERNS — where data leaves the system
# ═══════════════════════════════════════════════════════════════════════

_HTTP_SINKS = {
    ("requests", "post"), ("requests", "get"), ("requests", "put"),
    ("requests", "patch"), ("requests", "delete"),
    ("httpx", "post"), ("httpx", "get"), ("httpx", "put"),
    ("urllib", "request", "urlopen"),
    ("urllib.request", "urlopen"),
    ("aiohttp", "post"), ("aiohttp", "get"),
}

_EXEC_SINKS = {
    ("subprocess", "run"), ("subprocess", "call"), ("subprocess", "Popen"),
    ("subprocess", "check_output"), ("subprocess", "check_call"),
    ("os", "system"), ("os", "popen"),
}

_SOCKET_SINKS = {
    ("socket", "send"), ("socket", "sendall"), ("socket", "sendto"),
}

_BUILTIN_SINKS = {"eval", "exec"}


def _get_func_path(node: ast.expr) -> tuple[str, ...]:
    """Extract dotted function path from a Call node's func attribute."""
    if isinstance(node, ast.Name):
        return (node.id,)
    if isinstance(node, ast.Attribute):
        parent = _get_func_path(node.value)
        return parent + (node.attr,)
    return ()


def _get_source(text: str) -> str:
    """Get source segment from AST node."""
    try:
        return ast.get_source_segment(text, ast.parse(""))  # type: ignore
    except Exception:
        return ""


def _node_source(source: str, node: ast.AST) -> str:
    """Extract source code for an AST node."""
    try:
        seg = ast.get_source_segment(source, node)
        if seg:
            return seg[:120]
    except Exception:
        pass
    return f"line {getattr(node, 'lineno', '?')}"


class _TaintVisitor(ast.NodeVisitor):
    """AST visitor that tracks taint from sources to sinks."""

    def __init__(self, source_code: str):
        self._source = source_code
        self._tainted: dict[str, tuple[str, int, str]] = {}  # var -> (source_type, line, code)
        self._findings: list[DataflowFinding] = []

    @property
    def findings(self) -> list[DataflowFinding]:
        return self._findings

    def _mark_tainted(self, name: str, source_type: str, line: int, code: str):
        self._tainted[name] = (source_type, line, code)

    def _is_tainted(self, node: ast.expr) -> Optional[tuple[str, int, str, list[str]]]:
        """Check if an expression is tainted. Returns (source_type, line, code, chain) or None."""
        if isinstance(node, ast.Name) and node.id in self._tainted:
            st, sl, sc = self._tainted[node.id]
            return (st, sl, sc, [node.id])

        if isinstance(node, ast.Subscript):
            val_taint = self._is_tainted(node.value)
            if val_taint:
                return val_taint

        # String formatting: f"...{tainted}..."
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    t = self._is_tainted(value.value)
                    if t:
                        return t

        # BinOp (string concat, % formatting)
        if isinstance(node, ast.BinOp):
            for operand in (node.left, node.right):
                t = self._is_tainted(operand)
                if t:
                    return t

        # Container: list, tuple, dict, set
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for elt in node.elts:
                t = self._is_tainted(elt)
                if t:
                    return t
        if isinstance(node, ast.Dict):
            for v in node.values:
                if v is not None:
                    t = self._is_tainted(v)
                    if t:
                        return t

        # Call with tainted arg or on tainted object → conservative: result tainted
        if isinstance(node, ast.Call):
            # Method call on tainted object: tainted_var.read(), tainted_var.decode()
            if isinstance(node.func, ast.Attribute):
                t = self._is_tainted(node.func.value)
                if t:
                    return t
            for arg in node.args:
                t = self._is_tainted(arg)
                if t:
                    return t
            for kw in node.keywords:
                t = self._is_tainted(kw.value)
                if t:
                    return t

        # Attribute access on tainted object
        if isinstance(node, ast.Attribute):
            t = self._is_tainted(node.value)
            if t:
                return t

        return None

    def _check_source(self, node: ast.Call) -> Optional[tuple[str, int, str]]:
        """Check if a call is a taint source. Returns (source_type, line, code) or None."""
        func_path = _get_func_path(node.func)

        # os.getenv(...) / os.environ.get(...)
        if func_path[-2:] in {("os", "getenv"), ("environ", "get")}:
            return ("env_access", node.lineno, _node_source(self._source, node))

        # os.environ[...] via subscript is handled in visit_Subscript

        # keyring.get_password(...)
        if func_path[-2:] in _CREDENTIAL_FUNCS:
            return ("credential_access", node.lineno, _node_source(self._source, node))

        # open(...) / Path(...).read_text() with sensitive path
        if func_path == ("open",) or (len(func_path) >= 1 and func_path[-1] in ("read_text", "read_bytes")):
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if _SENSITIVE_FILE_PATTERNS.search(arg.value):
                        return ("file_read", node.lineno, _node_source(self._source, node))
                # Wrapped calls: open(os.path.expanduser("~/.ssh/..."))
                if isinstance(arg, ast.Call):
                    for inner_arg in arg.args:
                        if isinstance(inner_arg, ast.Constant) and isinstance(inner_arg.value, str):
                            if _SENSITIVE_FILE_PATTERNS.search(inner_arg.value):
                                return ("file_read", node.lineno, _node_source(self._source, node))
            for kw in node.keywords:
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    if _SENSITIVE_FILE_PATTERNS.search(kw.value.value):
                        return ("file_read", node.lineno, _node_source(self._source, node))

        # open("sensitive").read() — method call on open()
        if (isinstance(node.func, ast.Attribute)
                and node.func.attr in ("read", "readlines", "readline")
                and isinstance(node.func.value, ast.Call)):
            inner_path = _get_func_path(node.func.value.func)
            if inner_path == ("open",):
                for arg in node.func.value.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        if _SENSITIVE_FILE_PATTERNS.search(arg.value):
                            return ("file_read", node.lineno, _node_source(self._source, node))
                    # Wrapped: open(os.path.expanduser("~/.ssh/...")).read()
                    if isinstance(arg, ast.Call):
                        for inner_arg in arg.args:
                            if isinstance(inner_arg, ast.Constant) and isinstance(inner_arg.value, str):
                                if _SENSITIVE_FILE_PATTERNS.search(inner_arg.value):
                                    return ("file_read", node.lineno, _node_source(self._source, node))

        # Path("sensitive").read_text() / .read_bytes() — check constructor args
        if (isinstance(node.func, ast.Attribute)
                and node.func.attr in ("read_text", "read_bytes")
                and isinstance(node.func.value, ast.Call)):
            for arg in node.func.value.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if _SENSITIVE_FILE_PATTERNS.search(arg.value):
                        return ("file_read", node.lineno, _node_source(self._source, node))

        # subprocess.run(["cat", "/etc/passwd"]) — reading sensitive files
        if func_path[-2:] in _EXEC_SINKS or func_path[-1:] == ("run",):
            for arg in node.args:
                if isinstance(arg, ast.List):
                    for elt in arg.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            if _SENSITIVE_FILE_PATTERNS.search(elt.value):
                                return ("file_read", node.lineno, _node_source(self._source, node))

        return None

    def _check_sink(self, node: ast.Call) -> Optional[tuple[str, int, str]]:
        """Check if a call is a taint sink. Returns (sink_type, line, code) or None."""
        func_path = _get_func_path(node.func)

        # HTTP sinks
        if len(func_path) >= 2 and func_path[-2:] in _HTTP_SINKS:
            return ("http_send", node.lineno, _node_source(self._source, node))
        if len(func_path) >= 3 and func_path[-3:] in _HTTP_SINKS:
            return ("http_send", node.lineno, _node_source(self._source, node))
        # fetch(...) — common in polyglot patterns
        if func_path == ("fetch",):
            return ("http_send", node.lineno, _node_source(self._source, node))

        # Exec sinks
        if func_path[-2:] in _EXEC_SINKS:
            return ("exec_call", node.lineno, _node_source(self._source, node))
        if len(func_path) == 1 and func_path[0] in _BUILTIN_SINKS:
            return ("exec_call", node.lineno, _node_source(self._source, node))

        # Socket sinks
        if func_path[-2:] in _SOCKET_SINKS:
            return ("socket_send", node.lineno, _node_source(self._source, node))

        return None

    def _check_subscript_source(self, node: ast.Subscript) -> Optional[tuple[str, int, str]]:
        """Check if a subscript is os.environ[...] access."""
        if isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Name):
            if node.value.value.id == "os" and node.value.attr == "environ":
                return ("env_access", node.lineno, _node_source(self._source, node))
        return None

    def visit_Assign(self, node: ast.Assign):
        """Track taint through assignments."""
        # Check if RHS is a source call
        if isinstance(node.value, ast.Call):
            source = self._check_source(node.value)
            if source:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self._mark_tainted(target.id, *source)

        # Check if RHS is os.environ[...] subscript
        if isinstance(node.value, ast.Subscript):
            source = self._check_subscript_source(node.value)
            if source:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self._mark_tainted(target.id, *source)

        # Propagate taint through assignment
        taint = self._is_tainted(node.value)
        if taint:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    st, sl, sc, chain = taint
                    self._tainted[target.id] = (st, sl, sc)

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript):
        """Track os.environ[...] access."""
        if isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Name):
            if node.value.value.id == "os" and node.value.attr == "environ":
                # This is a source — mark parent assignment
                # Handled when used as RHS of assignment
                pass
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Check each call as potential sink with tainted args."""
        sink = self._check_sink(node)
        if sink:
            # Check if any argument is tainted
            all_args = list(node.args) + [kw.value for kw in node.keywords]
            for arg in all_args:
                taint = self._is_tainted(arg)
                if taint:
                    st, sl, sc, chain = taint
                    sink_type, sink_line, sink_code = sink
                    self._findings.append(DataflowFinding(
                        source_type=st,
                        source_line=sl,
                        source_code=sc,
                        sink_type=sink_type,
                        sink_line=sink_line,
                        sink_code=sink_code,
                        taint_chain=chain,
                    ))
                    break  # One finding per sink call

        # Also check if this call is a source (for non-assignment expressions)
        source = self._check_source(node)
        if source:
            # If used directly in a sink context, already handled above
            pass

        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        """Track taint through augmented assignments (+=, etc.)."""
        if isinstance(node.target, ast.Name):
            taint = self._is_tainted(node.value)
            if taint:
                st, sl, sc, chain = taint
                self._tainted[node.target.id] = (st, sl, sc)
        self.generic_visit(node)


# ═══════════════════════════════════════════════════════════════════════
# JS/TS REGEX FALLBACK
# ═══════════════════════════════════════════════════════════════════════

_JS_SOURCE_PATTERN = re.compile(
    r"process\.env\.[A-Z_]+|"
    r"process\.env\[",
    re.MULTILINE,
)

_JS_SINK_PATTERN = re.compile(
    r"fetch\s*\(|"
    r"axios\.\w+\s*\(|"
    r"\.post\s*\(|"
    r"\.get\s*\(|"
    r"\.put\s*\(",
    re.MULTILINE,
)


def _analyze_js_fallback(source: str, filename: str) -> list[DataflowFinding]:
    """Regex-based heuristic for JS/TS files — not full AST."""
    findings = []
    source_matches = list(_JS_SOURCE_PATTERN.finditer(source))
    sink_matches = list(_JS_SINK_PATTERN.finditer(source))

    if source_matches and sink_matches:
        # Simple line-correlation heuristic: if both exist in the same file,
        # flag it (conservative — may produce false positives)
        src = source_matches[0]
        snk = sink_matches[0]
        src_line = source[:src.start()].count("\n") + 1
        snk_line = source[:snk.start()].count("\n") + 1
        findings.append(DataflowFinding(
            source_type="env_access",
            source_line=src_line,
            source_code=src.group(0),
            sink_type="http_send",
            sink_line=snk_line,
            sink_code=snk.group(0),
            taint_chain=["(js-heuristic)"],
        ))
    return findings


# ═══════════════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════════════

class DataflowAnalyzer:
    """AST-based source→sink taint analysis for Python files.

    3-pass approach:
    1. Collect sources (credential/sensitive data access)
    2. Propagate taint through assignments, calls, returns
    3. Check if tainted data reaches sinks (network/exec)
    """

    def analyze(self, source: str, filename: str = "<unknown>") -> list[DataflowFinding]:
        """Analyze Python source code for dataflow issues.

        Falls back to regex for JS/TS files.
        """
        # JS/TS fallback
        if filename.endswith((".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx")):
            return _analyze_js_fallback(source, filename)

        try:
            tree = ast.parse(source, filename=filename)
        except SyntaxError:
            return []

        visitor = _TaintVisitor(source)
        visitor.visit(tree)
        return visitor.findings

    def analyze_file(self, path: Path) -> list[DataflowFinding]:
        """Analyze a file for dataflow issues."""
        path = Path(path)
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        return self.analyze(source, filename=str(path))
