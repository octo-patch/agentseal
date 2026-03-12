"""Tests for agentseal.mcp_runtime — MCP runtime connection engine."""

import asyncio
import json
import hashlib
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest

from agentseal.mcp_runtime import (
    # Data models
    MCPToolSnapshot,
    MCPPromptSnapshot,
    MCPResourceSnapshot,
    MCPServerSnapshot,
    MCPConnectionError,
    MCPProtocolError,
    # JSON-RPC helpers
    _make_request,
    _make_notification,
    _parse_jsonrpc,
    _extract_result,
    # Builders
    _build_tool_snapshot,
    _build_prompt_snapshot,
    _build_resource_snapshot,
    compute_tool_hash,
    _truncate_description,
    # Env
    sanitize_env,
    # SSE
    _parse_sse_stream,
    _SSEEvent,
    # Package
    parse_package_specifier,
    _is_safe_package_name,
    # Transport detection
    _detect_transport,
    _build_http_headers,
    # High-level
    connect_stdio,
    connect_http,
    scan_server,
    scan_servers,
    # Constants
    MAX_DESCRIPTION_BYTES,
    MAX_LINE_BYTES,
    MAX_TOOLS_PER_SERVER,
)


# ═══════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _jsonrpc_response(result: dict, req_id: int = 1) -> bytes:
    """Build a JSON-RPC success response as bytes with newline."""
    return json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result}).encode() + b"\n"


def _jsonrpc_error(code: int, message: str, req_id: int = 1) -> bytes:
    return json.dumps({
        "jsonrpc": "2.0", "id": req_id,
        "error": {"code": code, "message": message},
    }).encode() + b"\n"


def _jsonrpc_notification(method: str, params: dict | None = None) -> bytes:
    msg = {"jsonrpc": "2.0", "method": method}
    if params:
        msg["params"] = params
    return json.dumps(msg).encode() + b"\n"


def _init_response(
    tools: bool = True,
    prompts: bool = False,
    resources: bool = False,
    server_name: str = "test-server",
    req_id: int = 1,
) -> bytes:
    caps = {}
    if tools:
        caps["tools"] = {"listChanged": True}
    if prompts:
        caps["prompts"] = {"listChanged": True}
    if resources:
        caps["resources"] = {"listChanged": True, "subscribe": True}
    return _jsonrpc_response({
        "protocolVersion": "2025-03-26",
        "capabilities": caps,
        "serverInfo": {"name": server_name, "version": "1.0.0"},
        "instructions": "Test server instructions",
    }, req_id)


def _tools_response(tools: list[dict], req_id: int = 2, cursor: str | None = None) -> bytes:
    result: dict = {"tools": tools}
    if cursor:
        result["nextCursor"] = cursor
    return _jsonrpc_response(result, req_id)


# ═══════════════════════════════════════════════════════════════════════
# JSON-RPC HELPERS
# ═══════════════════════════════════════════════════════════════════════

class TestMakeRequest:
    def test_basic_request(self):
        data = _make_request("tools/list", None, 1)
        msg = json.loads(data)
        assert msg["jsonrpc"] == "2.0"
        assert msg["id"] == 1
        assert msg["method"] == "tools/list"
        assert "params" not in msg

    def test_request_with_params(self):
        data = _make_request("initialize", {"protocolVersion": "2025-03-26"}, 5)
        msg = json.loads(data)
        assert msg["id"] == 5
        assert msg["params"]["protocolVersion"] == "2025-03-26"

    def test_request_ends_with_newline(self):
        data = _make_request("test", None, 1)
        assert data.endswith(b"\n")
        # No embedded newlines in the JSON itself
        assert b"\n" not in data[:-1]


class TestMakeNotification:
    def test_notification_has_no_id(self):
        data = _make_notification("notifications/initialized")
        msg = json.loads(data)
        assert "id" not in msg
        assert msg["method"] == "notifications/initialized"

    def test_notification_ends_with_newline(self):
        data = _make_notification("test")
        assert data.endswith(b"\n")


class TestParseJsonrpc:
    def test_valid_response(self):
        msg = _parse_jsonrpc(b'{"jsonrpc":"2.0","id":1,"result":{}}')
        assert msg["id"] == 1

    def test_invalid_json(self):
        with pytest.raises(MCPProtocolError, match="Invalid JSON"):
            _parse_jsonrpc(b"not json")

    def test_non_object(self):
        with pytest.raises(MCPProtocolError, match="Expected JSON object"):
            _parse_jsonrpc(b"[1, 2, 3]")

    def test_string_input(self):
        msg = _parse_jsonrpc('{"jsonrpc":"2.0","id":1,"result":{}}')
        assert msg["id"] == 1

    def test_empty_bytes(self):
        with pytest.raises(MCPProtocolError):
            _parse_jsonrpc(b"")


class TestExtractResult:
    def test_success(self):
        msg = {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}
        result = _extract_result(msg, 1)
        assert result == {"tools": []}

    def test_error_response(self):
        msg = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "Method not found"}}
        with pytest.raises(MCPProtocolError, match="Method not found"):
            _extract_result(msg, 1)

    def test_id_mismatch(self):
        msg = {"jsonrpc": "2.0", "id": 99, "result": {}}
        with pytest.raises(MCPProtocolError, match="ID mismatch"):
            _extract_result(msg, 1)

    def test_missing_result_returns_empty(self):
        msg = {"jsonrpc": "2.0", "id": 1}
        result = _extract_result(msg, 1)
        assert result == {}


# ═══════════════════════════════════════════════════════════════════════
# TOOL HASH
# ═══════════════════════════════════════════════════════════════════════

class TestComputeToolHash:
    def test_deterministic(self):
        h1 = compute_tool_hash("add", "Add two numbers", {"type": "object"})
        h2 = compute_tool_hash("add", "Add two numbers", {"type": "object"})
        assert h1 == h2

    def test_different_name(self):
        h1 = compute_tool_hash("add", "desc", {})
        h2 = compute_tool_hash("subtract", "desc", {})
        assert h1 != h2

    def test_different_description(self):
        h1 = compute_tool_hash("add", "desc1", {})
        h2 = compute_tool_hash("add", "desc2", {})
        assert h1 != h2

    def test_different_schema(self):
        h1 = compute_tool_hash("add", "desc", {"type": "object"})
        h2 = compute_tool_hash("add", "desc", {"type": "string"})
        assert h1 != h2

    def test_schema_key_order_independent(self):
        h1 = compute_tool_hash("add", "desc", {"a": 1, "b": 2})
        h2 = compute_tool_hash("add", "desc", {"b": 2, "a": 1})
        assert h1 == h2

    def test_returns_hex_string(self):
        h = compute_tool_hash("add", "desc", {})
        assert len(h) == 64  # SHA256 hex
        assert all(c in "0123456789abcdef" for c in h)


# ═══════════════════════════════════════════════════════════════════════
# DESCRIPTION TRUNCATION
# ═══════════════════════════════════════════════════════════════════════

class TestTruncateDescription:
    def test_short_text_unchanged(self):
        assert _truncate_description("hello") == "hello"

    def test_long_text_truncated(self):
        long_text = "x" * (MAX_DESCRIPTION_BYTES + 100)
        result = _truncate_description(long_text)
        assert len(result.encode("utf-8")) <= MAX_DESCRIPTION_BYTES

    def test_unicode_safe_truncation(self):
        # Multibyte chars should not be split
        text = "日本語" * 20000
        result = _truncate_description(text)
        # Should be valid UTF-8
        result.encode("utf-8")
        assert len(result.encode("utf-8")) <= MAX_DESCRIPTION_BYTES


# ═══════════════════════════════════════════════════════════════════════
# SNAPSHOT BUILDERS
# ═══════════════════════════════════════════════════════════════════════

class TestBuildToolSnapshot:
    def test_basic(self):
        raw = {
            "name": "add",
            "description": "Add two numbers",
            "inputSchema": {"type": "object", "properties": {"a": {}, "b": {}}},
            "annotations": {"readOnlyHint": True},
        }
        tool = _build_tool_snapshot(raw)
        assert tool.name == "add"
        assert tool.description == "Add two numbers"
        assert tool.input_schema == raw["inputSchema"]
        assert tool.annotations == {"readOnlyHint": True}
        assert len(tool.signature_hash) == 64

    def test_missing_fields(self):
        raw = {"name": "test"}
        tool = _build_tool_snapshot(raw)
        assert tool.name == "test"
        assert tool.description == ""
        assert tool.input_schema == {}
        assert tool.annotations == {}

    def test_invalid_schema_type(self):
        raw = {"name": "test", "inputSchema": "not a dict"}
        tool = _build_tool_snapshot(raw)
        assert tool.input_schema == {}

    def test_invalid_annotations_type(self):
        raw = {"name": "test", "annotations": [1, 2]}
        tool = _build_tool_snapshot(raw)
        assert tool.annotations == {}

    def test_to_dict(self):
        raw = {"name": "add", "description": "desc", "inputSchema": {}, "annotations": {}}
        tool = _build_tool_snapshot(raw)
        d = tool.to_dict()
        assert d["name"] == "add"
        assert "signature_hash" in d


class TestBuildPromptSnapshot:
    def test_basic(self):
        raw = {
            "name": "greet",
            "description": "Greet a user",
            "arguments": [{"name": "user", "required": True}],
        }
        prompt = _build_prompt_snapshot(raw)
        assert prompt.name == "greet"
        assert len(prompt.arguments) == 1

    def test_missing_arguments(self):
        raw = {"name": "test"}
        prompt = _build_prompt_snapshot(raw)
        assert prompt.arguments == []

    def test_invalid_arguments_type(self):
        raw = {"name": "test", "arguments": "not a list"}
        prompt = _build_prompt_snapshot(raw)
        assert prompt.arguments == []


class TestBuildResourceSnapshot:
    def test_basic(self):
        raw = {
            "uri": "file:///data/test.txt",
            "name": "test.txt",
            "description": "A test file",
            "mimeType": "text/plain",
        }
        resource = _build_resource_snapshot(raw)
        assert resource.uri == "file:///data/test.txt"
        assert resource.mime_type == "text/plain"


class TestMCPServerSnapshot:
    def test_tools_hash_empty(self):
        snapshot = MCPServerSnapshot(
            server_name="test", server_version="", protocol_version="",
            instructions="", capabilities={}, tools=[], prompts=[],
            resources=[], connected_at="", connection_duration_ms=0.0,
        )
        assert snapshot.tools_hash == ""

    def test_tools_hash_deterministic(self):
        tool1 = _build_tool_snapshot({"name": "a", "description": "d1"})
        tool2 = _build_tool_snapshot({"name": "b", "description": "d2"})
        s1 = MCPServerSnapshot(
            server_name="test", server_version="", protocol_version="",
            instructions="", capabilities={}, tools=[tool1, tool2], prompts=[],
            resources=[], connected_at="", connection_duration_ms=0.0,
        )
        s2 = MCPServerSnapshot(
            server_name="test", server_version="", protocol_version="",
            instructions="", capabilities={}, tools=[tool2, tool1], prompts=[],
            resources=[], connected_at="", connection_duration_ms=0.0,
        )
        # Order-independent
        assert s1.tools_hash == s2.tools_hash

    def test_to_dict(self):
        snapshot = MCPServerSnapshot(
            server_name="test", server_version="1.0", protocol_version="2025-03-26",
            instructions="", capabilities={"tools": {}}, tools=[], prompts=[],
            resources=[], connected_at="2026-01-01T00:00:00Z", connection_duration_ms=100.0,
        )
        d = snapshot.to_dict()
        assert d["server_name"] == "test"
        assert d["server_version"] == "1.0"


# ═══════════════════════════════════════════════════════════════════════
# ENVIRONMENT SANITIZATION
# ═══════════════════════════════════════════════════════════════════════

class TestSanitizeEnv:
    def test_minimal_env_has_path(self):
        env = sanitize_env(None)
        assert "PATH" in env

    def test_server_env_added(self):
        env = sanitize_env({"MY_KEY": "my_value"})
        assert env["MY_KEY"] == "my_value"

    def test_non_string_keys_skipped(self):
        env = sanitize_env({123: "value", "OK": "yes"})
        assert "OK" in env
        assert 123 not in env

    def test_non_string_values_skipped(self):
        env = sanitize_env({"KEY": 123, "OK": "yes"})
        assert "OK" in env
        assert "KEY" not in env

    def test_server_env_overrides_base(self):
        env = sanitize_env({"PATH": "/custom/path"})
        assert env["PATH"] == "/custom/path"


# ═══════════════════════════════════════════════════════════════════════
# SSE PARSER
# ═══════════════════════════════════════════════════════════════════════

class TestSSEParser:
    def test_single_event(self):
        text = "data: hello\n\n"
        events = _parse_sse_stream(text)
        assert len(events) == 1
        assert events[0].data == "hello"
        assert events[0].event == "message"

    def test_multiline_data(self):
        text = "data: line1\ndata: line2\n\n"
        events = _parse_sse_stream(text)
        assert len(events) == 1
        assert events[0].data == "line1\nline2"

    def test_custom_event_type(self):
        text = "event: custom\ndata: payload\n\n"
        events = _parse_sse_stream(text)
        assert events[0].event == "custom"

    def test_comment_ignored(self):
        text = ": this is a comment\ndata: real data\n\n"
        events = _parse_sse_stream(text)
        assert len(events) == 1
        assert events[0].data == "real data"

    def test_multiple_events(self):
        text = "data: first\n\ndata: second\n\n"
        events = _parse_sse_stream(text)
        assert len(events) == 2
        assert events[0].data == "first"
        assert events[1].data == "second"

    def test_empty_stream(self):
        events = _parse_sse_stream("")
        assert events == []

    def test_json_data(self):
        msg = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})
        text = f"data: {msg}\n\n"
        events = _parse_sse_stream(text)
        parsed = json.loads(events[0].data)
        assert parsed["id"] == 1

    def test_crlf_line_endings(self):
        text = "data: hello\r\n\r\n"
        events = _parse_sse_stream(text)
        assert len(events) == 1
        assert events[0].data == "hello"

    def test_event_id(self):
        text = "id: 42\ndata: hello\n\n"
        events = _parse_sse_stream(text)
        assert events[0].id == "42"

    def test_leading_space_stripped(self):
        text = "data: hello world\n\n"
        events = _parse_sse_stream(text)
        assert events[0].data == "hello world"

    def test_no_space_after_colon(self):
        text = "data:nospace\n\n"
        events = _parse_sse_stream(text)
        assert events[0].data == "nospace"


# ═══════════════════════════════════════════════════════════════════════
# PACKAGE SPECIFIER
# ═══════════════════════════════════════════════════════════════════════

class TestParsePackageSpecifier:
    def test_pypi(self):
        result = parse_package_specifier("pypi:mcp-server-filesystem")
        assert result == ("uvx", ["mcp-server-filesystem"])

    def test_npm(self):
        result = parse_package_specifier("npm:@modelcontextprotocol/server-filesystem")
        assert result == ("npx", ["-y", "@modelcontextprotocol/server-filesystem"])

    def test_unknown_prefix(self):
        assert parse_package_specifier("docker:myimage") is None

    def test_empty_package(self):
        assert parse_package_specifier("pypi:") is None

    def test_whitespace_stripped(self):
        result = parse_package_specifier("  pypi:test-package  ")
        assert result == ("uvx", ["test-package"])


class TestIsSafePackageName:
    def test_simple_name(self):
        assert _is_safe_package_name("my-package") is True

    def test_scoped_npm(self):
        assert _is_safe_package_name("@org/package") is True

    def test_shell_injection(self):
        assert _is_safe_package_name("pkg; rm -rf /") is False

    def test_path_traversal(self):
        assert _is_safe_package_name("../../etc/passwd") is False

    def test_empty(self):
        assert _is_safe_package_name("") is False

    def test_too_long(self):
        assert _is_safe_package_name("a" * 201) is False

    def test_backtick(self):
        assert _is_safe_package_name("`whoami`") is False

    def test_dollar_sign(self):
        assert _is_safe_package_name("$(evil)") is False

    def test_pipe(self):
        assert _is_safe_package_name("pkg|cat /etc/passwd") is False

    def test_ampersand(self):
        assert _is_safe_package_name("pkg&&evil") is False

    def test_dotdot_traversal(self):
        assert _is_safe_package_name("@org/../../etc/passwd") is False

    def test_dotdot_simple(self):
        assert _is_safe_package_name("a..b") is False

    def test_single_dot_ok(self):
        assert _is_safe_package_name("my.package") is True


# ═══════════════════════════════════════════════════════════════════════
# STDIO CONNECTION (with mocked subprocess)
# ═══════════════════════════════════════════════════════════════════════

class TestConnectStdio:
    """Tests for connect_stdio using mocked subprocess."""

    def test_successful_connection(self):
        """Full happy path: initialize → list_tools → snapshot."""
        async def _run():
            init_resp = _init_response(tools=True, req_id=1)
            tools_resp = _tools_response([
                {"name": "add", "description": "Add numbers", "inputSchema": {"type": "object"}},
            ], req_id=2)

            responses = [init_resp, tools_resp]
            response_iter = iter(responses)

            mock_proc = AsyncMock()
            mock_proc.returncode = None
            mock_proc.stdin = AsyncMock()
            mock_proc.stdin.is_closing.return_value = False
            mock_proc.stderr = AsyncMock()

            async def mock_readline():
                try:
                    return next(response_iter)
                except StopIteration:
                    return b""

            mock_proc.stdout = AsyncMock()
            mock_proc.stdout.readline = mock_readline

            async def mock_wait():
                mock_proc.returncode = 0
                return 0
            mock_proc.wait = mock_wait
            mock_proc.terminate = MagicMock()
            mock_proc.kill = MagicMock()

            with patch("agentseal.mcp_runtime.asyncio.create_subprocess_exec", return_value=mock_proc):
                return await connect_stdio("node", ["server.js"], server_name="test-server")

        result = asyncio.run(_run())
        assert isinstance(result, MCPServerSnapshot)
        assert result.server_name == "test-server"
        assert result.server_version == "1.0.0"
        assert result.protocol_version == "2025-03-26"
        assert result.instructions == "Test server instructions"
        assert len(result.tools) == 1
        assert result.tools[0].name == "add"
        assert result.tools[0].description == "Add numbers"

    def test_command_not_found(self):
        async def _run():
            with patch(
                "agentseal.mcp_runtime.asyncio.create_subprocess_exec",
                side_effect=FileNotFoundError("not found"),
            ):
                return await connect_stdio("nonexistent_cmd", [])

        result = asyncio.run(_run())
        assert isinstance(result, MCPConnectionError)
        assert result.error_type == "missing_binary"

    def test_permission_denied(self):
        async def _run():
            with patch(
                "agentseal.mcp_runtime.asyncio.create_subprocess_exec",
                side_effect=PermissionError("denied"),
            ):
                return await connect_stdio("restricted_cmd", [])

        result = asyncio.run(_run())
        assert isinstance(result, MCPConnectionError)
        assert result.error_type == "spawn_failed"

    def test_server_crash_mid_session(self):
        """Server closes stdout before we get tools response."""
        async def _run():
            init_resp = _init_response(tools=True, req_id=1)
            call_count = [0]

            async def mock_readline():
                call_count[0] += 1
                if call_count[0] == 1:
                    return init_resp
                return b""  # EOF — server crashed

            mock_proc = AsyncMock()
            mock_proc.returncode = None
            mock_proc.stdin = AsyncMock()
            mock_proc.stdin.is_closing.return_value = False
            mock_proc.stderr = AsyncMock()
            mock_proc.stdout = AsyncMock()
            mock_proc.stdout.readline = mock_readline
            async def mock_wait():
                mock_proc.returncode = 1
                return 1
            mock_proc.wait = mock_wait
            mock_proc.terminate = MagicMock()
            mock_proc.kill = MagicMock()

            with patch("agentseal.mcp_runtime.asyncio.create_subprocess_exec", return_value=mock_proc):
                return await connect_stdio("node", ["server.js"], timeout=5.0)

        result = asyncio.run(_run())
        assert isinstance(result, MCPConnectionError)
        assert result.error_type == "crash"

    def test_server_error_response(self):
        """Server returns a JSON-RPC error during initialize."""
        async def _run():
            error_resp = _jsonrpc_error(-32601, "Method not found", req_id=1)

            mock_proc = AsyncMock()
            mock_proc.returncode = None
            mock_proc.stdin = AsyncMock()
            mock_proc.stdin.is_closing.return_value = False
            mock_proc.stderr = AsyncMock()
            mock_proc.stdout = AsyncMock()
            mock_proc.stdout.readline = AsyncMock(return_value=error_resp)
            async def mock_wait():
                mock_proc.returncode = 0
                return 0
            mock_proc.wait = mock_wait
            mock_proc.terminate = MagicMock()
            mock_proc.kill = MagicMock()

            with patch("agentseal.mcp_runtime.asyncio.create_subprocess_exec", return_value=mock_proc):
                return await connect_stdio("node", ["server.js"])

        result = asyncio.run(_run())
        assert isinstance(result, MCPConnectionError)
        assert result.error_type == "invalid"

    def test_no_tools_capability(self):
        """Server without tools capability → empty tools list."""
        async def _run():
            init_resp = _init_response(tools=False, req_id=1)

            mock_proc = AsyncMock()
            mock_proc.returncode = None
            mock_proc.stdin = AsyncMock()
            mock_proc.stdin.is_closing.return_value = False
            mock_proc.stderr = AsyncMock()
            mock_proc.stdout = AsyncMock()
            mock_proc.stdout.readline = AsyncMock(return_value=init_resp)
            async def mock_wait():
                mock_proc.returncode = 0
                return 0
            mock_proc.wait = mock_wait
            mock_proc.terminate = MagicMock()
            mock_proc.kill = MagicMock()

            with patch("agentseal.mcp_runtime.asyncio.create_subprocess_exec", return_value=mock_proc):
                return await connect_stdio("node", ["server.js"])

        result = asyncio.run(_run())
        assert isinstance(result, MCPServerSnapshot)
        assert result.tools == []

    def test_notifications_skipped(self):
        """Server sends notifications between responses — they should be skipped."""
        async def _run():
            init_resp = _init_response(tools=True, req_id=1)
            notification = _jsonrpc_notification("notifications/tools/list_changed")
            tools_resp = _tools_response([
                {"name": "test", "description": "Test tool"},
            ], req_id=2)

            responses = [init_resp, notification, tools_resp]
            response_iter = iter(responses)

            mock_proc = AsyncMock()
            mock_proc.returncode = None
            mock_proc.stdin = AsyncMock()
            mock_proc.stdin.is_closing.return_value = False
            mock_proc.stderr = AsyncMock()

            async def mock_readline():
                try:
                    return next(response_iter)
                except StopIteration:
                    return b""

            mock_proc.stdout = AsyncMock()
            mock_proc.stdout.readline = mock_readline
            async def mock_wait():
                mock_proc.returncode = 0
                return 0
            mock_proc.wait = mock_wait
            mock_proc.terminate = MagicMock()
            mock_proc.kill = MagicMock()

            with patch("agentseal.mcp_runtime.asyncio.create_subprocess_exec", return_value=mock_proc):
                return await connect_stdio("node", ["server.js"])

        result = asyncio.run(_run())
        assert isinstance(result, MCPServerSnapshot)
        assert len(result.tools) == 1
        assert result.tools[0].name == "test"

    def test_with_prompts_and_resources(self):
        """Server with tools, prompts, and resources."""
        async def _run():
            init_resp = _init_response(tools=True, prompts=True, resources=True, req_id=1)
            tools_resp = _tools_response([{"name": "t1", "description": "tool"}], req_id=2)
            prompts_resp = _jsonrpc_response({
                "prompts": [{"name": "p1", "description": "prompt", "arguments": []}],
            }, req_id=3)
            resources_resp = _jsonrpc_response({
                "resources": [{"uri": "file:///test", "name": "r1", "description": "resource"}],
            }, req_id=4)

            responses = [init_resp, tools_resp, prompts_resp, resources_resp]
            response_iter = iter(responses)

            mock_proc = AsyncMock()
            mock_proc.returncode = None
            mock_proc.stdin = AsyncMock()
            mock_proc.stdin.is_closing.return_value = False
            mock_proc.stderr = AsyncMock()

            async def mock_readline():
                try:
                    return next(response_iter)
                except StopIteration:
                    return b""

            mock_proc.stdout = AsyncMock()
            mock_proc.stdout.readline = mock_readline
            async def mock_wait():
                mock_proc.returncode = 0
                return 0
            mock_proc.wait = mock_wait
            mock_proc.terminate = MagicMock()
            mock_proc.kill = MagicMock()

            with patch("agentseal.mcp_runtime.asyncio.create_subprocess_exec", return_value=mock_proc):
                return await connect_stdio("node", ["server.js"])

        result = asyncio.run(_run())
        assert isinstance(result, MCPServerSnapshot)
        assert len(result.tools) == 1
        assert len(result.prompts) == 1
        assert len(result.resources) == 1
        assert result.prompts[0].name == "p1"
        assert result.resources[0].uri == "file:///test"


# ═══════════════════════════════════════════════════════════════════════
# scan_server / scan_servers
# ═══════════════════════════════════════════════════════════════════════

class TestScanServer:
    def test_missing_command_and_url(self):
        async def _run():
            return await scan_server({"name": "test"})

        result = asyncio.run(_run())
        assert isinstance(result, MCPConnectionError)
        assert result.error_type == "invalid"
        assert "no command or url" in result.detail

    def test_delegates_to_connect_stdio(self):
        async def _run():
            server = {"name": "myserver", "command": "node", "args": ["srv.js"], "env": {"K": "V"}}
            mock_snapshot = MCPServerSnapshot(
                server_name="myserver", server_version="", protocol_version="",
                instructions="", capabilities={}, tools=[], prompts=[],
                resources=[], connected_at="", connection_duration_ms=0.0,
            )
            with patch("agentseal.mcp_runtime.connect_stdio", return_value=mock_snapshot) as mock_conn:
                result = await scan_server(server)
            mock_conn.assert_awaited_once()
            return result

        result = asyncio.run(_run())
        assert isinstance(result, MCPServerSnapshot)


class TestScanServers:
    def test_empty_list(self):
        result = asyncio.run(scan_servers([]))
        assert result == []

    def test_preserves_order(self):
        async def _run():
            s1 = MCPServerSnapshot(
                server_name="first", server_version="", protocol_version="",
                instructions="", capabilities={}, tools=[], prompts=[],
                resources=[], connected_at="", connection_duration_ms=0.0,
            )
            s2 = MCPConnectionError(server_name="second", error_type="timeout", detail="timeout")

            async def mock_scan(server, timeout=30.0):
                if server["name"] == "a":
                    return s1
                return s2

            with patch("agentseal.mcp_runtime.scan_server", side_effect=mock_scan):
                return await scan_servers([
                    {"name": "a", "command": "x", "args": []},
                    {"name": "b", "command": "x", "args": []},
                ])

        results = asyncio.run(_run())
        assert len(results) == 2
        assert isinstance(results[0], MCPServerSnapshot)
        assert isinstance(results[1], MCPConnectionError)


# ═══════════════════════════════════════════════════════════════════════
# PAGINATION
# ═══════════════════════════════════════════════════════════════════════

class TestPagination:
    def test_multi_page_tools(self):
        """Server returns tools across two pages with nextCursor."""
        async def _run():
            init_resp = _init_response(tools=True, req_id=1)
            page1 = _jsonrpc_response({
                "tools": [{"name": "t1", "description": "tool1"}],
                "nextCursor": "page2",
            }, req_id=2)
            page2 = _jsonrpc_response({
                "tools": [{"name": "t2", "description": "tool2"}],
            }, req_id=3)

            responses = [init_resp, page1, page2]
            response_iter = iter(responses)

            mock_proc = AsyncMock()
            mock_proc.returncode = None
            mock_proc.stdin = AsyncMock()
            mock_proc.stdin.is_closing.return_value = False
            mock_proc.stderr = AsyncMock()

            async def mock_readline():
                try:
                    return next(response_iter)
                except StopIteration:
                    return b""

            mock_proc.stdout = AsyncMock()
            mock_proc.stdout.readline = mock_readline
            async def mock_wait():
                mock_proc.returncode = 0
                return 0
            mock_proc.wait = mock_wait
            mock_proc.terminate = MagicMock()
            mock_proc.kill = MagicMock()

            with patch("agentseal.mcp_runtime.asyncio.create_subprocess_exec", return_value=mock_proc):
                return await connect_stdio("node", ["server.js"], server_name="paginated")

        result = asyncio.run(_run())
        assert isinstance(result, MCPServerSnapshot)
        assert len(result.tools) == 2
        assert result.tools[0].name == "t1"
        assert result.tools[1].name == "t2"


class TestTimeout:
    def test_timeout_returns_error(self):
        """Connection that times out returns MCPConnectionError."""
        async def _run():
            mock_proc = AsyncMock()
            mock_proc.returncode = None
            mock_proc.stdin = AsyncMock()
            mock_proc.stdin.is_closing.return_value = False
            mock_proc.stderr = AsyncMock()

            async def mock_readline():
                await asyncio.sleep(10)  # will be cancelled by timeout
                return b""

            mock_proc.stdout = AsyncMock()
            mock_proc.stdout.readline = mock_readline
            async def mock_wait():
                mock_proc.returncode = 0
                return 0
            mock_proc.wait = mock_wait
            mock_proc.terminate = MagicMock()
            mock_proc.kill = MagicMock()

            with patch("agentseal.mcp_runtime.asyncio.create_subprocess_exec", return_value=mock_proc):
                return await connect_stdio("node", ["server.js"], timeout=0.1)

        result = asyncio.run(_run())
        assert isinstance(result, MCPConnectionError)
        assert result.error_type == "timeout"


class TestScanServerArgs:
    def test_int_args_converted(self):
        """Integer args from JSON config should be converted to strings."""
        async def _run():
            server = {"name": "test", "command": "node", "args": ["server.js", 8080]}
            mock_snapshot = MCPServerSnapshot(
                server_name="test", server_version="", protocol_version="",
                instructions="", capabilities={}, tools=[], prompts=[],
                resources=[], connected_at="", connection_duration_ms=0.0,
            )
            with patch("agentseal.mcp_runtime.connect_stdio", return_value=mock_snapshot) as mock_conn:
                result = await scan_server(server)
            # Verify args were passed as strings
            call_args = mock_conn.call_args
            assert call_args[0][1] == ["server.js", "8080"]
            return result

        result = asyncio.run(_run())
        assert isinstance(result, MCPServerSnapshot)


# ═══════════════════════════════════════════════════════════════════════
# TRANSPORT DETECTION
# ═══════════════════════════════════════════════════════════════════════

class TestDetectTransport:
    def test_stdio_config(self):
        assert _detect_transport({"command": "node", "args": ["server.js"]}) == "stdio"

    def test_http_config(self):
        assert _detect_transport({"url": "https://api.example.com/mcp"}) == "http"

    def test_http_takes_priority(self):
        # If both url and command are present, url wins (HTTP)
        assert _detect_transport({"url": "https://x.com/mcp", "command": "node"}) == "http"

    def test_empty_config(self):
        assert _detect_transport({}) == "unknown"

    def test_empty_command(self):
        assert _detect_transport({"command": ""}) == "unknown"

    def test_empty_url(self):
        assert _detect_transport({"url": ""}) == "unknown"


class TestBuildHttpHeaders:
    def test_explicit_headers(self):
        server = {"headers": {"Authorization": "Bearer tok123", "X-Custom": "val"}}
        h = _build_http_headers(server)
        assert h["Authorization"] == "Bearer tok123"
        assert h["X-Custom"] == "val"

    def test_api_key_field(self):
        server = {"apiKey": "sk-abc123"}
        h = _build_http_headers(server)
        assert h["Authorization"] == "Bearer sk-abc123"

    def test_explicit_auth_header_wins_over_api_key(self):
        server = {"headers": {"Authorization": "Bearer explicit"}, "apiKey": "sk-other"}
        h = _build_http_headers(server)
        assert h["Authorization"] == "Bearer explicit"

    def test_env_auth_var(self):
        server = {"env": {"API_KEY": "mytoken123"}}
        h = _build_http_headers(server)
        assert h["Authorization"] == "Bearer mytoken123"

    def test_env_var_reference_skipped(self):
        """Env var references like ${VAR} should not be used as auth."""
        server = {"env": {"API_KEY": "${MY_SECRET}"}}
        h = _build_http_headers(server)
        assert "Authorization" not in h

    def test_empty_server(self):
        assert _build_http_headers({}) == {}

    def test_non_string_headers_skipped(self):
        server = {"headers": {"Good": "val", 123: "bad", "Also-bad": 456}}
        h = _build_http_headers(server)
        assert h == {"Good": "val"}


# ═══════════════════════════════════════════════════════════════════════
# CONNECT HTTP (mocked httpx)
# ═══════════════════════════════════════════════════════════════════════

def _mock_httpx_response(
    body: dict | str,
    status_code: int = 200,
    content_type: str = "application/json",
    headers: dict | None = None,
) -> MagicMock:
    """Build a mock httpx.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp_headers = {"content-type": content_type}
    if headers:
        resp_headers.update(headers)
    resp.headers = resp_headers
    if isinstance(body, dict):
        resp.text = json.dumps(body)
    else:
        resp.text = body
    return resp


def _make_http_mock_client(post_side_effect):
    """Create a mock httpx.AsyncClient with a given post side_effect."""
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(side_effect=post_side_effect)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    return mock_client


class TestConnectHttp:
    def test_successful_json_response(self):
        """HTTP server returns application/json responses."""
        async def _run():
            init_result = {
                "jsonrpc": "2.0", "id": 1,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "remote", "version": "2.0.0"},
                    "instructions": "Remote server",
                },
            }
            tools_result = {
                "jsonrpc": "2.0", "id": 2,
                "result": {"tools": [
                    {"name": "search", "description": "Search the web", "inputSchema": {"type": "object"}},
                ]},
            }

            def mock_post(url, content=None, headers=None):
                body = json.loads(content)
                if body.get("method") == "initialize":
                    return _mock_httpx_response(init_result)
                if body.get("method") == "notifications/initialized":
                    return _mock_httpx_response({}, status_code=200)
                if body.get("method") == "tools/list":
                    return _mock_httpx_response(tools_result)
                return _mock_httpx_response({}, status_code=404)

            mock_client = _make_http_mock_client(mock_post)
            with patch("agentseal.mcp_runtime.httpx.AsyncClient", return_value=mock_client):
                return await connect_http(
                    "https://api.example.com/mcp",
                    server_name="remote-server",
                )

        result = asyncio.run(_run())
        assert isinstance(result, MCPServerSnapshot)
        assert result.server_name == "remote-server"
        assert result.server_version == "2.0.0"
        assert len(result.tools) == 1
        assert result.tools[0].name == "search"

    def test_sse_response(self):
        """HTTP server returns text/event-stream response."""
        async def _run():
            init_json = json.dumps({
                "jsonrpc": "2.0", "id": 1,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "serverInfo": {"name": "sse-server", "version": "1.0"},
                },
            })
            sse_body = f"data: {init_json}\n\n"

            def mock_post(url, content=None, headers=None):
                body = json.loads(content)
                if body.get("method") == "initialize":
                    return _mock_httpx_response(sse_body, content_type="text/event-stream")
                return _mock_httpx_response({}, status_code=200)

            mock_client = _make_http_mock_client(mock_post)
            with patch("agentseal.mcp_runtime.httpx.AsyncClient", return_value=mock_client):
                return await connect_http("https://sse.example.com/mcp")

        result = asyncio.run(_run())
        assert isinstance(result, MCPServerSnapshot)
        assert result.server_name == "https://sse.example.com/mcp"
        assert result.server_version == "1.0"

    def test_auth_failure_401(self):
        """HTTP 401 returns auth error."""
        async def _run():
            def mock_post(url, content=None, headers=None):
                return _mock_httpx_response({}, status_code=401)

            mock_client = _make_http_mock_client(mock_post)
            with patch("agentseal.mcp_runtime.httpx.AsyncClient", return_value=mock_client):
                return await connect_http("https://protected.com/mcp")

        result = asyncio.run(_run())
        assert isinstance(result, MCPConnectionError)
        assert result.error_type == "auth"

    def test_auth_failure_403(self):
        """HTTP 403 returns auth error."""
        async def _run():
            def mock_post(url, content=None, headers=None):
                return _mock_httpx_response({}, status_code=403)

            mock_client = _make_http_mock_client(mock_post)
            with patch("agentseal.mcp_runtime.httpx.AsyncClient", return_value=mock_client):
                return await connect_http("https://forbidden.com/mcp")

        result = asyncio.run(_run())
        assert isinstance(result, MCPConnectionError)
        assert result.error_type == "auth"

    def test_404_returns_invalid(self):
        """HTTP 404 returns invalid error."""
        async def _run():
            def mock_post(url, content=None, headers=None):
                return _mock_httpx_response({}, status_code=404)

            mock_client = _make_http_mock_client(mock_post)
            with patch("agentseal.mcp_runtime.httpx.AsyncClient", return_value=mock_client):
                return await connect_http("https://noexist.com/mcp")

        result = asyncio.run(_run())
        assert isinstance(result, MCPConnectionError)
        assert result.error_type == "invalid"

    def test_session_id_tracking(self):
        """Server returns Mcp-Session-Id header, subsequent requests include it."""
        async def _run():
            captured_headers = []
            init_result = {
                "jsonrpc": "2.0", "id": 1,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "session-test", "version": "1.0"},
                },
            }
            tools_result = {
                "jsonrpc": "2.0", "id": 2,
                "result": {"tools": []},
            }

            def mock_post(url, content=None, headers=None):
                captured_headers.append(dict(headers) if headers else {})
                body = json.loads(content)
                if body.get("method") == "initialize":
                    return _mock_httpx_response(
                        init_result,
                        headers={"mcp-session-id": "sess-abc123"},
                    )
                if body.get("method") == "notifications/initialized":
                    return _mock_httpx_response({}, status_code=200)
                if body.get("method") == "tools/list":
                    return _mock_httpx_response(tools_result)
                return _mock_httpx_response({}, status_code=200)

            mock_client = _make_http_mock_client(mock_post)
            with patch("agentseal.mcp_runtime.httpx.AsyncClient", return_value=mock_client):
                result = await connect_http("https://api.example.com/mcp")

            # First request (initialize) has no session ID
            assert "Mcp-Session-Id" not in captured_headers[0]
            # Second request (notification) should include the session ID
            assert captured_headers[1].get("Mcp-Session-Id") == "sess-abc123"
            return result

        result = asyncio.run(_run())
        assert isinstance(result, MCPServerSnapshot)

    def test_auth_headers_passed(self):
        """Custom auth headers are passed to the server."""
        async def _run():
            captured_headers = []
            init_result = {
                "jsonrpc": "2.0", "id": 1,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "serverInfo": {"name": "auth-test", "version": "1.0"},
                },
            }

            def mock_post(url, content=None, headers=None):
                captured_headers.append(dict(headers) if headers else {})
                body = json.loads(content)
                if body.get("method") == "initialize":
                    return _mock_httpx_response(init_result)
                return _mock_httpx_response({}, status_code=200)

            mock_client = _make_http_mock_client(mock_post)
            with patch("agentseal.mcp_runtime.httpx.AsyncClient", return_value=mock_client):
                result = await connect_http(
                    "https://api.example.com/mcp",
                    headers={"Authorization": "Bearer sk-secret123"},
                )
            # Verify auth header was sent
            assert captured_headers[0].get("Authorization") == "Bearer sk-secret123"
            return result

        result = asyncio.run(_run())
        assert isinstance(result, MCPServerSnapshot)

    def test_oversized_response_rejected(self):
        """Response with Content-Length exceeding MAX_LINE_BYTES is rejected."""
        async def _run():
            def mock_post(url, content=None, headers=None):
                return _mock_httpx_response(
                    {},
                    headers={"content-length": str(MAX_LINE_BYTES + 1)},
                )

            mock_client = _make_http_mock_client(mock_post)
            with patch("agentseal.mcp_runtime.httpx.AsyncClient", return_value=mock_client):
                return await connect_http("https://evil.com/mcp")

        result = asyncio.run(_run())
        assert isinstance(result, MCPConnectionError)
        assert result.error_type == "invalid"
        assert "too large" in result.detail


# ═══════════════════════════════════════════════════════════════════════
# scan_server ROUTING (stdio vs HTTP)
# ═══════════════════════════════════════════════════════════════════════

class TestScanServerRouting:
    def test_routes_to_stdio(self):
        """Config with 'command' routes to connect_stdio."""
        async def _run():
            mock_snapshot = MCPServerSnapshot(
                server_name="stdio-srv", server_version="", protocol_version="",
                instructions="", capabilities={}, tools=[], prompts=[],
                resources=[], connected_at="", connection_duration_ms=0.0,
            )
            with patch("agentseal.mcp_runtime.connect_stdio", return_value=mock_snapshot) as mock_conn:
                result = await scan_server({"name": "srv", "command": "node", "args": ["s.js"]})
            mock_conn.assert_awaited_once()
            return result

        result = asyncio.run(_run())
        assert isinstance(result, MCPServerSnapshot)

    def test_routes_to_http(self):
        """Config with 'url' routes to connect_http."""
        async def _run():
            mock_snapshot = MCPServerSnapshot(
                server_name="http-srv", server_version="", protocol_version="",
                instructions="", capabilities={}, tools=[], prompts=[],
                resources=[], connected_at="", connection_duration_ms=0.0,
            )
            with patch("agentseal.mcp_runtime.connect_http", return_value=mock_snapshot) as mock_conn:
                result = await scan_server({"name": "srv", "url": "https://api.example.com/mcp"})
            mock_conn.assert_awaited_once()
            # Verify URL was passed
            call_args = mock_conn.call_args
            assert call_args[0][0] == "https://api.example.com/mcp"
            return result

        result = asyncio.run(_run())
        assert isinstance(result, MCPServerSnapshot)

    def test_http_with_api_key(self):
        """Config with 'url' and 'apiKey' passes auth header to connect_http."""
        async def _run():
            mock_snapshot = MCPServerSnapshot(
                server_name="auth-srv", server_version="", protocol_version="",
                instructions="", capabilities={}, tools=[], prompts=[],
                resources=[], connected_at="", connection_duration_ms=0.0,
            )
            with patch("agentseal.mcp_runtime.connect_http", return_value=mock_snapshot) as mock_conn:
                result = await scan_server({
                    "name": "srv",
                    "url": "https://api.example.com/mcp",
                    "apiKey": "sk-secret",
                })
            call_kwargs = mock_conn.call_args[1]
            assert call_kwargs["headers"]["Authorization"] == "Bearer sk-secret"
            return result

        result = asyncio.run(_run())
        assert isinstance(result, MCPServerSnapshot)

    def test_http_with_explicit_headers(self):
        """Config with 'url' and 'headers' passes them to connect_http."""
        async def _run():
            mock_snapshot = MCPServerSnapshot(
                server_name="hdr-srv", server_version="", protocol_version="",
                instructions="", capabilities={}, tools=[], prompts=[],
                resources=[], connected_at="", connection_duration_ms=0.0,
            )
            with patch("agentseal.mcp_runtime.connect_http", return_value=mock_snapshot) as mock_conn:
                result = await scan_server({
                    "name": "srv",
                    "url": "https://api.example.com/mcp",
                    "headers": {"Authorization": "Bearer tok", "X-Custom": "val"},
                })
            call_kwargs = mock_conn.call_args[1]
            assert call_kwargs["headers"]["Authorization"] == "Bearer tok"
            assert call_kwargs["headers"]["X-Custom"] == "val"
            return result

        result = asyncio.run(_run())
        assert isinstance(result, MCPServerSnapshot)

    def test_no_command_no_url(self):
        """Config with neither command nor url returns error."""
        async def _run():
            return await scan_server({"name": "broken"})

        result = asyncio.run(_run())
        assert isinstance(result, MCPConnectionError)
        assert result.error_type == "invalid"
        assert "no command or url" in result.detail


# ═══════════════════════════════════════════════════════════════════════
# MCPConnectionError
# ═══════════════════════════════════════════════════════════════════════

class TestMCPConnectionError:
    def test_to_dict(self):
        err = MCPConnectionError(server_name="s", error_type="timeout", detail="timed out")
        d = err.to_dict()
        assert d["server_name"] == "s"
        assert d["error_type"] == "timeout"
        assert d["detail"] == "timed out"
