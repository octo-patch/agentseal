# tests/test_llm_judge.py
"""Tests for LLM Judge — all LLM calls are mocked, no real API traffic."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agentseal.llm_judge import (
    LLMJudge,
    LLMJudgeResult,
    MAX_CONTENT_BYTES,
    _detect_provider,
    _parse_response,
)


# ═══════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _make_openai_response(content: str, total_tokens: int = 100):
    """Build a fake openai ChatCompletion response."""
    msg = SimpleNamespace(content=content)
    choice = SimpleNamespace(message=msg)
    usage = SimpleNamespace(total_tokens=total_tokens)
    return SimpleNamespace(choices=[choice], usage=usage)


def _make_mock_openai_module():
    """Build a mock openai module with exception classes and AsyncOpenAI."""
    mock_openai = MagicMock()
    mock_openai.AuthenticationError = type("AuthenticationError", (Exception,), {})
    mock_openai.RateLimitError = type("RateLimitError", (Exception,), {})
    return mock_openai


def _make_anthropic_response(content: str, input_tokens: int = 50, output_tokens: int = 50):
    """Build a fake anthropic Messages response."""
    block = SimpleNamespace(text=content)
    usage = SimpleNamespace(input_tokens=input_tokens, output_tokens=output_tokens)
    return SimpleNamespace(content=[block], usage=usage)


# ═══════════════════════════════════════════════════════════════════════
# PARSING TESTS
# ═══════════════════════════════════════════════════════════════════════

def test_parse_valid_json_response():
    raw = json.dumps({"verdict": "danger", "confidence": 0.95, "findings": [
        {"title": "Cred theft", "severity": "critical", "evidence": "curl", "reasoning": "exfil"}
    ]})
    result = _parse_response(raw, "gpt-4o", 42)
    assert result.verdict == "danger"
    assert result.confidence == 0.95
    assert len(result.findings) == 1
    assert result.findings[0]["title"] == "Cred theft"
    assert result.tokens_used == 42
    assert result.error is None


def test_parse_json_in_markdown_block():
    raw = "Here is my analysis:\n```json\n" + json.dumps({
        "verdict": "warning", "confidence": 0.7, "findings": []
    }) + "\n```\nDone."
    result = _parse_response(raw, "gpt-4o", 10)
    assert result.verdict == "warning"
    assert result.confidence == 0.7
    assert result.error is None


def test_parse_json_with_surrounding_text():
    raw = "I found issues. " + json.dumps({
        "verdict": "safe", "confidence": 0.9, "findings": []
    }) + " That's all."
    result = _parse_response(raw, "gpt-4o", 10)
    assert result.verdict == "safe"
    assert result.error is None


def test_parse_unparseable_response_returns_error():
    result = _parse_response("I cannot help with that.", "gpt-4o", 5)
    assert result.error is not None
    assert "Could not parse" in result.error


# ═══════════════════════════════════════════════════════════════════════
# NORMALISATION TESTS
# ═══════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("raw_verdict,expected", [
    ("SAFE", "safe"),
    ("Safe", "safe"),
    ("malicious", "danger"),
    ("suspicious", "warning"),
    ("DANGER", "danger"),
    ("WARNING", "warning"),
])
def test_verdict_normalization(raw_verdict, expected):
    raw = json.dumps({"verdict": raw_verdict, "confidence": 0.5, "findings": []})
    result = _parse_response(raw, "test", 0)
    assert result.verdict == expected


@pytest.mark.parametrize("raw_conf,expected", [
    (1.5, 1.0),
    (-0.1, 0.0),
    (0.5, 0.5),
    (0.0, 0.0),
    (1.0, 1.0),
])
def test_confidence_clamping(raw_conf, expected):
    raw = json.dumps({"verdict": "safe", "confidence": raw_conf, "findings": []})
    result = _parse_response(raw, "test", 0)
    assert result.confidence == expected


def test_missing_findings_defaults_empty():
    raw = json.dumps({"verdict": "safe", "confidence": 0.8})
    result = _parse_response(raw, "test", 0)
    assert result.findings == []


def test_malformed_findings_skipped():
    raw = json.dumps({
        "verdict": "warning",
        "confidence": 0.6,
        "findings": [
            {"title": "Good finding", "severity": "high", "evidence": "x", "reasoning": "y"},
            "not a dict",
            42,
            {"no_title": True},  # missing title -> skipped
        ],
    })
    result = _parse_response(raw, "test", 0)
    assert len(result.findings) == 1
    assert result.findings[0]["title"] == "Good finding"


# ═══════════════════════════════════════════════════════════════════════
# ASYNC BEHAVIOUR TESTS (use asyncio.run to avoid pytest-asyncio dep)
# ═══════════════════════════════════════════════════════════════════════

def test_timeout_returns_error():
    async def _run():
        judge = LLMJudge(model="gpt-4o", api_key="test-key")

        mock_openai = _make_mock_openai_module()
        mock_client_instance = MagicMock()
        mock_client_instance.chat.completions.create = AsyncMock(
            side_effect=asyncio.TimeoutError()
        )
        mock_openai.AsyncOpenAI.return_value = mock_client_instance

        with patch.dict("sys.modules", {"openai": mock_openai}):
            result = await judge.analyze_skill("some content", "SKILL.md")

        assert result.error is not None
        assert "timed out" in result.error.lower()

    asyncio.run(_run())


def test_empty_content_returns_safe():
    async def _run():
        judge = LLMJudge(model="gpt-4o", api_key="test-key")
        result = await judge.analyze_skill("", "empty.md")
        assert result.verdict == "safe"
        assert result.confidence == 1.0
        assert result.error is None

        result2 = await judge.analyze_skill("   \n  ", "whitespace.md")
        assert result2.verdict == "safe"

    asyncio.run(_run())


def test_token_tracking():
    async def _run():
        judge = LLMJudge(model="gpt-4o", api_key="test-key")
        fake_resp = _make_openai_response(
            json.dumps({"verdict": "safe", "confidence": 0.9, "findings": []}),
            total_tokens=237,
        )

        mock_openai = _make_mock_openai_module()
        mock_client_instance = MagicMock()
        mock_client_instance.chat.completions.create = AsyncMock(return_value=fake_resp)
        mock_openai.AsyncOpenAI.return_value = mock_client_instance

        with patch.dict("sys.modules", {"openai": mock_openai}):
            result = await judge.analyze_skill("test content", "SKILL.md")

        assert result.tokens_used == 237

    asyncio.run(_run())


def test_content_truncation():
    async def _run():
        judge = LLMJudge(model="gpt-4o", api_key="test-key")
        big_content = "A" * (MAX_CONTENT_BYTES + 1000)
        fake_resp = _make_openai_response(
            json.dumps({"verdict": "safe", "confidence": 1.0, "findings": []}),
            total_tokens=50,
        )

        mock_openai = _make_mock_openai_module()
        mock_client_instance = MagicMock()
        mock_create = AsyncMock(return_value=fake_resp)
        mock_client_instance.chat.completions.create = mock_create
        mock_openai.AsyncOpenAI.return_value = mock_client_instance

        with patch.dict("sys.modules", {"openai": mock_openai}):
            result = await judge.analyze_skill(big_content, "big.md")

        # Verify the content sent to the LLM was truncated
        call_args = mock_create.call_args
        user_content = call_args.kwargs["messages"][1]["content"]
        # The user message includes the filename header, so just check it's bounded
        assert len(user_content) < MAX_CONTENT_BYTES + 500
        assert result.error is None

    asyncio.run(_run())


def test_batch_analysis_respects_concurrency():
    async def _run():
        judge = LLMJudge(model="gpt-4o", api_key="test-key")
        max_concurrent = 0
        current_concurrent = 0
        lock = asyncio.Lock()

        async def tracking_analyze(content: str, filename: str) -> LLMJudgeResult:
            nonlocal max_concurrent, current_concurrent
            async with lock:
                current_concurrent += 1
                if current_concurrent > max_concurrent:
                    max_concurrent = current_concurrent
            await asyncio.sleep(0.05)  # simulate work
            async with lock:
                current_concurrent -= 1
            return LLMJudgeResult(verdict="safe", confidence=1.0, model="gpt-4o")

        judge.analyze_skill = tracking_analyze  # type: ignore[assignment]

        files = [(f"content {i}", f"file{i}.md") for i in range(10)]
        results = await judge.analyze_batch(files, concurrency=2)

        assert len(results) == 10
        assert max_concurrent <= 2

    asyncio.run(_run())


# ═══════════════════════════════════════════════════════════════════════
# PROVIDER ROUTING TESTS
# ═══════════════════════════════════════════════════════════════════════

def test_provider_routing_openai():
    assert _detect_provider("gpt-4o") == "openai"
    assert _detect_provider("gpt-4o-mini") == "openai"
    judge = LLMJudge(model="gpt-4o")
    assert judge.provider == "openai"


def test_provider_routing_anthropic():
    assert _detect_provider("claude-sonnet-4-5-20250929") == "anthropic"
    assert _detect_provider("claude-3-haiku-20240307") == "anthropic"
    judge = LLMJudge(model="claude-sonnet-4-5-20250929")
    assert judge.provider == "anthropic"


def test_provider_routing_ollama():
    assert _detect_provider("ollama/llama3.1") == "ollama"
    judge = LLMJudge(model="ollama/llama3.1:8b")
    assert judge.provider == "ollama"
    assert judge.base_url == "http://localhost:11434/v1"
