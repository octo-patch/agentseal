# agentseal/connectors/anthropic.py
"""
Anthropic/Claude connector via raw HTTP (for CLI use).

Layer 3: no agentseal imports.
"""

import os


def build_anthropic_chat(model: str, system_prompt: str, api_key: str = None):
    """Build an async chat function for the Anthropic Messages API.

    Args:
        model: Anthropic model name (e.g. "claude-sonnet-4-5-20250929").
        system_prompt: The system prompt to use.
        api_key: API key (falls back to ANTHROPIC_API_KEY env).
    """
    import httpx

    key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")

    async def chat(message: str) -> str:
        url = "https://api.anthropic.com/v1/messages"
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(url, json={
                "model": model,
                "max_tokens": 1024,
                "system": system_prompt,
                "messages": [{"role": "user", "content": message}],
            }, headers={
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            })
            resp.raise_for_status()
            return resp.json()["content"][0]["text"]

    return chat
