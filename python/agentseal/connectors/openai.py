# agentseal/connectors/openai.py
"""
OpenAI-compatible connector via raw HTTP (for CLI use).

Layer 3: no agentseal imports.
"""

import os


def build_openai_chat(model: str, system_prompt: str, api_key: str = None):
    """Build an async chat function for the OpenAI Chat Completions API.

    Args:
        model: Model name (e.g. "gpt-4o").
        system_prompt: The system prompt to use.
        api_key: API key (falls back to OPENAI_API_KEY env).
    """
    import httpx

    key = api_key or os.environ.get("OPENAI_API_KEY", "")

    async def chat(message: str) -> str:
        url = "https://api.openai.com/v1/chat/completions"
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(url, json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": message},
                ],
            }, headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
            })
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]

    return chat
