# agentseal/connectors/litellm.py
"""
LiteLLM proxy connector.

Layer 3: no agentseal imports.
"""


def build_litellm_chat(model: str, system_prompt: str, litellm_url: str,
                       api_key: str = None):
    """Build an async chat function for a LiteLLM proxy endpoint.

    Args:
        model: Model name as configured in LiteLLM.
        system_prompt: The system prompt to use.
        litellm_url: LiteLLM proxy base URL.
        api_key: Optional API key for the proxy.
    """
    import httpx

    async def chat(message: str) -> str:
        url = f"{litellm_url}/v1/chat/completions"
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(url, json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": message},
                ],
            }, headers={"Authorization": f"Bearer {api_key}"} if api_key else {})
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]

    return chat
