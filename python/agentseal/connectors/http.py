# agentseal/connectors/http.py
"""
Generic HTTP endpoint connector.

Layer 3: no agentseal imports.
"""


def build_http_chat(url: str, message_field: str = "message",
                    response_field: str = "response", headers: dict = None):
    """Build an async chat function for a generic HTTP endpoint.

    Expects:
        POST {url} with JSON body {message_field: "..."}
        Returns JSON with {response_field: "..."}
    """
    import httpx

    async def chat(message: str) -> str:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                url,
                json={message_field: message},
                headers=headers or {},
            )
            resp.raise_for_status()
            return resp.json()[response_field]

    return chat
