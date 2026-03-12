# agentseal/detection/refusal.py
"""
Refusal detection helper - extracted from validator.py _detect_extraction().

The refusal phrase matching was originally inline in the extraction detection
function. Factored out so it can be reused by other detection logic.

Layer 2: imports from constants.
"""

from agentseal.constants import REFUSAL_PHRASES


def is_refusal(response: str) -> bool:
    """Check if a response contains refusal phrases."""
    response_lower = response.lower()
    return any(p in response_lower for p in REFUSAL_PHRASES)
