# agentseal/exceptions.py
"""
AgentSeal exception hierarchy.

Layer 0: No internal imports.
"""


class AgentSealError(Exception):
    """Base exception for all AgentSeal errors."""


class ScanError(AgentSealError):
    """Raised when a scan cannot complete."""


class ConnectionError(AgentSealError):
    """Raised when the agent endpoint is unreachable."""


class TimeoutError(AgentSealError):
    """Raised when a probe or scan exceeds its timeout."""


class LicenseError(AgentSealError):
    """Raised when a Pro feature is used without a valid license."""
