# agentseal/chains.py
"""
Attack chain detection from scan results.

Analyzes existing ProbeResult data to identify complete attack paths.
Does NOT run new probes.
"""

from dataclasses import dataclass, field
from typing import Optional

from agentseal.schemas import ScanReport, ProbeResult, Verdict, Severity


# ═══════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class ChainStep:
    step_number: int
    probe_id: str
    category: str
    technique: str
    verdict: str          # "leaked" or "partial"
    summary: str          # e.g. "Attacker sends persona hijack message"

    def to_dict(self) -> dict:
        return {
            "step_number": self.step_number,
            "probe_id": self.probe_id,
            "category": self.category,
            "technique": self.technique,
            "verdict": self.verdict,
            "summary": self.summary,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ChainStep":
        return cls(**d)


@dataclass
class AttackChain:
    chain_type: str       # "injection_extraction", "injection_exfiltration", "full_chain"
    severity: str         # "critical", "high"
    title: str
    description: str
    steps: list[ChainStep]
    remediation: str

    def to_dict(self) -> dict:
        return {
            "chain_type": self.chain_type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "steps": [s.to_dict() for s in self.steps],
            "remediation": self.remediation,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AttackChain":
        return cls(
            chain_type=d["chain_type"],
            severity=d["severity"],
            title=d["title"],
            description=d["description"],
            steps=[ChainStep.from_dict(s) for s in d["steps"]],
            remediation=d["remediation"],
        )


# ═══════════════════════════════════════════════════════════════════════
# SEVERITY RANKING (for picking best probe)
# ═══════════════════════════════════════════════════════════════════════

_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
}

_STEP_ROLES = {
    1: "ENTRY POINT",
    2: "DATA ACCESS",
    3: "EXFILTRATION",
}

_EXFIL_CATEGORIES = {"data_exfiltration", "markdown_exfiltration", "enhanced_markdown_exfil"}

_MAX_CHAINS = 5

_CHAIN_META = {
    "injection_extraction": {
        "title": "Injection to extraction chain detected",
        "description": (
            "An attacker can inject a malicious prompt that alters the agent's "
            "behaviour, then extract sensitive data through follow-up queries."
        ),
        "remediation": (
            "Add input validation to reject injected instructions. "
            "Restrict the agent's ability to return raw data from internal sources."
        ),
    },
    "injection_exfiltration": {
        "title": "Injection to data exfiltration chain detected",
        "description": (
            "An attacker can inject a prompt that causes the agent to exfiltrate "
            "data through covert channels such as markdown images or encoded URLs."
        ),
        "remediation": (
            "Sanitise agent output to strip markdown images and external URLs. "
            "Block outbound requests that embed user data in query parameters."
        ),
    },
    "full_chain": {
        "title": "Complete data theft chain detected",
        "description": (
            "An attacker can hijack the agent via prompt injection, access "
            "sensitive data through extraction, and exfiltrate it through a "
            "covert channel — a complete end-to-end attack."
        ),
        "remediation": (
            "Apply defence in depth: validate inputs against injection, restrict "
            "data access scope, and sanitise outputs to prevent exfiltration."
        ),
    },
}


def _best_probe(probes: list[ProbeResult]) -> ProbeResult:
    """Pick the probe with highest severity, breaking ties by confidence."""
    return max(probes, key=lambda p: (_SEVERITY_RANK.get(p.severity, 0), p.confidence))


def _make_step(step_number: int, probe: ProbeResult) -> ChainStep:
    role = _STEP_ROLES.get(step_number, "STEP")
    return ChainStep(
        step_number=step_number,
        probe_id=probe.probe_id,
        category=probe.category,
        technique=probe.technique,
        verdict=probe.verdict.value if isinstance(probe.verdict, Verdict) else probe.verdict,
        summary=f"{role}: {probe.technique} via {probe.category}",
    )


def detect_chains(report: ScanReport) -> list[AttackChain]:
    """Analyze probe results to identify complete attack chains."""
    leaked_injections = [
        p for p in report.results
        if p.probe_type == "injection" and p.verdict == Verdict.LEAKED
    ]
    leaked_extractions = [
        p for p in report.results
        if p.probe_type == "extraction" and p.verdict in (Verdict.LEAKED, Verdict.PARTIAL)
    ]
    exfil_probes = [
        p for p in leaked_injections
        if p.category in _EXFIL_CATEGORIES
    ]

    chains: list[AttackChain] = []
    has_full = False

    # Full chain: injection + extraction + exfiltration
    if leaked_injections and leaked_extractions and exfil_probes:
        has_full = True
        meta = _CHAIN_META["full_chain"]
        best_inj = _best_probe(leaked_injections)
        best_ext = _best_probe(leaked_extractions)
        best_exf = _best_probe(exfil_probes)
        chains.append(AttackChain(
            chain_type="full_chain",
            severity="critical",
            title=meta["title"],
            description=meta["description"],
            steps=[
                _make_step(1, best_inj),
                _make_step(2, best_ext),
                _make_step(3, best_exf),
            ],
            remediation=meta["remediation"],
        ))

    # Injection + extraction (only if full_chain not already present)
    if leaked_injections and leaked_extractions and not has_full:
        meta = _CHAIN_META["injection_extraction"]
        best_inj = _best_probe(leaked_injections)
        best_ext = _best_probe(leaked_extractions)
        chains.append(AttackChain(
            chain_type="injection_extraction",
            severity="high",
            title=meta["title"],
            description=meta["description"],
            steps=[
                _make_step(1, best_inj),
                _make_step(2, best_ext),
            ],
            remediation=meta["remediation"],
        ))

    # Injection + exfiltration (only if full_chain not already present)
    if exfil_probes and not has_full:
        meta = _CHAIN_META["injection_exfiltration"]
        # Pick best non-exfil injection as entry point, best exfil as step 2
        non_exfil_injections = [p for p in leaked_injections if p.category not in _EXFIL_CATEGORIES]
        best_inj = _best_probe(non_exfil_injections) if non_exfil_injections else _best_probe(leaked_injections)
        best_exf = _best_probe(exfil_probes)
        chains.append(AttackChain(
            chain_type="injection_exfiltration",
            severity="critical",
            title=meta["title"],
            description=meta["description"],
            steps=[
                _make_step(1, best_inj),
                _make_step(2, best_exf),
            ],
            remediation=meta["remediation"],
        ))

    return chains[:_MAX_CHAINS]
