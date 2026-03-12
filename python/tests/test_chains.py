# tests/test_chains.py
"""Tests for attack chain detection."""

import pytest

from agentseal.schemas import ScanReport, ProbeResult, Verdict, Severity, TrustLevel
from agentseal.chains import detect_chains, AttackChain, ChainStep


# ═══════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _probe(
    probe_id: str = "p1",
    category: str = "persona_hijack",
    probe_type: str = "injection",
    technique: str = "direct_injection",
    severity: Severity = Severity.HIGH,
    verdict: Verdict = Verdict.LEAKED,
    confidence: float = 0.9,
) -> ProbeResult:
    return ProbeResult(
        probe_id=probe_id,
        category=category,
        probe_type=probe_type,
        technique=technique,
        severity=severity,
        attack_text="attack",
        response_text="response",
        verdict=verdict,
        confidence=confidence,
        reasoning="test",
        duration_ms=10.0,
    )


def _report(results: list[ProbeResult] | None = None) -> ScanReport:
    results = results or []
    leaked = sum(1 for r in results if r.verdict == Verdict.LEAKED)
    partial = sum(1 for r in results if r.verdict == Verdict.PARTIAL)
    blocked = sum(1 for r in results if r.verdict == Verdict.BLOCKED)
    errors = sum(1 for r in results if r.verdict == Verdict.ERROR)
    return ScanReport(
        agent_name="test-agent",
        scan_id="scan-001",
        timestamp="2026-01-01T00:00:00Z",
        duration_seconds=1.0,
        total_probes=len(results),
        probes_blocked=blocked,
        probes_leaked=leaked,
        probes_partial=partial,
        probes_error=errors,
        trust_score=50.0,
        trust_level=TrustLevel.MEDIUM,
        score_breakdown={},
        results=results,
        ground_truth_provided=False,
    )


# ═══════════════════════════════════════════════════════════════════════
# TESTS
# ═══════════════════════════════════════════════════════════════════════

def test_no_chains_all_blocked():
    report = _report([
        _probe(verdict=Verdict.BLOCKED, probe_type="injection"),
        _probe(probe_id="p2", verdict=Verdict.BLOCKED, probe_type="extraction"),
    ])
    assert detect_chains(report) == []


def test_injection_extraction_chain():
    report = _report([
        _probe(probe_id="inj1", probe_type="injection", verdict=Verdict.LEAKED),
        _probe(probe_id="ext1", probe_type="extraction", verdict=Verdict.LEAKED),
    ])
    chains = detect_chains(report)
    assert len(chains) == 1
    assert chains[0].chain_type == "injection_extraction"
    assert chains[0].severity == "high"
    assert len(chains[0].steps) == 2


def test_injection_exfiltration_chain():
    report = _report([
        _probe(
            probe_id="exf1",
            probe_type="injection",
            category="data_exfiltration",
            verdict=Verdict.LEAKED,
        ),
    ])
    chains = detect_chains(report)
    assert len(chains) == 1
    assert chains[0].chain_type == "injection_exfiltration"
    assert chains[0].severity == "critical"


def test_full_chain_detected():
    report = _report([
        _probe(probe_id="inj1", probe_type="injection", verdict=Verdict.LEAKED),
        _probe(probe_id="ext1", probe_type="extraction", verdict=Verdict.LEAKED),
        _probe(
            probe_id="exf1",
            probe_type="injection",
            category="data_exfiltration",
            verdict=Verdict.LEAKED,
        ),
    ])
    chains = detect_chains(report)
    types = [c.chain_type for c in chains]
    assert "full_chain" in types
    assert chains[0].severity == "critical"
    assert len(chains[0].steps) == 3


def test_full_chain_subsumes_injection_extraction():
    report = _report([
        _probe(probe_id="inj1", probe_type="injection", verdict=Verdict.LEAKED),
        _probe(probe_id="ext1", probe_type="extraction", verdict=Verdict.LEAKED),
        _probe(
            probe_id="exf1",
            probe_type="injection",
            category="data_exfiltration",
            verdict=Verdict.LEAKED,
        ),
    ])
    chains = detect_chains(report)
    types = [c.chain_type for c in chains]
    assert "injection_extraction" not in types
    assert "full_chain" in types


def test_partial_extraction_included():
    report = _report([
        _probe(probe_id="inj1", probe_type="injection", verdict=Verdict.LEAKED),
        _probe(probe_id="ext1", probe_type="extraction", verdict=Verdict.PARTIAL),
    ])
    chains = detect_chains(report)
    assert len(chains) == 1
    assert chains[0].chain_type == "injection_extraction"
    ext_step = chains[0].steps[1]
    assert ext_step.verdict == "partial"


def test_chain_uses_highest_severity_probe():
    report = _report([
        _probe(
            probe_id="inj_low",
            probe_type="injection",
            severity=Severity.LOW,
            confidence=0.5,
            verdict=Verdict.LEAKED,
        ),
        _probe(
            probe_id="inj_crit",
            probe_type="injection",
            severity=Severity.CRITICAL,
            confidence=0.9,
            verdict=Verdict.LEAKED,
        ),
        _probe(probe_id="ext1", probe_type="extraction", verdict=Verdict.LEAKED),
    ])
    chains = detect_chains(report)
    inj_step = chains[0].steps[0]
    assert inj_step.probe_id == "inj_crit"


def test_chain_remediation_text_present():
    report = _report([
        _probe(probe_id="inj1", probe_type="injection", verdict=Verdict.LEAKED),
        _probe(probe_id="ext1", probe_type="extraction", verdict=Verdict.LEAKED),
    ])
    chains = detect_chains(report)
    assert chains[0].remediation
    assert len(chains[0].remediation) > 10


def test_only_extraction_leaked_no_chain():
    report = _report([
        _probe(probe_id="ext1", probe_type="extraction", verdict=Verdict.LEAKED),
    ])
    assert detect_chains(report) == []


def test_only_injection_leaked_no_chain():
    """No extraction and no exfil category -> no chain."""
    report = _report([
        _probe(probe_id="inj1", probe_type="injection", category="persona_hijack", verdict=Verdict.LEAKED),
    ])
    assert detect_chains(report) == []


def test_empty_report_empty_chains():
    report = _report([])
    assert detect_chains(report) == []


def test_chain_to_dict_roundtrip():
    chain = AttackChain(
        chain_type="full_chain",
        severity="critical",
        title="Test chain",
        description="A test chain",
        steps=[
            ChainStep(
                step_number=1,
                probe_id="p1",
                category="persona_hijack",
                technique="direct_injection",
                verdict="leaked",
                summary="ENTRY POINT: direct_injection via persona_hijack",
            ),
        ],
        remediation="Fix it",
    )
    d = chain.to_dict()
    restored = AttackChain.from_dict(d)
    assert restored.chain_type == chain.chain_type
    assert restored.severity == chain.severity
    assert restored.title == chain.title
    assert restored.description == chain.description
    assert restored.remediation == chain.remediation
    assert len(restored.steps) == len(chain.steps)
    assert restored.steps[0].probe_id == chain.steps[0].probe_id


def test_chain_step_to_dict_roundtrip():
    step = ChainStep(
        step_number=2,
        probe_id="p99",
        category="data_exfiltration",
        technique="markdown_img",
        verdict="leaked",
        summary="DATA ACCESS: markdown_img via data_exfiltration",
    )
    d = step.to_dict()
    restored = ChainStep.from_dict(d)
    assert restored.step_number == step.step_number
    assert restored.probe_id == step.probe_id
    assert restored.category == step.category
    assert restored.technique == step.technique
    assert restored.verdict == step.verdict
    assert restored.summary == step.summary
