# agentseal/compare.py
"""
Scan comparison - diff two scan reports to show changes between runs.

Layer 5: imports from schemas.
"""

import json
from pathlib import Path
from typing import Optional


def compare_reports(a: dict, b: dict) -> dict:
    """Compare two scan report dicts and return the diff.

    Args:
        a: The baseline (older) scan report dict.
        b: The current (newer) scan report dict.

    Returns:
        A dict with score deltas, flipped probes, and summary.
    """
    score_a = a.get("trust_score", 0)
    score_b = b.get("trust_score", 0)
    delta = score_b - score_a

    breakdown_a = a.get("score_breakdown", {})
    breakdown_b = b.get("score_breakdown", {})

    breakdown_delta = {}
    for key in ("extraction_resistance", "injection_resistance",
                "boundary_integrity", "consistency", "overall"):
        val_a = breakdown_a.get(key, 0)
        val_b = breakdown_b.get(key, 0)
        breakdown_delta[key] = round(val_b - val_a, 1)

    # Build probe verdict maps
    probes_a = {r["probe_id"]: r["verdict"] for r in a.get("results", [])}
    probes_b = {r["probe_id"]: r["verdict"] for r in b.get("results", [])}

    all_ids = sorted(set(probes_a.keys()) | set(probes_b.keys()))

    flipped = []
    for pid in all_ids:
        va = probes_a.get(pid)
        vb = probes_b.get(pid)
        if va != vb:
            flipped.append({
                "probe_id": pid,
                "was": va or "(absent)",
                "now": vb or "(absent)",
            })

    improved = [f for f in flipped if _is_improvement(f["was"], f["now"])]
    regressed = [f for f in flipped if _is_regression(f["was"], f["now"])]

    return {
        "score_a": score_a,
        "score_b": score_b,
        "score_delta": round(delta, 1),
        "level_a": a.get("trust_level", "unknown"),
        "level_b": b.get("trust_level", "unknown"),
        "breakdown_delta": breakdown_delta,
        "total_flipped": len(flipped),
        "improved": improved,
        "regressed": regressed,
        "flipped": flipped,
    }


def print_comparison(diff: dict):
    """Pretty-print a comparison result to the terminal."""
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    delta = diff["score_delta"]
    delta_color = GREEN if delta > 0 else RED if delta < 0 else DIM

    print()
    print(f"{BLUE}{'═' * 60}{RESET}")
    print(f"{BLUE}  AgentSeal - Scan Comparison{RESET}")
    print(f"{BLUE}{'═' * 60}{RESET}")
    print()
    print(f"  Score:  {diff['score_a']:.0f}  →  {diff['score_b']:.0f}  "
          f"({delta_color}{'+' if delta > 0 else ''}{delta:.1f}{RESET})")
    print(f"  Level:  {diff['level_a']}  →  {diff['level_b']}")
    print()

    bd = diff["breakdown_delta"]
    for key in ("extraction_resistance", "injection_resistance",
                "boundary_integrity", "consistency"):
        d = bd.get(key, 0)
        color = GREEN if d > 0 else RED if d < 0 else DIM
        label = key.replace("_", " ").title()
        print(f"  {DIM}{label:24s}{RESET}  {color}{'+' if d > 0 else ''}{d:.1f}{RESET}")
    print()

    if diff["improved"]:
        print(f"  {GREEN}{BOLD}IMPROVED ({len(diff['improved'])}):{RESET}")
        for f in diff["improved"]:
            print(f"    {GREEN}↑{RESET} {f['probe_id']:25s}  {f['was']:8s} → {f['now']}")
        print()

    if diff["regressed"]:
        print(f"  {RED}{BOLD}REGRESSED ({len(diff['regressed'])}):{RESET}")
        for f in diff["regressed"]:
            print(f"    {RED}↓{RESET} {f['probe_id']:25s}  {f['was']:8s} → {f['now']}")
        print()

    if not diff["improved"] and not diff["regressed"]:
        print(f"  {DIM}No probe verdicts changed.{RESET}")
        print()

    print(f"{BLUE}{'═' * 60}{RESET}")
    print()


def load_report(path: str) -> dict:
    """Load a scan report from a JSON file."""
    return json.loads(Path(path).read_text())


# ── Helpers ──────────────────────────────────────────────────────────

_VERDICT_RANK = {"leaked": 0, "partial": 1, "error": 2, "blocked": 3}


def _is_improvement(was: str, now: str) -> bool:
    return _VERDICT_RANK.get(now, -1) > _VERDICT_RANK.get(was, -1)


def _is_regression(was: str, now: str) -> bool:
    return _VERDICT_RANK.get(now, -1) < _VERDICT_RANK.get(was, -1)
