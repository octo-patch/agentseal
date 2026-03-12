"""Tests for agentseal.profiles module."""

import argparse

import pytest

from agentseal.profiles import (
    PROFILES,
    ProfileConfig,
    apply_profile,
    list_profiles,
    resolve_profile,
)


# ---- resolve_profile ----

def test_resolve_known_profile():
    for name in PROFILES:
        cfg = resolve_profile(name)
        assert isinstance(cfg, ProfileConfig)
        assert cfg is PROFILES[name]


def test_resolve_unknown_profile():
    with pytest.raises(ValueError, match="Unknown profile 'nope'") as exc_info:
        resolve_profile("nope")
    # Error message should list valid profile names
    for name in PROFILES:
        assert name in str(exc_info.value)


def test_resolve_case_insensitive():
    assert resolve_profile("Quick") is PROFILES["quick"]
    assert resolve_profile("FULL") is PROFILES["full"]
    assert resolve_profile("Code-Agent") is PROFILES["code-agent"]


# ---- apply_profile ----

def _make_args(**kwargs) -> argparse.Namespace:
    """Create a Namespace with all profile-relevant fields defaulted."""
    defaults = dict(
        adaptive=False, semantic=False, mcp=False, rag=False,
        multimodal=False, genome=False, use_canary_only=False,
        concurrency=None, timeout=None, output=None, min_score=None,
    )
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def test_apply_profile_sets_flags():
    args = _make_args()
    apply_profile(args, resolve_profile("code-agent"))
    assert args.adaptive is True
    assert args.mcp is True
    assert args.semantic is True
    # Flags not in code-agent stay False
    assert args.rag is False
    assert args.multimodal is False


def test_apply_profile_explicit_flag_wins():
    # User explicitly set adaptive=True; a profile with adaptive=False shouldn't clear it
    args = _make_args(adaptive=True)
    apply_profile(args, resolve_profile("default"))
    assert args.adaptive is True


def test_apply_profile_none_fields_not_set():
    args = _make_args()
    apply_profile(args, resolve_profile("default"))
    assert args.concurrency is None
    assert args.timeout is None
    assert args.output is None


def test_apply_profile_concurrency_override():
    args = _make_args()
    apply_profile(args, resolve_profile("quick"))
    assert args.concurrency == 5
    assert args.timeout == 15


def test_apply_profile_user_concurrency_wins():
    args = _make_args(concurrency=10)
    apply_profile(args, resolve_profile("quick"))
    assert args.concurrency == 10  # user value preserved


# ---- profile-specific ----

def test_quick_profile_canary_only():
    cfg = resolve_profile("quick")
    assert cfg.use_canary_only is True
    assert cfg.concurrency == 5
    assert cfg.timeout == 15


def test_full_profile_enables_all():
    cfg = resolve_profile("full")
    assert cfg.adaptive is True
    assert cfg.semantic is True
    assert cfg.mcp is True
    assert cfg.rag is True
    assert cfg.multimodal is True
    assert cfg.genome is True


def test_ci_profile_sets_output_json():
    cfg = resolve_profile("ci")
    assert cfg.output == "json"
    assert cfg.concurrency == 5
    assert cfg.timeout == 15


def test_default_profile_changes_nothing():
    args = _make_args()
    original = argparse.Namespace(**vars(args))
    apply_profile(args, resolve_profile("default"))
    assert vars(args) == vars(original)


# ---- list_profiles ----

def test_list_profiles_returns_string():
    result = list_profiles()
    assert isinstance(result, str)
    for name in PROFILES:
        assert name in result


# ---- misc ----

def test_profiles_dict_not_empty():
    assert len(PROFILES) >= 8


def test_profile_config_defaults():
    cfg = ProfileConfig(description="test")
    assert cfg.adaptive is False
    assert cfg.semantic is False
    assert cfg.mcp is False
    assert cfg.rag is False
    assert cfg.multimodal is False
    assert cfg.genome is False
    assert cfg.use_canary_only is False
    assert cfg.concurrency is None
    assert cfg.timeout is None
    assert cfg.output is None
    assert cfg.min_score is None
