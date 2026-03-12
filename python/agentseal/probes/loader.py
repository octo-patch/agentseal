# agentseal/probes/loader.py
"""
Custom probe loader - YAML probe definitions from files and directories.

Layer 2: imports from schemas, probes.base.
"""

import logging
import re
import warnings
from pathlib import Path
from typing import Union

import yaml

from agentseal.probes.base import generate_canary
from agentseal.schemas import Severity

logger = logging.getLogger(__name__)

_REQUIRED_FIELDS = {"probe_id", "category", "technique", "severity", "payload"}
_PROBE_ID_RE = re.compile(r"^[a-zA-Z0-9_-]+$")
_RESERVED_PREFIXES = ("ext_", "inj_", "mcp_", "rag_", "mm_")
_SEVERITY_MAP = {s.value: s for s in Severity}
_MAX_PROBES_PER_FILE = 500
_MAX_FILES_PER_DIR = 10


def load_custom_probes(path: Union[str, Path]) -> list[dict]:
    """Load custom probes from a YAML file or directory of YAML files.

    Args:
        path: Path to a .yaml file or a directory containing .yaml files.

    Returns:
        List of validated probe dicts ready for the pipeline.

    Raises:
        FileNotFoundError: If the path does not exist.
        ValueError: On validation errors or duplicate probe_ids.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Probe path does not exist: {path}")

    if path.is_file():
        return _parse_yaml_file(path)

    if path.is_dir():
        yaml_files = sorted(path.glob("*.yaml")) + sorted(path.glob("*.yml"))
        # deduplicate while preserving order
        seen_paths: set[Path] = set()
        unique_files: list[Path] = []
        for f in yaml_files:
            resolved = f.resolve()
            if resolved not in seen_paths:
                seen_paths.add(resolved)
                unique_files.append(f)
        yaml_files = unique_files

        if len(yaml_files) > _MAX_FILES_PER_DIR:
            raise ValueError(
                f"Directory contains {len(yaml_files)} YAML files, "
                f"maximum is {_MAX_FILES_PER_DIR}: {path}"
            )

        all_probes: list[dict] = []
        all_ids: set[str] = set()

        for yf in yaml_files:
            try:
                probes = _parse_yaml_file(yf)
            except (PermissionError, yaml.YAMLError):
                warnings.warn(f"Skipping {yf}: permission denied or invalid YAML")
                continue

            for p in probes:
                pid = p["probe_id"]
                if pid in all_ids:
                    raise ValueError(
                        f"Duplicate probe_id '{pid}' found across files in {path}"
                    )
                all_ids.add(pid)

            all_probes.extend(probes)

        return all_probes

    raise ValueError(f"Path is neither a file nor directory: {path}")


def load_all_custom_probes() -> list[dict]:
    """Auto-discover probes from ~/.agentseal/probes/ and .agentseal/probes/.

    Returns:
        Combined list of probes from both locations.

    Raises:
        ValueError: If duplicate probe_ids exist across locations.
    """
    search_dirs = [
        Path.home() / ".agentseal" / "probes",
        Path.cwd() / ".agentseal" / "probes",
    ]

    all_probes: list[dict] = []
    all_ids: set[str] = set()

    for d in search_dirs:
        if not d.is_dir():
            continue

        yaml_files = sorted(d.glob("*.yaml")) + sorted(d.glob("*.yml"))
        if len(yaml_files) > _MAX_FILES_PER_DIR:
            warnings.warn(
                f"Directory {d} contains {len(yaml_files)} YAML files, "
                f"maximum is {_MAX_FILES_PER_DIR}; skipping"
            )
            continue
        for yf in yaml_files:
            try:
                probes = _parse_yaml_file(yf)
            except (PermissionError, yaml.YAMLError):
                warnings.warn(f"Skipping {yf}: permission denied or invalid YAML")
                continue

            for p in probes:
                pid = p["probe_id"]
                if pid in all_ids:
                    raise ValueError(
                        f"Duplicate probe_id '{pid}' found during auto-discovery"
                    )
                all_ids.add(pid)

            all_probes.extend(probes)

    return all_probes


def _parse_yaml_file(path: Path) -> list[dict]:
    """Parse a single YAML probe file.

    Args:
        path: Path to the YAML file.

    Returns:
        List of validated probe dicts.

    Raises:
        ValueError: On validation or format errors.
        yaml.YAMLError: On malformed YAML.
    """
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    # Empty file or comments-only file
    if data is None:
        return []

    if not isinstance(data, dict):
        raise ValueError(f"Expected a YAML mapping at top level in {path}")

    # Version check
    version = data.get("version")
    if version is None:
        raise ValueError(f"Missing 'version' field in {path}")
    if version != 1:
        raise ValueError(
            f"Unsupported probe file version {version} in {path}; only version 1 is supported"
        )

    probes_raw = data.get("probes")
    if probes_raw is None:
        return []

    if not isinstance(probes_raw, list):
        raise ValueError(f"'probes' must be a list in {path}")

    if len(probes_raw) > _MAX_PROBES_PER_FILE:
        raise ValueError(
            f"File contains {len(probes_raw)} probes, "
            f"maximum is {_MAX_PROBES_PER_FILE}: {path}"
        )

    # Check for duplicate probe_ids within a single file
    ids_in_file: set[str] = set()
    validated: list[dict] = []

    for i, raw_probe in enumerate(probes_raw):
        if not isinstance(raw_probe, dict):
            raise ValueError(f"Probe #{i + 1} is not a mapping in {path}")

        source = f"{path}:probe[{i}]"
        errors = _validate_probe(raw_probe, source)
        if errors:
            raise ValueError(
                f"Validation errors in {source}:\n  " + "\n  ".join(errors)
            )

        pid = raw_probe["probe_id"]
        if pid in ids_in_file:
            raise ValueError(
                f"Duplicate probe_id '{pid}' within file {path}"
            )
        ids_in_file.add(pid)

        probe = _build_probe(raw_probe)
        validated.append(probe)

    return validated


def _validate_probe(probe: dict, source: str) -> list[str]:
    """Validate a raw probe dict.

    Args:
        probe: The raw probe dict from YAML.
        source: Human-readable source location for error messages.

    Returns:
        List of error messages. Empty list means valid.
    """
    errors: list[str] = []

    # Required fields
    for field in _REQUIRED_FIELDS:
        if field not in probe:
            errors.append(f"Missing required field '{field}'")

    if errors:
        # Can't validate further without required fields
        return errors

    # probe_id format
    pid = probe["probe_id"]
    if not isinstance(pid, str) or not _PROBE_ID_RE.match(pid):
        errors.append(
            f"probe_id '{pid}' must match ^[a-zA-Z0-9_-]+$ (alphanumeric, underscore, hyphen)"
        )

    # Reserved prefix check
    if isinstance(pid, str):
        for prefix in _RESERVED_PREFIXES:
            if pid.startswith(prefix):
                errors.append(
                    f"probe_id '{pid}' uses reserved prefix '{prefix}'"
                )
                break

    # Severity
    sev = probe["severity"]
    if isinstance(sev, str):
        if sev.lower() not in _SEVERITY_MAP:
            valid_sevs = ", ".join(sorted(_SEVERITY_MAP.keys()))
            errors.append(
                f"Invalid severity '{sev}'; must be one of: {valid_sevs}"
            )
    else:
        errors.append(f"Severity must be a string, got {type(sev).__name__}")

    # Payload type
    payload = probe["payload"]
    if not isinstance(payload, (str, list)):
        errors.append(f"payload must be a string or list of strings, got {type(payload).__name__}")
    elif isinstance(payload, list):
        for j, item in enumerate(payload):
            if not isinstance(item, str):
                errors.append(f"payload[{j}] must be a string, got {type(item).__name__}")

    # Category and technique type check
    category = probe["category"]
    if not isinstance(category, str):
        errors.append(f"category must be a string, got {type(category).__name__}")
    technique = probe["technique"]
    if not isinstance(technique, str):
        errors.append(f"technique must be a string, got {type(technique).__name__}")

    # Tags type check
    if "tags" in probe and not isinstance(probe["tags"], list):
        errors.append(f"tags must be a list, got {type(probe['tags']).__name__}")

    # Remediation type check
    if "remediation" in probe and not isinstance(probe["remediation"], str):
        errors.append(f"remediation must be a string, got {type(probe['remediation']).__name__}")

    # Type field
    probe_type = probe.get("type", "extraction")
    if probe_type not in ("extraction", "injection"):
        errors.append(f"type must be 'extraction' or 'injection', got '{probe_type}'")

    # Canary position
    canary_pos = probe.get("canary_position", "suffix")
    if canary_pos not in ("suffix", "inline", "prefix"):
        errors.append(
            f"canary_position must be 'suffix', 'inline', or 'prefix', got '{canary_pos}'"
        )

    return errors


def _build_probe(raw: dict) -> dict:
    """Build a validated probe dict from raw YAML data.

    Applies defaults, auto-generates canary, normalizes severity.
    """
    probe_type = raw.get("type", "extraction")
    payload = raw["payload"]
    is_multi_turn = raw.get("is_multi_turn", isinstance(payload, list))

    # Normalize severity
    severity = _SEVERITY_MAP[raw["severity"].lower()]

    probe: dict = {
        "probe_id": raw["probe_id"],
        "category": raw["category"],
        "technique": raw["technique"],
        "severity": severity,
        "payload": payload,
        "type": probe_type,
        "is_multi_turn": is_multi_turn,
    }

    # Canary handling
    if probe_type == "injection":
        canary = raw.get("canary")
        if canary is None:
            canary = generate_canary()
        probe["canary"] = canary
        probe["canary_position"] = raw.get("canary_position", "suffix")
    elif "canary" in raw:
        warnings.warn(
            f"Canary specified for extraction probe '{raw['probe_id']}' will be ignored",
            UserWarning,
            stacklevel=4,
        )

    # Optional fields
    if "tags" in raw:
        probe["tags"] = raw["tags"]
    if "remediation" in raw:
        probe["remediation"] = raw["remediation"]

    return probe
