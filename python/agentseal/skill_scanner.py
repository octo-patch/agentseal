# agentseal/skill_scanner.py
"""
Skill Scanner — orchestrates layered threat detection for skill files.

Scans SKILL.md, .cursorrules, CLAUDE.md, and other agent instruction files
for malware, prompt injection, credential theft, and other threats.

Detection layers (applied in order, cheapest first):
  1. Blocklist check (SHA256 hash, instant)
  2. Static pattern matching (compiled regex, ~1ms)
  3. Semantic analysis (MiniLM-L6-v2 embeddings, ~50ms, optional)
"""

import hashlib
import sys
from pathlib import Path

import yaml

from agentseal.blocklist import Blocklist
from agentseal.deobfuscate import deobfuscate
from agentseal.detection.dataflow import DataflowAnalyzer
from agentseal.detection.skill_detector import SkillDetector
from agentseal.guard_models import GuardVerdict, SkillFinding, SkillResult


class SkillScanner:
    """Scan skill files for malware, injection, and suspicious patterns."""

    def __init__(self, semantic: bool = True, llm_judge=None):
        self._detector = SkillDetector()
        self._blocklist = Blocklist()
        self._dataflow = DataflowAnalyzer()
        self._llm_judge = llm_judge

        # Check if semantic analysis is available
        self._semantic_available = False
        if semantic:
            try:
                from agentseal.detection.semantic import is_available
                if is_available():
                    self._semantic_available = True
                else:
                    raise ImportError("semantic deps not installed")
            except ImportError:
                print(
                    "  \033[90mSemantic detection not available. "
                    "Install with: pip install agentseal[semantic]\033[0m",
                    file=sys.stderr,
                )

    # Max file size to scan (10 MB — anything larger is not a skill file)
    MAX_FILE_SIZE = 10 * 1024 * 1024

    def scan_file(self, path: Path) -> SkillResult:
        """Scan a single skill file."""
        path = Path(path)
        name = _extract_skill_name(path)

        try:
            file_size = path.stat().st_size
            if file_size > self.MAX_FILE_SIZE:
                return SkillResult(
                    name=name,
                    path=str(path),
                    verdict=GuardVerdict.ERROR,
                    findings=[SkillFinding(
                        code="SKILL-ERR",
                        title="File too large",
                        description=f"File is {file_size // 1024 // 1024}MB, max is 10MB.",
                        severity="low",
                        evidence="",
                        remediation="Skill files should be small text files.",
                    )],
                )

            # Read raw bytes for accurate hash, then decode for analysis
            raw_bytes = path.read_bytes()
            sha256 = hashlib.sha256(raw_bytes).hexdigest()
            content = raw_bytes.decode("utf-8", errors="replace")
        except OSError as e:
            return SkillResult(
                name=name,
                path=str(path),
                verdict=GuardVerdict.ERROR,
                findings=[SkillFinding(
                    code="SKILL-ERR",
                    title="Could not read file",
                    description=str(e),
                    severity="low",
                    evidence="",
                    remediation="Check file permissions.",
                )],
            )

        if not content.strip():
            return SkillResult(name=name, path=str(path), verdict=GuardVerdict.SAFE)

        # Layer 1: Blocklist check
        if self._blocklist.is_blocked(sha256):
            return SkillResult(
                name=name,
                path=str(path),
                verdict=GuardVerdict.DANGER,
                findings=[SkillFinding(
                    code="SKILL-000",
                    title="Known malicious skill",
                    description="This skill matches a known malware hash in the AgentSeal threat database.",
                    severity="critical",
                    evidence=f"SHA256: {sha256}",
                    remediation="Remove this skill immediately and rotate all credentials.",
                )],
                blocklist_match=True,
                sha256=sha256,
            )

        # Layer 2: Static pattern matching (on original + deobfuscated content)
        findings = self._detector.scan_patterns(content)
        deobfuscated = deobfuscate(content)
        if deobfuscated != content:
            deob_findings = self._detector.scan_patterns(deobfuscated)
            existing = {(f.code, f.evidence) for f in findings}
            for f in deob_findings:
                if (f.code, f.evidence) not in existing:
                    findings.append(f)

        # Layer 2b: Dataflow analysis (Python/JS files only)
        suffix = path.suffix.lower()
        if suffix in (".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"):
            df_findings = self._dataflow.analyze(content, filename=str(path))
            for df in df_findings:
                findings.append(SkillFinding(
                    code="SKILL-010",
                    title="Credential-to-network dataflow",
                    description=f"Data flows from {df.source_type} (line {df.source_line}) "
                                f"to {df.sink_type} (line {df.sink_line}).",
                    severity="critical",
                    evidence=f"Source: {df.source_code} → Sink: {df.sink_code}",
                    remediation="Review this data flow — sensitive data reaches a network sink.",
                ))

        # Layer 3: Semantic analysis (if available and no critical patterns found)
        if self._semantic_available:
            semantic_findings = self._detector.scan_semantic(content)
            # Only add semantic findings for codes not already covered by patterns
            existing_codes = {f.code for f in findings}
            for sf in semantic_findings:
                if sf.code not in existing_codes:
                    findings.append(sf)

        # Layer 4: LLM judge (if configured)
        if self._llm_judge is not None:
            try:
                import asyncio
                llm_findings, _ = asyncio.run(self.analyze_with_llm(content, str(path)))
                existing_codes = {f.code for f in findings}
                for lf in llm_findings:
                    if lf.code not in existing_codes:
                        findings.append(lf)
            except Exception:
                pass  # LLM judge is best-effort — never block scanning

        verdict = _compute_verdict(findings)

        return SkillResult(
            name=name,
            path=str(path),
            verdict=verdict,
            findings=findings,
            sha256=sha256,
        )

    async def analyze_with_llm(self, content: str, filename: str) -> tuple[list[SkillFinding], int]:
        """Run LLM judge analysis and convert results to SkillFindings.

        Returns (findings, tokens_used). Returns ([], 0) if llm_judge is
        None or the result has an error.
        """
        if self._llm_judge is None:
            return [], 0
        result = await self._llm_judge.analyze_skill(content, filename)
        if result.error:
            return [], result.tokens_used
        findings = []
        for f in result.findings:
            findings.append(SkillFinding(
                code=f"LLM-{f.get('severity', 'medium').upper()[:4]}",
                title=f.get("title", "LLM-detected issue"),
                description=f.get("reasoning", ""),
                severity=f.get("severity", "medium"),
                evidence=f.get("evidence", ""),
                remediation="Review this finding from LLM analysis.",
            ))
        return findings, result.tokens_used

    def scan_paths(self, paths: list[Path]) -> list[SkillResult]:
        """Scan a list of skill file paths."""
        results = []
        for path in paths:
            results.append(self.scan_file(path))
        return results


def _extract_skill_name(path: Path) -> str:
    """Extract skill name from YAML frontmatter or filename."""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return path.stem

    # Try YAML frontmatter (SKILL.md format: ---\nname: foo\n---\n...)
    if content.startswith("---\n") or content.startswith("---\r"):
        try:
            # Find closing --- that starts on its own line
            end = content.index("\n---", 3)
            frontmatter = yaml.safe_load(content[4:end])
            if isinstance(frontmatter, dict) and "name" in frontmatter:
                name_val = str(frontmatter["name"])[:200]  # Limit name length
                return name_val
        except (ValueError, yaml.YAMLError):
            pass

    # If file is named SKILL.md, use parent directory name
    if path.name.lower() == "skill.md":
        return path.parent.name

    # Otherwise use filename without extension
    return path.stem


def _compute_verdict(findings: list[SkillFinding]) -> GuardVerdict:
    """Determine verdict from findings. Worst severity wins."""
    if not findings:
        return GuardVerdict.SAFE
    if any(f.severity == "critical" for f in findings):
        return GuardVerdict.DANGER
    if any(f.severity in ("high", "medium") for f in findings):
        return GuardVerdict.WARNING
    return GuardVerdict.SAFE
