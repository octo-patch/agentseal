# tests/test_unicode_detection.py
"""Tests for Unicode invisible character detection (GAP 2)."""

from agentseal.deobfuscate import (
    deobfuscate,
    has_invisible_chars,
    strip_bidi_controls,
    strip_html_comments,
    strip_tag_chars,
    strip_variation_selectors,
)
from agentseal.detection.skill_detector import SkillDetector


class TestStripTagChars:
    """Unicode Tag Characters (ASCII smuggling)."""

    def test_strip_tag_chars(self):
        # Tag characters U+E0041 = 'A', U+E0042 = 'B' etc.
        text = "hello\U000e0041\U000e0042\U000e0043world"
        assert strip_tag_chars(text) == "helloworld"

    def test_no_tag_chars(self):
        assert strip_tag_chars("normal text") == "normal text"


class TestStripVariationSelectors:
    def test_strip_variation_selectors(self):
        text = "hello\ufe00\ufe0fworld"
        assert strip_variation_selectors(text) == "helloworld"

    def test_strip_extended_variation_selectors(self):
        text = "a\U000e0100b\U000e01efc"
        assert strip_variation_selectors(text) == "abc"


class TestStripBidiControls:
    def test_strip_bidi_controls(self):
        # LRE, RLE, PDF, LRO, RLO
        text = "normal\u202a\u202bhidden\u202ctext"
        assert strip_bidi_controls(text) == "normalhiddentext"

    def test_strip_lrm_rlm(self):
        text = "hello\u200eworld\u200f"
        assert strip_bidi_controls(text) == "helloworld"


class TestStripHtmlComments:
    def test_strip_html_comments(self):
        text = "visible<!-- hidden instructions -->content"
        assert strip_html_comments(text) == "visiblecontent"

    def test_multiline_comment(self):
        text = "a<!-- \nhidden\n -->b"
        assert strip_html_comments(text) == "ab"


class TestHasInvisibleChars:
    def test_detects_zero_width(self):
        assert has_invisible_chars("hello\u200bworld") is True

    def test_detects_tag_chars(self):
        assert has_invisible_chars("hello\U000e0041world") is True

    def test_detects_bidi(self):
        assert has_invisible_chars("hello\u202aworld") is True

    def test_no_invisible(self):
        assert has_invisible_chars("normal text") is False


class TestDeobfuscatePipeline:
    """Verify the full deobfuscation pipeline strips all invisible types."""

    def test_strips_all_invisible_types(self):
        text = (
            "hello"
            "\u200b"           # zero-width
            "\U000e0041"       # tag char
            "\ufe00"           # variation selector
            "\u202a"           # bidi
            "world"
        )
        result = deobfuscate(text)
        assert result == "helloworld"

    def test_html_comments_stripped(self):
        text = "curl <!-- hidden --> evil.com"
        result = deobfuscate(text)
        assert "hidden" not in result
        assert "curl" in result


class TestSkillDetectorInvisibleChars:
    """SKILL-011 fires on invisible characters."""

    def test_skill_011_fires_on_tag_chars(self):
        detector = SkillDetector()
        content = "Follow these instructions\U000e0041\U000e0042\U000e0043"
        findings = detector.scan_patterns(content)
        codes = [f.code for f in findings]
        assert "SKILL-011" in codes

    def test_skill_011_fires_on_bidi(self):
        detector = SkillDetector()
        content = "Normal text\u202awith bidi\u202c controls"
        findings = detector.scan_patterns(content)
        codes = [f.code for f in findings]
        assert "SKILL-011" in codes

    def test_no_skill_011_on_clean_text(self):
        detector = SkillDetector()
        content = "This is a normal skill file with no hidden chars."
        findings = detector.scan_patterns(content)
        codes = [f.code for f in findings]
        assert "SKILL-011" not in codes

    def test_skill_011_evidence_has_category(self):
        detector = SkillDetector()
        content = "text\U000e0041\U000e0042hidden"
        findings = detector.scan_patterns(content)
        skill_011 = [f for f in findings if f.code == "SKILL-011"]
        assert len(skill_011) == 1
        assert "Tag Characters" in skill_011[0].evidence
