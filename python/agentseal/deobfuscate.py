"""Text deobfuscation transforms for skill file content.

Applied BEFORE regex pattern matching to make obfuscated payloads
visible to existing detection patterns. Stdlib only: re, base64, unicodedata.
"""

from __future__ import annotations

import base64
import re
import unicodedata

__all__ = [
    "deobfuscate",
    "strip_zero_width",
    "strip_tag_chars",
    "strip_variation_selectors",
    "strip_bidi_controls",
    "strip_html_comments",
    "has_invisible_chars",
    "normalize_unicode",
    "decode_base64_blocks",
    "unescape_sequences",
    "expand_string_concat",
]

# Zero-width and invisible characters to strip.
_ZERO_WIDTH = re.compile("[\u200b\u200c\u200d\ufeff\u00ad\u2060]")

# Unicode Tag Characters (ASCII smuggling) — U+E0001 to U+E007F
_TAG_CHARS = re.compile("[\U000e0001-\U000e007f]")

# Variation Selectors — U+FE00-FE0F + U+E0100-E01EF
_VARIATION_SELECTORS = re.compile("[\ufe00-\ufe0f\U000e0100-\U000e01ef]")

# BiDi Control Characters
_BIDI_CONTROLS = re.compile("[\u202a-\u202e\u2066-\u2069\u200e\u200f]")

# HTML comments with hidden instructions
_HTML_COMMENTS = re.compile(r"<!--[\s\S]*?-->")

# Combined invisible character detection pattern (for pre-strip detection)
_INVISIBLE_CHARS = re.compile(
    "[\u200b\u200c\u200d\ufeff\u00ad\u2060"
    "\U000e0001-\U000e007f"
    "\ufe00-\ufe0f\U000e0100-\U000e01ef"
    "\u202a-\u202e\u2066-\u2069\u200e\u200f]"
)

# Base64 block: standalone token of 8+ base64 chars (including padding).
# We use a non-capturing group approach instead of variable-width lookbehind.
_BASE64_BLOCK = re.compile(
    r"(?:(?<=[\"\'\s(])|(?<=^))([A-Za-z0-9+/=]{8,})(?=[\"'\s)]|$)",
    re.MULTILINE,
)

# Hex escape: \xHH
_HEX_ESCAPE = re.compile(r"\\x([0-9A-Fa-f]{2})")

# Unicode escape: \uHHHH
_UNICODE_ESCAPE = re.compile(r"\\u([0-9A-Fa-f]{4})")

# Common backslash escapes.
_SIMPLE_ESCAPES = {"\\n": "\n", "\\t": "\t", "\\r": "\r", "\\\\": "\\"}

# Adjacent string concatenation: "..." + "..." or '...' + '...'
_CONCAT_DOUBLE = re.compile(r'"([^"]*?)"\s*\+\s*"([^"]*?)"')
_CONCAT_SINGLE = re.compile(r"'([^']*?)'\s*\+\s*'([^']*?)'")


def strip_zero_width(text: str) -> str:
    """Remove zero-width characters: U+200B, U+200C, U+200D, U+FEFF, U+00AD, U+2060."""
    return _ZERO_WIDTH.sub("", text)


def strip_tag_chars(text: str) -> str:
    """Remove Unicode Tag Characters (U+E0001–U+E007F) used in ASCII smuggling."""
    return _TAG_CHARS.sub("", text)


def strip_variation_selectors(text: str) -> str:
    """Remove Variation Selectors (U+FE00–FE0F, U+E0100–E01EF)."""
    return _VARIATION_SELECTORS.sub("", text)


def strip_bidi_controls(text: str) -> str:
    """Remove BiDi control characters that can hide text direction."""
    return _BIDI_CONTROLS.sub("", text)


def strip_html_comments(text: str) -> str:
    """Remove HTML comments that may contain hidden instructions."""
    return _HTML_COMMENTS.sub("", text)


def has_invisible_chars(text: str) -> bool:
    """Check if text contains any invisible/obfuscation characters (before stripping)."""
    return bool(_INVISIBLE_CHARS.search(text))


def normalize_unicode(text: str) -> str:
    """Apply NFKC unicode normalization."""
    return unicodedata.normalize("NFKC", text)


def _is_printable_text(data: bytes) -> bool:
    """Check if bytes are valid printable UTF-8 text."""
    try:
        s = data.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return False
    # Reject if more than 10% non-printable (excluding whitespace).
    non_printable = sum(1 for c in s if not c.isprintable() and c not in "\n\r\t ")
    return non_printable <= len(s) * 0.1


def decode_base64_blocks(text: str) -> str:
    """Find and decode inline base64 strings.

    Only decodes standalone tokens >= 8 chars that produce valid printable UTF-8.
    Single pass (no recursive decoding).
    """

    def _replace(m: re.Match) -> str:
        token = m.group(1)
        # Skip tokens that look like normal words (all lowercase alpha, no
        # digits, no uppercase mix that suggests encoding).
        if token.isalpha() and token.islower():
            return m.group(0)
        try:
            decoded = base64.b64decode(token, validate=True)
        except Exception:
            return m.group(0)
        if _is_printable_text(decoded):
            # Preserve surrounding delimiters from the original match.
            prefix = m.group(0)[: m.start(1) - m.start(0)]
            suffix = m.group(0)[m.end(1) - m.start(0) :]
            return prefix + decoded.decode("utf-8") + suffix
        return m.group(0)

    return _BASE64_BLOCK.sub(_replace, text)


def unescape_sequences(text: str) -> str:
    r"""Convert common escape sequences to actual characters.

    Handles: \xHH, \uHHHH, \\n, \\t, \\r, \\\\.
    Does NOT eval() anything.
    """
    # Protect literal \\ (double-backslash) from being partially consumed
    # by \xHH / \uHHHH regex subs.  Use a placeholder that cannot appear
    # in valid input, then restore after all other processing.
    _BKSL_PLACEHOLDER = "\x00BKSL\x00"
    text = text.replace("\\\\", _BKSL_PLACEHOLDER)

    # Hex / unicode escapes.
    text = _HEX_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), text)
    text = _UNICODE_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), text)

    # Simple escapes (\n, \t, \r) — skip \\\\ which is already handled.
    for seq, char in _SIMPLE_ESCAPES.items():
        if seq == "\\\\":
            continue
        text = text.replace(seq, char)

    # Restore literal backslashes.
    text = text.replace(_BKSL_PLACEHOLDER, "\\")
    return text


def expand_string_concat(text: str) -> str:
    """Join adjacent string literal concatenations.

    "abc" + "def" -> "abcdef"
    'abc' + 'def' -> 'abcdef'

    Iterates until no more concatenations remain (handles chains like "a"+"b"+"c").
    Does NOT expand variables or function calls.
    """
    prev = None
    while prev != text:
        prev = text
        text = _CONCAT_DOUBLE.sub(r'"\1\2"', text)
        text = _CONCAT_SINGLE.sub(r"'\1\2'", text)
    return text


def deobfuscate(text: str) -> str:
    """Apply all deobfuscation transforms to text.

    Returns cleaned text for regex pattern matching.
    Transforms applied in order:
    1. strip_zero_width - Remove zero-width unicode characters
    2. strip_tag_chars - Remove Unicode Tag Characters (ASCII smuggling)
    3. strip_variation_selectors - Remove Variation Selectors
    4. strip_bidi_controls - Remove BiDi control characters
    5. strip_html_comments - Remove HTML comments with hidden instructions
    6. normalize_unicode - NFKC normalization (homoglyphs -> ASCII)
    7. decode_base64_blocks - Find and decode inline base64 strings
    8. unescape_sequences - Convert \\x and \\u escapes to characters
    9. expand_string_concat - Join adjacent string literals
    """
    text = strip_zero_width(text)
    text = strip_tag_chars(text)
    text = strip_variation_selectors(text)
    text = strip_bidi_controls(text)
    text = strip_html_comments(text)
    text = normalize_unicode(text)
    text = decode_base64_blocks(text)
    text = unescape_sequences(text)
    text = expand_string_concat(text)
    return text
