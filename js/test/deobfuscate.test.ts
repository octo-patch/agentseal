import { describe, it, expect } from "vitest";
import {
  deobfuscate,
  stripZeroWidth,
  stripTagChars,
  stripVariationSelectors,
  stripBidiControls,
  stripHtmlComments,
  hasInvisibleChars,
  normalizeUnicode,
  decodeBase64Blocks,
  unescapeSequences,
  expandStringConcat,
} from "../src/deobfuscate.js";

// ═══════════════════════════════════════════════════════════════════════
// STRIP FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════

describe("stripZeroWidth", () => {
  it("removes U+200B, U+200C, U+200D, U+FEFF, U+00AD, U+2060", () => {
    expect(stripZeroWidth("hel\u200Blo\u200Cwor\u200Dld\uFEFF")).toBe(
      "helloworld"
    );
    expect(stripZeroWidth("te\u00ADst\u2060")).toBe("test");
  });

  it("preserves normal text", () => {
    expect(stripZeroWidth("hello world")).toBe("hello world");
  });

  it("handles empty string", () => {
    expect(stripZeroWidth("")).toBe("");
  });
});

describe("stripTagChars", () => {
  it("removes Unicode Tag Characters U+E0001-U+E007F", () => {
    const smuggled = "he\u{E0001}ll\u{E0041}o";
    expect(stripTagChars(smuggled)).toBe("hello");
  });
});

describe("stripVariationSelectors", () => {
  it("removes U+FE00-FE0F variation selectors", () => {
    expect(stripVariationSelectors("te\uFE0Fst")).toBe("test");
  });
});

describe("stripBidiControls", () => {
  it("removes BiDi override characters", () => {
    expect(stripBidiControls("he\u202Allo\u202B")).toBe("hello");
    expect(stripBidiControls("a\u200Eb\u200F")).toBe("ab");
  });
});

describe("stripHtmlComments", () => {
  it("removes HTML comments", () => {
    expect(stripHtmlComments("before<!-- hidden -->after")).toBe("beforeafter");
  });

  it("removes multiline HTML comments", () => {
    expect(
      stripHtmlComments("start<!--\nhidden\ninstruction\n-->end")
    ).toBe("startend");
  });

  it("preserves text without comments", () => {
    expect(stripHtmlComments("no comments here")).toBe("no comments here");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// INVISIBLE CHARACTER DETECTION
// ═══════════════════════════════════════════════════════════════════════

describe("hasInvisibleChars", () => {
  it("detects zero-width characters", () => {
    expect(hasInvisibleChars("he\u200Bllo")).toBe(true);
  });

  it("detects BiDi controls", () => {
    expect(hasInvisibleChars("he\u202Allo")).toBe(true);
  });

  it("returns false for normal text", () => {
    expect(hasInvisibleChars("hello world")).toBe(false);
  });

  it("returns false for empty string", () => {
    expect(hasInvisibleChars("")).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// UNICODE NORMALIZATION
// ═══════════════════════════════════════════════════════════════════════

describe("normalizeUnicode", () => {
  it("normalizes fullwidth characters to ASCII", () => {
    expect(normalizeUnicode("\uFF21")).toBe("A"); // Fullwidth A
    expect(normalizeUnicode("\uFF42")).toBe("b"); // Fullwidth b
  });

  it("normalizes common homoglyphs via NFKC", () => {
    // Ligatures
    expect(normalizeUnicode("\uFB01")).toBe("fi"); // fi ligature
  });

  it("preserves normal ASCII", () => {
    expect(normalizeUnicode("hello")).toBe("hello");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// BASE64 DECODING
// ═══════════════════════════════════════════════════════════════════════

describe("decodeBase64Blocks", () => {
  it("decodes inline base64 strings", () => {
    const result = decodeBase64Blocks("the key is aGVsbG8gd29ybGQ= here");
    expect(result).toContain("hello world");
  });

  it("leaves short strings alone", () => {
    expect(decodeBase64Blocks("abc")).toBe("abc");
  });

  it("leaves normal lowercase words alone", () => {
    expect(decodeBase64Blocks("function something return")).toBe(
      "function something return"
    );
  });

  it("handles base64 in quotes", () => {
    const result = decodeBase64Blocks('"aGVsbG8="');
    expect(result).toContain("hello");
  });

  it("leaves invalid base64 untouched", () => {
    expect(decodeBase64Blocks("NOT!VALID!BASE64!!")).toBe(
      "NOT!VALID!BASE64!!"
    );
  });
});

// ═══════════════════════════════════════════════════════════════════════
// ESCAPE SEQUENCE HANDLING
// ═══════════════════════════════════════════════════════════════════════

describe("unescapeSequences", () => {
  it("unescapes hex sequences", () => {
    expect(unescapeSequences("\\x41\\x42")).toBe("AB");
  });

  it("unescapes unicode sequences", () => {
    expect(unescapeSequences("\\u0041")).toBe("A");
    expect(unescapeSequences("\\u0048\\u0069")).toBe("Hi");
  });

  it("unescapes simple escapes", () => {
    expect(unescapeSequences("line1\\nline2")).toBe("line1\nline2");
    expect(unescapeSequences("col1\\tcol2")).toBe("col1\tcol2");
  });

  it("preserves literal backslashes", () => {
    expect(unescapeSequences("path\\\\file")).toBe("path\\file");
  });

  it("handles mixed escapes", () => {
    expect(unescapeSequences("\\x48\\u0065llo\\nworld")).toBe("Hello\nworld");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// STRING CONCATENATION
// ═══════════════════════════════════════════════════════════════════════

describe("expandStringConcat", () => {
  it("expands double-quoted concatenation", () => {
    expect(expandStringConcat('"~/.s" + "sh"')).toBe('"~/.ssh"');
  });

  it("expands single-quoted concatenation", () => {
    expect(expandStringConcat("'~/.s' + 'sh'")).toBe("'~/.ssh'");
  });

  it("expands chained concatenation", () => {
    expect(expandStringConcat('"a" + "b" + "c"')).toBe('"abc"');
  });

  it("does not expand variables", () => {
    const text = 'var + "foo"';
    expect(expandStringConcat(text)).toBe(text);
  });

  it("does not expand mixed quotes", () => {
    const text = '"a" + \'b\'';
    expect(expandStringConcat(text)).toBe(text);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// FULL PIPELINE
// ═══════════════════════════════════════════════════════════════════════

describe("deobfuscate", () => {
  it("applies full pipeline: zero-width + base64 + concat", () => {
    const text = '\u200Bcat\u200C "~/.s" + "sh/id_rsa"';
    const result = deobfuscate(text);
    expect(result).toContain("~/.ssh/id_rsa");
    expect(result).not.toContain("\u200B");
  });

  it("is idempotent", () => {
    const text = '\u200Bhello\u200C world aGVsbG8=';
    const once = deobfuscate(text);
    const twice = deobfuscate(once);
    expect(once).toBe(twice);
  });

  it("returns empty string for empty input", () => {
    expect(deobfuscate("")).toBe("");
  });

  it("passes through pure ASCII unchanged", () => {
    const text = "Just normal text with no tricks.";
    expect(deobfuscate(text)).toBe(text);
  });

  it("handles combined obfuscation techniques", () => {
    // Zero-width in path + HTML comment with hidden instruction
    const text =
      '<!-- ignore this -->r\u200Be\u200Bad "\\x2F\\x65\\x74\\x63\\x2F\\x70\\x61\\x73\\x73\\x77\\x64"';
    const result = deobfuscate(text);
    expect(result).toContain("read");
    expect(result).toContain("/etc/passwd");
    expect(result).not.toContain("<!--");
  });

  it("performs well on large text", () => {
    const big = "normal text ".repeat(8000); // ~96KB
    const start = performance.now();
    deobfuscate(big);
    const elapsed = performance.now() - start;
    expect(elapsed).toBeLessThan(1000); // under 1s
  });
});
