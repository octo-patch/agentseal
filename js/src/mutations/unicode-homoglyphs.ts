const REPLACEMENTS: Record<string, string> = {
  a: "\u0430", // Cyrillic а
  e: "\u0435", // Cyrillic е
  o: "\u043e", // Cyrillic о
  p: "\u0440", // Cyrillic р
  c: "\u0441", // Cyrillic с
  x: "\u0445", // Cyrillic х
  y: "\u0443", // Cyrillic у
  i: "\u0456", // Cyrillic і
};

/** Replace Latin chars with Cyrillic/Greek lookalikes. */
export function unicodeHomoglyphs(text: string): string {
  const result: string[] = [];
  for (const ch of text) {
    const repl = REPLACEMENTS[ch.toLowerCase()];
    if (repl && /[a-zA-Z]/.test(ch)) {
      result.push(ch === ch.toUpperCase() ? repl.toUpperCase() : repl);
    } else {
      result.push(ch);
    }
  }
  return result.join("");
}
