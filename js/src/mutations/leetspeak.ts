const LEET_MAP: Record<string, string> = {
  a: "4", e: "3", i: "1", o: "0",
  s: "5", t: "7", l: "1", g: "9",
};

/** Convert to leetspeak. */
export function leetspeak(text: string): string {
  const result: string[] = [];
  for (const ch of text) {
    const repl = LEET_MAP[ch.toLowerCase()];
    if (repl && /[a-zA-Z]/.test(ch)) {
      result.push(repl);
    } else {
      result.push(ch);
    }
  }
  return result.join("");
}
