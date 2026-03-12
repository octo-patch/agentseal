/** Alternating case scramble. */
export function caseScramble(text: string): string {
  const result: string[] = [];
  let toggle = false;
  for (const ch of text) {
    if (/[a-zA-Z]/.test(ch)) {
      result.push(toggle ? ch.toUpperCase() : ch.toLowerCase());
      toggle = !toggle;
    } else {
      result.push(ch);
    }
  }
  return result.join("");
}
