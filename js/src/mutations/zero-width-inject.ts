const ZW_CHARS = ["\u200b", "\u200c", "\u200d", "\ufeff"];
const KEYWORDS = ["system", "prompt", "instructions", "reveal", "show", "display", "output", "share"];

/** Insert zero-width characters between keywords to bypass filters. */
export function zeroWidthInject(text: string): string {
  let result = text;
  for (const keyword of KEYWORDS) {
    const idx = result.toLowerCase().indexOf(keyword);
    if (idx === -1) continue;
    const original = result.slice(idx, idx + keyword.length);
    let injected = "";
    for (let j = 0; j < original.length; j++) {
      injected += original[j];
      if (j < original.length - 1) {
        injected += ZW_CHARS[j % ZW_CHARS.length];
      }
    }
    result = result.slice(0, idx) + injected + result.slice(idx + keyword.length);
  }
  return result;
}
