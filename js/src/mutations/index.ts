export { base64Wrap } from "./base64-wrap.js";
export { rot13Wrap } from "./rot13-wrap.js";
export { unicodeHomoglyphs } from "./unicode-homoglyphs.js";
export { zeroWidthInject } from "./zero-width-inject.js";
export { leetspeak } from "./leetspeak.js";
export { caseScramble } from "./case-scramble.js";
export { reverseEmbed } from "./reverse-embed.js";
export { prefixPadding } from "./prefix-padding.js";
export { generateMutations } from "./generate.js";

import { base64Wrap } from "./base64-wrap.js";
import { rot13Wrap } from "./rot13-wrap.js";
import { unicodeHomoglyphs } from "./unicode-homoglyphs.js";
import { zeroWidthInject } from "./zero-width-inject.js";
import { leetspeak } from "./leetspeak.js";
import { caseScramble } from "./case-scramble.js";
import { reverseEmbed } from "./reverse-embed.js";
import { prefixPadding } from "./prefix-padding.js";

/** Registry of all transform functions by name. */
export const TRANSFORMS: Record<string, (text: string) => string> = {
  base64_wrap: base64Wrap,
  rot13_wrap: rot13Wrap,
  unicode_homoglyphs: unicodeHomoglyphs,
  zero_width_inject: zeroWidthInject,
  leetspeak,
  case_scramble: caseScramble,
  reverse_embed: reverseEmbed,
  prefix_padding: prefixPadding,
};
