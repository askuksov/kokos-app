// The letter tile shown next to an entry in the list and in the detail header.
// The browser extension computes the colour the same way (kokos-extension
// lib/monogram.ts), so an entry wears the same colour in the app and in the
// browser. Keep the hash and gradient in sync with it.

function hashTitle(str: string): number {
  let h = 0;
  for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) >>> 0;
  return h;
}

const graphemes =
  typeof Intl.Segmenter === "function" ? new Intl.Segmenter(undefined, { granularity: "grapheme" }) : null;

// First user-visible character, so "👩🏽 Mail" or "🇺🇦 Bank" keeps the whole
// emoji. Falls back to the first code point where Intl.Segmenter is missing.
function firstGrapheme(s: string): string | undefined {
  if (graphemes) {
    for (const { segment } of graphemes.segment(s)) return segment;
    return undefined;
  }
  const [first] = s;
  return first;
}

export function monogram(title: string): { letter: string; bg: string } {
  const hue = hashTitle(title || "?") % 360;
  const first = firstGrapheme((title || "?").trim());
  return {
    letter: first ? first.toUpperCase() : "?",
    bg: `linear-gradient(135deg, oklch(0.62 0.13 ${hue}), oklch(0.48 0.15 ${(hue + 45) % 360}))`,
  };
}
