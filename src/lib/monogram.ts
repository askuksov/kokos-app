// The letter tile shown next to an entry in the list and in the detail header.
// The browser extension computes the colour the same way (kokos-extension
// lib/monogram.ts), so an entry wears the same colour in the app and in the
// browser. Keep the hash and gradient in sync with it.

function hashTitle(str: string): number {
  let h = 0;
  for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) >>> 0;
  return h;
}

export function monogram(title: string): { letter: string; bg: string } {
  const hue = hashTitle(title || "?") % 360;
  // First code point, not first UTF-16 unit: an emoji title keeps its whole glyph.
  const [first] = (title || "?").trim();
  return {
    letter: first ? first.toUpperCase() : "?",
    bg: `linear-gradient(135deg, oklch(0.62 0.13 ${hue}), oklch(0.48 0.15 ${(hue + 45) % 360}))`,
  };
}
