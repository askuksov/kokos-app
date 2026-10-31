export interface TagColorPreset {
  id: string;
  name: string;
  hex: string;
}

export const TAG_COLORS: TagColorPreset[] = [
  { id: "red", name: "Red", hex: "#E5484D" },
  { id: "orange", name: "Orange", hex: "#F76B15" },
  { id: "amber", name: "Amber", hex: "#FFB224" },
  { id: "yellow", name: "Yellow", hex: "#F5D90A" },
  { id: "lime", name: "Lime", hex: "#99D52A" },
  { id: "green", name: "Green", hex: "#30A46C" },
  { id: "emerald", name: "Emerald", hex: "#3CB179" },
  { id: "teal", name: "Teal", hex: "#12A594" },
  { id: "cyan", name: "Cyan", hex: "#05A2C2" },
  { id: "sky", name: "Sky", hex: "#2EA6D6" },
  { id: "blue", name: "Blue", hex: "#4D8FD6" },
  { id: "indigo", name: "Indigo", hex: "#5B5BD6" },
  { id: "violet", name: "Violet", hex: "#7C66DC" },
  { id: "purple", name: "Purple", hex: "#8E4EC6" },
  { id: "pink", name: "Pink", hex: "#D6409F" },
  { id: "rose", name: "Rose", hex: "#E54666" },
];

const HEX = /^#[0-9a-fA-F]{6}$/;

/** A tag dot's color: its stored hex, or a neutral fallback token.
 * Falls back to `--text-3`, the dimmest of the three text tones defined in
 * tokens.css for both themes. The fallback must be a defined token: consumers
 * (e.g. Sidebar.tsx's tag list) use this value as a raw background, so an
 * undefined variable would leave an uncolored tag's `.kv-tag-dot` with no
 * fill. */
export function tagColor(color: string | null): string {
  return color && HEX.test(color) ? color : "var(--text-3)";
}
