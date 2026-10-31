export const IS_MAC = /Mac|iPhone|iPad/.test(
  navigator.userAgent || navigator.platform || "",
);

export const IS_WINDOWS = /Windows/.test(
  navigator.userAgent || navigator.platform || "",
);

export function modKey(key: string): string {
  return IS_MAC ? `⌘${key}` : `Ctrl+${key}`;
}
