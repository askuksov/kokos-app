import { useEffect, useRef } from "react";

export type HotkeyHandler = (e: KeyboardEvent) => void;

const UNGUARDED = new Set(["escape", "mod+k"]);

function isEditable(el: Element | null): boolean {
  return el != null && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || (el as HTMLElement).isContentEditable);
}

export function useHotkeys(map: Record<string, HotkeyHandler>): void {
  const mapRef = useRef(map);
  mapRef.current = map;

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Meta" || e.key === "Control" || e.key === "Shift" || e.key === "Alt") return;
      const mod = e.metaKey || e.ctrlKey;
      const key = e.key.toLowerCase();
      const token = mod ? `mod+${key}` : key;
      const handler = mapRef.current[token];
      if (!handler) return;
      if (isEditable(document.activeElement) && !UNGUARDED.has(token)) return;
      e.preventDefault();
      handler(e);
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);
}
