// A tray "Settings…" click that arrived while no unlocked vault screen was
// mounted. The tab bar switches to an unlocked tab and the vault screen
// consumes the request when it mounts.
let pending = false;

export function requestTraySettings() {
  pending = true;
}

export function takeTraySettingsRequest(): boolean {
  const p = pending;
  pending = false;
  return p;
}
