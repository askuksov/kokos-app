// A tray "Settings…" click that arrived while no unlocked vault screen was
// mounted. The tab bar switches to an unlocked tab and that tab's vault screen
// consumes the request when it mounts. The request names its target vault, is
// dropped by whichever vault screen mounts next, and is cleared by any other
// tab switch, so a superseded switch cannot open Settings later.
let pending: string | null = null;

export function requestTraySettings(vaultId: string) {
  pending = vaultId;
}

export function takeTraySettingsRequest(vaultId: string): boolean {
  const hit = pending === vaultId;
  pending = null;
  return hit;
}

export function clearTraySettingsRequest() {
  pending = null;
}
