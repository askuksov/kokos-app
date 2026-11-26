// A restore whose vault opened but whose Drive binding failed. Opening the
// vault replaces the welcome screen, and the restore wizard with it, before
// the binding answers, so the failure is parked here, keyed by the restored
// vault's id (its path), until that vault's screen is mounted to show it.
const pending = new Map<string, string>();
const listeners = new Set<() => void>();

export function reportRestoreBindFailure(vaultId: string, error: string) {
  pending.set(vaultId, error);
  listeners.forEach((l) => l());
}

export function takeRestoreBindFailure(vaultId: string): string | null {
  const e = pending.get(vaultId);
  if (e === undefined) return null;
  pending.delete(vaultId);
  return e;
}

export function onRestoreBindFailure(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}
