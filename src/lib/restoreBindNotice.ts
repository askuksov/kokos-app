// A restore whose vault opened but whose Drive binding failed. Opening the
// vault replaces the welcome screen, and the restore wizard with it, before
// the binding answers, so the failure is parked here and shown by the vault
// screen that is mounted (or mounts next).
let pending: string | null = null;
const listeners = new Set<() => void>();

export function reportRestoreBindFailure(error: string) {
  pending = error;
  listeners.forEach((l) => l());
}

export function takeRestoreBindFailure(): string | null {
  const e = pending;
  pending = null;
  return e;
}

export function onRestoreBindFailure(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}
