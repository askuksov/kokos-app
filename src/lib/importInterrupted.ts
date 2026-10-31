// A vault lock tears down the whole vault tree (and with it any running text
// import). This in-memory flag lets the lock screen tell the user what became
// of the import: "saved" = a sealed review snapshot waits for the unlock,
// "discarded" = the analysis was still running and was stopped. Per vault id;
// never persisted.
export type ImportInterruption = "saved" | "discarded";

const interrupted = new Map<string, ImportInterruption>();

export function markImportInterrupted(vaultId: string, kind: ImportInterruption) {
  interrupted.set(vaultId, kind);
}

/// Returns the mark once and clears it.
export function takeImportInterrupted(vaultId: string): ImportInterruption | null {
  const k = interrupted.get(vaultId) ?? null;
  interrupted.delete(vaultId);
  return k;
}
