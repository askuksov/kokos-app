import { detectRemoteChanges } from "../ipc/commands";
import type { SyncOutcome } from "../ipc/types";

export async function backgroundReconcile(vaultId?: string): Promise<SyncOutcome | null> {
  try {
    return await detectRemoteChanges(vaultId);
  } catch {
    return null;
  }
}
