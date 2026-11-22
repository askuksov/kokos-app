import { useCallback, useEffect, useRef, useState } from "react";
import { syncStatus, syncNow as syncNowCmd } from "../ipc/commands";
import type { SyncStatusInfo } from "../ipc/types";
import { deriveSyncView, type SyncPhase, type SyncView } from "./syncView";

/** Fired by other sync controls (Settings → Sync) after they change the sync state. */
export const SYNC_STATUS_CHANGED = "kokos-sync-status-changed";

/**
 * `changeKey` is any value whose identity changes when the vault content
 * changes (the entry list); each change re-reads the status so "upload
 * pending" shows up without waiting for the window to regain focus.
 */
export function useSyncStatus(
  vaultId: string | undefined,
  refreshStatus: () => Promise<void>,
  changeKey?: unknown,
): { view: SyncView; busy: boolean; syncNow: () => Promise<void>; refresh: () => Promise<void> } {
  const [status, setStatus] = useState<SyncStatusInfo | null>(null);
  const [phase, setPhase] = useState<SyncPhase>("idle");
  const [readFailed, setReadFailed] = useState(false);
  const refreshRef = useRef<() => Promise<void>>(async () => {});
  // Every status read takes a number; only the latest one may write, so an
  // older answer that lands last cannot turn "Upload pending" back into "Synced".
  const statusSeq = useRef(0);

  useEffect(() => {
    if (!vaultId) {
      setStatus(null);
      setPhase("idle");
      setReadFailed(false);
      refreshRef.current = async () => {};
      return;
    }
    setPhase("idle");
    // Another vault's status must not show while this one loads or fails.
    setStatus(null);
    setReadFailed(false);
    let ignore = false;
    const refresh = async () => {
      const seq = ++statusSeq.current;
      await readStatus(vaultId, () => !ignore && seq === statusSeq.current);
    };
    refreshRef.current = refresh;
    refresh();
    const onRefresh = () => refresh();
    window.addEventListener("focus", onRefresh);
    window.addEventListener(SYNC_STATUS_CHANGED, onRefresh);
    return () => {
      ignore = true;
      window.removeEventListener("focus", onRefresh);
      window.removeEventListener(SYNC_STATUS_CHANGED, onRefresh);
    };
  }, [vaultId]);

  const isFirstChange = useRef(true);
  useEffect(() => {
    // The vaultId effect above already loads the status on mount.
    if (isFirstChange.current) {
      isFirstChange.current = false;
      return;
    }
    void refreshRef.current();
  }, [changeKey]);

  const refresh = useCallback(() => refreshRef.current(), []);

  // Writes only while `isLatest()` holds. A failed read keeps the last known
  // status and flags it, instead of reporting sync as off.
  async function readStatus(id: string | undefined, isLatest: () => boolean) {
    try {
      const s = await syncStatus(id);
      if (isLatest()) {
        setStatus(s);
        setReadFailed(false);
      }
    } catch (e) {
      console.error("sync_status failed:", e);
      if (isLatest()) setReadFailed(true);
    }
  }

  const syncNow = async () => {
    setPhase("syncing");
    try {
      const o = await syncNowCmd(vaultId);
      if (o.requires_reopen) {
        await refreshStatus();
      }
      const seq = ++statusSeq.current;
      await readStatus(vaultId, () => seq === statusSeq.current);
      setPhase("idle");
    } catch {
      setPhase("error");
      const seq = ++statusSeq.current;
      await readStatus(vaultId, () => seq === statusSeq.current);
    }
  };

  return { view: deriveSyncView(status, phase, readFailed), busy: phase === "syncing", syncNow, refresh };
}
