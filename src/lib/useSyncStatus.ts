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
  const refreshRef = useRef<() => Promise<void>>(async () => {});

  useEffect(() => {
    if (!vaultId) {
      setStatus(null);
      setPhase("idle");
      refreshRef.current = async () => {};
      return;
    }
    setPhase("idle");
    let ignore = false;
    const refresh = async () => {
      try {
        const s = await syncStatus(vaultId);
        if (!ignore) setStatus(s);
      } catch {
        if (!ignore) setStatus(null);
      }
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

  const syncNow = async () => {
    setPhase("syncing");
    try {
      const o = await syncNowCmd(vaultId);
      if (o.requires_reopen) {
        await refreshStatus();
      }
      try {
        setStatus(await syncStatus(vaultId));
      } catch {
      }
      setPhase("idle");
    } catch {
      setPhase("error");
      try {
        setStatus(await syncStatus(vaultId));
      } catch {
      }
    }
  };

  return { view: deriveSyncView(status, phase), busy: phase === "syncing", syncNow, refresh };
}
