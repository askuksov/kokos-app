import { useEffect, useState } from "react";
import { syncStatus, syncNow as syncNowCmd } from "../ipc/commands";
import type { SyncStatusInfo } from "../ipc/types";
import { deriveSyncView, type SyncPhase, type SyncView } from "./syncView";

export function useSyncStatus(
  vaultId: string | undefined,
  refreshStatus: () => Promise<void>,
): { view: SyncView; busy: boolean; syncNow: () => Promise<void> } {
  const [status, setStatus] = useState<SyncStatusInfo | null>(null);
  const [phase, setPhase] = useState<SyncPhase>("idle");

  useEffect(() => {
    if (!vaultId) {
      setStatus(null);
      setPhase("idle");
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
    refresh();
    const onRefresh = () => refresh();
    window.addEventListener("focus", onRefresh);
    return () => {
      ignore = true;
      window.removeEventListener("focus", onRefresh);
    };
  }, [vaultId]);

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

  return { view: deriveSyncView(status, phase), busy: phase === "syncing", syncNow };
}
