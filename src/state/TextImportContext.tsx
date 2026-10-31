import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { listen } from "@tauri-apps/api/event";
import { useVault } from "./VaultContext";
import { aiTextImportCancel, aiTextImportDiscard, aiTextImportHasStash, aiTextImportRestore } from "../ipc/commands";
import { VAULT_LOCKED } from "../lib/events";
import { markImportInterrupted } from "../lib/importInterrupted";
import type { TextImportReport } from "../ipc/types";

export type ImportSource = { kind: "file"; path: string } | { kind: "folder"; dir: string };

/// Review snapshot sealed in the backend (see `ai_text_import_stash`): source +
/// the user's edited drafts, restored after the vault is unlocked again.
export interface ImportSnapshot {
  source: ImportSource;
  entries: unknown[];
  unparsed: unknown[];
  entriesDropped?: number;
}

interface TextImportCtx {
  source: ImportSource | null;
  snapshot: ImportSnapshot | null;
  minimized: boolean;
  lastReport: TextImportReport | null;
  start: (src: ImportSource) => void;
  minimize: () => void;
  resume: () => void;
  close: () => void;
  finish: (report: TextImportReport) => Promise<void>;
  dismissToast: () => void;
}

const Ctx = createContext<TextImportCtx | null>(null);

export function TextImportProvider({ children }: { children: ReactNode }) {
  const { refreshEntries, refreshFolders, refreshTags, vaultId } = useVault();
  const [source, setSource] = useState<ImportSource | null>(null);
  const [snapshot, setSnapshot] = useState<ImportSnapshot | null>(null);
  const [minimized, setMinimized] = useState(false);
  const [lastReport, setLastReport] = useState<TextImportReport | null>(null);

  // A lock unmounts this provider (App.tsx renders only unlocked vaults), which
  // drops the proposal with its secrets. Stop the backend analysis and leave a
  // note for the lock screen so the loss is never silent.
  const sourceRef = useRef(source);
  sourceRef.current = source;
  useEffect(() => {
    const un = listen<{ vault_id: string | null } | null>(VAULT_LOCKED, (e) => {
      if (!sourceRef.current) return;
      const id = e.payload?.vault_id ?? null;
      if (id !== null && id !== vaultId) return;
      void aiTextImportCancel();
      if (!vaultId) return;
      // Review in progress → its sealed snapshot survives; analysis still
      // running → nothing to keep.
      void aiTextImportHasStash(vaultId)
        .catch(() => false)
        .then((saved) => markImportInterrupted(vaultId, saved ? "saved" : "discarded"));
    });
    return () => {
      void un.then((f) => f());
    };
  }, [vaultId]);

  // Mounted = this vault is unlocked: pick up a snapshot sealed before a lock.
  useEffect(() => {
    if (!vaultId) return;
    let ignore = false;
    aiTextImportRestore(vaultId)
      .then((raw) => {
        if (ignore || !raw) return;
        try {
          const snap = JSON.parse(raw) as ImportSnapshot;
          setSnapshot(snap);
          setSource(snap.source);
          setMinimized(false);
        } catch {
          void aiTextImportDiscard(vaultId);
        }
      })
      .catch(() => {});
    return () => {
      ignore = true;
    };
  }, [vaultId]);

  const start = useCallback((src: ImportSource) => {
    // A new import supersedes any older sealed review of this vault.
    if (vaultId) void aiTextImportDiscard(vaultId);
    setSnapshot(null);
    setSource(src);
    setMinimized(false);
  }, [vaultId]);
  const minimize = useCallback(() => setMinimized(true), []);
  const resume = useCallback(() => setMinimized(false), []);
  const close = useCallback(() => {
    if (vaultId) void aiTextImportDiscard(vaultId);
    setSource(null);
    setSnapshot(null);
    setMinimized(false);
  }, [vaultId]);
  const finish = useCallback(
    async (report: TextImportReport) => {
      await Promise.all([refreshEntries(), refreshFolders(), refreshTags()]).catch((e) =>
        console.error("post-text-import refresh failed:", e),
      );
      if (vaultId) void aiTextImportDiscard(vaultId);
      setLastReport(report);
      setSource(null);
      setSnapshot(null);
      setMinimized(false);
    },
    [refreshEntries, refreshFolders, refreshTags, vaultId],
  );
  const dismissToast = useCallback(() => setLastReport(null), []);

  const value = useMemo(
    () => ({ source, snapshot, minimized, lastReport, start, minimize, resume, close, finish, dismissToast }),
    [source, snapshot, minimized, lastReport, start, minimize, resume, close, finish, dismissToast],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useTextImport(): TextImportCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error("useTextImport must be used within a TextImportProvider");
  return c;
}
