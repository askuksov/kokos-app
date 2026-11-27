import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { listen } from "@tauri-apps/api/event";
import { useVault } from "./VaultContext";
import { useSettings } from "./SettingsContext";
import {
  aiTextImportAnalyze,
  aiTextImportAnalyzeFolder,
  aiTextImportCancel,
  aiTextImportCommit,
  aiTextImportDiscard,
  aiTextImportHasStash,
  aiTextImportRestore,
} from "../ipc/commands";
import { VAULT_LOCKED } from "../lib/events";
import { markImportInterrupted } from "../lib/importInterrupted";
import type { CommitProposal, ImportProposal, TextImportReport } from "../ipc/types";

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
  /** The analysis of `src`: started on the first call, the same promise for
   *  every later call while `src` is the current import (a remounted review
   *  joins the run instead of starting a second one). */
  analyze: (src: ImportSource) => Promise<ImportProposal>;
  /** Remember the review's current state so a remount resumes it. */
  keepReview: (snap: ImportSnapshot) => void;
  /** The review state last passed to `keepReview` for the current import. */
  keptReview: () => ImportSnapshot | null;
  /** Commit the reviewed drafts once and `finish` the import on success. A
   *  second call while one is in flight returns the same promise. */
  commit: (proposal: CommitProposal) => Promise<TextImportReport>;
  /** The commit in flight for the current import, if any (a remounted review
   *  opens in the committing phase instead of offering Import again). */
  pendingCommit: () => Promise<TextImportReport> | null;
}

/** Failures a later attempt can get past (another run finishing, the model
 *  still loading): the cached run is dropped so a retry starts afresh. */
function isTransientAnalyzeError(e: unknown): boolean {
  const s = String(e);
  return s.includes("import_in_progress") || s.includes("gen_model_not_ready");
}

const Ctx = createContext<TextImportCtx | null>(null);

export function TextImportProvider({ children }: { children: ReactNode }) {
  const { refreshEntries, refreshFolders, refreshTags, vaultId } = useVault();
  const { refresh: refreshSettings } = useSettings();
  const [source, setSource] = useState<ImportSource | null>(null);
  const [snapshot, setSnapshot] = useState<ImportSnapshot | null>(null);
  const [minimized, setMinimized] = useState(false);
  const [lastReport, setLastReport] = useState<TextImportReport | null>(null);

  // The review panel unmounts whenever another tab or the welcome screen takes
  // over, and on minimize. The run and the edited review live here, so the
  // remounted panel neither re-fires the analysis nor loses the user's edits.
  const runRef = useRef<{ source: ImportSource; promise: Promise<ImportProposal> } | null>(null);
  const keptRef = useRef<ImportSnapshot | null>(null);
  const commitRef = useRef<Promise<TextImportReport> | null>(null);
  const resetRun = useCallback(() => {
    runRef.current = null;
    keptRef.current = null;
    commitRef.current = null;
  }, []);
  const analyze = useCallback((src: ImportSource) => {
    if (runRef.current?.source === src) return runRef.current.promise;
    const promise = src.kind === "folder" ? aiTextImportAnalyzeFolder(src.dir) : aiTextImportAnalyze([src.path]);
    runRef.current = { source: src, promise };
    // Each caller handles the rejection on its own; here only a transient
    // failure un-caches the run, so a retry or remount analyzes again.
    promise.catch((e) => {
      if (isTransientAnalyzeError(e) && runRef.current?.promise === promise) runRef.current = null;
    });
    return promise;
  }, []);
  const keepReview = useCallback((snap: ImportSnapshot) => {
    keptRef.current = snap;
  }, []);
  const keptReview = useCallback(() => keptRef.current, []);

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
    resetRun();
    setSnapshot(null);
    setSource(src);
    setMinimized(false);
  }, [vaultId, resetRun]);
  const minimize = useCallback(() => setMinimized(true), []);
  const resume = useCallback(() => setMinimized(false), []);
  const close = useCallback(() => {
    if (vaultId) void aiTextImportDiscard(vaultId);
    resetRun();
    setSource(null);
    setSnapshot(null);
    setMinimized(false);
  }, [vaultId, resetRun]);
  const finish = useCallback(
    async (report: TextImportReport) => {
      await Promise.all([refreshEntries(), refreshFolders(), refreshTags()]).catch((e) =>
        console.error("post-text-import refresh failed:", e),
      );
      if (vaultId) void aiTextImportDiscard(vaultId);
      resetRun();
      setLastReport(report);
      setSource(null);
      setSnapshot(null);
      setMinimized(false);
    },
    [refreshEntries, refreshFolders, refreshTags, vaultId, resetRun],
  );
  const dismissToast = useCallback(() => setLastReport(null), []);
  const commit = useCallback(
    (proposal: CommitProposal) => {
      if (commitRef.current) return commitRef.current;
      // Finishing here, not in the review: the panel may be unmounted (another
      // tab) when the commit lands, and must not be able to commit twice.
      const promise = aiTextImportCommit(proposal, vaultId).then(async (report) => {
        await refreshSettings().catch(() => {});
        await finish(report);
        return report;
      });
      commitRef.current = promise;
      promise.catch(() => {
        if (commitRef.current === promise) commitRef.current = null;
      });
      return promise;
    },
    [vaultId, refreshSettings, finish],
  );
  const pendingCommit = useCallback(() => commitRef.current, []);

  const value = useMemo(
    () => ({
      source,
      snapshot,
      minimized,
      lastReport,
      start,
      minimize,
      resume,
      close,
      finish,
      dismissToast,
      analyze,
      keepReview,
      keptReview,
      commit,
      pendingCommit,
    }),
    [
      source,
      snapshot,
      minimized,
      lastReport,
      start,
      minimize,
      resume,
      close,
      finish,
      dismissToast,
      analyze,
      keepReview,
      keptReview,
      commit,
      pendingCommit,
    ],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useTextImport(): TextImportCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error("useTextImport must be used within a TextImportProvider");
  return c;
}
