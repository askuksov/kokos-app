import { useCallback, useEffect, useState } from "react";
import { Sidebar } from "../components/Sidebar";
import { EntryList } from "../components/EntryList";
import { EntryDetail } from "../components/EntryDetail";
import { GettingStarted } from "../components/GettingStarted";
import { EntryEditor } from "../components/EntryEditor";
import { SaveErrorBanner } from "../components/SaveErrorBanner";
import { ManageFolders } from "../components/ManageFolders";
import { ManageTags } from "../components/ManageTags";
import { Trash } from "../components/Trash";
import { Settings } from "../components/Settings";
import { CommandPalette } from "../components/CommandPalette";
import { ClipboardPill } from "../components/ClipboardPill";
import { SyncReopenBanner } from "../components/SyncReopenBanner";
import { TextImportReview } from "../components/TextImportReview";
import { ImportDoneToast } from "../components/ImportDoneToast";
import { useVault } from "../state/VaultContext";
import { useSettings } from "../state/SettingsContext";
import { useTextImport } from "../state/TextImportContext";
import { lockVault, noteActivity } from "../ipc/commands";
import { useHotkeys } from "../hooks/useHotkeys";
import { useSyncStatus } from "../lib/useSyncStatus";
import { useOnboarding } from "../lib/useOnboarding";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { VAULT_LOCKED } from "../lib/events";
import { clearClipboard } from "../lib/clipboard";
import { useClipboard } from "../state/ClipboardContext";

type EditorState =
  | null
  | { mode: "create"; folderId: string | null; tagId: string | null }
  | { mode: "edit"; id: string };

/// Anything matching this owns Escape while it is open, so the screen-level
/// Escape handler (clear the search, else clear the selection) stands down.
const ESC_OVERLAYS = '[role="dialog"], .kv-modal-scrim, .kv-lb-scrim, .kv-search-pop, .kv-bulk-pop';

export function VaultScreen() {
  const {
    vaultId,
    saveError,
    route,
    refreshStatus,
    setRoute,
    focusSearch,
    nav,
    remoteNewer,
    dismissRemoteNewer,
    search,
    setSearch,
    select,
  } = useVault();
  const { source, snapshot, minimized, minimize, resume, close, finish, lastReport, dismissToast } = useTextImport();
  const { settings } = useSettings();
  const onboarding = useOnboarding();
  const { reset: resetClipboard } = useClipboard();
  const [editor, setEditor] = useState<EditorState>(null);
  const [detailVersion, setDetailVersion] = useState(0);
  const [paletteOpen, setPaletteOpen] = useState(false);

  const { syncNow: applySync, busy: reopenBusy } = useSyncStatus(vaultId, refreshStatus);
  async function doReopen() {
    await applySync();
  }
  const onNewEntry = useCallback(() => {
    setRoute("main");
    setEditor((prev) =>
      prev?.mode === "create"
        ? prev
        : {
            mode: "create",
            folderId: nav.kind === "folder" ? nav.id : null,
            tagId: nav.kind === "tag" ? nav.id : null,
          },
    );
  }, [setRoute, nav]);
  const onLock = useCallback(async () => {
    try {
      void clearClipboard();
      resetClipboard();
      await lockVault();
      await refreshStatus();
    } catch (e) {
      console.error("lock_vault failed:", e);
    }
  }, [refreshStatus, resetClipboard]);
  const onEscape = useCallback(() => {
    if (route !== "main" || editor || paletteOpen || (source && !minimized)) return;
    // HistoryModal, the attachment lightbox and the sidebar's filter popover
    // close on their own document-level Escape without stopping the event, so
    // without this check one press would both close the overlay and drop the
    // selection.
    if (document.querySelector(ESC_OVERLAYS)) return;
    const el = document.activeElement;
    if (search && el instanceof HTMLInputElement && el.closest(".kv-search-hint")) {
      setSearch("");
      return;
    }
    select(null);
  }, [route, editor, paletteOpen, source, minimized, search, setSearch, select]);
  useHotkeys({
    "mod+n": onNewEntry,
    "mod+l": () => void onLock(),
    "mod+f": focusSearch,
    "/": focusSearch,
    "mod+k": () => setPaletteOpen((o) => !o),
    escape: onEscape,
  });

  useEffect(() => {
    let last = 0;
    const ping = () => {
      const now = Date.now();
      if (now - last > 5000) {
        last = now;
        void noteActivity();
      }
    };
    document.addEventListener("pointerdown", ping);
    document.addEventListener("keydown", ping);
    const un = listen(VAULT_LOCKED, () => {
      void clearClipboard();
      resetClipboard();
      void refreshStatus();
    });
    return () => {
      document.removeEventListener("pointerdown", ping);
      document.removeEventListener("keydown", ping);
      un.then((f) => f());
    };
  }, [refreshStatus, resetClipboard]);

  useEffect(() => {
    const un = getCurrentWindow().onFocusChanged(({ payload: focused }) => {
      if (!focused && settings.lock_on_blur) void onLock();
    });
    return () => {
      un.then((f) => f());
    };
  }, [settings.lock_on_blur, onLock]);

  return (
    <div
      className={
        "kv-window" +
        (saveError ? " has-banner" : "") +
        (remoteNewer ? " has-reopen-banner" : "")
      }
      data-density={settings.density}
    >
      <SaveErrorBanner />
      {remoteNewer && (
        <SyncReopenBanner busy={reopenBusy} onReopen={doReopen} onDismiss={dismissRemoteNewer} />
      )}
      <Sidebar />
      {source && !minimized ? (
        <TextImportReview
          variant="panel"
          source={source}
          snapshot={snapshot}
          onClose={(report) => {
            if (report) void finish(report);
            else close();
          }}
        />
      ) : route === "manage-folders" ? (
        <ManageFolders />
      ) : route === "manage-tags" ? (
        <ManageTags />
      ) : route === "trash" ? (
        <Trash />
      ) : route === "settings" ? (
        <Settings />
      ) : editor ? (
        <EntryEditor
          entryId={editor.mode === "edit" ? editor.id : null}
          initialFolderId={editor.mode === "create" ? editor.folderId : null}
          initialTagId={editor.mode === "create" ? editor.tagId : null}
          onClose={() => setEditor(null)}
          onSaved={() => setDetailVersion((v) => v + 1)}
        />
      ) : (
        <>
          <EntryList onNewEntry={onNewEntry} />
          <EntryDetail
            key={detailVersion}
            emptyOverride={onboarding.visible ? <GettingStarted onboarding={onboarding} /> : null}
            onEdit={(id) => setEditor({ mode: "edit", id })}
            onNewEntry={onNewEntry}
          />
        </>
      )}
      {source && minimized && (
        <TextImportReview
          source={source}
          snapshot={snapshot}
          minimized={minimized}
          onMinimize={minimize}
          onResume={resume}
          onClose={(report) => {
            if (report) void finish(report);
            else close();
          }}
        />
      )}
      {lastReport && <ImportDoneToast report={lastReport} onDismiss={dismissToast} />}
      <ClipboardPill />
      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        onNewEntry={onNewEntry}
        onLock={onLock}
      />
    </div>
  );
}
