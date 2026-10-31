import { useCallback, useEffect } from "react";
import { Sidebar } from "../components/Sidebar";
import { EntryList } from "../components/EntryList";
import { EntryDetail } from "../components/EntryDetail";
import { SaveErrorBanner } from "../components/SaveErrorBanner";
import { ClipboardPill } from "../components/ClipboardPill";
import { useVault } from "../state/VaultContext";
import { useSettings } from "../state/SettingsContext";
import { lockVault, noteActivity } from "../ipc/commands";
import { useHotkeys } from "../hooks/useHotkeys";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { VAULT_LOCKED } from "../lib/events";
import { clearClipboard } from "../lib/clipboard";
import { useClipboard } from "../state/ClipboardContext";

/// Anything matching this owns Escape while it is open, so the screen-level
/// Escape handler (clear the search, else clear the selection) stands down.
const ESC_OVERLAYS = '[role="dialog"], .kv-modal-scrim, .kv-lb-scrim, .kv-search-pop, .kv-bulk-pop';

export function VaultScreen() {
  const {
    saveError,
    route,
    refreshStatus,
    setRoute,
    focusSearch,
    search,
    setSearch,
    select,
  } = useVault();
  const { settings } = useSettings();
  const { reset: resetClipboard } = useClipboard();
  const onNewEntry = useCallback(() => {
    setRoute("main");
  }, [setRoute]);
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
    if (route !== "main") return;
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
  }, [route, search, setSearch, select]);
  useHotkeys({
    "mod+n": onNewEntry,
    "mod+l": () => void onLock(),
    "mod+f": focusSearch,
    "/": focusSearch,
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
      className={"kv-window" + (saveError ? " has-banner" : "")}
      data-density={settings.density}
    >
      <SaveErrorBanner />
      <Sidebar />
      <EntryList onNewEntry={onNewEntry} />
      <EntryDetail onEdit={() => {}} onNewEntry={onNewEntry} />
      <ClipboardPill />
    </div>
  );
}
