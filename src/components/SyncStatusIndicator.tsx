import { useEffect, useRef, useState, type ReactNode } from "react";
import { useVault } from "../state/VaultContext";
import { useT } from "../state/LangContext";
import { useSyncStatus } from "../lib/useSyncStatus";
import { SyncStatusPopover } from "./SyncStatusPopover";
import type { SyncVisualState } from "../lib/syncView";
import "./SyncStatusIndicator.css";

const STATE_LABEL_KEY: Record<SyncVisualState, string> = {
  synced: "sync.state.synced",
  syncing: "sync.syncing",
  warning: "sync.needsAttention",
  error: "sync.state.error",
  off: "sync.pill.off",
};

const STATE_GLYPH: Record<SyncVisualState, ReactNode> = {
  synced: (
    <g>
      <circle cx="12" cy="12" r="8.4" />
      <path d="M8.4 12.4l2.4 2.4 4.9-5.3" />
    </g>
  ),
  syncing: (
    <g>
      <path d="M19.5 12a7.5 7.5 0 10-2.2 5.3" />
      <path d="M19.7 6.7V12h-5.3" />
    </g>
  ),
  warning: (
    <g>
      <path d="M12 4.7l7.7 13.3H4.3L12 4.7z" />
      <path d="M12 10.2v3.5" />
      <circle cx="12" cy="16.3" r="0.7" fill="currentColor" stroke="none" />
    </g>
  ),
  error: (
    <g>
      <circle cx="12" cy="12" r="8.4" />
      <path d="M9.2 9.2l5.6 5.6M14.8 9.2l-5.6 5.6" />
    </g>
  ),
  off: (
    <g>
      <path d="M7 18a4 4 0 010-8 5 5 0 019.6-1.3A3.5 3.5 0 0117 18H7z" />
      <path d="M4.5 4.5l15 15" />
    </g>
  ),
};

function SyncIcon({ state }: { state: SyncVisualState }) {
  return (
    <svg
      className="kv-ico kv-sync-ind-ico"
      width={15}
      height={15}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.7}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {STATE_GLYPH[state]}
    </svg>
  );
}

export function SyncStatusIndicator() {
  const t = useT();
  const { vaultId, refreshStatus, setRoute, setSettingsTab } = useVault();
  const { view, busy, syncNow } = useSyncStatus(vaultId, refreshStatus);
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    function onPointerDown(e: PointerEvent) {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    }
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") {
        e.stopPropagation();
        setOpen(false);
        triggerRef.current?.focus();
      }
    }
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown, true);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown, true);
    };
  }, [open]);

  const openSyncSettings = () => {
    setSettingsTab("sync");
    setRoute("settings");
    setOpen(false);
  };

  return (
    <div className="kv-sync-indicator" ref={rootRef}>
      <button
        type="button"
        ref={triggerRef}
        className={`kv-side-item kv-sync-ind is-${view.state}`}
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        <SyncIcon state={view.state} />
        <span className="label">{t(STATE_LABEL_KEY[view.state])}</span>
      </button>
      {open ? (
        <SyncStatusPopover
          view={view}
          busy={busy}
          onSyncNow={syncNow}
          onOpenSyncSettings={openSyncSettings}
        />
      ) : null}
    </div>
  );
}
