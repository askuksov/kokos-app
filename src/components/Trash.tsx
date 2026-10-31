import { useCallback, useEffect, useState } from "react";
import { useVault } from "../state/VaultContext";
import { useT, useTn } from "../state/LangContext";
import type { TFn, TnFn } from "../lib/i18n";
import { emptyTrash, listTrash, permanentDeleteEntry, restoreEntry } from "../ipc/commands";
import type { TrashItem } from "../ipc/types";
import "./Trash.css";

type TrashIcon = "chevronLeft" | "trash" | "restore" | "folder";

const ICON_PATHS: Record<TrashIcon, React.ReactNode> = {
  chevronLeft: <path d="M14.5 6.5l-5.5 5.5 5.5 5.5" />,
  trash: (
    <g>
      <path d="M4.5 7h15" />
      <path d="M9.5 7V5.2A1.2 1.2 0 0110.7 4h2.6a1.2 1.2 0 011.2 1.2V7" />
      <path d="M6.5 7l.8 12a1.5 1.5 0 001.5 1.4h6.4a1.5 1.5 0 001.5-1.4l.8-12" />
      <path d="M10 11v5.5M14 11v5.5" />
    </g>
  ),
  restore: (
    <g>
      <path d="M4.5 4.5v5.5h5.5" />
      <path d="M6.6 16a8.5 8.5 0 1 0 2-11.9L4.5 10" />
    </g>
  ),
  folder: <path d="M3.5 7a2 2 0 012-2h4l2 2.2h7a2 2 0 012 2V17a2 2 0 01-2 2h-13a2 2 0 01-2-2V7z" />,
};

function Icon({
  name,
  size = 15,
  strokeWidth = 1.7,
}: {
  name: TrashIcon;
  size?: number;
  strokeWidth?: number;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {ICON_PATHS[name]}
    </svg>
  );
}

const MINUTE = 60;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

function relativeTime(t: TFn, tn: TnFn, unixSeconds: number | null): string {
  if (unixSeconds === null) return "—";
  const diff = Math.max(0, Math.floor(Date.now() / 1000) - unixSeconds);
  if (diff < MINUTE) return t("trash.justNow");
  if (diff < HOUR) return tn("trash.minutesAgo", Math.floor(diff / MINUTE));
  if (diff < DAY) return tn("trash.hoursAgo", Math.floor(diff / HOUR));
  return tn("trash.daysAgo", Math.floor(diff / DAY));
}

function TrashRow({
  item,
  busy,
  confirming,
  disabled,
  onRestore,
  onPermanentDelete,
}: {
  item: TrashItem;
  busy: boolean;
  confirming: boolean;
  disabled: boolean;
  onRestore: (id: string) => void;
  onPermanentDelete: (id: string) => void;
}) {
  const t = useT();
  const tn = useTn();
  const folderName = item.folder_name ?? "Root";

  return (
    <div className="kv-manage-row kv-trash-row">
      <div className="kv-trash-row-main">
        <div className="kv-trash-title">{item.title}</div>
        <div className="kv-entry-meta">
          <Icon name="folder" size={12} />
          {folderName}
          <span className="sep">·</span>
          {relativeTime(t, tn, item.deleted_at)}
        </div>
      </div>
      <button
        type="button"
        className="kv-btn is-ghost"
        disabled={disabled}
        aria-label={t("trash.restoreNamed", { name: item.title })}
        onClick={() => onRestore(item.id)}
      >
        <Icon name="restore" size={13} /> {busy ? t("trash.restoring") : t("trash.restore")}
      </button>
      <button
        type="button"
        className="kv-btn is-ghost is-danger"
        disabled={disabled}
        data-confirming={confirming ? "true" : undefined}
        aria-label={t("trash.deleteForeverNamed", { name: item.title })}
        onClick={() => onPermanentDelete(item.id)}
      >
        <Icon name="trash" size={13} /> {busy ? t("trash.deleting") : confirming ? t("trash.confirmDelete") : t("trash.deleteForever")}
      </button>
    </div>
  );
}

/**
 * Full-page Recycle Bin screen: lists deleted entries with per-row Restore /
 * Permanent delete, plus an Empty action. Follows
 * `src/components/ManageFolders.tsx`/`ManageTags.tsx` as the sibling
 * `.kv-settings`-page pattern: same shell classes (`.kv-settings`/
 * `.kv-settings-inner`/`.kv-settings-sub`/`.kv-settings-back`, the
 * `.kv-settings`-scoped `.kv-btn` variants) and the same unscoped
 * `.kv-card`/`.kv-manage-row`, reused as-is rather than redeclared.
 *
 * Unlike ManageFolders/ManageTags, the list here is NOT VaultContext
 * state — `folders`/`tags` are fetched once per vault-open and cached
 * centrally because many components read them (Sidebar's tree, the
 * folder/tag pickers, EntryDetail's folder line); trash is read by this
 * page alone, so it stays local `useState<TrashItem[]>`, fetched directly
 * via `listTrash()` — the same "local fetch, not threaded through
 * VaultContext" call Sidebar.tsx's own `trashCount` badge makes for the
 * identical command.
 *
 * Sidebar.tsx's `trashCount` badge effect re-fetches on every `route`
 * change, so it does NOT live-update while the user stays on this page
 * performing multiple restore/delete/empty actions in a row. It catches up
 * the moment the user leaves: `setRoute("main")` (the Back button below)
 * or any other navigation changes `route`, and Sidebar's effect re-fires
 * and re-reads a now-correct count. The badge is only ever stale WHILE
 * this page is the active route, never after leaving it.
 *
 * Every action (restore / permanent-delete / empty) re-fetches the trash
 * list AND `refreshEntries()`/`refreshFolders()`/`refreshTags()` (a restore
 * brings an entry back into the live list, its folder's `entry_count` and
 * its tags' `usage` — all three is_deleted-filtered; a permanent-delete/
 * empty on an already-`is_deleted` row cannot change any of them, so those
 * refreshes are harmless no-ops there, not skipped as an optimization —
 * uniform post-action refresh is simpler than a per-action carve-out for
 * zero behavioural gain).
 *
 * Errors are reported via `console.error` only, matching ManageFolders.tsx/
 * ManageTags.tsx's own row-mutation handlers (create/rename/delete/move) —
 * not EntryDetail.tsx's `setSaveError` banner, which exists specifically
 * for the "an in-memory edit may not have persisted" situation autosave-
 * on-mutation creates for entry create/update/delete. Restore/permanent-
 * delete/empty have no such in-memory-edit counterpart to lose; they are
 * one-shot commands on an already-persisted row, the same shape as a
 * folder rename or tag delete.
 *
 * `busyId`/`emptying` gate ALL action buttons (not just the row/header
 * button that triggered them) while any one of the three is in flight —
 * the async gap between a confirm resolving and the IPC call finishing is
 * still a real window for a second click to race a first mutation against
 * the same (or another) row — the same "disable while busy" instinct
 * EntryDetail.tsx's `deleting`/`favoriting` flags follow, widened here to
 * cover the whole list since any of the three actions can invalidate what
 * any row shows.
 *
 * Permanent-delete/empty are irreversible, so they still keep a safety
 * gate — just not `window.confirm`, which is a no-op in this app's
 * WKWebView: it returns `false` WITHOUT ever showing a dialog (same
 * failure family as `window.prompt` returning null there).
 * `confirmingId`/`confirmingEmpty` implement a dependency-free two-step
 * confirm instead: a first click arms the flag and flips that one
 * control's own label to "Confirm?"/"Sure?"; a second click on that SAME
 * control performs the real mutation and clears the flag. The `mousedown`
 * effect below cancels a pending confirm the moment the user clicks
 * anything else (another row's delete button, the header Empty button,
 * Restore, …), so it never lingers silently armed.
 */
export function Trash() {
  const { refreshEntries, refreshFolders, refreshTags, setRoute } = useVault();
  const t = useT();
  const [items, setItems] = useState<TrashItem[]>([]);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [emptying, setEmptying] = useState(false);
  const [confirmingId, setConfirmingId] = useState<string | null>(null);
  const [confirmingEmpty, setConfirmingEmpty] = useState(false);
  const anyBusy = busyId !== null || emptying;

  useEffect(() => {
    if (confirmingId === null && !confirmingEmpty) return;
    function onDocMouseDown(ev: MouseEvent) {
      const target = ev.target as Element | null;
      if (target?.closest('[data-confirming="true"]')) return;
      setConfirmingId(null);
      setConfirmingEmpty(false);
    }
    document.addEventListener("mousedown", onDocMouseDown);
    return () => document.removeEventListener("mousedown", onDocMouseDown);
  }, [confirmingId, confirmingEmpty]);

  const load = useCallback(async () => {
    try {
      setItems(await listTrash());
    } catch (e) {
      console.error("list_trash failed:", e);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function afterAction() {
    await load();
    await refreshEntries();
    await refreshFolders();
    await refreshTags();
  }

  async function handleRestore(id: string) {
    if (anyBusy) return;
    setConfirmingId(null);
    setConfirmingEmpty(false);
    setBusyId(id);
    try {
      await restoreEntry(id);
      await afterAction();
    } catch (e) {
      console.error("restore_entry failed:", e);
    } finally {
      setBusyId(null);
    }
  }

  function handlePermanentDeleteClick(id: string) {
    if (anyBusy) return;
    if (confirmingId !== id) {
      setConfirmingId(id);
      setConfirmingEmpty(false);
      return;
    }
    void handlePermanentDelete(id);
  }

  async function handlePermanentDelete(id: string) {
    setConfirmingId(null);
    setBusyId(id);
    try {
      await permanentDeleteEntry(id);
      await afterAction();
    } catch (e) {
      console.error("permanent_delete_entry failed:", e);
    } finally {
      setBusyId(null);
    }
  }

  function handleEmptyTrashClick() {
    if (anyBusy || items.length === 0) return;
    if (!confirmingEmpty) {
      setConfirmingEmpty(true);
      setConfirmingId(null);
      return;
    }
    void handleEmptyTrash();
  }

  async function handleEmptyTrash() {
    setConfirmingEmpty(false);
    setEmptying(true);
    try {
      await emptyTrash();
      await afterAction();
    } catch (e) {
      console.error("empty_trash failed:", e);
    } finally {
      setEmptying(false);
    }
  }

  return (
    <main className="kv-settings" data-screen-label="Recycle Bin page">
      <div className="kv-settings-inner">
        <button type="button" className="kv-btn is-ghost kv-settings-back" onClick={() => setRoute("main")}>
          <Icon name="chevronLeft" size={13} strokeWidth={2} /> {t("common.back")}
        </button>
        <h1>{t("trash.title")}</h1>
        <div className="kv-trash-toolbar">
          <p className="kv-settings-sub">{t("trash.subtitle")}</p>
          <button
            type="button"
            className="kv-btn is-ghost is-danger"
            disabled={anyBusy || items.length === 0}
            data-confirming={confirmingEmpty ? "true" : undefined}
            onClick={handleEmptyTrashClick}
          >
            <Icon name="trash" size={13} /> {emptying ? t("trash.emptying") : confirmingEmpty ? t("trash.sureConfirm") : t("trash.emptyTrash")}
          </button>
        </div>

        {items.length === 0 ? (
          <div className="kv-card">
            <p className="kv-trash-empty">{t("trash.emptyState")}</p>
          </div>
        ) : (
          <div className="kv-card">
            {items.map((item) => (
              <TrashRow
                key={item.id}
                item={item}
                busy={busyId === item.id}
                confirming={confirmingId === item.id}
                disabled={anyBusy}
                onRestore={handleRestore}
                onPermanentDelete={handlePermanentDeleteClick}
              />
            ))}
          </div>
        )}
      </div>
    </main>
  );
}
