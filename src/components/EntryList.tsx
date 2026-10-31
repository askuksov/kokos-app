import { useEffect, useRef, useState } from "react";
import { bulkDeleteEntries, bulkMoveEntries, bulkSetTag, exportJson, pickSavePath, revealField } from "../ipc/commands";
import { useVault } from "../state/VaultContext";
import type { Nav } from "../state/VaultContext";
import { useSettings } from "../state/SettingsContext";
import { useT } from "../state/LangContext";
import type { TFn } from "../lib/i18n";
import type { EntrySummary, FolderNode, Tag, View } from "../ipc/types";
import { tagColor } from "../lib/tagColors";
import { entryTypeMeta } from "../lib/entryTypes";
import { useClipboard } from "../state/ClipboardContext";
import "./EntryList.css";

function hashTitle(str: string): number {
  let h = 0;
  for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) >>> 0;
  return h;
}

function monogram(title: string): { letter: string; bg: string } {
  const hue = hashTitle(title || "?") % 360;
  return {
    letter: (title || "?").trim().charAt(0).toUpperCase(),
    bg: `linear-gradient(135deg, oklch(0.62 0.13 ${hue}), oklch(0.48 0.15 ${(hue + 45) % 360}))`,
  };
}

function Monogram({ title }: { title: string }) {
  const m = monogram(title);
  return (
    <div
      className="kv-monogram"
      style={{
        width: 34,
        height: 34,
        fontSize: 34 * 0.44,
        background: m.bg,
        borderRadius: "var(--radius-sm)",
      }}
    >
      {m.letter}
    </div>
  );
}

type ListIcon = "star" | "shield" | "clip" | "plus" | "card" | "note" | "wifi" | "user" | "lock" | "check";

const ICON_PATHS: Record<ListIcon, string> = {
  star: "M12 3.5l2.6 5.3 5.9.9-4.2 4.1 1 5.8L12 16.9l-5.2 2.7 1-5.8L3.5 9.7l5.9-.9L12 3.5z",
  shield: "M12 3l7.5 2.8v5.7c0 4.3-2.9 7.3-7.5 9-4.6-1.7-7.5-4.7-7.5-9V5.8L12 3z",
  clip: "M20 11.5l-7.6 7.6a5 5 0 01-7-7L13 4.5a3.3 3.3 0 014.7 4.7l-7.6 7.5a1.7 1.7 0 01-2.3-2.3l7-7",
  plus: "M12 5.5v13M5.5 12h13",
  card: "M3.5 6.5h17a1 1 0 011 1v9a1 1 0 01-1 1h-17a1 1 0 01-1-1v-9a1 1 0 011-1z M2.5 10.5h19",
  note: "M13.5 3.5H7a2 2 0 00-2 2v13a2 2 0 002 2h10a2 2 0 002-2V9l-5.5-5.5z M13.5 3.5V9h5.5 M8.5 13h7 M8.5 16.5h7",
  wifi: "M4.5 12.5a10.5 10.5 0 0115 0 M7.8 15.6a6 6 0 018.4 0 M12 19.2v.01",
  user: "M12 12.4a3.7 3.7 0 100-7.4 3.7 3.7 0 000 7.4z M5.2 19.5a6.8 6.8 0 0113.6 0",
  lock: "M7 10V7.5a5 5 0 0110 0V10 M5.75 10h12.5a.75.75 0 01.75.75v7.5a.75.75 0 01-.75.75H5.75a.75.75 0 01-.75-.75v-7.5A.75.75 0 015.75 10z",
  check: "M5 12.5l4.5 4.5L19 7",
};

function Icon({
  name,
  size = 11,
  className,
  filled,
}: {
  name: ListIcon;
  size?: number;
  className?: string;
  filled?: boolean;
}) {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill={filled ? "currentColor" : "none"}
      stroke="currentColor"
      strokeWidth={1.7}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={ICON_PATHS[name]} />
    </svg>
  );
}

const VIEW_LABEL_KEYS: Record<View, string> = {
  all: "common.allItems",
  favorites: "common.favorites",
  recent: "common.recent",
};

function findFolder(nodes: FolderNode[], id: string): FolderNode | null {
  for (const n of nodes) {
    if (n.id === id) return n;
    const found = findFolder(n.children, id);
    if (found) return found;
  }
  return null;
}

function flattenFolders(nodes: FolderNode[], out: { id: string; name: string }[] = []): { id: string; name: string }[] {
  for (const n of nodes) {
    out.push({ id: n.id, name: n.name });
    flattenFolders(n.children, out);
  }
  return out;
}

function navTitle(t: TFn, nav: Nav, folders: FolderNode[], tags: Tag[]): string {
  if (nav.kind === "view") return t(VIEW_LABEL_KEYS[nav.view]);
  if (nav.kind === "folder") return findFolder(folders, nav.id)?.name ?? t("list.folderFallback");
  return tags.find((tag) => tag.id === nav.id)?.name ?? t("list.tagFallback");
}

/**
 * Center-panel entry list: a list-head (the current view/folder/tag's
 * title, its entry count, and a "+ new" button) above scrollable rows,
 * each a monogram avatar, title, username, and favorite/tag-colour
 * (`kv-row-dots`)/TOTP/attachment indicators. Order is whatever
 * `useVault()` returns — the backend `view` already sorts/filters; this
 * component must not re-sort.
 */
export function EntryList({ onNewEntry }: { onNewEntry: () => void }) {
  const t = useT();
  const {
    visibleEntries,
    entriesLoaded,
    selectedId,
    select,
    nav,
    search,
    folders,
    tags,
    filters,
    refreshEntries,
    refreshFolders,
    refreshTags,
    setSaveError,
  } = useVault();

  const { copySecret, copyEpoch } = useClipboard();
  const { refresh: refreshSettings } = useSettings();
  const copyToken = useRef(0);
  // Invalidate any in-flight password copy when the list unmounts.
  useEffect(() => {
    return () => {
      copyToken.current += 1;
    };
  }, []);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  function flashCopied(key: string) {
    setCopiedKey(key);
    window.setTimeout(() => setCopiedKey((c) => (c === key ? null : c)), 1400);
  }
  function copyUsername(entry: EntrySummary) {
    if (!entry.username) return;
    copyToken.current += 1;
    copySecret(entry.username)
      .then(() => flashCopied(entry.id + ":u"))
      .catch((e) => console.error("copy username failed:", e));
  }
  async function copyPassword(entry: EntrySummary) {
    if (!entry.password_field_id) return;
    const token = ++copyToken.current;
    const epoch = copyEpoch();
    try {
      const value = await revealField(entry.id, entry.password_field_id);
      if (copyToken.current !== token) return;
      await copySecret(value, epoch);
      flashCopied(entry.id + ":p");
    } catch (e) {
      console.error("copy password failed:", e);
    }
  }

  const [selectMode, setSelectMode] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [anchor, setAnchor] = useState<number | null>(null);
  const [openPopover, setOpenPopover] = useState<"move" | "tag" | null>(null);
  const [busy, setBusy] = useState(false);
  const [exportDone, setExportDone] = useState(false);
  const moveAnchorRef = useRef<HTMLDivElement | null>(null);
  const tagAnchorRef = useRef<HTMLDivElement | null>(null);

  const viewSignature = `${nav.kind}:${nav.kind === "view" ? nav.view : nav.id}:${filters.favoritesOnly}:${filters.regex}:${search}`;

  const toggleAt = (i: number, id: string, shift: boolean) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (shift && anchor !== null) {
        const maxIdx = visibleEntries.length - 1;
        const lo = Math.max(0, Math.min(anchor, i));
        const hi = Math.min(maxIdx, Math.max(anchor, i));
        for (let k = lo; k <= hi; k++) {
          const entry = visibleEntries[k];
          if (entry) next.add(entry.id);
        }
      } else {
        next.has(id) ? next.delete(id) : next.add(id);
      }
      return next;
    });
    setAnchor(i);
  };
  const exitSelect = () => {
    setSelectMode(false);
    setSelected(new Set());
    setAnchor(null);
    setOpenPopover(null);
  };
  const ids = () => [...selected];

  useEffect(() => {
    exitSelect();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [viewSignature]);

  useEffect(() => {
    if (!openPopover) return;
    const anchorRef = openPopover === "move" ? moveAnchorRef : tagAnchorRef;
    function onDown(ev: PointerEvent) {
      if (anchorRef.current && !anchorRef.current.contains(ev.target as Node)) setOpenPopover(null);
    }
    function onKey(ev: KeyboardEvent) {
      if (ev.key === "Escape") setOpenPopover(null);
    }
    document.addEventListener("pointerdown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [openPopover]);

  function refreshAfterBulkChange(label: string) {
    void Promise.all([refreshEntries(), refreshFolders(), refreshTags()]).catch((e) =>
      console.error(`post-bulk-${label} refresh failed:`, e)
    );
  }

  async function doBulkDelete() {
    setBusy(true);
    try {
      await bulkDeleteEntries(ids());
    } catch (e) {
      console.error("bulk_delete_entries failed:", e);
      setSaveError(String(e));
      return;
    } finally {
      setBusy(false);
    }
    exitSelect();
    refreshAfterBulkChange("delete");
  }

  async function doBulkMove(folderId: string) {
    setBusy(true);
    try {
      await bulkMoveEntries(ids(), folderId);
    } catch (e) {
      console.error("bulk_move_entries failed:", e);
      setSaveError(String(e));
      return;
    } finally {
      setBusy(false);
    }
    exitSelect();
    refreshAfterBulkChange("move");
  }

  async function doBulkTag(tagId: string) {
    setBusy(true);
    try {
      await bulkSetTag(ids(), tagId, true);
    } catch (e) {
      console.error("bulk_set_tag failed:", e);
      setSaveError(String(e));
      return;
    } finally {
      setBusy(false);
    }
    exitSelect();
    refreshAfterBulkChange("tag");
  }

  async function doBulkExport() {
    setBusy(true);
    try {
      const path = await pickSavePath("kokos-selected.json");
      if (!path) return;
      await exportJson(path, ids());
      await refreshSettings();
      setExportDone(true);
      setTimeout(() => setExportDone(false), 1400);
    } catch (e) {
      console.error("export_json failed:", e);
      setSaveError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="kv-list">
      <div className="kv-list-head">
        <div className="kv-list-title">
          {navTitle(t, nav, folders, tags)}
          <span className="n">{visibleEntries.length}</span>
        </div>
        <button
          type="button"
          className={"kv-btn is-ghost kv-list-select-toggle" + (selectMode ? " is-on" : "")}
          aria-pressed={selectMode}
          onClick={() => (selectMode ? exitSelect() : setSelectMode(true))}
        >
          {selectMode ? t("list.doneSelect") : t("list.select")}
        </button>
        <button
          type="button"
          className="kv-btn is-icon"
          title={t("list.newEntry")}
          aria-label={t("list.newEntry")}
          onClick={onNewEntry}
        >
          <Icon name="plus" size={14} />
        </button>
      </div>
      <div
        className="kv-list-scroll"
        // Clicking past the rows clears the selection — the detail panel's
        // no-selection state (the getting-started card) has to be reachable
        // again after a row was clicked. Rows and their copy
        // buttons all sit inside `.kv-row-wrap`.
        onClick={(ev) => {
          if (selectMode) return;
          if ((ev.target as Element).closest(".kv-row-wrap")) return;
          select(null);
        }}
      >
        {visibleEntries.length === 0 ? (
          entriesLoaded ? (
            <div className="kv-empty">
              <p>
                {search.trim()
                  ? t("list.noMatches")
                  : nav.kind === "view" && nav.view === "all"
                    ? t("list.noEntries")
                    : t("list.emptyView")}
              </p>
            </div>
          ) : null
        ) : (
          visibleEntries.map((entry, i) => (
            <div className="kv-row-wrap" key={entry.id}>
              <button
                type="button"
                data-entry-id={entry.id}
                className={
                  "kv-row" +
                  (entry.id === selectedId ? " is-active" : "") +
                  (selectMode && selected.has(entry.id) ? " is-checked" : "")
                }
                style={{ animationDelay: `${Math.min(i * 22, 280)}ms` }}
                aria-pressed={selectMode ? selected.has(entry.id) : undefined}
                onClick={(ev) => (selectMode ? toggleAt(i, entry.id, ev.shiftKey) : select(entry.id))}
              >
                {selectMode && (
                  <input
                    type="checkbox"
                    className="kv-entry-check"
                    tabIndex={-1}
                    readOnly
                    aria-hidden="true"
                    checked={selected.has(entry.id)}
                  />
                )}
                <span className="kv-avatar">
                  <Monogram title={entry.title} />
                  {entry.entry_type !== "login" ? (
                    <span
                      className="kv-avatar-badge"
                      style={{ background: entryTypeMeta(entry.entry_type).color }}
                    >
                      <Icon name={entryTypeMeta(entry.entry_type).icon as ListIcon} size={9} />
                    </span>
                  ) : null}
                </span>
                <div className="kv-row-main">
                  <div className="kv-row-title">
                    {entry.title}
                    {entry.is_favorite ? (
                      <Icon name="star" className="kv-fav-star" filled />
                    ) : null}
                  </div>
                  <div className="kv-row-sub">{entry.username ?? "—"}</div>
                </div>
                {entry.has_totp || entry.has_attachments ? (
                  <div className="kv-row-indicators">
                    {entry.has_totp ? <Icon name="shield" /> : null}
                    {entry.has_attachments ? <Icon name="clip" /> : null}
                  </div>
                ) : null}
                {entry.tags.length > 0 ? (
                  <div className="kv-row-dots">
                    {entry.tags.slice(0, 3).map((tag) => (
                      <i key={tag.id} style={{ background: tagColor(tag.color) }} />
                    ))}
                  </div>
                ) : null}
              </button>
              {!selectMode && (entry.username || entry.password_field_id) ? (
                <div className="kv-row-copy">
                  {entry.username ? (
                    <button
                      type="button"
                      className="kv-row-copy-btn"
                      title={t("list.copyUsername")}
                      aria-label={t("list.copyUsername")}
                      onClick={() => copyUsername(entry)}
                    >
                      <Icon name={copiedKey === entry.id + ":u" ? "check" : "user"} size={14} />
                    </button>
                  ) : null}
                  {entry.password_field_id ? (
                    <button
                      type="button"
                      className="kv-row-copy-btn"
                      title={t("list.copyPassword")}
                      aria-label={t("list.copyPassword")}
                      onClick={() => void copyPassword(entry)}
                    >
                      <Icon name={copiedKey === entry.id + ":p" ? "check" : "lock"} size={14} />
                    </button>
                  ) : null}
                </div>
              ) : null}
            </div>
          ))
        )}
      </div>
      {selectMode && selected.size > 0 && (
        <div className="kv-bulk-bar">
          <span className="kv-bulk-count">{t("list.selectedN", { n: selected.size })}</span>
          <button
            type="button"
            className="kv-btn is-ghost"
            disabled={busy}
            onClick={() => setSelected(new Set(visibleEntries.map((e) => e.id)))}
          >
            {t("list.selectAll")}
          </button>
          <button
            type="button"
            className="kv-btn is-ghost is-danger"
            disabled={busy}
            onClick={() => void doBulkDelete()}
          >
            {t("list.bulkDelete")}
          </button>
          <div className="kv-bulk-anchor" ref={moveAnchorRef}>
            <button
              type="button"
              className="kv-btn is-ghost"
              disabled={busy}
              onClick={() => setOpenPopover((p) => (p === "move" ? null : "move"))}
            >
              {t("list.bulkMove")}
            </button>
            {openPopover === "move" && (
              <div className="kv-bulk-pop">
                {flattenFolders(folders).map((f) => (
                  <button
                    key={f.id}
                    type="button"
                    className="kv-bulk-pop-opt"
                    disabled={busy}
                    onClick={() => void doBulkMove(f.id)}
                  >
                    {f.name}
                  </button>
                ))}
              </div>
            )}
          </div>
          <div className="kv-bulk-anchor" ref={tagAnchorRef}>
            <button
              type="button"
              className="kv-btn is-ghost"
              disabled={busy}
              onClick={() => setOpenPopover((p) => (p === "tag" ? null : "tag"))}
            >
              {t("list.bulkTag")}
            </button>
            {openPopover === "tag" && (
              <div className="kv-bulk-pop">
                {tags.length === 0 ? (
                  <div className="kv-bulk-pop-empty">{t("list.noTags")}</div>
                ) : (
                  tags.map((tag) => (
                    <button
                      key={tag.id}
                      type="button"
                      className="kv-bulk-pop-opt"
                      disabled={busy}
                      onClick={() => void doBulkTag(tag.id)}
                    >
                      <span className="kv-tag-dot" style={{ background: tagColor(tag.color) }} />
                      {tag.name}
                    </button>
                  ))
                )}
              </div>
            )}
          </div>
          <button
            type="button"
            className="kv-btn is-ghost"
            disabled={busy}
            style={exportDone ? { color: "var(--ok)" } : undefined}
            onClick={() => void doBulkExport()}
          >
            {t("list.bulkExport")}
          </button>
        </div>
      )}
    </section>
  );
}
