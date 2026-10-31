import { Fragment, useEffect, useRef, useState } from "react";
import type { DragEvent } from "react";
import { useVault } from "../state/VaultContext";
import { useT } from "../state/LangContext";
import { lockVault, listEntries, listTrash, moveFolder, reorderFolder } from "../ipc/commands";
import type { FolderNode, View } from "../ipc/types";
import { tagColor } from "../lib/tagColors";
import { clearClipboard } from "../lib/clipboard";
import { useClipboard } from "../state/ClipboardContext";
import { ThemeToggle } from "./ThemeToggle";
import { SyncStatusIndicator } from "./SyncStatusIndicator";
import { modKey } from "../lib/platform";
import "./Sidebar.css";

const VIEWS: { id: View; labelKey: string; icon: SideIcon }[] = [
  { id: "all", labelKey: "common.allItems", icon: "folder" },
  { id: "favorites", labelKey: "common.favorites", icon: "star" },
  { id: "recent", labelKey: "common.recent", icon: "clock" },
];

type SideIcon =
  | "folder"
  | "chevron"
  | "trash"
  | "dots"
  | "search"
  | "star"
  | "clock"
  | "lock"
  | "gear"
  | "filter";

const ICON_PATHS: Record<SideIcon, React.ReactNode> = {
  folder: <path d="M3.5 7a2 2 0 012-2h4l2 2.2h7a2 2 0 012 2V17a2 2 0 01-2 2h-13a2 2 0 01-2-2V7z" />,
  chevron: <path d="M9.5 6.5l5.5 5.5-5.5 5.5" />,
  trash: (
    <g>
      <path d="M4.5 7h15" />
      <path d="M9.5 7V5.2A1.2 1.2 0 0110.7 4h2.6a1.2 1.2 0 011.2 1.2V7" />
      <path d="M6.5 7l.8 12a1.5 1.5 0 001.5 1.4h6.4a1.5 1.5 0 001.5-1.4l.8-12" />
      <path d="M10 11v5.5M14 11v5.5" />
    </g>
  ),
  dots: (
    <g>
      <circle cx="5.5" cy="12" r="1.1" fill="currentColor" stroke="none" />
      <circle cx="12" cy="12" r="1.1" fill="currentColor" stroke="none" />
      <circle cx="18.5" cy="12" r="1.1" fill="currentColor" stroke="none" />
    </g>
  ),
  search: (
    <g>
      <circle cx="10.3" cy="10.3" r="6.3" />
      <path d="M19.5 19.5l-4.7-4.7" />
    </g>
  ),
  star: <path d="M12 3.5l2.6 5.3 5.9.9-4.2 4.1 1 5.8L12 16.9l-5.2 2.7 1-5.8L3.5 9.7l5.9-.9L12 3.5z" />,
  clock: (
    <g>
      <circle cx="12" cy="12" r="8.2" />
      <path d="M12 7.6V12l3.4 2" />
    </g>
  ),
  lock: (
    <g>
      <rect x="5" y="10.5" width="14" height="9.5" rx="2" />
      <path d="M8.5 10.5V7.5a3.5 3.5 0 017 0v3" />
    </g>
  ),
  gear: (
    <g>
      <circle cx="12" cy="12" r="5.4" />
      <circle cx="12" cy="12" r="2" />
      <path d="M17.4 12L19.8 12M14.7 16.7L15.9 18.8M9.3 16.7L8.1 18.8M6.6 12L4.2 12M9.3 7.3L8.1 5.2M14.7 7.3L15.9 5.2" />
    </g>
  ),
  filter: <path d="M4 5.5h16l-6.2 7.2v5.1l-3.6-1.8v-3.3L4 5.5z" />,
};

function Icon({
  name,
  size = 15,
  strokeWidth = 1.7,
  className,
}: {
  name: SideIcon;
  size?: number;
  strokeWidth?: number;
  className?: string;
}) {
  return (
    <svg
      className={className}
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

function subtreeCount(node: FolderNode): number {
  return node.children.reduce((sum, child) => sum + subtreeCount(child), node.entry_count);
}

type DropPos = "before" | "after" | "inside";
type DropTarget = { id: string; pos: DropPos };

function findFolder(nodes: FolderNode[], id: string): FolderNode | null {
  for (const n of nodes) {
    if (n.id === id) return n;
    const found = findFolder(n.children, id);
    if (found) return found;
  }
  return null;
}

function subtreeIncludes(node: FolderNode, id: string): boolean {
  return node.id === id || node.children.some((c) => subtreeIncludes(c, id));
}

function isDescendant(folders: FolderNode[], dragId: string, targetId: string): boolean {
  const dragNode = findFolder(folders, dragId);
  return dragNode !== null && subtreeIncludes(dragNode, targetId);
}

/**
 * Left sidebar: the search field (`.kv-search-hint`, a real `<input>` bound
 * to `useVault().search`, plus a filter button + popover hosting the
 * Favorites/Regex chips), the view switcher (per-view icons + counts), the
 * folder tree (with drag-to-reorder/nest), the tag list, the Folders/Tags
 * header "manage" buttons (routing to the manage-folders/manage-tags pages),
 * and the footer (sync status, Recycle Bin, Lock, `<ThemeToggle/>`, and the
 * Settings row routing to Settings.tsx; Field templates and Password Health
 * live as tabs inside Settings). There is no vault-name / traffic-light
 * header: `.kv-side`'s top padding reserves that space, and the real
 * traffic lights are OS-drawn via titleBarStyle "Overlay".
 */
export function Sidebar() {
  const t = useT();
  const {
    nav,
    setNav,
    setRoute,
    route,
    folders,
    tags,
    entries,
    search,
    setSearch,
    searchInputRef,
    refreshStatus,
    refreshFolders,
    filters,
    setFilters,
  } = useVault();
  const { reset: resetClipboard } = useClipboard();
  const [collapsed, setCollapsed] = useState<Set<string>>(() => new Set());
  const [dragId, setDragId] = useState<string | null>(null);
  const [drop, setDrop] = useState<DropTarget | null>(null);
  const [filterOpen, setFilterOpen] = useState(false);
  const filterBtnRef = useRef<HTMLButtonElement | null>(null);
  const filterPopRef = useRef<HTMLDivElement | null>(null);
  const dragIdRef = useRef<string | null>(null);
  const dropRef = useRef<DropTarget | null>(null);
  const [trashCount, setTrashCount] = useState(0);

  useEffect(() => {
    if (!filterOpen) return;
    function onDown(e: MouseEvent) {
      const target = e.target as Node;
      if (filterPopRef.current?.contains(target) || filterBtnRef.current?.contains(target)) return;
      setFilterOpen(false);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setFilterOpen(false);
    }
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [filterOpen]);

  useEffect(() => {
    listTrash()
      .then((items) => setTrashCount(items.length))
      .catch((e) => console.error("list_trash failed:", e));
  }, [route]);

  const [viewCounts, setViewCounts] = useState<Record<View, number>>({
    all: 0,
    favorites: 0,
    recent: 0,
  });
  useEffect(() => {
    let cancelled = false;
    Promise.all([listEntries("all"), listEntries("favorites"), listEntries("recent")])
      .then(([all, favorites, recent]) => {
        if (cancelled) return;
        setViewCounts({ all: all.length, favorites: favorites.length, recent: recent.length });
      })
      .catch((e) => console.error("list_entries (sidebar view counts) failed:", e));
    return () => {
      cancelled = true;
    };
  }, [entries]);

  async function onLock() {
    try {
      void clearClipboard();
      resetClipboard();
      await lockVault();
      await refreshStatus();
    } catch (e) {
      console.error("lock_vault failed:", e);
    }
  }

  function toggleCollapsed(id: string) {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function onDragStartRow(ev: DragEvent<HTMLButtonElement>, node: FolderNode) {
    if (node.id === "root") {
      ev.preventDefault();
      return;
    }
    dragIdRef.current = node.id;
    setDragId(node.id);
    ev.dataTransfer.effectAllowed = "move";
  }

  async function commitMove() {
    const dId = dragIdRef.current;
    const d = dropRef.current;
    dragIdRef.current = null;
    dropRef.current = null;
    setDragId(null);
    setDrop(null);
    if (!dId || !d) return;
    try {
      if (d.pos === "inside") {
        await moveFolder(dId, d.id);
      } else {
        await reorderFolder(dId, d.id, d.pos);
      }
      await refreshFolders();
    } catch (e) {
      console.error("folder move/reorder failed:", e);
    }
  }

  function onDragEndRow() {
    void commitMove();
  }

  function onDragOverRow(ev: DragEvent<HTMLButtonElement>, node: FolderNode) {
    ev.preventDefault();
    if (!dragId || dragId === node.id || isDescendant(folders, dragId, node.id)) {
      dropRef.current = null;
      setDrop(null);
      return;
    }
    const rect = ev.currentTarget.getBoundingClientRect();
    const y = (ev.clientY - rect.top) / rect.height;
    const pos: DropPos = node.id === "root" ? "inside" : y < 0.28 ? "before" : y > 0.72 ? "after" : "inside";
    dropRef.current = { id: node.id, pos };
    setDrop({ id: node.id, pos });
  }

  function onDragLeaveRow(node: FolderNode) {
    setDrop((prev) => (prev && prev.id === node.id ? null : prev));
  }

  async function onDropRow(ev: DragEvent<HTMLButtonElement>, _node: FolderNode) {
    ev.preventDefault();
    void commitMove();
  }

  function renderFolder(node: FolderNode, depth: number) {
    const hasChildren = node.children.length > 0;
    const isCollapsed = collapsed.has(node.id);
    const isActive = route === "main" && nav.kind === "folder" && nav.id === node.id;
    const count = subtreeCount(node);
    const dropPos = drop && drop.id === node.id ? drop.pos : null;
    return (
      <Fragment key={node.id}>
        <button
          type="button"
          className={
            "kv-side-item kv-group-item" +
            (isActive ? " is-active" : "") +
            (dragId === node.id ? " is-dragging" : "") +
            (dropPos === "inside"
              ? " is-drop-inside"
              : dropPos === "before"
                ? " is-drop-before"
                : dropPos === "after"
                  ? " is-drop-after"
                  : "")
          }
          style={{ paddingLeft: 8 + depth * 16 }}
          aria-current={isActive ? "page" : undefined}
          draggable={node.id !== "root"}
          onDragStart={(e) => onDragStartRow(e, node)}
          onDragEnd={onDragEndRow}
          onDragOver={(e) => onDragOverRow(e, node)}
          onDragLeave={() => onDragLeaveRow(node)}
          onDrop={(e) => onDropRow(e, node)}
          title={t("sidebar.dragReorderHint")}
          onClick={() => {
            setNav({ kind: "folder", id: node.id });
            setRoute("main");
          }}
        >
          <span
            className={"kv-chev" + (hasChildren ? "" : " is-empty") + (isCollapsed ? "" : " is-open")}
            onClick={(e) => {
              e.stopPropagation();
              if (!hasChildren) return;
              toggleCollapsed(node.id);
            }}
          >
            {hasChildren ? <Icon name="chevron" size={11} strokeWidth={2} /> : null}
          </span>
          <Icon name="folder" className="kv-ico" />
          <span className="label">{node.name}</span>
          {count > 0 ? <span className="kv-count">{count}</span> : null}
        </button>
        {!isCollapsed ? node.children.map((child) => renderFolder(child, depth + 1)) : null}
      </Fragment>
    );
  }

  return (
    <aside className="kv-side" data-tauri-drag-region>
      <div className="kv-search-hint">
        <Icon name="search" size={14} className="kv-ico" />
        <input
          ref={searchInputRef}
          className="grow"
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder={t("sidebar.searchPlaceholder")}
          aria-label={t("sidebar.searchAriaLabel")}
          autoCapitalize="off"
          autoCorrect="off"
          spellCheck={false}
        />
        <span className="kv-kbd">{modKey("K")}</span>
        <button
          type="button"
          ref={filterBtnRef}
          className={"kv-search-filter" + (filters.favoritesOnly || filters.regex ? " is-on" : "")}
          aria-label={t("sidebar.searchFilters")}
          aria-expanded={filterOpen}
          onClick={() => setFilterOpen((o) => !o)}
        >
          <Icon name="filter" size={14} className="kv-ico" />
        </button>
        {filterOpen && (
          <div className="kv-search-pop" ref={filterPopRef}>
            <button
              type="button"
              className={"kv-chip" + (filters.favoritesOnly ? " is-on" : "")}
              aria-pressed={filters.favoritesOnly}
              onClick={() => setFilters({ ...filters, favoritesOnly: !filters.favoritesOnly })}
            >
              <Icon name="star" size={13} />
              {t("common.favorites")}
            </button>
            <button
              type="button"
              className={"kv-chip" + (filters.regex ? " is-on" : "")}
              aria-pressed={filters.regex}
              title={t("list.regexTitle")}
              onClick={() => setFilters({ ...filters, regex: !filters.regex })}
            >
              <span className="kv-chip-glyph">.*</span>
              {t("list.regexLabel")}
            </button>
          </div>
        )}
      </div>
      <div className="kv-side-scroll">
        {VIEWS.map(({ id, labelKey, icon }) => {
          const isActive = route === "main" && nav.kind === "view" && nav.view === id;
          const count = viewCounts[id];
          return (
            <button
              key={id}
              type="button"
              className={"kv-side-item" + (isActive ? " is-active" : "")}
              aria-current={isActive ? "page" : undefined}
              onClick={() => {
                setNav({ kind: "view", view: id });
                setRoute("main");
              }}
            >
              <Icon name={icon} className="kv-ico" />
              <span className="label">{t(labelKey)}</span>
              {count > 0 ? <span className="kv-count">{count}</span> : null}
            </button>
          );
        })}

        <div className="kv-side-label">
          {t("sidebar.folders")}
          <button
            type="button"
            className="kv-btn is-icon"
            title={t("sidebar.manageFolders")}
            onClick={() => setRoute("manage-folders")}
          >
            <Icon name="dots" size={14} />
          </button>
        </div>
        {folders.map((f) => renderFolder(f, 0))}

        <div className="kv-side-label">
          {t("sidebar.tags")}
          <button
            type="button"
            className="kv-btn is-icon"
            title={t("sidebar.manageTags")}
            onClick={() => setRoute("manage-tags")}
          >
            <Icon name="dots" size={14} />
          </button>
        </div>
        {tags.map((tag) => {
          const isActive = route === "main" && nav.kind === "tag" && nav.id === tag.id;
          const dot = tagColor(tag.color);
          return (
            <button
              key={tag.id}
              type="button"
              className={"kv-side-item" + (isActive ? " is-active" : "")}
              aria-current={isActive ? "page" : undefined}
              onClick={() => {
                setNav({ kind: "tag", id: tag.id });
                setRoute("main");
              }}
            >
              <span className="kv-tag-dot" style={{ background: dot, color: dot }} />
              <span className="label">{tag.name}</span>
              {tag.usage > 0 ? <span className="kv-count">{tag.usage}</span> : null}
            </button>
          );
        })}
      </div>
      <div className="kv-side-foot">
        <SyncStatusIndicator />
        <button
          type="button"
          className={"kv-side-item" + (route === "trash" ? " is-active" : "")}
          aria-current={route === "trash" ? "page" : undefined}
          onClick={() => setRoute("trash")}
        >
          <Icon name="trash" className="kv-ico" />
          <span className="label">{t("sidebar.recycleBin")}</span>
          {trashCount > 0 ? <span className="kv-count">{trashCount}</span> : null}
        </button>
        <button type="button" className="kv-side-item" onClick={onLock}>
          <Icon name="lock" className="kv-ico" />
          <span className="label">{t("sidebar.lock")}</span>
        </button>
        <ThemeToggle />
        <button
          type="button"
          className={"kv-side-item" + (route === "settings" ? " is-active" : "")}
          aria-current={route === "settings" ? "page" : undefined}
          onClick={() => setRoute("settings")}
        >
          <Icon name="gear" className="kv-ico" />
          <span className="label">{t("sidebar.settings")}</span>
        </button>
      </div>
    </aside>
  );
}
