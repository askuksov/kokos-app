import { useEffect, useRef, useState } from "react";
import { aiSemanticSearch, aiStatus, searchEntries } from "../ipc/commands";
import { useVault } from "../state/VaultContext";
import { useTabs } from "../state/TabsContext";
import { useT } from "../state/LangContext";
import type { EntrySummary, FolderNode, SemanticHit } from "../ipc/types";
import { modKey } from "../lib/platform";
import "./CommandPalette.css";

const ICON_PATHS = {
  search: (
    <g>
      <circle cx="10.3" cy="10.3" r="6.3" />
      <path d="M19.5 19.5l-4.7-4.7" />
    </g>
  ),
} as const;

function Icon({ name, size = 16 }: { name: keyof typeof ICON_PATHS; size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.7}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {ICON_PATHS[name]}
    </svg>
  );
}

type PaletteItem =
  | { kind: "entry"; id: string; title: string; username: string | null; score?: number }
  | { kind: "action"; id: string; label: string; hint?: string; keepOpen?: boolean; run: () => void };

type Mode = "root" | "folders" | "tags";

function flattenFolders(nodes: FolderNode[], out: { id: string; name: string }[] = []): { id: string; name: string }[] {
  for (const n of nodes) {
    out.push({ id: n.id, name: n.name });
    flattenFolders(n.children, out);
  }
  return out;
}

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  onNewEntry: () => void;
  onLock: () => void;
}

export function CommandPalette({ open, onClose, onNewEntry, onLock }: CommandPaletteProps) {
  const { select, setRoute, setSettingsTab, setNav, focusSearch, folders, tags } = useVault();
  const { tabs, activeIndex, beginAdd, closeActive, lockAllTabs, activate: activateTab } = useTabs();
  const t = useT();
  const [mode, setMode] = useState<Mode>("root");
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<EntrySummary[]>([]);
  const [related, setRelated] = useState<SemanticHit[]>([]);
  const [aiEnabled, setAiEnabled] = useState(false);
  const [selRaw, setSelRaw] = useState(0);
  const reqTokenRef = useRef(0);
  const relTokenRef = useRef(0);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const listRef = useRef<HTMLDivElement | null>(null);
  const lastMouseRef = useRef<{ x: number; y: number }>({ x: -1, y: -1 });

  useEffect(() => {
    setMode("root");
    setQuery("");
    setResults([]);
    setRelated([]);
    setSelRaw(0);
  }, [open]);

  useEffect(() => {
    if (open) inputRef.current?.focus({ preventScroll: true });
  }, [open]);

  useEffect(() => {
    if (!open) return;
    aiStatus()
      .then((s) => setAiEnabled(s.enabled))
      .catch(() => setAiEnabled(false));
  }, [open]);

  useEffect(() => {
    const q = query.trim();
    const token = ++reqTokenRef.current;
    if (!open || mode !== "root" || !q) {
      setResults((prev) => (prev.length ? [] : prev));
      return;
    }
    const handle = setTimeout(() => {
      searchEntries(q, {})
        .then((res) => {
          if (token === reqTokenRef.current) {
            setResults(res);
            setSelRaw(0);
          }
        })
        .catch((e) => {
          if (token === reqTokenRef.current) {
            console.error("search_entries (palette) failed:", e);
            setResults([]);
          }
        });
    }, 150);
    return () => clearTimeout(handle);
  }, [query, open, mode]);

  useEffect(() => {
    const q = query.trim();
    const token = ++relTokenRef.current;
    if (!open || mode !== "root" || !q || !aiEnabled) {
      setRelated((prev) => (prev.length ? [] : prev));
      return;
    }
    const handle = setTimeout(() => {
      aiSemanticSearch(q)
        .then((res) => {
          if (token === relTokenRef.current) setRelated(res);
        })
        .catch((e) => {
          if (token === relTokenRef.current) {
            console.error("ai_semantic_search (palette) failed:", e);
            setRelated([]);
          }
        });
    }, 150);
    return () => clearTimeout(handle);
  }, [query, open, mode, aiEnabled]);

  function enter(m: Mode) {
    setMode(m);
    setQuery("");
    setResults([]);
    setRelated([]);
    setSelRaw(0);
  }

  const actions: PaletteItem[] = [
    { kind: "action", id: "new", label: t("palette.newEntry"), hint: modKey("N"), run: onNewEntry },
    { kind: "action", id: "open-vault", label: t("palette.openVault"), hint: modKey("T"), run: beginAdd },
    { kind: "action", id: "lock-this", label: t("palette.lockThisVault"), hint: modKey("L"), run: onLock },
    { kind: "action", id: "lock-all", label: t("palette.lockAllVaults"), run: () => void lockAllTabs() },
    { kind: "action", id: "close-tab", label: t("palette.closeTab"), hint: modKey("W"), run: () => void closeActive() },
    { kind: "action", id: "focus-search", label: t("palette.focusSearch"), hint: modKey("F"), run: focusSearch },
    {
      kind: "action",
      id: "manage-templates",
      label: t("palette.manageFieldTemplates"),
      run: () => {
        setSettingsTab("templates");
        setRoute("settings");
      },
    },
    {
      kind: "action",
      id: "health",
      label: t("palette.health"),
      run: () => {
        setSettingsTab("health");
        setRoute("settings");
      },
    },
    { kind: "action", id: "manage-folders", label: t("palette.manageFolders"), run: () => setRoute("manage-folders") },
    { kind: "action", id: "manage-tags", label: t("palette.manageTags"), run: () => setRoute("manage-tags") },
    { kind: "action", id: "trash", label: t("palette.openRecycleBin"), run: () => setRoute("trash") },
    { kind: "action", id: "jump-folder", label: t("palette.jumpToFolder"), keepOpen: true, run: () => enter("folders") },
    { kind: "action", id: "jump-tag", label: t("palette.jumpToTag"), keepOpen: true, run: () => enter("tags") },
  ];

  const q = query.trim().toLowerCase();
  const sections: { header: string; items: PaletteItem[] }[] = [];
  if (mode === "folders") {
    const items: PaletteItem[] = flattenFolders(folders)
      .filter((f) => !q || f.name.toLowerCase().includes(q))
      .map((f) => ({
        kind: "action",
        id: "folder:" + f.id,
        label: f.name,
        run: () => {
          setNav({ kind: "folder", id: f.id });
          setRoute("main");
        },
      }));
    sections.push({ header: t("palette.sectionFolders"), items });
  } else if (mode === "tags") {
    const items: PaletteItem[] = tags
      .filter((t) => !q || t.name.toLowerCase().includes(q))
      .map((t) => ({
        kind: "action",
        id: "tag:" + t.id,
        label: t.name,
        hint: t.usage ? String(t.usage) : undefined,
        run: () => {
          setNav({ kind: "tag", id: t.id });
          setRoute("main");
        },
      }));
    sections.push({ header: t("palette.sectionTags"), items });
  } else {
    const acts = actions.filter((a) => a.kind === "action" && (!q || a.label.toLowerCase().includes(q)));
    const tabItems: PaletteItem[] = tabs
      .map((tab, i) => ({ tab, i }))
      .filter(({ i }) => i !== activeIndex)
      .filter(({ tab }) => !q || tab.name.toLowerCase().includes(q))
      .map(({ tab, i }) => ({
        kind: "action" as const,
        id: "switch:" + tab.vaultId,
        label: t("palette.switchToVault", { name: tab.name }),
        run: () => activateTab(i),
      }));
    const entryItems: PaletteItem[] = results
      .slice(0, 8)
      .map((e) => ({ kind: "entry", id: e.id, title: e.title, username: e.username }));
    if (acts.length) sections.push({ header: t("palette.sectionActions"), items: acts });
    if (tabItems.length) sections.push({ header: t("palette.sectionTabs"), items: tabItems });
    if (entryItems.length) sections.push({ header: t("palette.sectionEntries"), items: entryItems });

    const exactIds = new Set(entryItems.map((it) => it.id));
    const relatedItems: PaletteItem[] = related
      .filter((h) => !exactIds.has(h.entry.id))
      .slice(0, 5)
      .map((h) => ({ kind: "entry", id: h.entry.id, title: h.entry.title, username: h.entry.username, score: h.score }));
    if (relatedItems.length) sections.push({ header: t("palette.sectionRelated"), items: relatedItems });
  }

  const flat = sections.flatMap((s) => s.items);
  const sel = flat.length ? Math.min(selRaw, flat.length - 1) : 0;

  useEffect(() => {
    const list = listRef.current;
    const el = list?.querySelector<HTMLElement>(".kv-palette-item.is-selected");
    if (!list || !el) return;
    const lr = list.getBoundingClientRect();
    const er = el.getBoundingClientRect();
    if (er.bottom > lr.bottom) list.scrollTop += er.bottom - lr.bottom + 6;
    else if (er.top < lr.top) list.scrollTop -= lr.top - er.top + 6;
  }, [sel, mode, results, related, folders, tags, query]);

  if (!open) return null;

  function activate(item: PaletteItem | undefined) {
    if (!item) return;
    if (item.kind === "entry") {
      setRoute("main");
      select(item.id);
      onClose();
      return;
    }
    item.run();
    if (!item.keepOpen) onClose();
  }

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelRaw((i) => Math.min(i + 1, Math.max(flat.length - 1, 0)));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelRaw((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      activate(flat[sel]);
    } else if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      if (mode !== "root") enter("root");
      else onClose();
    }
  }

  const placeholder = mode === "folders" ? t("palette.jumpToFolder") : mode === "tags" ? t("palette.jumpToTag") : t("palette.searchPlaceholder");
  const emptyText = q
    ? t("palette.noMatchesFor", { query: query.trim() })
    : mode === "folders"
      ? t("palette.noFolders")
      : mode === "tags"
        ? t("palette.noTags")
        : t("palette.typeToSearch");

  let rowIndex = -1;
  return (
    <div className="kv-palette-scrim" onClick={onClose}>
      <div
        className="kv-palette"
        role="dialog"
        aria-modal="true"
        aria-label={t("palette.ariaLabel")}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="kv-palette-input">
          <Icon name="search" size={17} />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setSelRaw(0);
            }}
            onKeyDown={onKeyDown}
            placeholder={placeholder}
            aria-label={t("palette.searchAriaLabel")}
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
          />
          <span className="kv-kbd">esc</span>
        </div>
        <div className="kv-palette-list" ref={listRef}>
          {flat.length === 0 ? (
            <div className="kv-palette-empty">{emptyText}</div>
          ) : (
            sections.map((s) => (
              <div key={s.header}>
                <div className="kv-palette-group">{s.header}</div>
                {s.items.map((item) => {
                  rowIndex += 1;
                  const i = rowIndex;
                  const label = item.kind === "entry" ? item.title : item.label;
                  const hint =
                    item.kind === "entry"
                      ? item.score != null
                        ? item.score.toFixed(2)
                        : item.username
                      : item.hint;
                  return (
                    <div
                      key={item.id}
                      className={"kv-palette-item" + (i === sel ? " is-selected" : "")}
                      onMouseMove={(e) => {
                        if (e.clientX === lastMouseRef.current.x && e.clientY === lastMouseRef.current.y) return;
                        lastMouseRef.current = { x: e.clientX, y: e.clientY };
                        setSelRaw(i);
                      }}
                      onClick={() => activate(item)}
                    >
                      <span className="label">{label}</span>
                      {hint ? <span className="hint">{hint}</span> : null}
                    </div>
                  );
                })}
              </div>
            ))
          )}
        </div>
        <div className="kv-palette-foot">
          <span><span className="kv-kbd">↑↓</span> {t("palette.hintNavigate")}</span>
          <span><span className="kv-kbd">↵</span> {t("palette.hintOpen")}</span>
          <span><span className="kv-kbd">esc</span> {mode === "root" ? t("palette.hintClose") : t("palette.hintBack")}</span>
        </div>
      </div>
    </div>
  );
}
