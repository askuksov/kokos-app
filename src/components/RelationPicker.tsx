import { useEffect, useRef, useState } from "react";
import type { KeyboardEvent as ReactKeyboardEvent } from "react";
import { listEntries } from "../ipc/commands";
import type { EntrySummary } from "../ipc/types";
import { useT } from "../state/LangContext";

const RELATION_TYPE_OPTIONS: { value: string; labelKey: string }[] = [
  { value: "related", labelKey: "detail.relationRelated" },
  { value: "parent", labelKey: "detail.relationParent" },
  { value: "child", labelKey: "detail.relationChild" },
  { value: "duplicate", labelKey: "detail.relationDuplicate" },
  { value: "see-also", labelKey: "detail.relationSeeAlso" },
];

const MAX_CANDIDATES = 50;

/**
 * Presentational link picker: a relation-type `<select>` plus a search
 * combobox over every entry in the vault, used by EntryDetail.tsx's
 * "Linked entries" card to CREATE a relation (the card itself handles the
 * read/navigate/delete side). This component never calls `add_relation`
 * itself — clicking a candidate calls `onAdd(otherId, relationType)` and the
 * caller (EntryDetail's `handleAddRelation`) owns the IPC call, the
 * `selectionTokenRef`-guarded refetch, and error surfacing. Structurally
 * modeled on EntryEditor.tsx's own `TagMultiSelect` (`.kv-tagselect*`
 * markup + the pointerdown-to-close effect), minus
 * the multi-select "chips": a link picks ONE entry and fires immediately,
 * it doesn't accumulate a pending selection the way tag-picking does.
 *
 * SEARCH SCOPE: fetches via `listEntries("all")`, deliberately NOT
 * `useVault().entries` — the vault-wide list a caller might otherwise reach
 * for is narrowed by whatever favorites/recent VIEW the sidebar currently
 * has selected, which would silently hide perfectly linkable entries from
 * this picker (e.g. every non-favorite entry, while the sidebar sits on
 * Favorites). Fetched LAZILY, on the first focus/open rather than on
 * mount — `loadedRef` (a ref, not state) guards against a fast double-focus
 * firing two overlapping fetches before the first `setAllEntries` lands;
 * a failed fetch clears the guard so the next focus can retry. `list_entries`
 * already excludes soft-deleted entries server-side (`kokos-core::entries::
 * list`, `WHERE e.is_deleted = 0` unconditional on the view), so there is no
 * trashed-entry case for this component to filter out itself.
 *
 * This component is remounted fresh on every entry switch: EntryDetail.tsx
 * renders it with `key={entry.id}` at its call site, so a new selection
 * already discards this component's `q`/`open`/`type`/`allEntries` state for
 * free — no reset effect needed here. (EntryDetail as a component is NOT
 * itself remounted by selection — Vault.tsx keys `<EntryDetail>` on
 * `detailVersion`, which only bumps on editor save, not on selection. The
 * ancestor `<div className="kv-detail-inner" key={entry.id}>` a few dozen
 * lines up in that file already forces the same full-subtree remount on its
 * own; keying this component directly makes that contract explicit at its
 * own call site too, instead of relying on it only implicitly.)
 *
 * No secrets involved — entry titles are not protected data, so there is
 * nothing here for the reveal/copy security model to guard.
 */
export function RelationPicker({
  currentEntryId,
  excludeIds,
  onAdd,
  disabled,
}: {
  currentEntryId: string;
  excludeIds: Set<string>;
  onAdd: (otherId: string, relationType: string) => void;
  disabled?: boolean;
}) {
  const t = useT();
  const [q, setQ] = useState("");
  const [type, setType] = useState("related");
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const [allEntries, setAllEntries] = useState<EntrySummary[]>([]);
  const loadedRef = useRef(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    function onDown(ev: PointerEvent) {
      if (rootRef.current && !rootRef.current.contains(ev.target as Node)) setOpen(false);
    }
    document.addEventListener("pointerdown", onDown);
    return () => document.removeEventListener("pointerdown", onDown);
  }, []);
  useEffect(() => setActive(0), [q, open]);

  function ensureLoaded() {
    if (loadedRef.current) return;
    loadedRef.current = true;
    listEntries("all")
      .then(setAllEntries)
      .catch((e) => {
        console.error("list_entries failed:", e);
        loadedRef.current = false;
      });
  }

  const norm = q.trim().toLowerCase();
  const candidates = allEntries
    .filter(
      (e) =>
        e.id !== currentEntryId &&
        !excludeIds.has(e.id) &&
        (!norm || e.title.toLowerCase().includes(norm)),
    )
    .slice(0, MAX_CANDIDATES);

  function choose(entry: EntrySummary) {
    onAdd(entry.id, type);
    setQ("");
    setActive(0);
    inputRef.current?.focus();
  }

  function onKeyDown(ev: ReactKeyboardEvent<HTMLInputElement>) {
    if (ev.key === "ArrowDown") {
      ev.preventDefault();
      setOpen(true);
      setActive((i) => Math.min(i + 1, candidates.length - 1));
    } else if (ev.key === "ArrowUp") {
      ev.preventDefault();
      setActive((i) => Math.max(i - 1, 0));
    } else if (ev.key === "Enter") {
      ev.preventDefault();
      if (open && candidates.length) choose(candidates[Math.min(active, candidates.length - 1)]);
    } else if (ev.key === "Escape") {
      if (open) {
        ev.stopPropagation();
        setOpen(false);
      }
    }
  }

  return (
    <div className="kv-relation-picker">
      <select
        className="kv-input"
        aria-label={t("relation.linkAs")}
        title={t("relation.linkAs")}
        value={type}
        disabled={disabled}
        onChange={(e) => setType(e.target.value)}
      >
        {RELATION_TYPE_OPTIONS.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {t(opt.labelKey)}
          </option>
        ))}
      </select>
      <div className={"kv-tagselect" + (open ? " is-open" : "")} ref={rootRef}>
        <div
          className="kv-tagselect-control"
          onClick={() => {
            if (disabled) return;
            ensureLoaded();
            setOpen(true);
            inputRef.current?.focus();
          }}
        >
          <input
            ref={inputRef}
            className="kv-tagselect-input"
            placeholder={t("relation.searchPlaceholder")}
            value={q}
            disabled={disabled}
            onChange={(e) => {
              setQ(e.target.value);
              setOpen(true);
            }}
            onFocus={() => {
              ensureLoaded();
              setOpen(true);
            }}
            onKeyDown={onKeyDown}
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
          />
        </div>
        {open && !disabled ? (
          <div className="kv-tagselect-pop">
            {candidates.length === 0 ? (
              <div className="kv-tagselect-empty">
                {norm ? t("relation.noMatching") : t("relation.noOthers")}
              </div>
            ) : (
              candidates.map((entry, i) => (
                <div
                  key={entry.id}
                  className={"kv-tagselect-opt" + (i === active ? " is-active" : "")}
                  onMouseEnter={() => setActive(i)}
                  onClick={() => choose(entry)}
                >
                  <span className="name">{entry.title}</span>
                </div>
              ))
            )}
          </div>
        ) : null}
      </div>
    </div>
  );
}
