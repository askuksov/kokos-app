import { useEffect, useRef, useState } from "react";
import { useVault } from "../state/VaultContext";
import { useClipboard } from "../state/ClipboardContext";
import { useSettings } from "../state/SettingsContext";
import { useT, useLang } from "../state/LangContext";
import type { Lang } from "../lib/i18n";
import { getCurrentWindow } from "@tauri-apps/api/window";
import {
  addEntryTag,
  addRelation,
  aiStatus,
  aiSuggestFolders,
  aiSuggestTags,
  clearFieldHistory,
  deleteAttachment,
  deleteEntry,
  deleteRelation,
  downloadAttachment,
  getEntry,
  listAttachments,
  listFieldHistory,
  listRelations,
  pickSavePath,
  revealField,
  toggleFavorite,
  updateEntry,
} from "../ipc/commands";
import type { AttachmentMeta, Entry, Field, FolderNode, FolderSuggestion, HistoryEntry, RelationView, TagSuggestion } from "../ipc/types";
import { formatBytes } from "../lib/format";
import { tagColor } from "../lib/tagColors";
import { entryTypeMeta } from "../lib/entryTypes";
import type { StrengthScore } from "../lib/strength";
import { previewKind, type PreviewKind } from "../lib/attachmentPreview";
import { AttachmentLightbox } from "./AttachmentLightbox";
import { RelationPicker } from "./RelationPicker";
import { TotpField } from "./TotpField";
import "./EntryDetail.css";

const PREVIEWABLE_KINDS = new Set<PreviewKind>(["image", "text", "pdf"]);

type DetailIcon =
  | "shield"
  | "globe"
  | "lock"
  | "arrowOut"
  | "note"
  | "eye"
  | "eyeOff"
  | "copy"
  | "check"
  | "plus"
  | "pencil"
  | "trash"
  | "star"
  | "folder"
  | "tag"
  | "clip"
  | "download"
  | "link"
  | "clock"
  | "user"
  | "card"
  | "wifi";

const ICON_PATHS: Record<DetailIcon, React.ReactNode> = {
  shield: <path d="M12 3l7.5 2.8v5.7c0 4.3-2.9 7.3-7.5 9-4.6-1.7-7.5-4.7-7.5-9V5.8L12 3z" />,
  globe: (
    <g>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M3.5 12h17M12 3.5c2.3 2.2 3.5 5.2 3.5 8.5s-1.2 6.3-3.5 8.5c-2.3-2.2-3.5-5.2-3.5-8.5s1.2-6.3 3.5-8.5z" />
    </g>
  ),
  lock: (
    <g>
      <rect x="5" y="10.5" width="14" height="9.5" rx="2" />
      <path d="M8.5 10.5V7.5a3.5 3.5 0 017 0v3" />
    </g>
  ),
  arrowOut: <path d="M7.5 16.5l9-9M9 7.5h7.5V15" />,
  note: (
    <g>
      <path d="M5 4.5h14v11l-4 4H5v-15z" />
      <path d="M15 19.5v-4h4" />
    </g>
  ),
  eye: (
    <g>
      <path d="M2.8 12S6.2 5.8 12 5.8 21.2 12 21.2 12 17.8 18.2 12 18.2 2.8 12 2.8 12z" />
      <circle cx="12" cy="12" r="2.8" />
    </g>
  ),
  eyeOff: (
    <g>
      <path d="M4 4l16 16" />
      <path d="M9.9 5.2A9.6 9.6 0 0112 5c5.8 0 9.2 7 9.2 7a16.6 16.6 0 01-3 3.7M6.1 7.6A15.6 15.6 0 002.8 12s3.4 6.2 9.2 6.2a8.9 8.9 0 003.4-.7" />
      <path d="M9.9 9.9a2.9 2.9 0 004.1 4.1" />
    </g>
  ),
  copy: (
    <g>
      <rect x="8.5" y="8.5" width="11" height="11" rx="2" />
      <path d="M5 14.5V6a2 2 0 012-2h8.5" />
    </g>
  ),
  check: <path d="M5 13l4.2 4.2L19 7.5" />,
  plus: <path d="M12 5.5v13M5.5 12h13" />,
  pencil: <path d="M14.5 5.5l4 4L8 20H4v-4L14.5 5.5zM12.5 7.5l4 4" />,
  trash: (
    <g>
      <path d="M4.5 7h15" />
      <path d="M9.5 7V5.2A1.2 1.2 0 0110.7 4h2.6a1.2 1.2 0 011.2 1.2V7" />
      <path d="M6.5 7l.8 12a1.5 1.5 0 001.5 1.4h6.4a1.5 1.5 0 001.5-1.4l.8-12" />
      <path d="M10 11v5.5M14 11v5.5" />
    </g>
  ),
  star: <path d="M12 3.5l2.6 5.3 5.9.9-4.2 4.1 1 5.8L12 16.9l-5.2 2.7 1-5.8L3.5 9.7l5.9-.9L12 3.5z" />,
  folder: <path d="M3.5 7a2 2 0 012-2h4l2 2.2h7a2 2 0 012 2V17a2 2 0 01-2 2h-13a2 2 0 01-2-2V7z" />,
  tag: (
    <g>
      <path d="M20.4 13.2l-7 7a1.8 1.8 0 01-2.6 0l-7-7V5.4a1.8 1.8 0 011.8-1.8h7.8l7 7a1.8 1.8 0 010 2.6z" />
      <circle cx="8" cy="8" r="1" />
    </g>
  ),
  clip: <path d="M20 11.5l-7.6 7.6a5 5 0 01-7-7L13 4.5a3.3 3.3 0 014.7 4.7l-7.6 7.5a1.7 1.7 0 01-2.3-2.3l7-7" />,
  download: <path d="M12 3v10m0 0l4-4m-4 4l-4-4M5 20h14" />,
  link: (
    <path d="M10 13a5 5 0 007.5.5l3-3a5 5 0 00-7-7l-1.5 1.5M14 11a5 5 0 00-7.5-.5l-3 3a5 5 0 007 7l1.5-1.5" />
  ),
  clock: (
    <g>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 7.5V12l3.2 1.9" />
    </g>
  ),
  user: (
    <path d="M4.5 20v-1.2a4.5 4.5 0 014.5-4.5h6a4.5 4.5 0 014.5 4.5V20 M12 3.6a3.8 3.8 0 100 7.6 3.8 3.8 0 000-7.6z" />
  ),
  card: <path d="M3.5 6.5h17a1 1 0 011 1v9a1 1 0 01-1 1h-17a1 1 0 01-1-1v-9a1 1 0 011-1z M2.5 10.5h19" />,
  wifi: <path d="M4.5 12.5a10.5 10.5 0 0115 0 M7.8 15.6a6 6 0 018.4 0 M12 19.2v.01" />,
};

function Icon({
  name,
  size = 15,
  strokeWidth = 1.7,
  className,
  filled,
}: {
  name: DetailIcon;
  size?: number;
  strokeWidth?: number;
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
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {ICON_PATHS[name]}
    </svg>
  );
}

function CopyButton({ getValue, label }: { getValue: () => Promise<string>; label: string }) {
  const t = useT();
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);
  const { copySecret, copyEpoch } = useClipboard();

  async function copy() {
    if (busy) return;
    setBusy(true);
    try {
      const epoch = copyEpoch();
      const value = await getValue();
      await copySecret(value, epoch);
      setDone(true);
      setTimeout(() => setDone(false), 1400);
    } catch (e) {
      console.error("copy failed:", e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <button
      type="button"
      className="kv-btn is-icon"
      title={t("detail.copyAction", { label: label.toLowerCase() })}
      aria-label={t("detail.copyAction", { label })}
      onClick={copy}
      disabled={busy}
      style={done ? { color: "var(--ok)" } : undefined}
    >
      <Icon name={done ? "check" : "copy"} strokeWidth={done ? 2.2 : 1.7} />
    </button>
  );
}

function FieldLayout({
  icon,
  label,
  mono,
  actions,
  children,
}: {
  icon: DetailIcon;
  label: string;
  mono?: boolean;
  actions?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="kv-field">
      <Icon name={icon} size={16} className="kv-field-icon" />
      <div className="kv-field-body">
        <div className="kv-field-label">{label}</div>
        <div className={"kv-field-value" + (mono ? " is-mono" : "")}>{children}</div>
      </div>
      {actions ? <div className="kv-field-actions">{actions}</div> : null}
    </div>
  );
}

const FIELD_PRESENTATION: Record<string, { icon: DetailIcon; mono: boolean }> = {
  text: { icon: "globe", mono: true },
  secret: { icon: "lock", mono: true },
  url: { icon: "arrowOut", mono: false },
  email: { icon: "globe", mono: true },
  date: { icon: "note", mono: false },
  phone: { icon: "globe", mono: false },
};
const DEFAULT_FIELD_PRESENTATION: { icon: DetailIcon; mono: boolean } = { icon: "globe", mono: true };

function presentField(fieldType: string) {
  return FIELD_PRESENTATION[fieldType] ?? DEFAULT_FIELD_PRESENTATION;
}

const FIELD_MASK = "•".repeat(10);

interface RevealState {
  value: string;
  shown: boolean;
}

function strengthTone(score: StrengthScore): "weak" | "fair" | "strong" {
  if (score <= 1) return "weak";
  if (score === 2) return "fair";
  return "strong";
}

function StrengthBar({ score }: { score: StrengthScore }) {
  const t = useT();
  const label = t("strength." + score);
  return (
    <div className="kv-strength" data-tone={strengthTone(score)}>
      <div className="kv-strength-track">
        <div className="kv-strength-fill" style={{ width: `${(score + 1) * 20}%` }} />
      </div>
      <span className="kv-strength-label">{label}</span>
    </div>
  );
}

function EntryFieldRow({
  field,
  reveal,
  busy,
  onToggleReveal,
  onCopySecret,
  onShowHistory,
}: {
  field: Field;
  reveal: RevealState | undefined;
  busy: boolean;
  onToggleReveal: (fieldId: string) => void;
  onCopySecret: (fieldId: string) => Promise<string>;
  onShowHistory: (field: Field) => void;
}) {
  const t = useT();
  const { icon, mono } = presentField(field.field_type);

  if (!field.is_protected) {
    const value = field.value;
    return (
      <FieldLayout
        icon={icon}
        label={field.name}
        mono={mono}
        actions={
          value !== null ? (
            <CopyButton getValue={() => Promise.resolve(value)} label={field.name} />
          ) : undefined
        }
      >
        {value !== null ? value : <span className="kv-field-empty">—</span>}
      </FieldLayout>
    );
  }

  const value = reveal && reveal.shown ? reveal.value : null;
  const shown = value !== null;

  return (
    <FieldLayout
      icon={icon}
      label={field.name}
      mono={mono}
      actions={
        <>
          <button
            type="button"
            className="kv-btn is-icon"
            title={shown ? t("detail.conceal") : t("detail.reveal")}
            aria-label={
              shown ? t("detail.concealField", { name: field.name }) : t("detail.revealField", { name: field.name })
            }
            aria-pressed={shown}
            disabled={busy}
            onClick={() => onToggleReveal(field.id)}
          >
            <Icon name={shown ? "eyeOff" : "eye"} />
          </button>
          <CopyButton getValue={() => onCopySecret(field.id)} label={field.name} />
          {field.field_type === "secret" ? (
            <button
              type="button"
              className="kv-btn is-icon"
              title={t("detail.passwordHistory")}
              aria-label={t("detail.passwordHistoryFor", { name: field.name })}
              onClick={() => onShowHistory(field)}
            >
              <Icon name="clock" />
            </button>
          ) : null}
        </>
      }
    >
      {value !== null ? (
        <span className="kv-reveal-in">{value}</span>
      ) : (
        <span className="kv-field-mask" aria-label={t("detail.hidden")}>
          {FIELD_MASK}
        </span>
      )}
      {field.field_type === "secret" && field.strength !== null ? (
        <StrengthBar score={field.strength as StrengthScore} />
      ) : null}
    </FieldLayout>
  );
}

function formatDate(unixSeconds: number, lang: Lang): string {
  return new Intl.DateTimeFormat(lang, { year: "numeric", month: "short", day: "numeric" }).format(
    new Date(unixSeconds * 1000),
  );
}

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
        width: 56,
        height: 56,
        fontSize: 56 * 0.44,
        background: m.bg,
        borderRadius: "var(--radius-sm)",
      }}
    >
      {m.letter}
    </div>
  );
}

function findFolder(nodes: FolderNode[], id: string): FolderNode | null {
  for (const n of nodes) {
    if (n.id === id) return n;
    const found = findFolder(n.children, id);
    if (found) return found;
  }
  return null;
}

const RELATION_TYPE_ORDER = ["related", "parent", "child", "duplicate", "see-also"] as const;
const RELATION_LABEL_KEYS: Record<string, string> = {
  related: "detail.relationRelated",
  parent: "detail.relationParent",
  child: "detail.relationChild",
  duplicate: "detail.relationDuplicate",
  "see-also": "detail.relationSeeAlso",
};

function HistoryModal({
  entryId,
  field,
  onClose,
}: {
  entryId: string;
  field: Field;
  onClose: () => void;
}) {
  const t = useT();
  const lang = useLang();
  const [rows, setRows] = useState<HistoryEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [revealed, setRevealed] = useState<Record<string, boolean>>({});
  const [confirming, setConfirming] = useState(false);
  const [clearing, setClearing] = useState(false);

  useEffect(() => {
    let cancelled = false;
    listFieldHistory(entryId, field.name)
      .then((h) => {
        if (!cancelled) {
          setRows(h);
          setLoading(false);
        }
      })
      .catch((e) => {
        console.error("list_field_history failed:", e);
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [entryId, field.name]);

  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useEffect(() => {
    function onKeyDown(ev: KeyboardEvent) {
      if (ev.key === "Escape") onCloseRef.current();
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  useEffect(() => {
    if (!confirming) return;
    function onDocMouseDown(ev: MouseEvent) {
      const target = ev.target as Element | null;
      if (target?.closest('[data-confirming="true"]')) return;
      setConfirming(false);
    }
    document.addEventListener("mousedown", onDocMouseDown);
    return () => document.removeEventListener("mousedown", onDocMouseDown);
  }, [confirming]);

  function toggleRevealed(id: string) {
    setRevealed((r) => ({ ...r, [id]: !r[id] }));
  }

  async function onClearClick() {
    if (clearing) return;
    if (!confirming) {
      setConfirming(true);
      return;
    }
    setConfirming(false);
    setClearing(true);
    try {
      await clearFieldHistory(entryId, field.name);
      setRows([]);
      setRevealed({});
    } catch (e) {
      console.error("clear_field_history failed:", e);
    } finally {
      setClearing(false);
    }
  }

  return (
    <div className="kv-modal-scrim" onClick={onClose}>
      <div
        className="kv-modal"
        role="dialog"
        aria-modal="true"
        aria-label={t("detail.historyAriaLabel", { name: field.name })}
        onClick={(ev) => ev.stopPropagation()}
      >
        <div className="kv-modal-header">
          <h2>{t("detail.historyTitle", { name: field.name })}</h2>
        </div>
        <div className="kv-modal-body">
          {loading ? (
            <p className="kv-relation-empty">{t("common.loading")}</p>
          ) : rows.length === 0 ? (
            <p className="kv-relation-empty">{t("detail.noHistoryYet")}</p>
          ) : (
            rows.map((row) => {
              const shown = !!revealed[row.id];
              const when = formatDate(row.changed_at, lang);
              return (
                <div key={row.id} className="kv-manage-row">
                  <span className="kv-history-date">{when}</span>
                  <span className="kv-history-value">
                    {shown ? (
                      <span className="kv-reveal-in">{row.value ?? ""}</span>
                    ) : (
                      <span className="kv-field-mask" aria-label={t("detail.hidden")}>
                        {FIELD_MASK}
                      </span>
                    )}
                  </span>
                  <button
                    type="button"
                    className="kv-btn is-icon"
                    title={shown ? t("detail.conceal") : t("detail.reveal")}
                    aria-label={
                      shown ? t("detail.concealValueFrom", { when }) : t("detail.revealValueFrom", { when })
                    }
                    aria-pressed={shown}
                    onClick={() => toggleRevealed(row.id)}
                  >
                    <Icon name={shown ? "eyeOff" : "eye"} />
                  </button>
                  <CopyButton
                    getValue={() => Promise.resolve(row.value ?? "")}
                    label={t("detail.fieldFromDate", { name: field.name, when })}
                  />
                </div>
              );
            })
          )}
        </div>
        <div className="kv-modal-footer">
          {!loading && rows.length > 0 ? (
            <button
              type="button"
              className="kv-btn is-ghost is-danger"
              disabled={clearing}
              data-confirming={confirming ? "true" : undefined}
              aria-label={t("detail.clearHistoryFor", { name: field.name })}
              onClick={onClearClick}
            >
              <Icon name="trash" size={13} />{" "}
              {clearing ? t("detail.clearingHistory") : confirming ? t("detail.confirmClear") : t("detail.clearHistory")}
            </button>
          ) : null}
        </div>
      </div>
    </div>
  );
}

function withKey(prev: Set<string>, key: string, present: boolean): Set<string> {
  const next = new Set(prev);
  if (present) next.add(key);
  else next.delete(key);
  return next;
}

/**
 * Right-panel entry detail. Layout: a `.kv-detail-bar` (favorite star,
 * icon-only Delete, Edit), a header (hash-colored monogram duplicated from
 * EntryList.tsx's avatar, title, and a `.kv-entry-meta` line with type, folder
 * and absolute "Edited {date}"), then the cards: fields, notes, tags,
 * attachments, linked entries, and a created/modified/strength meta grid.
 * Notes and attachments cards are hidden when empty; the tags card also shows
 * when AI suggestions are enabled. URL fields render their value as plain
 * text, not as an outbound link. With no entry selected the bar is just an
 * empty drag region; an empty vault shows a "create your first entry" CTA
 * (`onNewEntry`), otherwise `emptyOverride` or the select prompt. `onEdit`
 * is a plain callback, so this component stays agnostic of the editor's
 * open/close state, which Vault.tsx owns.
 *
 * STRENGTH: the score is computed by the Rust backend (`kokos-core::strength`,
 * on the decrypted plaintext, never round-tripped as plaintext) and arrives
 * as `field.strength` (0-4, or `null`) on every `Field` (`src/ipc/types.ts`).
 * `StrengthBar` and the meta-grid cell read that integer directly,
 * independent of `reveals`: the bar renders under a masked field exactly as
 * under a revealed one, and the meta-grid cell shows an em dash only for a
 * `null` score (e.g. an empty secret).
 *
 * SECURITY: the backend withholds `field.value` for protected fields; the
 * plaintext is fetched only on an explicit reveal/copy via `revealField`.
 * Revealed values live only in `reveals` below (a local `useState` map,
 * `fieldId -> { value, shown }`), never in `VaultContext`, never
 * `console.log`'d. They are cleared every time `selectedId` changes, in the
 * same effect that (re)fetches the entry, so a newly-selected entry always
 * starts fully masked and never inherits the previous entry's secrets.
 * `selectionTokenRef` (bumped per selection) and `concealEpochRef` (bumped on
 * window-blur conceal and unmount) are snapshotted before every reveal/copy
 * await, and a continuation that finds either changed drops its result.
 * Revealed fields are also auto-concealed after `settings.conceal_seconds`
 * (when > 0).
 *
 * DELETE is a soft delete (`kokos-core::entries::soft_delete`) that also
 * autosaves on the backend, so it can fail its disk write like create/update.
 * On success it clears the selection and refetches (`select(null)` first,
 * then `refreshEntries()`/`refreshFolders()`/`refreshTags()`, so the panel
 * and the list drop the entry together); on rejection it reports through the
 * same `setSaveError` channel EntryEditor uses, since a failed delete leaves
 * the same "change is in memory, not on disk" state the save-error banner
 * (SaveErrorBanner.tsx) exists to surface.
 *
 * FAVORITE: the star toggles ONLY through `toggleFavorite`, the one IPC
 * command that flips `entries.is_favorite` AND syncs the reserved favorite
 * tag link atomically (`kokos_core::tags::toggle_favorite`). It never goes
 * through `updateEntry`/`EntryPatch.is_favorite`: that path (which
 * EntryEditor.tsx's save carries as a pass-through of the loaded value)
 * writes the column WITHOUT touching the tag; per `toggle_favorite`'s doc
 * comment (src-tauri/src/commands.rs) that desync is a known gap this command
 * routes around. A successful toggle refreshes both caches of favorite state:
 * `refreshEntries()` (the list and any Favorites view) and a re-`getEntry`
 * (this panel's `entry.is_favorite`). Like `handleDelete`, it assumes the
 * selection has not moved on since the click.
 *
 * ATTACHMENTS come from a dedicated `list_attachments` fetch (they are their
 * own table, not part of `Entry`) with their own `[selectedId]`-keyed
 * cancelled-guard effect. This panel is preview/download/delete only;
 * uploading is the editor's job. Deleting an attachment only flips the derived
 * `EntrySummary.has_attachments` badge, never folder/tag membership, so only
 * `refreshEntries()` runs (plus the local `attachments` update).
 *
 * LINKED ENTRIES use their own `relations` state and effect, mirroring the
 * attachments pair. Rows group by `relation_type` in the fixed
 * RELATION_TYPE_ORDER rather than fetch order, so section order never
 * jitters; `relation_type` arrives already inverse-mapped from
 * `list_for_entry` (kokos-core::relations), so this component only buckets
 * it. Clicking a non-trashed row's title calls `select(other_id)`, which the
 * `[selectedId]`-keyed effects then pick up like any other selection change;
 * a trashed target (`other_is_deleted`) renders as plain flagged text, since
 * navigating there would land on a soft-deleted entry. Relations are not
 * reflected on `EntrySummary`, so deleting one only filters local
 * `relations`. The card always renders (an empty-state hint replaces the
 * list) so `RelationPicker` stays reachable before any links exist.
 * `linkedIds` feeds the picker's `excludeIds`, so an already-linked entry is
 * not offered again (one pair cannot get a second relation type through the
 * picker; `add_relation`'s DuplicateRelation/SelfRelation errors remain the
 * backstop, surfaced via `setSaveError`). `handleAddRelation` refetches
 * `listRelations` instead of appending locally, because `add_relation`
 * returns `void` and there is no `relation_id`/inverse-mapped label to build
 * a `RelationView` from; the refetch is guarded by `selectionTokenRef`.
 */
export function EntryDetail({
  onEdit,
  onNewEntry,
  emptyOverride,
}: {
  onEdit: (id: string) => void;
  onNewEntry: () => void;
  /// Rendered instead of the "select an entry" placeholder. Ignored while the
  /// vault is empty, because the "create your first entry" CTA outranks it.
  emptyOverride?: React.ReactNode;
}) {
  const t = useT();
  const lang = useLang();
  const { selectedId, select, setSaveError, refreshEntries, refreshFolders, refreshTags, folders,
    nav, search, visibleEntries, entriesLoaded } = useVault();
  const { settings } = useSettings();
  const [entry, setEntry] = useState<Entry | null>(null);
  const [loadError, setLoadError] = useState(false);
  const [reveals, setReveals] = useState<Record<string, RevealState>>({});
  const [revealing, setRevealing] = useState<Record<string, boolean>>({});
  const [deleting, setDeleting] = useState(false);
  const [favoriting, setFavoriting] = useState(false);
  const [attachments, setAttachments] = useState<AttachmentMeta[]>([]);
  const [attachmentBusy, setAttachmentBusy] = useState<Record<string, boolean>>({});
  const [previewId, setPreviewId] = useState<string | null>(null);
  const [relations, setRelations] = useState<RelationView[]>([]);
  const [historyFor, setHistoryFor] = useState<Field | null>(null);
  const [aiOn, setAiOn] = useState(false);
  const [suggestions, setSuggestions] = useState<FolderSuggestion[] | null>(null);
  const [suggesting, setSuggesting] = useState(false);
  const [tagSuggestions, setTagSuggestions] = useState<TagSuggestion[] | null>(null);
  const [suggestingTags, setSuggestingTags] = useState(false);
  const [applyingKeys, setApplyingKeys] = useState<Set<string>>(new Set());
  const [addedTags, setAddedTags] = useState<Set<string>>(new Set());
  const selectionTokenRef = useRef(0);
  // Bumped when reveals are concealed on window blur (and on unmount) so
  // reveal/copy continuations started earlier cannot restore plaintext.
  const concealEpochRef = useRef(0);

  const addingRelationRef = useRef<Set<string>>(new Set());

  const concealTimersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());
  // fieldId -> time (ms) the field was revealed, for rescheduling on timeout change.
  const concealStartsRef = useRef<Map<string, number>>(new Map());

  useEffect(() => {
    selectionTokenRef.current += 1;

    setReveals({});
    setRevealing({});
    setLoadError(false);
    setHistoryFor(null);
    setPreviewId(null);
    setSuggestions(null);
    setSuggesting(false);
    setTagSuggestions(null);
    setSuggestingTags(false);
    setApplyingKeys(new Set());
    setAddedTags(new Set());

    if (!selectedId) {
      setEntry(null);
      return;
    }

    let cancelled = false;
    getEntry(selectedId)
      .then((e) => {
        if (!cancelled) setEntry(e);
      })
      .catch((e) => {
        console.error("get_entry failed:", e);
        if (!cancelled) {
          setEntry(null);
          setLoadError(true);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [selectedId]);

  useEffect(() => {
    setAttachments([]);

    if (!selectedId) return;

    let cancelled = false;
    listAttachments(selectedId)
      .then((a) => {
        if (!cancelled) setAttachments(a);
      })
      .catch((e) => {
        console.error("list_attachments failed:", e);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedId]);

  useEffect(() => {
    setRelations([]);

    if (!selectedId) return;

    let cancelled = false;
    listRelations(selectedId)
      .then((r) => {
        if (!cancelled) setRelations(r);
      })
      .catch((e) => {
        console.error("list_relations failed:", e);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedId]);

  useEffect(() => {
    let cancelled = false;
    const probe = () => {
      aiStatus()
        .then((st) => {
          if (!cancelled) setAiOn(st.enabled);
        })
        .catch(() => {
          if (!cancelled) setAiOn(false);
        });
    };
    probe();
    window.addEventListener("focus", probe);
    return () => {
      cancelled = true;
      window.removeEventListener("focus", probe);
    };
  }, []);

  useEffect(() => {
    const timers = concealTimersRef.current;
    const starts = concealStartsRef.current;
    const seconds = settings.conceal_seconds;
    const now = Date.now();
    for (const [fieldId, st] of Object.entries(reveals)) {
      if (seconds > 0 && st.shown) {
        // Keep the ORIGINAL reveal time so a changed timeout is applied to
        // already-revealed fields (elapsed >= new timeout conceals right away).
        const started = starts.get(fieldId) ?? now;
        starts.set(fieldId, started);
        const existing = timers.get(fieldId);
        if (existing !== undefined) clearTimeout(existing);
        const id = setTimeout(() => {
          timers.delete(fieldId);
          starts.delete(fieldId);
          setReveals((r) => {
            if (!r[fieldId]) return r;
            const next = { ...r };
            delete next[fieldId];
            return next;
          });
        }, Math.max(0, started + seconds * 1000 - now));
        timers.set(fieldId, id);
      }
    }
    for (const [fieldId, id] of timers) {
      if (seconds <= 0 || !reveals[fieldId]?.shown) {
        clearTimeout(id);
        timers.delete(fieldId);
      }
    }
    for (const fieldId of starts.keys()) {
      if (seconds <= 0 || !reveals[fieldId]?.shown) starts.delete(fieldId);
    }
  }, [reveals, settings.conceal_seconds]);

  useEffect(() => {
    const timers = concealTimersRef.current;
    return () => {
      for (const id of timers.values()) clearTimeout(id);
      timers.clear();
      concealStartsRef.current.clear();
      concealEpochRef.current += 1;
    };
  }, []);

  useEffect(() => {
    const un = getCurrentWindow().onFocusChanged(({ payload: focused }) => {
      if (!focused && settings.conceal_on_blur) {
        concealEpochRef.current += 1;
        setReveals({});
      }
    });
    return () => {
      void un.then((f) => f());
    };
  }, [settings.conceal_on_blur]);

  async function onToggleReveal(fieldId: string) {
    const existing = reveals[fieldId];
    if (existing) {
      setReveals((r) => ({ ...r, [fieldId]: { ...existing, shown: !existing.shown } }));
      return;
    }
    if (!entry || revealing[fieldId]) return;
    const token = selectionTokenRef.current;
    const concealEpoch = concealEpochRef.current;
    setRevealing((r) => ({ ...r, [fieldId]: true }));
    try {
      const value = await revealField(entry.id, fieldId);
      if (selectionTokenRef.current !== token || concealEpochRef.current !== concealEpoch) return;
      setReveals((r) => ({ ...r, [fieldId]: { value, shown: true } }));
    } catch (e) {
      console.error("reveal_field failed:", e);
    } finally {
      if (selectionTokenRef.current === token) {
        setRevealing((r) => ({ ...r, [fieldId]: false }));
      }
    }
  }

  async function onCopySecret(fieldId: string): Promise<string> {
    const existing = reveals[fieldId];
    if (existing) return existing.value;
    if (!entry) throw new Error("no entry loaded");
    const token = selectionTokenRef.current;
    const concealEpoch = concealEpochRef.current;
    const value = await revealField(entry.id, fieldId);
    if (selectionTokenRef.current !== token || concealEpochRef.current !== concealEpoch) {
      throw new Error("selection changed or window concealed before copy resolved; aborted");
    }
    return value;
  }

  async function handleSuggestFolders() {
    if (!entry || suggesting) return;
    const token = selectionTokenRef.current;
    setSuggesting(true);
    try {
      const res = await aiSuggestFolders(entry.id, 3);
      if (selectionTokenRef.current !== token) return;
      setSuggestions(res);
    } catch (e) {
      console.error("ai_suggest_folders failed:", e);
      if (selectionTokenRef.current === token) setSuggestions([]);
    } finally {
      if (selectionTokenRef.current === token) setSuggesting(false);
    }
  }

  async function handleApplyFolder(folderId: string) {
    if (!entry) return;
    const key = `folder:${entry.id}`;
    if (applyingKeys.has(key)) return;
    const token = selectionTokenRef.current;
    setApplyingKeys((p) => withKey(p, key, true));
    try {
      await updateEntry(entry.id, { folder_id: folderId });
      setSuggestions(null);
      await refreshEntries();
      await refreshFolders();
      if (selectionTokenRef.current === token) {
        const fresh = await getEntry(entry.id);
        if (selectionTokenRef.current === token) setEntry(fresh);
      }
    } catch (e) {
      console.error("apply folder suggestion failed:", e);
      setSaveError(String(e));
    } finally {
      setApplyingKeys((p) => withKey(p, key, false));
    }
  }

  async function handleSuggestTags() {
    if (!entry || suggestingTags) return;
    const token = selectionTokenRef.current;
    setSuggestingTags(true);
    try {
      const res = await aiSuggestTags(entry.id, 3);
      if (selectionTokenRef.current !== token) return;
      setTagSuggestions(res);
    } catch (e) {
      console.error("ai_suggest_tags failed:", e);
      if (selectionTokenRef.current === token) setTagSuggestions([]);
    } finally {
      if (selectionTokenRef.current === token) setSuggestingTags(false);
    }
  }

  async function handleApplyTag(tagId: string) {
    if (!entry) return;
    const key = `tag:${tagId}`;
    if (applyingKeys.has(key) || addedTags.has(tagId)) return;
    const token = selectionTokenRef.current;
    setApplyingKeys((p) => withKey(p, key, true));
    try {
      await addEntryTag(entry.id, tagId);
      if (selectionTokenRef.current === token) {
        setAddedTags((p) => withKey(p, tagId, true));
      }
      await refreshEntries();
      if (selectionTokenRef.current === token) {
        const fresh = await getEntry(entry.id);
        if (selectionTokenRef.current === token) setEntry(fresh);
      }
    } catch (e) {
      console.error("apply tag suggestion failed:", e);
      setSaveError(String(e));
    } finally {
      setApplyingKeys((p) => withKey(p, key, false));
    }
  }

  async function handleDelete() {
    if (!selectedId || deleting) return;
    setDeleting(true);
    try {
      await deleteEntry(selectedId);
      select(null);
      try {
        await refreshEntries();
        await refreshFolders();
        await refreshTags();
      } catch (e) {
        console.error("refresh after delete failed:", e);
      }
    } catch (e) {
      console.error("delete_entry failed:", e);
      setSaveError(String(e));
    } finally {
      setDeleting(false);
    }
  }

  async function handleToggleFavorite() {
    if (!entry || favoriting) return;
    const id = entry.id;
    setFavoriting(true);
    try {
      await toggleFavorite(id);
      await refreshEntries();
      setEntry(await getEntry(id));
    } catch (e) {
      console.error("toggle_favorite failed:", e);
      setSaveError(String(e));
    } finally {
      setFavoriting(false);
    }
  }

  async function handleDownloadAttachment(a: AttachmentMeta) {
    if (attachmentBusy[a.id]) return;
    setAttachmentBusy((m) => ({ ...m, [a.id]: true }));
    try {
      const path = await pickSavePath(a.filename);
      if (!path) return;
      await downloadAttachment(a.id, path);
    } catch (e) {
      console.error("download_attachment failed:", e);
      setSaveError(String(e));
    } finally {
      setAttachmentBusy((m) => ({ ...m, [a.id]: false }));
    }
  }

  async function handleDeleteAttachment(id: string) {
    if (attachmentBusy[id]) return;
    setAttachmentBusy((m) => ({ ...m, [id]: true }));
    try {
      await deleteAttachment(id);
      setAttachments((prev) => prev.filter((a) => a.id !== id));
      await refreshEntries();
    } catch (e) {
      console.error("delete_attachment failed:", e);
      setSaveError(String(e));
    } finally {
      setAttachmentBusy((m) => ({ ...m, [id]: false }));
    }
  }

  async function handleDeleteRelation(relationId: string) {
    try {
      await deleteRelation(relationId);
      setRelations((prev) => prev.filter((r) => r.relation_id !== relationId));
    } catch (e) {
      console.error("delete_relation failed:", e);
      setSaveError(String(e));
    }
  }

  async function handleAddRelation(otherId: string, relationType: string) {
    if (!entry) return;
    const key = `${otherId}:${relationType}`;
    if (addingRelationRef.current.has(key)) return;
    addingRelationRef.current.add(key);
    const id = entry.id;
    const token = selectionTokenRef.current;
    try {
      await addRelation(id, otherId, relationType);
      const fresh = await listRelations(id);
      if (selectionTokenRef.current !== token) return;
      setRelations(fresh);
    } catch (e) {
      console.error("add_relation failed:", e);
      setSaveError(String(e));
    } finally {
      addingRelationRef.current.delete(key);
    }
  }

  if (!entry) {
    const emptyVault =
      entriesLoaded && nav.kind === "view" && nav.view === "all" && !search.trim() && visibleEntries.length === 0;
    if (emptyOverride && entriesLoaded && !emptyVault && !loadError) {
      return (
        <main className="kv-detail">
          <div className="kv-detail-bar" data-tauri-drag-region />
          <div className="kv-detail-scroll">{emptyOverride}</div>
        </main>
      );
    }
    return (
      <main className="kv-detail">
        <div className="kv-detail-bar" data-tauri-drag-region />
        <div className="kv-detail-scroll">
          <div className="kv-empty">
            <div className="ring">
              <Icon name="shield" size={30} strokeWidth={1.3} />
            </div>
            {emptyVault && !loadError ? (
              <>
                <p>{t("detail.emptyVaultTitle")}</p>
                <button type="button" className="kv-btn is-primary is-lg kv-empty-cta" onClick={onNewEntry}>
                  {t("detail.emptyVaultCta")}
                </button>
              </>
            ) : (
              <p>{loadError ? t("detail.loadError") : t("detail.selectPrompt")}</p>
            )}
          </div>
        </div>
      </main>
    );
  }

  const folderNode = entry.folder_id ? findFolder(folders, entry.folder_id) : null;
  const folderName = folderNode?.name ?? "Root";

  const passwordField = entry.fields.find((f) => f.field_type === "secret");
  const strengthLabel =
    passwordField && passwordField.strength !== null
      ? t("strength." + passwordField.strength)
      : "—";

  const groupedRelations = relations.reduce<Record<string, RelationView[]>>((acc, r) => {
    (acc[r.relation_type] ??= []).push(r);
    return acc;
  }, {});

  const linkedIds = new Set(relations.map((r) => r.other_id));

  return (
    <main className="kv-detail">
      <div className="kv-detail-bar">
        <button
          type="button"
          className="kv-btn is-icon"
          title={entry.is_favorite ? t("detail.removeFavorite") : t("detail.addFavorite")}
          aria-label={entry.is_favorite ? t("detail.removeFavorite") : t("detail.addFavorite")}
          aria-pressed={entry.is_favorite}
          disabled={favoriting}
          onClick={handleToggleFavorite}
          style={entry.is_favorite ? { color: "var(--warn)" } : undefined}
        >
          <Icon name="star" size={16} filled={entry.is_favorite} />
        </button>
        <button
          type="button"
          className="kv-btn is-icon is-danger"
          disabled={deleting}
          onClick={handleDelete}
          title={deleting ? t("detail.deleting") : t("detail.delete")}
          aria-label={t("detail.delete")}
        >
          <Icon name="trash" size={15} />
        </button>
        <button type="button" className="kv-btn is-ghost" onClick={() => onEdit(entry.id)}>
          <Icon name="pencil" size={13} /> {t("detail.edit")}
        </button>
      </div>
      <div className="kv-detail-scroll">
        <div className="kv-detail-inner" key={entry.id}>
          <header className="kv-entry-head">
            <Monogram title={entry.title} />
            <div>
              <h1>{entry.title}</h1>
              <div className="kv-entry-meta">
                <span className="kv-type-tag" style={{ color: entryTypeMeta(entry.entry_type).color }}>
                  <Icon name={entryTypeMeta(entry.entry_type).icon as DetailIcon} size={12} />
                  {t(entryTypeMeta(entry.entry_type).labelKey)}
                </span>
                <span className="sep">·</span>
                <Icon name="folder" size={12} />
                {folderName}
                <span className="sep">·</span>
                {t("detail.editedOn", { date: formatDate(entry.updated_at, lang) })}
              </div>
              {aiOn ? (
                <div className="kv-suggest">
                  {suggestions === null ? (
                    <button
                      type="button"
                      className="kv-btn is-ghost kv-suggest-trigger"
                      disabled={suggesting}
                      onClick={handleSuggestFolders}
                    >
                      <Icon name="folder" size={12} />{" "}
                      {suggesting ? t("detail.suggestFolderLoading") : t("detail.suggestFolder")}
                    </button>
                  ) : suggestions.length === 0 ? (
                    <span className="kv-suggest-empty">{t("detail.suggestFolderNone")}</span>
                  ) : (
                    <div className="kv-suggest-chips" role="list" aria-label={t("detail.suggestFolder")}>
                      {suggestions.map((sug) => (
                        <button
                          key={sug.folder_id}
                          type="button"
                          role="listitem"
                          className="kv-suggest-chip"
                          disabled={applyingKeys.has(`folder:${entry.id}`)}
                          onClick={() => handleApplyFolder(sug.folder_id)}
                          title={t("detail.suggestFolderApply", { name: sug.name })}
                        >
                          <Icon name="folder" size={11} /> {sug.name}
                          <span className="kv-suggest-score">{Math.round(sug.score * 100)}%</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              ) : null}
            </div>
          </header>

          {entry.fields.length > 0 ? (
            <div className="kv-card">
              {entry.fields.map((field) =>
                field.field_type === "otp" || field.template_id === "tpl_totp" ? (
                  <TotpField key={field.id} entryId={entry.id} fieldId={field.id} label={field.name} />
                ) : (
                  <EntryFieldRow
                    key={field.id}
                    field={field}
                    reveal={reveals[field.id]}
                    busy={!!revealing[field.id]}
                    onToggleReveal={onToggleReveal}
                    onCopySecret={onCopySecret}
                    onShowHistory={setHistoryFor}
                  />
                ),
              )}
            </div>
          ) : null}

          {entry.notes ? (
            <div className="kv-card">
              <FieldLayout icon="note" label={t("detail.notes")}>
                <span className="kv-notes-text">{entry.notes}</span>
              </FieldLayout>
            </div>
          ) : null}

          {entry.tags.length > 0 || aiOn ? (
            <div className="kv-card">
              <FieldLayout icon="tag" label={t("detail.tags")}>
                {entry.tags.length > 0 ? (
                  <div className="kv-chip-row">
                    {entry.tags.map((tag) => (
                      <span key={tag.id} className="kv-tag-badge">
                        <span className="kv-tag-dot" style={{ background: tagColor(tag.color) }} />
                        {tag.name}
                      </span>
                    ))}
                  </div>
                ) : null}
                {aiOn ? (
                  <div className="kv-suggest">
                    {tagSuggestions === null ? (
                      <button
                        type="button"
                        className="kv-btn is-ghost kv-suggest-trigger"
                        disabled={suggestingTags}
                        onClick={handleSuggestTags}
                      >
                        <Icon name="tag" size={12} />{" "}
                        {suggestingTags ? t("detail.suggestTagsLoading") : t("detail.suggestTags")}
                      </button>
                    ) : tagSuggestions.length === 0 ? (
                      <span className="kv-suggest-empty">{t("detail.suggestTagsNone")}</span>
                    ) : (
                      <div className="kv-suggest-chips" role="list" aria-label={t("detail.suggestTags")}>
                        {tagSuggestions.map((sug) => {
                          const added = addedTags.has(sug.tag_id);
                          return (
                            <button
                              key={sug.tag_id}
                              type="button"
                              role="listitem"
                              className="kv-suggest-chip"
                              disabled={added || applyingKeys.has(`tag:${sug.tag_id}`)}
                              onClick={() => handleApplyTag(sug.tag_id)}
                              title={t("detail.suggestTagsApply", { name: sug.name })}
                            >
                              <span className="kv-tag-dot" style={{ background: tagColor(sug.color) }} />
                              {sug.name}
                              {added ? (
                                <Icon name="check" size={11} />
                              ) : (
                                <span className="kv-suggest-score">{Math.round(sug.score * 100)}%</span>
                              )}
                            </button>
                          );
                        })}
                      </div>
                    )}
                  </div>
                ) : null}
              </FieldLayout>
            </div>
          ) : null}

          {attachments.length > 0 ? (
            <div className="kv-card">
              <FieldLayout icon="clip" label={t("detail.attachments")}>
                <div className="kv-attach-list">
                  {attachments.map((a) => (
                    <div key={a.id} className="kv-manage-row">
                      <Icon name="clip" size={14} />
                      <div className="kv-attach-info">
                        <span className="kv-attach-name">{a.filename}</span>
                        <span className="kv-attach-meta">
                          {formatBytes(a.size)} · {formatDate(a.created_at, lang)}
                        </span>
                      </div>
                      {(() => {
                        const k = previewKind(a.mime_type, a.filename);
                        return k && PREVIEWABLE_KINDS.has(k) ? (
                          <button
                            type="button"
                            className="kv-btn is-icon"
                            title={t("detail.preview")}
                            aria-label={t("detail.previewFile", { name: a.filename })}
                            onClick={() => setPreviewId(a.id)}
                          >
                            <Icon name="eye" size={14} />
                          </button>
                        ) : null;
                      })()}
                      <button
                        type="button"
                        className="kv-btn is-icon"
                        title={t("detail.download")}
                        aria-label={t("detail.downloadFile", { name: a.filename })}
                        disabled={!!attachmentBusy[a.id]}
                        onClick={() => handleDownloadAttachment(a)}
                      >
                        <Icon name="download" size={14} />
                      </button>
                      <button
                        type="button"
                        className="kv-btn is-icon is-danger"
                        title={t("detail.remove")}
                        aria-label={t("detail.removeFile", { name: a.filename })}
                        disabled={!!attachmentBusy[a.id]}
                        onClick={() => handleDeleteAttachment(a.id)}
                      >
                        <Icon name="trash" size={14} />
                      </button>
                    </div>
                  ))}
                </div>
              </FieldLayout>
            </div>
          ) : null}

          <div className="kv-card kv-card-relations">
            <FieldLayout icon="link" label={t("detail.linkedEntries")}>
              {relations.length > 0 ? (
                <div className="kv-relation-groups">
                  {RELATION_TYPE_ORDER.filter((relType) => groupedRelations[relType]?.length).map((relType) => (
                    <div key={relType} className="kv-relation-group">
                      <div className="kv-relation-group-label">{t(RELATION_LABEL_KEYS[relType])}</div>
                      {groupedRelations[relType].map((r) => (
                        <div key={r.relation_id} className="kv-manage-row">
                          {r.other_is_deleted ? (
                            <span className="kv-relation-name is-trashed" title={r.other_title}>
                              <span className="kv-relation-name-text">{r.other_title}</span>
                              <span className="kv-relation-badge">{t("detail.inRecycleBin")}</span>
                            </span>
                          ) : (
                            <button
                              type="button"
                              className="kv-relation-name is-link"
                              title={r.other_title}
                              onClick={() => select(r.other_id)}
                            >
                              {r.other_title}
                            </button>
                          )}
                          <button
                            type="button"
                            className="kv-btn is-icon is-danger"
                            title={t("detail.removeLink")}
                            aria-label={t("detail.removeLinkTo", { name: r.other_title })}
                            onClick={() => handleDeleteRelation(r.relation_id)}
                          >
                            <Icon name="trash" size={14} />
                          </button>
                        </div>
                      ))}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="kv-relation-empty">{t("detail.noLinkedEntries")}</p>
              )}
              <RelationPicker key={entry.id} currentEntryId={entry.id} excludeIds={linkedIds} onAdd={handleAddRelation} />
            </FieldLayout>
          </div>

          <div className="kv-meta-grid">
            <div>
              {t("detail.created")}
              <b>{formatDate(entry.created_at, lang)}</b>
            </div>
            <div>
              {t("detail.lastModified")}
              <b>{formatDate(entry.updated_at, lang)}</b>
            </div>
            <div>
              {t("detail.strength")}
              <b>{strengthLabel}</b>
            </div>
          </div>
        </div>
      </div>
      {historyFor ? (
        <HistoryModal entryId={entry.id} field={historyFor} onClose={() => setHistoryFor(null)} />
      ) : null}
      {previewId ? (
        <AttachmentLightbox
          items={attachments.filter((a) => {
            const k = previewKind(a.mime_type, a.filename);
            return k !== null && PREVIEWABLE_KINDS.has(k);
          })}
          startId={previewId}
          onClose={() => setPreviewId(null)}
        />
      ) : null}
    </main>
  );
}
