import { useEffect, useRef, useState } from "react";
import { useVault } from "../state/VaultContext";
import { useT, useTn } from "../state/LangContext";
import { createTag, deleteTag, recolorTag, renameTag } from "../ipc/commands";
import type { Tag } from "../ipc/types";
import { TAG_COLORS, tagColor } from "../lib/tagColors";
import "./ManageTags.css";

type ManageIcon = "plus" | "trash" | "chevronLeft";

const ICON_PATHS: Record<ManageIcon, React.ReactNode> = {
  plus: <path d="M12 5.5v13M5.5 12h13" />,
  trash: (
    <g>
      <path d="M4.5 7h15" />
      <path d="M9.5 7V5.2A1.2 1.2 0 0110.7 4h2.6a1.2 1.2 0 011.2 1.2V7" />
      <path d="M6.5 7l.8 12a1.5 1.5 0 001.5 1.4h6.4a1.5 1.5 0 001.5-1.4l.8-12" />
      <path d="M10 11v5.5M14 11v5.5" />
    </g>
  ),
  chevronLeft: <path d="M14.5 6.5l-5.5 5.5 5.5 5.5" />,
};

function Icon({
  name,
  size = 15,
  strokeWidth = 1.7,
  style,
}: {
  name: ManageIcon;
  size?: number;
  strokeWidth?: number;
  style?: React.CSSProperties;
}) {
  return (
    <svg
      style={style}
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

const HEX_RE = /^#[0-9a-fA-F]{6}$/;

function ColorPopover({
  activeColor,
  anchorRef,
  onPick,
  onClose,
}: {
  activeColor: string | null;
  anchorRef: React.RefObject<HTMLSpanElement | null>;
  onPick: (hex: string) => void;
  onClose: () => void;
}) {
  const t = useT();
  const activeLower = activeColor ? activeColor.toLowerCase() : null;
  const presetMatch = activeLower ? TAG_COLORS.find((c) => c.hex.toLowerCase() === activeLower) : undefined;
  const customColor = activeLower && !presetMatch && HEX_RE.test(activeLower) ? activeColor : null;
  const [hexDraft, setHexDraft] = useState(customColor ?? "#4d8fd6");

  useEffect(() => {
    function onDown(ev: PointerEvent) {
      if (anchorRef.current && !anchorRef.current.contains(ev.target as Node)) onClose();
    }
    document.addEventListener("pointerdown", onDown);
    return () => document.removeEventListener("pointerdown", onDown);
  }, [onClose, anchorRef]);

  function applyHexDraft(v: string) {
    let h = v.trim();
    if (!h.startsWith("#")) h = "#" + h;
    if (HEX_RE.test(h)) {
      setHexDraft(h);
      onPick(h);
    } else {
      setHexDraft(customColor ?? "#4d8fd6");
    }
  }

  return (
    <div className="kv-color-pop">
      <div className="kv-swatch-grid">
        {TAG_COLORS.map((c) => (
          <button
            key={c.id}
            type="button"
            className={"kv-swatch" + (presetMatch?.id === c.id ? " is-active" : "")}
            style={{ background: c.hex, color: c.hex }}
            title={c.name}
            aria-label={`Set color ${c.name}`}
            aria-pressed={presetMatch?.id === c.id}
            onClick={() => onPick(c.hex)}
          />
        ))}
      </div>
      <div className="kv-color-custom">
        <span className="kv-color-custom-label">{t("tags.customColor")}</span>
        <input
          type="color"
          value={customColor ?? hexDraft}
          title={t("tags.pickColor")}
          aria-label={t("tags.customColorPicker")}
          className={customColor ? "is-active" : ""}
          onChange={(e) => {
            setHexDraft(e.target.value);
            onPick(e.target.value);
          }}
          autoCapitalize="off"
          autoCorrect="off"
          spellCheck={false}
        />
        <input
          className="kv-input is-mono"
          aria-label={t("tags.customHexColor")}
          value={hexDraft}
          onChange={(e) => setHexDraft(e.target.value)}
          onBlur={(e) => applyHexDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") e.currentTarget.blur();
          }}
          autoCapitalize="off"
          autoCorrect="off"
          spellCheck={false}
        />
      </div>
    </div>
  );
}

function TagRow({
  tag,
  colorOpen,
  onRename,
  onToggleColor,
  onRecolor,
  onCloseColor,
  onDelete,
}: {
  tag: Tag;
  colorOpen: boolean;
  onRename: (id: string, name: string) => void;
  onToggleColor: (id: string) => void;
  onRecolor: (id: string, hex: string) => void;
  onCloseColor: () => void;
  onDelete: (id: string) => void;
}) {
  const t = useT();
  const tn = useTn();
  const [name, setName] = useState(tag.name);
  useEffect(() => setName(tag.name), [tag.id, tag.name]);
  const anchorRef = useRef<HTMLSpanElement>(null);

  function commit() {
    const trimmed = name.trim();
    if (trimmed && trimmed !== tag.name) onRename(tag.id, trimmed);
    else setName(tag.name);
  }

  const countLabel = tag.usage === 0 ? t("common.noItems") : tn("common.items", tag.usage);

  return (
    <div className="kv-manage-row">
      <input
        className="kv-input"
        value={name}
        aria-label={t("tags.nameAriaLabel")}
        onChange={(e) => setName(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => {
          if (e.key === "Enter") e.currentTarget.blur();
        }}
        autoCapitalize="off"
        autoCorrect="off"
        spellCheck={false}
      />
      <span className="kv-count">{countLabel}</span>
      <span className="kv-color-anchor" ref={anchorRef}>
        <button
          type="button"
          className="kv-color-btn"
          title={t("tags.changeColor")}
          aria-label={t("tags.changeColorFor", { name: tag.name })}
          aria-haspopup="true"
          aria-expanded={colorOpen}
          style={{ background: tagColor(tag.color) }}
          onClick={() => onToggleColor(tag.id)}
        />
        {colorOpen ? (
          <ColorPopover
            activeColor={tag.color}
            anchorRef={anchorRef}
            onPick={(hex) => onRecolor(tag.id, hex)}
            onClose={onCloseColor}
          />
        ) : null}
      </span>
      <button
        type="button"
        className="kv-btn is-icon is-danger"
        title={t("tags.deleteTitle")}
        aria-label={t("common.deleteNamed", { name: tag.name })}
        onClick={() => onDelete(tag.id)}
      >
        <Icon name="trash" size={14} />
      </button>
    </div>
  );
}

/**
 * Full-page tag management screen: a `.kv-card` of renamable/recolorable/
 * deletable tag rows plus an add-row, following
 * `src/components/ManageFolders.tsx` as the sibling `.kv-settings`-page
 * pattern — same page chrome classes
 * (`.kv-settings`/`.kv-settings-inner`/`.kv-settings-sub`/`.kv-card`/
 * `.kv-manage-row`/`.kv-count`/the `.kv-settings`-scoped `.kv-btn`/
 * `.kv-input`), reused as-is rather than redeclared.
 *
 * The back button mirrors ManageFolders.tsx's own and returns to the
 * "main" route.
 */
export function ManageTags() {
  const { tags, refreshTags, refreshEntries, nav, setNav, setRoute } = useVault();
  const t = useT();
  const [newName, setNewName] = useState("");
  const [colorOpenFor, setColorOpenFor] = useState<string | null>(null);

  async function handleRename(id: string, name: string) {
    try {
      await renameTag(id, name);
      await refreshTags();
      await refreshEntries();
    } catch (e) {
      console.error("rename_tag failed:", e);
    }
  }

  async function handleRecolor(id: string, hex: string) {
    try {
      await recolorTag(id, hex);
      await refreshTags();
      await refreshEntries();
    } catch (e) {
      console.error("recolor_tag failed:", e);
    }
  }

  async function handleDelete(id: string) {
    try {
      await deleteTag(id);
      await refreshTags();
      await refreshEntries();
      setColorOpenFor((cur) => (cur === id ? null : cur));
      if (nav.kind === "tag" && nav.id === id) setNav({ kind: "view", view: "all" });
    } catch (e) {
      console.error("delete_tag failed:", e);
    }
  }

  async function handleAdd() {
    const name = newName.trim();
    if (!name) return;
    try {
      await createTag(name, null);
      setNewName("");
      await refreshTags();
    } catch (e) {
      console.error("create_tag failed:", e);
    }
  }

  return (
    <main className="kv-settings" data-screen-label="Manage tags page">
      <div className="kv-settings-inner">
        <button type="button" className="kv-btn is-ghost kv-settings-back" onClick={() => setRoute("main")}>
          <Icon name="chevronLeft" size={13} strokeWidth={2} /> {t("common.back")}
        </button>
        <h1>{t("tags.title")}</h1>
        <p className="kv-settings-sub">{t("tags.subtitle")}</p>

        <div className="kv-card is-overflow-visible">
          {tags.map((tag) => (
            <TagRow
              key={tag.id}
              tag={tag}
              colorOpen={colorOpenFor === tag.id}
              onRename={handleRename}
              onToggleColor={(id) => setColorOpenFor((cur) => (cur === id ? null : id))}
              onRecolor={handleRecolor}
              onCloseColor={() => setColorOpenFor(null)}
              onDelete={handleDelete}
            />
          ))}
          <div className="kv-manage-row">
            <input
              className="kv-input"
              placeholder={t("tags.newNamePlaceholder")}
              aria-label={t("tags.newNameAriaLabel")}
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") handleAdd();
              }}
              autoCapitalize="off"
              autoCorrect="off"
              spellCheck={false}
            />
            <button type="button" className="kv-btn is-ghost" onClick={handleAdd}>
              <Icon name="plus" size={13} /> {t("tags.addTag")}
            </button>
          </div>
        </div>
      </div>
    </main>
  );
}
