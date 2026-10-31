import { useEffect, useId, useRef, useState } from "react";
import { ENTRY_TYPES, entryTypeMeta, type EntryType } from "../lib/entryTypes";
import { useT } from "../state/LangContext";
import "./EntryTypeSelect.css";

export function EntryTypeSelect({
  value,
  onChange,
  disabled,
  hideLabel,
}: {
  value: EntryType;
  onChange: (t: EntryType) => void;
  disabled?: boolean;
  hideLabel?: boolean;
}) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const labelId = useId();

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

  const current = entryTypeMeta(value);

  return (
    <div className={(hideLabel ? "" : "kv-float has-value ") + "kv-typeselect"} ref={rootRef}>
      <button
        type="button"
        ref={triggerRef}
        id={hideLabel ? undefined : labelId}
        className="kv-input kv-typeselect-trigger"
        disabled={disabled}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={hideLabel ? t("editor.type") : undefined}
        onClick={() => setOpen((o) => !o)}
      >
        <span className="kv-typeselect-dot" style={{ background: current.color }} aria-hidden="true" />
        <span className="kv-typeselect-current">{t(current.labelKey)}</span>
        <span className="kv-typeselect-caret" aria-hidden="true">▾</span>
      </button>
      {hideLabel ? null : <label htmlFor={labelId}>{t("editor.type")}</label>}
      {open ? (
        <div className="kv-typeselect-pop" role="listbox" aria-label={t("editor.type")}>
          {ENTRY_TYPES.map((et, i) => {
            const meta = entryTypeMeta(et);
            return (
              <button
                key={et}
                type="button"
                role="option"
                aria-selected={et === value}
                autoFocus={i === 0}
                className={"kv-typeselect-option" + (et === value ? " is-active" : "")}
                onClick={() => {
                  onChange(et);
                  setOpen(false);
                  triggerRef.current?.focus();
                }}
              >
                <span className="kv-typeselect-dot" style={{ background: meta.color }} aria-hidden="true" />
                {t(meta.labelKey)}
              </button>
            );
          })}
        </div>
      ) : null}
    </div>
  );
}
