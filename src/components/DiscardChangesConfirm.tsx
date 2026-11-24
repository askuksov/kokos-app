import { useId, useRef } from "react";
import { useModalFocus } from "../hooks/useModalFocus";
import { useT } from "../state/LangContext";

/**
 * Asks before a navigation throws away the entry editor's unsaved changes.
 * Escape and the scrim keep editing; the editor underneath must not see that
 * Escape, or it would close and drop the draft anyway.
 */
export function DiscardChangesConfirm({ onDiscard, onCancel }: { onDiscard: () => void; onCancel: () => void }) {
  const t = useT();
  const titleId = useId();
  const dialogRef = useRef<HTMLDivElement>(null);
  const keepRef = useRef<HTMLButtonElement>(null);
  useModalFocus(dialogRef, { initialFocus: keepRef });

  return (
    <div className="kv-modal-scrim" role="presentation" onMouseDown={onCancel}>
      <div
        ref={dialogRef}
        className="kv-modal"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        onMouseDown={(e) => e.stopPropagation()}
        onKeyDown={(e) => {
          if (e.key !== "Escape") return;
          e.preventDefault();
          e.stopPropagation();
          onCancel();
        }}
      >
        <div className="kv-modal-header">
          <h2 id={titleId}>{t("editor.discardTitle")}</h2>
        </div>
        <div className="kv-modal-body">
          <p className="kv-settings-row-hint">{t("editor.discardBody")}</p>
        </div>
        <div className="kv-modal-footer">
          <button ref={keepRef} type="button" className="kv-btn is-ghost" onClick={onCancel}>
            {t("editor.keepEditing")}
          </button>
          <button type="button" className="kv-btn is-danger" onClick={onDiscard}>
            {t("editor.discardConfirm")}
          </button>
        </div>
      </div>
    </div>
  );
}
