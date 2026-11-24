import { useEffect, useId, useRef, useState } from "react";
import { useModalFocus } from "../hooks/useModalFocus";
import { useT } from "../state/LangContext";
import { useVault } from "../state/VaultContext";
import { onRestoreBindFailure, takeRestoreBindFailure } from "../lib/restoreBindNotice";

/**
 * Tells the user that a vault restored from Google Drive opened but is not
 * connected to Drive, and how to connect it. The restore session is gone by
 * then, so the restore itself cannot retry the binding.
 */
export function RestoreBindNotice() {
  const t = useT();
  const { setRoute, setSettingsTab } = useVault();
  const [error, setError] = useState<string | null>(null);
  const titleId = useId();
  const dialogRef = useRef<HTMLDivElement>(null);
  useModalFocus(dialogRef, { open: error !== null });

  useEffect(() => {
    const pick = () => {
      const e = takeRestoreBindFailure();
      if (e !== null) setError(e);
    };
    pick();
    return onRestoreBindFailure(pick);
  }, []);

  if (error === null) return null;
  const close = () => setError(null);

  return (
    <div className="kv-modal-scrim" role="presentation" onMouseDown={close}>
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
          close();
        }}
      >
        <div className="kv-modal-header">
          <h2 id={titleId}>{t("restore.bindFailedTitle")}</h2>
        </div>
        <div className="kv-modal-body">
          <p className="kv-error">{error}</p>
          <p className="kv-settings-row-hint">{t("restore.bindFailedHint")}</p>
        </div>
        <div className="kv-modal-footer">
          <button type="button" className="kv-btn is-ghost" onClick={close}>
            {t("restore.bindFailedLater")}
          </button>
          <button
            type="button"
            className="kv-btn is-primary"
            onClick={() => {
              close();
              setSettingsTab("sync");
              setRoute("settings");
            }}
          >
            {t("restore.bindFailedOpenSync")}
          </button>
        </div>
      </div>
    </div>
  );
}
