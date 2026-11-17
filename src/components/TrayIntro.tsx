import { useEffect, useId, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { useT } from "../state/LangContext";
import { useSettings } from "../state/SettingsContext";
import { appQuit, trayHideWindow } from "../ipc/commands";
import { TRAY_CLOSE_INTRO } from "../lib/events";
import { IS_MAC } from "../lib/platform";
import "./TrayIntro.css";

// One-time dialog on the first window close with close-to-tray on. The
// backend prevented the close and waits for an answer: "Keep running" hides
// to the tray and is remembered, "Quit" exits and asks again next time.
export function TrayIntro() {
  const t = useT();
  const { settings, refresh } = useSettings();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const headingId = useId();
  const hideRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const un = listen(TRAY_CLOSE_INTRO, () => setOpen(true));
    return () => {
      un.then((f) => f());
    };
  }, []);

  useEffect(() => {
    if (open) hideRef.current?.focus();
  }, [open]);

  if (!open) return null;

  const hide = async () => {
    setBusy(true);
    try {
      await trayHideWindow();
      setOpen(false);
      await refresh();
    } catch (e) {
      console.error("tray_hide_window failed:", e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="kv-modal-scrim kv-tray-intro-scrim">
      <div
        className="kv-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby={headingId}
        tabIndex={-1}
        onKeyDown={(e) => {
          if (e.key === "Escape") setOpen(false);
        }}
      >
        <div className="kv-modal-header">
          <h2 id={headingId}>{t("trayIntro.title")}</h2>
        </div>
        <div className="kv-modal-body">
          <p className="kv-tray-intro-line">{IS_MAC ? t("trayIntro.bodyMac") : t("trayIntro.bodyOther")}</p>
          {settings.lock_on_close ? (
            <>
              <p className="kv-tray-intro-line kv-tray-intro-lock">{t("trayIntro.lockNote")}</p>
              <p className="kv-tray-intro-hint">{t("trayIntro.lockSettingNote")}</p>
            </>
          ) : (
            <p className="kv-tray-intro-hint">{t("trayIntro.settingsNote")}</p>
          )}
        </div>
        <div className="kv-modal-footer">
          <button type="button" className="kv-btn is-ghost" disabled={busy} onClick={() => void appQuit()}>
            {t("trayIntro.quit")}
          </button>
          <button type="button" className="kv-btn is-primary" ref={hideRef} disabled={busy} onClick={() => void hide()}>
            {t("trayIntro.hide")}
          </button>
        </div>
      </div>
    </div>
  );
}
