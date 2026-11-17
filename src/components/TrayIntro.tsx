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
  const quitRef = useRef<HTMLButtonElement>(null);
  const prevFocusRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    const un = listen(TRAY_CLOSE_INTRO, () => {
      if (document.activeElement instanceof HTMLElement) prevFocusRef.current = document.activeElement;
      setOpen(true);
    });
    return () => {
      un.then((f) => f());
    };
  }, []);

  useEffect(() => {
    if (open) hideRef.current?.focus({ preventScroll: true });
  }, [open]);

  // Escape dismisses (the window stays open); Tab cycles between the two
  // buttons so focus cannot reach the screen behind the scrim.
  useEffect(() => {
    if (!open) return;
    function onDocKeyDown(ev: KeyboardEvent) {
      if (ev.key === "Escape") {
        ev.stopPropagation();
        dismiss();
        return;
      }
      if (ev.key !== "Tab") return;
      const stops = [quitRef.current, hideRef.current].filter((el): el is HTMLButtonElement => el != null);
      if (stops.length < 2) return;
      const idx = stops.findIndex((el) => el === document.activeElement);
      ev.preventDefault();
      const next = ev.shiftKey ? (idx <= 0 ? stops.length - 1 : idx - 1) : (idx + 1) % stops.length;
      stops[next].focus({ preventScroll: true });
    }
    document.addEventListener("keydown", onDocKeyDown, true);
    return () => document.removeEventListener("keydown", onDocKeyDown, true);
  }, [open]);

  function dismiss() {
    setOpen(false);
    const prev = prevFocusRef.current;
    prevFocusRef.current = null;
    if (prev && prev.isConnected) prev.focus({ preventScroll: true });
  }

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
          <button type="button" className="kv-btn is-ghost" ref={quitRef} disabled={busy} onClick={() => void appQuit()}>
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
