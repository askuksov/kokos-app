import { useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { useT } from "../state/LangContext";
import { useTabs } from "../state/TabsContext";
import { nmhUnlockReply } from "../ipc/commands";
import { NMH_UNLOCK_REQUEST, NMH_UNLOCK_CANCEL, VAULT_UNLOCKED } from "../lib/events";
import { CountdownRing } from "./CountdownRing";
import { UnlockForm } from "./UnlockForm";
import { vaultLabels } from "./NmhConfirm";
import "../screens/Lock.css";
import "./NmhConfirm.css";

type NmhUnlockRequest = {
  req_id: string;
  domain: string;
  // The locked vaults, in tab order.
  vault_choices: string[];
  default_vault: string | null;
  expires_at_ms: number;
};

// The backend's wait, used when its deadline cannot be read.
const DEFAULT_TIMEOUT_SECS = 80;

// The browser extension found Kokos locked and asked to unlock it. The
// password is typed here only; the extension learns just whether a vault
// opened.
export function NmhUnlock() {
  const t = useT();
  const { activeTab } = useTabs();
  const [req, setReq] = useState<NmhUnlockRequest | null>(null);
  const reqRef = useRef<NmhUnlockRequest | null>(null);
  const [vault, setVault] = useState<string | null>(null);
  const [secondsLeft, setSecondsLeft] = useState(DEFAULT_TIMEOUT_SECS);
  const [total, setTotal] = useState(DEFAULT_TIMEOUT_SECS);
  const dialogRef = useRef<HTMLDivElement | null>(null);
  // What had focus before the dialog opened, to give it back on close.
  const returnFocusRef = useRef<Element | null>(null);
  const wasOpenRef = useRef(false);
  // Cancels that arrived before their request (the backend closed it while
  // the request event was still on its way): that request must not show.
  const cancelledIdsRef = useRef<string[]>([]);
  const activeRef = useRef(activeTab);
  activeRef.current = activeTab;

  function close(unlocked: boolean) {
    const current = reqRef.current;
    if (!current) return;
    reqRef.current = null;
    setReq(null);
    void nmhUnlockReply(current.req_id, unlocked);
  }

  useEffect(() => {
    const uns: Array<Promise<() => void>> = [
      listen<NmhUnlockRequest>(NMH_UNLOCK_REQUEST, (ev) => {
        const incoming = ev.payload;
        const early = cancelledIdsRef.current.indexOf(incoming.req_id);
        if (early >= 0) {
          cancelledIdsRef.current.splice(early, 1);
          return;
        }
        // Already past the backend's deadline on arrival: that request is over.
        if (Number.isFinite(incoming.expires_at_ms) && incoming.expires_at_ms <= Date.now()) return;
        const current = reqRef.current;
        if (current && current.req_id !== incoming.req_id) void nmhUnlockReply(current.req_id, false);
        if (!current) returnFocusRef.current = document.activeElement;
        reqRef.current = incoming;
        setReq(incoming);
        // Preselect the active tab when it is one of the locked vaults.
        const active = activeRef.current?.vaultId;
        setVault(active && incoming.vault_choices.includes(active) ? active : incoming.default_vault);
      }),
      listen<{ req_id: string | null }>(NMH_UNLOCK_CANCEL, (ev) => {
        const id = ev.payload.req_id;
        const current = reqRef.current;
        if (current && (id === null || id === current.req_id)) {
          reqRef.current = null;
          setReq(null);
        } else if (id !== null) {
          cancelledIdsRef.current = [...cancelledIdsRef.current.slice(-15), id];
        }
      }),
      // A vault unlocked anywhere (the tab behind the dialog, the tray)
      // answers the request too.
      listen(VAULT_UNLOCKED, () => close(true)),
    ];
    return () => {
      uns.forEach((u) => u.then((f) => f()));
    };
  }, []);

  useEffect(() => {
    if (!req) return;
    // The default applies only to a missing or unreadable deadline; an
    // expired one never gets here (dropped on arrival).
    const left = Math.ceil((req.expires_at_ms - Date.now()) / 1000);
    const full = Number.isFinite(left) ? Math.min(Math.max(left, 0), DEFAULT_TIMEOUT_SECS) : DEFAULT_TIMEOUT_SECS;
    const deadline = Date.now() + full * 1000;
    setTotal(full);
    const id = req.req_id;
    const tick = () => {
      const left = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
      setSecondsLeft(left);
      // Past the backend's deadline: the request is over whether or not its
      // cancel event got here. Close without answering (no Cancel cooldown).
      if (left === 0 && reqRef.current?.req_id === id) {
        reqRef.current = null;
        setReq(null);
      }
    };
    tick();
    const timer = window.setInterval(tick, 250);
    return () => window.clearInterval(timer);
  }, [req?.req_id]);

  useEffect(() => {
    if (!req) return;
    function onDocKeyDown(ev: KeyboardEvent) {
      // The tray intro renders above this dialog and owns the keyboard.
      if (document.querySelector(".kv-tray-intro-scrim")) return;
      if (ev.key === "Escape") {
        ev.stopPropagation();
        close(false);
        return;
      }
      if (ev.key !== "Tab") return;
      const root = dialogRef.current;
      if (!root) return;
      const stops = Array.from(
        root.querySelectorAll<HTMLElement>("button:not([disabled]), input:not([disabled]), select:not([disabled])"),
      );
      if (stops.length === 0) return;
      if (stops.length === 1) {
        // Only Cancel is enabled (an unlock is running): Tab stays on it.
        ev.preventDefault();
        stops[0].focus({ preventScroll: true });
        return;
      }
      const first = stops[0];
      const last = stops[stops.length - 1];
      const idx = stops.findIndex((el) => el === document.activeElement);
      if (ev.shiftKey ? idx <= 0 : idx === -1 || idx === stops.length - 1) {
        ev.preventDefault();
        (ev.shiftKey ? last : first).focus({ preventScroll: true });
      }
    }
    document.addEventListener("keydown", onDocKeyDown, true);
    return () => document.removeEventListener("keydown", onDocKeyDown, true);
  }, [req]);

  // Closed while the window stays up: hand focus back to where it was. When
  // that element is gone (an unlock replaces the lock screen), focus the
  // first control of the screen that took its place.
  useEffect(() => {
    if (req) {
      wasOpenRef.current = true;
      return;
    }
    if (!wasOpenRef.current) return;
    wasOpenRef.current = false;
    const back = returnFocusRef.current;
    returnFocusRef.current = null;
    if (back instanceof HTMLElement && back !== document.body && back.isConnected) {
      back.focus({ preventScroll: true });
      return;
    }
    const frame = requestAnimationFrame(() => {
      if (reqRef.current) return;
      const active = document.activeElement;
      if (active && active !== document.body) return;
      document
        .querySelector<HTMLElement>(".kv-body input:not([disabled]), .kv-body button:not([disabled])")
        ?.focus({ preventScroll: true });
    });
    return () => cancelAnimationFrame(frame);
  }, [req]);

  if (!req || !vault) return null;

  const headingId = "kv-nmh-unlock-heading";
  const choices = req.vault_choices;
  const labels = vaultLabels(choices.map((id) => ({ id, locked: true })));

  return (
    <div className="kv-modal-scrim kv-nmh-scrim">
      <div
        className="kv-modal kv-nmh-unlock"
        role="dialog"
        aria-modal="true"
        aria-labelledby={headingId}
        tabIndex={-1}
        ref={dialogRef}
      >
        <div className="kv-modal-header">
          <h2 id={headingId}>{t("nmhUnlock.title")}</h2>
        </div>
        <div className="kv-modal-body">
          <p className="kv-nmh-line kv-nmh-site">{t("nmhUnlock.forSite", { domain: req.domain })}</p>
          {choices.length >= 2 && (
            <label className="kv-nmh-vault">
              <span>{t("nmhUnlock.vault")}</span>
              <span className="kv-nmh-vault-wrap">
                <select
                  className="kv-nmh-vault-select"
                  value={vault}
                  onChange={(ev) => setVault(ev.target.value)}
                >
                  {choices.map((id) => (
                    <option key={id} value={id}>{labels.get(id) ?? id}</option>
                  ))}
                </select>
              </span>
            </label>
          )}
          <div className="kv-nmh-unlock-form">
            <UnlockForm key={vault} path={vault} onUnlocked={() => close(true)} />
          </div>
          <p className="kv-nmh-hint kv-nmh-expires">
            <span>{t("nmhUnlock.expiresIn")}</span>
            <span role="timer" aria-label={t("nmh.secondsLeft", { seconds: secondsLeft })}>
              <CountdownRing remaining={secondsLeft} total={total} />
            </span>
          </p>
        </div>
        <div className="kv-modal-footer">
          <button type="button" className="kv-btn is-ghost" onClick={() => close(false)}>
            {t("nmhUnlock.cancel")}
          </button>
        </div>
      </div>
    </div>
  );
}
