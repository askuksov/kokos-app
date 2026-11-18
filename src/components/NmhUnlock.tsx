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
        const current = reqRef.current;
        if (current && current.req_id !== incoming.req_id) void nmhUnlockReply(current.req_id, false);
        reqRef.current = incoming;
        setReq(incoming);
        // Preselect the active tab when it is one of the locked vaults.
        const active = activeRef.current?.vaultId;
        setVault(active && incoming.vault_choices.includes(active) ? active : incoming.default_vault);
      }),
      listen<{ req_id: string | null }>(NMH_UNLOCK_CANCEL, (ev) => {
        const current = reqRef.current;
        if (current && (ev.payload.req_id === null || ev.payload.req_id === current.req_id)) {
          reqRef.current = null;
          setReq(null);
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
    const left = Math.ceil((req.expires_at_ms - Date.now()) / 1000);
    const full = Number.isFinite(left) && left > 0 ? Math.min(left, DEFAULT_TIMEOUT_SECS) : DEFAULT_TIMEOUT_SECS;
    const deadline = Date.now() + full * 1000;
    setTotal(full);
    const tick = () => setSecondsLeft(Math.max(0, Math.ceil((deadline - Date.now()) / 1000)));
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
      if (stops.length < 2) return;
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
