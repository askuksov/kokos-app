import { useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { useT } from "../state/LangContext";
import { nmhConfirmReply } from "../ipc/commands";
import { CountdownRing } from "./CountdownRing";
import { vaultDisplayName } from "../lib/format";
import { useModalFocus } from "../hooks/useModalFocus";
import "./NmhConfirm.css";

type NmhConfirmRequest = {
  req_id: string;
  action: string;
  domain: string;
  title: string;
  username: string | null;
  field: string | null;
  mode: string;
  session_minutes: number;
  timeout_secs?: number;
  expires_at_ms?: number;
  // save_login with two or more open vaults: where the login can go.
  vault_choices?: VaultChoice[];
  default_vault?: string | null;
};

type VaultChoice = { id: string; locked: boolean };

// Vault names for the picker. Vaults that share a file name get as many of
// their parent folders as it takes to tell them apart, else the full path.
export function vaultLabels(choices: VaultChoice[]): Map<string, string> {
  const folders = choices.map((c) => c.id.split(/[\\/]/).filter(Boolean).slice(0, -1));
  const labelAt = (i: number, depth: number) => {
    const name = vaultDisplayName(choices[i].id);
    if (depth === 0) return name;
    return `${name} (${folders[i].slice(-depth).join("/")})`;
  };
  const labels = new Map<string, string>();
  choices.forEach((c, i) => {
    for (let depth = 0; depth <= folders[i].length; depth++) {
      const mine = labelAt(i, depth);
      if (!choices.some((_, j) => j !== i && labelAt(j, depth) === mine)) {
        labels.set(c.id, mine);
        return;
      }
    }
    labels.set(c.id, c.id);
  });
  // Labels found at different depths can still match (`/c/logins (a).kokos`
  // vs `/a/logins.kokos`); any label still shared falls back to the path.
  const seen = new Map<string, number>();
  labels.forEach((l) => seen.set(l, (seen.get(l) ?? 0) + 1));
  labels.forEach((l, id) => {
    if ((seen.get(l) ?? 0) > 1) labels.set(id, id);
  });
  return labels;
}

// Fallback when an older backend sends no timeout_secs (its deadline was 60 s).
const DEFAULT_TIMEOUT_SECS = 60;

// Allow and "remember" stay disabled this long after a request is shown, so a
// click aimed at the previous prompt (or at whatever was under the window)
// cannot approve one the user has not read.
const ARM_DELAY_MS = 700;

type NmhConfirmCancel = { req_id: string | null };

const ACTION_KEYS: Record<string, string> = {
  get_secret: "nmh.actionGetSecret",
  get_totp: "nmh.actionGetTotp",
  save_login: "nmh.actionSaveLogin",
  update_login: "nmh.actionUpdateLogin",
};

// The tray intro renders above this dialog and owns the keyboard while open.
function trayIntroOpen(): boolean {
  return document.querySelector(".kv-tray-intro-scrim") != null;
}

export function NmhConfirm() {
  const t = useT();
  const [req, setReq] = useState<NmhConfirmRequest | null>(null);
  const reqRef = useRef<NmhConfirmRequest | null>(null);
  const denyRef = useRef<HTMLButtonElement | null>(null);
  // Choices are keyed by the request they were made on, so a request that
  // replaces the shown one starts clean even before the next render.
  const [rememberFor, setRememberFor] = useState<string | null>(null);
  const [secondsLeft, setSecondsLeft] = useState(DEFAULT_TIMEOUT_SECS);
  const [vaultPick, setVaultPick] = useState<{ reqId: string; vault: string } | null>(null);
  const [armedId, setArmedId] = useState<string | null>(null);

  const reqId = req?.req_id ?? null;
  const remember = reqId != null && rememberFor === reqId;
  const vault = vaultPick && vaultPick.reqId === reqId ? vaultPick.vault : (req?.default_vault ?? null);
  const armed = reqId != null && armedId === reqId;

  function replyOnce(id: string, allowed: boolean, rememberSite = false, pickedVault: string | null = null) {
    void nmhConfirmReply(id, allowed, allowed && rememberSite, allowed ? pickedVault : null);
  }

  useEffect(() => {
    let cancelledRequest = false;
    let unlistenRequest: (() => void) | undefined;
    let cancelledCancel = false;
    let unlistenCancel: (() => void) | undefined;

    listen<NmhConfirmRequest>("nmh-confirm-request", (ev) => {
      const incoming = ev.payload;
      const current = reqRef.current;
      if (current && current.req_id !== incoming.req_id) {
        replyOnce(current.req_id, false);
      }
      reqRef.current = incoming;
      setReq(incoming);
    }).then((u) => {
      if (cancelledRequest) u();
      else unlistenRequest = u;
    });

    listen<NmhConfirmCancel>("nmh-confirm-cancel", (ev) => {
      const id = ev.payload.req_id;
      const current = reqRef.current;
      if (!current) return;
      if (id === null || id === current.req_id) {
        reqRef.current = null;
        setReq(null);
      }
    }).then((u) => {
      if (cancelledCancel) u();
      else unlistenCancel = u;
    });

    return () => {
      cancelledRequest = true;
      unlistenRequest?.();
      cancelledCancel = true;
      unlistenCancel?.();
    };
  }, []);

  useEffect(() => {
    if (reqId == null) return;
    const timer = window.setTimeout(() => setArmedId(reqId), ARM_DELAY_MS);
    return () => window.clearTimeout(timer);
  }, [reqId]);

  // Count down to the backend's auto-deny. The backend closes the prompt itself
  // (nmh-confirm-cancel) when the time is up; this only shows how long is left.
  useEffect(() => {
    if (!req) return;
    const total = req.timeout_secs ?? DEFAULT_TIMEOUT_SECS;
    // The backend's deadline when present (same machine clock); never later
    // than a full countdown from now.
    const local = Date.now() + total * 1000;
    const deadline = req.expires_at_ms ? Math.min(req.expires_at_ms, local) : local;
    const tick = () => setSecondsLeft(Math.max(0, Math.ceil((deadline - Date.now()) / 1000)));
    tick();
    const timer = window.setInterval(tick, 250);
    return () => window.clearInterval(timer);
  }, [req?.req_id]);

  // Tab trap and focus return. Called before the focus effect below so the
  // element to return to is read before focus moves to Deny.
  const dialogRef = useRef<HTMLDivElement | null>(null);
  useModalFocus(dialogRef, { open: req != null, initialFocus: false, blocked: trayIntroOpen });

  useEffect(() => {
    // Behind an open tray intro, Enter would deny unseen; the intro hands
    // focus over when it closes.
    if (req && !trayIntroOpen()) denyRef.current?.focus({ preventScroll: true });
  }, [req]);

  // `shownId` is the request the clicked button was rendered for. A request
  // that replaced it after that render has not been seen yet: the click is
  // dropped rather than answering it.
  function close(allowed: boolean, shownId: string | null = reqId) {
    const current = reqRef.current;
    if (!current || current.req_id !== shownId) return;
    if (allowed && !armed) return;
    reqRef.current = null;
    setReq(null);
    const picked = (current.vault_choices?.length ?? 0) >= 2 ? vault : null;
    replyOnce(current.req_id, allowed, remember, picked);
  }

  useEffect(() => {
    if (!req) return;
    function onDocKeyDown(ev: KeyboardEvent) {
      // The tray intro renders above this dialog and owns the keyboard while
      // it is open; both listen on document, so yield to it here.
      if (trayIntroOpen()) return;
      if (ev.key === "Escape") {
        ev.stopPropagation();
        close(false);
      }
    }
    document.addEventListener("keydown", onDocKeyDown, true);
    return () => document.removeEventListener("keydown", onDocKeyDown, true);
  }, [req, vault, remember, armed]);

  if (!req) return null;

  const actionKey = ACTION_KEYS[req.action];
  const headingId = "kv-nmh-confirm-heading";
  const isRead = req.action === "get_secret" || req.action === "get_totp";
  const choices = req.vault_choices ?? [];
  const labels = vaultLabels(choices);

  return (
    <div className="kv-modal-scrim kv-nmh-scrim">
      <div
        ref={dialogRef}
        className="kv-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby={headingId}
        tabIndex={-1}
      >
        <div className="kv-modal-header">
          <h2 id={headingId}>{t("nmh.confirmTitle")}</h2>
        </div>
        <div className="kv-modal-body">
          <p className="kv-nmh-line">{actionKey ? `${t(actionKey)} ${req.title}` : req.title}</p>
          <p className="kv-nmh-line kv-nmh-site">{t("nmh.forSite", { domain: req.domain })}</p>
          {req.username != null && (
            <p className="kv-nmh-line">{t("nmh.asUser", { username: req.username })}</p>
          )}
          {req.field != null && (
            <p className="kv-nmh-line">{t("nmh.fieldLine", { field: req.field })}</p>
          )}
          {choices.length >= 2 && (
            <label className="kv-nmh-vault">
              <span>{t("nmh.saveTo")}</span>
              <span className="kv-nmh-vault-wrap">
                <select
                  className="kv-nmh-vault-select"
                  value={vault ?? ""}
                  onChange={(ev) => setVaultPick({ reqId: req.req_id, vault: ev.target.value })}
                >
                  {choices.map((c) => (
                    <option key={c.id} value={c.id} disabled={c.locked}>
                      {c.locked
                        ? t("nmh.vaultLocked", { name: labels.get(c.id) ?? c.id })
                        : labels.get(c.id) ?? c.id}
                    </option>
                  ))}
                </select>
              </span>
            </label>
          )}
          {isRead && req.mode === "session_domain" && (
            <p className="kv-nmh-hint">
              {t("nmh.grantHint", { domain: req.domain, minutes: req.session_minutes })}
            </p>
          )}
          {isRead && req.mode === "remember_site" && (
            <>
              <label className="kv-nmh-remember">
                <input
                  key={req.req_id}
                  type="checkbox"
                  checked={remember}
                  disabled={!armed}
                  onChange={(ev) => setRememberFor(ev.target.checked ? req.req_id : null)}
                />
                {t("nmh.rememberSite")}
              </label>
              <p className="kv-nmh-hint">{t("nmh.rememberHint", { domain: req.domain })}</p>
            </>
          )}
          {isRead && req.mode === "always" && (
            <p className="kv-nmh-hint">{t("nmh.alwaysModeHint")}</p>
          )}
          <p className="kv-nmh-hint kv-nmh-expires">
            <span>{t("nmh.expiresIn")}</span>
            <span role="timer" aria-label={t("nmh.secondsLeft", { seconds: secondsLeft })}>
              <CountdownRing remaining={secondsLeft} total={req.timeout_secs ?? DEFAULT_TIMEOUT_SECS} />
            </span>
          </p>
        </div>
        <div className="kv-modal-footer">
          <button type="button" className="kv-btn is-primary" ref={denyRef} onClick={() => close(false, req.req_id)}>
            {t("nmh.deny")}
          </button>
          {/* Keyed by request: a replacement mounts a new button, so a press
              that began on the old prompt cannot complete as a click on the
              new one, however long it is held. */}
          <button
            key={req.req_id}
            type="button"
            className="kv-btn is-ghost"
            disabled={!armed}
            onClick={() => close(true, req.req_id)}
          >
            {t("nmh.allow")}
          </button>
        </div>
      </div>
    </div>
  );
}
