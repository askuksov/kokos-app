import { useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { useT } from "../state/LangContext";
import { nmhConfirmReply } from "../ipc/commands";
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
};

type NmhConfirmCancel = { req_id: string | null };

const ACTION_KEYS: Record<string, string> = {
  get_secret: "nmh.actionGetSecret",
  get_totp: "nmh.actionGetTotp",
  save_login: "nmh.actionSaveLogin",
  update_login: "nmh.actionUpdateLogin",
};

export function NmhConfirm() {
  const t = useT();
  const [req, setReq] = useState<NmhConfirmRequest | null>(null);
  const reqRef = useRef<NmhConfirmRequest | null>(null);
  const denyRef = useRef<HTMLButtonElement | null>(null);
  const allowRef = useRef<HTMLButtonElement | null>(null);
  const [remember, setRemember] = useState(false);
  const rememberRef = useRef<HTMLInputElement | null>(null);

  function replyOnce(id: string, allowed: boolean) {
    void nmhConfirmReply(id, allowed, allowed && remember);
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
    setRemember(false);
  }, [req?.req_id]);

  useEffect(() => {
    if (req) denyRef.current?.focus({ preventScroll: true });
  }, [req]);

  function close(allowed: boolean) {
    const current = reqRef.current;
    if (!current) return;
    reqRef.current = null;
    setReq(null);
    replyOnce(current.req_id, allowed);
  }

  useEffect(() => {
    if (!req) return;
    function onDocKeyDown(ev: KeyboardEvent) {
      if (ev.key === "Escape") {
        ev.stopPropagation();
        close(false);
        return;
      }
      if (ev.key !== "Tab") return;
      const stops = [rememberRef.current, denyRef.current, allowRef.current].filter(
        (el): el is HTMLInputElement | HTMLButtonElement => el != null,
      );
      if (stops.length < 2) return;
      const first = stops[0];
      const last = stops[stops.length - 1];
      const active = document.activeElement;
      const idx = stops.findIndex((el) => el === active);
      if (ev.shiftKey) {
        if (idx === -1 || idx === 0) {
          ev.preventDefault();
          last.focus({ preventScroll: true });
        }
      } else {
        if (idx === -1 || idx === stops.length - 1) {
          ev.preventDefault();
          first.focus({ preventScroll: true });
        }
      }
    }
    document.addEventListener("keydown", onDocKeyDown, true);
    return () => document.removeEventListener("keydown", onDocKeyDown, true);
  }, [req]);

  if (!req) return null;

  const actionKey = ACTION_KEYS[req.action];
  const headingId = "kv-nmh-confirm-heading";
  const isRead = req.action === "get_secret" || req.action === "get_totp";

  return (
    <div className="kv-modal-scrim kv-nmh-scrim">
      <div
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
          {isRead && req.mode === "session_domain" && (
            <p className="kv-nmh-hint">
              {t("nmh.grantHint", { domain: req.domain, minutes: req.session_minutes })}
            </p>
          )}
          {isRead && req.mode === "remember_site" && (
            <>
              <label className="kv-nmh-remember">
                <input
                  type="checkbox"
                  ref={rememberRef}
                  checked={remember}
                  onChange={(ev) => setRemember(ev.target.checked)}
                />
                {t("nmh.rememberSite")}
              </label>
              <p className="kv-nmh-hint">{t("nmh.rememberHint", { domain: req.domain })}</p>
            </>
          )}
          {isRead && req.mode === "always" && (
            <p className="kv-nmh-hint">{t("nmh.alwaysModeHint")}</p>
          )}
          <p className="kv-nmh-hint">{t("nmh.expiresHint")}</p>
        </div>
        <div className="kv-modal-footer">
          <button type="button" className="kv-btn is-primary" ref={denyRef} onClick={() => close(false)}>
            {t("nmh.deny")}
          </button>
          <button type="button" className="kv-btn is-ghost" ref={allowRef} onClick={() => close(true)}>
            {t("nmh.allow")}
          </button>
        </div>
      </div>
    </div>
  );
}
