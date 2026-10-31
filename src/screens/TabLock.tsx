import { useEffect, useState } from "react";
import {
  openVault,
  keychainHas,
  keychainUnlock,
  biometricAvailable,
  biometricHas,
  touchidUnlock,
  getVaultHeaderInfo,
  pickAnyFile,
  switchVault,
} from "../ipc/commands";
import { useT } from "../state/LangContext";
import { PasswordField } from "../components/PasswordField";
import { KeyfileField } from "../components/KeyfileField";
import { errorMessage } from "../lib/errors";
import { takeImportInterrupted } from "../lib/importInterrupted";
import kokosLogo from "../assets/kokos-logo.png";
import "./Lock.css";

export function TabLock({ path }: { path: string }) {
  const t = useT();
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hint, setHint] = useState<string | null>(null);
  const [hasSaved, setHasSaved] = useState(false);
  const [hasBiometric, setHasBiometric] = useState(false);
  const [requiresKeyfile, setRequiresKeyfile] = useState(false);
  const [keyfile, setKeyfile] = useState<string | null>(null);
  const [importInterrupted] = useState(() => takeImportInterrupted(path));

  useEffect(() => {
    setKeyfile(null);
    let ignore = false;
    getVaultHeaderInfo(path)
      .then((h) => {
        if (ignore) return;
        setHint(h.hint || null);
        setRequiresKeyfile(h.requires_keyfile);
      })
      .catch(() => {
        if (ignore) return;
        setHint(null);
        setRequiresKeyfile(false);
      });
    return () => { ignore = true; };
  }, [path]);

  useEffect(() => {
    let ignore = false;
    keychainHas(path).then((h) => { if (!ignore) setHasSaved(h); }).catch(() => { if (!ignore) setHasSaved(false); });
    return () => { ignore = true; };
  }, [path]);

  useEffect(() => {
    let ignore = false;
    Promise.all([biometricAvailable(), biometricHas(path)])
      .then(([a, h]) => { if (!ignore) setHasBiometric(a && h); })
      .catch(() => { if (!ignore) setHasBiometric(false); });
    return () => { ignore = true; };
  }, [path]);

  async function pickKeyfile() {
    const p = await pickAnyFile();
    if (p) setKeyfile(p);
  }

  async function afterOpen() {
    await switchVault(path).catch(() => {});
  }

  async function onFastUnlock() {
    setError(null); setBusy(true);
    try {
      await keychainUnlock(path);
      await afterOpen();
    } catch (err) { setHasSaved(false); setError(errorMessage(err, t)); }
    finally { setBusy(false); }
  }

  async function onTouchIdUnlock() {
    setError(null); setBusy(true);
    try {
      await touchidUnlock(path);
      await afterOpen();
    } catch (err) { setError(errorMessage(err, t)); }
    finally { setBusy(false); }
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null); setBusy(true);
    try {
      await openVault(path, password, keyfile);
      await afterOpen();
    } catch (err) {
      setError(String(err));
    } finally { setBusy(false); }
  }

  return (
    <div className="kv-lock">
      <div className="kv-lock-logo">
        <img className="kv-lock-logo-img" src={kokosLogo} alt={t("lock.title")} />
      </div>
      <div className="kv-lock-head">
        <h2>{t("lock.title")}</h2>
        <p>{t("lock.subtitle")}</p>
      </div>
      {importInterrupted && (
        <p className="kv-lock-hint" role="status">
          {t(importInterrupted === "saved" ? "textImport.lockedSaved" : "textImport.interruptedByLock")}
        </p>
      )}
      {hint && <p className="kv-lock-hint">{t("common.hint", { hint })}</p>}
      {hasBiometric && !requiresKeyfile && (
        <button type="button" className="kv-btn is-primary is-lg is-block" onClick={onTouchIdUnlock} disabled={busy}>
          {t("common.unlockTouchId")}
        </button>
      )}
      {hasSaved && !requiresKeyfile && (
        <button type="button" className={`kv-btn is-lg is-block ${hasBiometric ? "is-ghost" : "is-primary"}`} onClick={onFastUnlock} disabled={busy}>
          {t("common.unlockSavedPassword")}
        </button>
      )}
      <form className="kv-lock-form" onSubmit={onSubmit}>
        <PasswordField value={password} onChange={setPassword} placeholder={t("common.masterPasswordPlaceholder")} autoFocus autoComplete="current-password" disabled={busy} />
        {requiresKeyfile && (
          <KeyfileField
            value={keyfile}
            onPick={() => void pickKeyfile()}
            onClear={() => setKeyfile(null)}
            disabled={busy}
            pickClassName="kv-btn is-lg is-block"
          />
        )}
        {error && <p className="kv-error">{error}</p>}
        <button type="submit" className={`kv-btn is-lg is-block ${hasBiometric || hasSaved ? "is-ghost" : "is-primary"}`} disabled={busy}>
          {busy ? t("lock.unlocking") : t("lock.unlock")}
        </button>
      </form>
    </div>
  );
}
