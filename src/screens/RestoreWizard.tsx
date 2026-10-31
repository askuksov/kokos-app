import { useEffect, useId, useRef, useState } from "react";
import { restoreSignin, restoreDownload, restoreBind, restoreCancel, pickSavePath, openVault } from "../ipc/commands";
import type { RestoreFile } from "../ipc/types";
import { useT } from "../state/LangContext";
import { useVault } from "../state/VaultContext";
import { PasswordField } from "../components/PasswordField";
import { formatBytes, restoreBackupLabel } from "../lib/format";
import "./RestoreWizard.css";

type Step = "signin" | "pick" | "unlock";

/**
 * Restore-from-Google-Drive wizard. Pre-unlock, three-step
 * modal offered from Welcome's landing view: sign in -> pick a remote vault
 * file -> download it locally and unlock. Mirrors EntryDetail.tsx's
 * HistoryModal shell (`.kv-modal-scrim`/`.kv-modal`/-header/-body/-footer,
 * Escape-to-close via a document keydown listener) rather than inventing a
 * new one.
 *
 * The `.kv-modal*` classes live in EntryDetail.css, but that file is never
 * imported here or by Welcome.tsx — they still render correctly because
 * this app has no route-based code-splitting: every screen (Welcome/Lock/
 * Vault) is a static import from App.tsx, so Vite's production build
 * concatenates every reachable component's CSS into the single stylesheet
 * `index.html` loads unconditionally on launch (verified against a prior
 * `dist/assets/*.css` build — `.kv-modal-scrim` is already present in that
 * one bundled file). `RestoreWizard.css` only adds the restore-list rows,
 * which have no existing counterpart to reuse.
 *
 * Deliberately does NOT call `backgroundReconcile()` (lib/sync.ts) the way
 * Welcome's own `onSubmit`/`onFastUnlock`/`onTouchIdUnlock` do after opening
 * a vault: `restoreDownload` already fetched the latest bytes from Drive, and
 * `restoreBind` (not `detect_remote_changes`) is what binds `sync.json` to
 * this vault — reconciling here would run against a not-yet-bound target.
 */
export function RestoreWizard({ onClose }: { onClose: () => void }) {
  const t = useT();
  const { refreshStatus } = useVault();
  const headerId = useId();
  const [step, setStep] = useState<Step>("signin");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [files, setFiles] = useState<RestoreFile[]>([]);
  const [dest, setDest] = useState<string | null>(null);
  const [password, setPassword] = useState("");

  async function cancel() {
    try {
      await restoreCancel();
    } catch {
    }
    onClose();
  }

  const cancelRef = useRef(cancel);
  cancelRef.current = cancel;

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") void cancelRef.current();
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  async function doSignin() {
    setBusy(true);
    setError(null);
    try {
      const remoteFiles = await restoreSignin();
      setFiles(remoteFiles);
      setStep("pick");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function doPick(f: RestoreFile) {
    setBusy(true);
    setError(null);
    try {
      const path = await pickSavePath(f.name);
      if (!path) {
        setBusy(false);
        return;
      }
      await restoreDownload(f.id, path);
      setDest(path);
      setStep("unlock");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function doUnlock(e: React.FormEvent) {
    e.preventDefault();
    if (!dest) return;
    setBusy(true);
    setError(null);
    try {
      await openVault(dest, password, null);
    } catch (e) {
      setError(String(e));
      setBusy(false);
      return;
    }
    try {
      try {
        await restoreBind();
      } catch (e) {
        console.error("restore: sync bind failed", e);
      }
      await refreshStatus();
    } catch (e) {
      setError(String(e));
      setBusy(false);
    }
  }

  return (
    <div className="kv-modal-scrim" onClick={cancel}>
      <div
        className="kv-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby={headerId}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="kv-modal-header">
          <h2 id={headerId}>{t("restore.title")}</h2>
        </div>
        <div className="kv-modal-body">
          {error && <p className="kv-error">{error}</p>}
          {step === "signin" && (
            <div className="kv-restore-step">
              <p className="kv-restore-blurb">{t("restore.signinBlurb")}</p>
              <button type="button" className="kv-btn is-primary is-lg is-block" disabled={busy} onClick={doSignin}>
                {t("restore.signinButton")}
              </button>
            </div>
          )}
          {step === "pick" &&
            (files.length === 0 ? (
              <p className="kv-relation-empty">{t("restore.noVaults")}</p>
            ) : (
              <ul className="kv-restore-list">
                {files.map((f) => (
                  <li key={f.id}>
                    <button
                      type="button"
                      className="kv-restore-item"
                      disabled={busy}
                      onClick={() => doPick(f)}
                    >
                      <span className="kv-restore-name">
                        {f.vault_name ? (
                          <>
                            {f.vault_name}
                            {f.note ? <span className="kv-restore-tag"> ({f.note})</span> : null}
                          </>
                        ) : (
                          <>
                            {t("restore.backupLabel")}
                            {restoreBackupLabel(f.name).tag ? (
                              <span className="kv-restore-tag"> · {restoreBackupLabel(f.name).tag}</span>
                            ) : null}
                          </>
                        )}
                      </span>
                      <span className="kv-restore-meta">
                        {new Date(f.modified_time).toLocaleString(undefined, {
                          year: "numeric", month: "short", day: "numeric",
                          hour: "numeric", minute: "2-digit",
                        })}
                        {f.size != null ? ` · ${formatBytes(f.size)}` : ""}
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            ))}
          {step === "unlock" && (
            <form className="kv-restore-step" onSubmit={doUnlock}>
              <p className="kv-restore-blurb">{t("restore.unlockBlurb")}</p>
              <PasswordField
                value={password}
                onChange={setPassword}
                placeholder={t("restore.passwordPlaceholder")}
                autoFocus
                autoComplete="current-password"
                disabled={busy}
              />
              <button type="submit" className="kv-btn is-primary is-lg is-block" disabled={busy || !password}>
                {t("restore.unlockButton")}
              </button>
            </form>
          )}
        </div>
        <div className="kv-modal-footer">
          <button type="button" className="kv-btn is-ghost" onClick={cancel}>
            {t("common.cancel")}
          </button>
        </div>
      </div>
    </div>
  );
}
