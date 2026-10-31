import { useState } from "react";
import { useVault } from "../state/VaultContext";
import { saveVault } from "../ipc/commands";
import { useT } from "../state/LangContext";
import "./SaveErrorBanner.css";

/**
 * Persistent save-error banner. A mutation (create/update via EntryEditor,
 * soft-delete via EntryDetail) can succeed against the in-memory vault
 * while its follow-up disk write fails — the change then exists only in
 * memory until the vault is saved again. `saveError`/`setSaveError`
 * (VaultContext) is the single channel every vault mutation reports that
 * failure through; this component is its only reader, mounted once at the
 * top of VaultScreen (Vault.tsx).
 *
 * Deliberately a banner, not a transient auto-dismissing toast: "your
 * change may not be on disk" needs a retry affordance and must stay up
 * until the user explicitly acts.
 *
 * Positioned to overlay all three panels (`position:absolute` inside
 * `.kv-window`, already `position:relative` — base.css) and z-indexed
 * above EntryEditor's `.kv-scrim`/`.kv-slideover` (40/50 — EntryEditor.css):
 * a failed save from inside the open editor (EntryEditor.tsx's
 * `handleSave` catch) does not close the slide-over, so the banner must
 * still read clearly on top of both, not dimmed under the scrim.
 *
 * SECURITY: the message is a fixed, generic string. `saveError`'s actual
 * content (`String(err)` from a rejected IPC call, set by EntryEditor's
 * `handleSave` catch or EntryDetail's `handleDelete` catch) is never read
 * or interpolated here — even though the backend's save-path errors carry
 * no secret material, this persistent UI chrome simply never becomes a
 * place that renders raw error internals.
 */
export function SaveErrorBanner() {
  const { saveError, setSaveError } = useVault();
  const t = useT();
  const [retrying, setRetrying] = useState(false);

  if (!saveError) return null;

  async function handleRetry() {
    setRetrying(true);
    try {
      await saveVault();
      setSaveError(null);
    } catch (e) {
      console.error("save_vault retry failed:", e);
    } finally {
      setRetrying(false);
    }
  }

  return (
    <div className="kv-save-error-banner" role="alert">
      <span className="kv-save-error-text">{t("saveError.message")}</span>
      <div className="kv-save-error-actions">
        <button type="button" className="kv-btn is-ghost" disabled={retrying} onClick={handleRetry}>
          {retrying ? t("saveError.retrying") : t("saveError.retry")}
        </button>
        <button
          type="button"
          className="kv-btn"
          disabled={retrying}
          onClick={() => setSaveError(null)}
        >
          {t("saveError.dismiss")}
        </button>
      </div>
    </div>
  );
}
