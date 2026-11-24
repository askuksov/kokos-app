import { useSettings } from "../state/SettingsContext";
import { useT } from "../state/LangContext";
import "./SaveErrorBanner.css";

/** Shown when the backend rejected a settings write; the change was rolled back. */
export function SettingsSaveError() {
  const { saveFailed, dismissSaveFailed } = useSettings();
  const t = useT();
  if (!saveFailed) return null;
  return (
    <div className="kv-save-error-banner is-fixed" role="alert">
      <span className="kv-save-error-text">{t("settings.saveFailed")}</span>
      <div className="kv-save-error-actions">
        <button type="button" className="kv-btn" onClick={dismissSaveFailed}>
          {t("saveError.dismiss")}
        </button>
      </div>
    </div>
  );
}
