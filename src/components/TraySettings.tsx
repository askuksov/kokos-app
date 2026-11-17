import { useEffect, useState } from "react";
import { useSettings } from "../state/SettingsContext";
import { useT } from "../state/LangContext";
import { traySupported } from "../ipc/commands";

function OnOff({ label, value, disabled, onChange }: {
  label: string;
  value: boolean;
  disabled?: boolean;
  onChange: (v: boolean) => void;
}) {
  const t = useT();
  return (
    <div className="kv-settings-segmented" role="group" aria-label={label}>
      <button
        type="button"
        className={"kv-settings-seg-btn" + (value ? " is-active" : "")}
        aria-pressed={value}
        disabled={disabled}
        onClick={() => onChange(true)}
      >
        {t("common.on")}
      </button>
      <button
        type="button"
        className={"kv-settings-seg-btn" + (!value ? " is-active" : "")}
        aria-pressed={!value}
        disabled={disabled}
        onClick={() => onChange(false)}
      >
        {t("common.off")}
      </button>
    </div>
  );
}

// Close-to-tray rows for Settings → Security. Without a tray on this desktop
// (Linux without a StatusNotifier host) closing quits, so the switch is shown
// off and disabled with the reason.
export function TraySettings() {
  const { settings, update } = useSettings();
  const t = useT();
  const [supported, setSupported] = useState(true);
  useEffect(() => {
    traySupported().then(setSupported).catch(() => setSupported(true));
  }, []);
  const toTray = supported && settings.close_to_tray;

  return (
    <>
      <div className="kv-settings-row">
        <div className="kv-settings-row-text">
          <span className="kv-settings-row-label">{t("settings.closeToTrayLabel")}</span>
          <span className="kv-settings-row-hint">
            {supported ? t("settings.closeToTrayHint") : t("settings.closeToTrayUnsupported")}
          </span>
        </div>
        <OnOff
          label={t("settings.closeToTrayLabel")}
          value={toTray}
          disabled={!supported}
          onChange={(v) => void update({ close_to_tray: v })}
        />
      </div>
      {toTray && (
        <div className="kv-settings-row">
          <div className="kv-settings-row-text">
            <span className="kv-settings-row-label">{t("settings.lockOnCloseLabel")}</span>
            <span className="kv-settings-row-hint">{t("settings.lockOnCloseHint")}</span>
          </div>
          <OnOff
            label={t("settings.lockOnCloseLabel")}
            value={settings.lock_on_close}
            onChange={(v) => void update({ lock_on_close: v })}
          />
        </div>
      )}
    </>
  );
}
