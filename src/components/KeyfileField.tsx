import { useT } from "../state/LangContext";
import { fileBasename } from "../lib/format";
import "./KeyfileField.css";

interface KeyfileFieldProps {
  /** Absolute path of the picked key file, or null when none is chosen. */
  value: string | null;
  onPick: () => void;
  onClear: () => void;
  disabled?: boolean;
  /** Defaults to «Choose key file»; the create flow says «Add key file». */
  pickLabel?: string;
  /** Class list for the picker button — the lock screen wants the full-width
      `is-lg is-block` shape, Settings' rows the compact default. */
  pickClassName?: string;
}

export function KeyfileField({
  value,
  onPick,
  onClear,
  disabled,
  pickLabel,
  pickClassName = "kv-btn",
}: KeyfileFieldProps) {
  const t = useT();

  return (
    <div className="kv-keyfile-row">
      {value === null ? (
        <button type="button" className={pickClassName} onClick={onPick} disabled={disabled}>
          {pickLabel ?? t("common.chooseKeyfile")}
        </button>
      ) : (
        <>
          <input
            className="kv-input"
            style={{ paddingRight: 40 }}
            value={fileBasename(value)}
            title={value}
            readOnly
            disabled={disabled}
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
          />
          <button
            type="button"
            className="kv-btn is-icon kv-keyfile-clear"
            onClick={onClear}
            disabled={disabled}
            aria-label={t("common.clear")}
            title={t("common.clear")}
          >
            <svg
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth={1.7}
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <path d="M6 6l12 12M18 6L6 18" />
            </svg>
          </button>
        </>
      )}
    </div>
  );
}
