import { useId, useState } from "react";
import { useT } from "../state/LangContext";
import "./PasswordField.css";

interface PasswordFieldProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  autoFocus?: boolean;
  disabled?: boolean;
  autoComplete?: string;
  id?: string;
}

export function PasswordField({
  value,
  onChange,
  placeholder,
  autoFocus,
  disabled,
  autoComplete,
  id,
}: PasswordFieldProps) {
  const t = useT();
  const [revealed, setRevealed] = useState(false);
  const generatedId = useId();
  const inputId = id ?? generatedId;

  return (
    <div className="kv-password-field">
      <input
        id={inputId}
        className="kv-input"
        style={{ paddingRight: 40 }}
        type={revealed ? "text" : "password"}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        autoFocus={autoFocus}
        disabled={disabled}
        autoComplete={autoComplete}
        autoCapitalize="off"
        autoCorrect="off"
        spellCheck={false}
      />
      <button
        type="button"
        className="kv-btn is-icon kv-pw-reveal"
        onClick={() => setRevealed((r) => !r)}
        disabled={disabled}
        aria-label={revealed ? t("password.hidePassword") : t("password.showPassword")}
        aria-pressed={revealed}
        title={revealed ? t("detail.conceal") : t("detail.reveal")}
      >
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          {revealed ? (
            <g>
              <path d="M4 4l16 16" />
              <path d="M9.9 5.2A9.6 9.6 0 0112 5c5.8 0 9.2 7 9.2 7a16.6 16.6 0 01-3 3.7M6.1 7.6A15.6 15.6 0 002.8 12s3.4 6.2 9.2 6.2a8.9 8.9 0 003.4-.7" />
              <path d="M9.9 9.9a2.9 2.9 0 004.1 4.1" />
            </g>
          ) : (
            <g>
              <path d="M2.8 12S6.2 5.8 12 5.8 21.2 12 21.2 12 17.8 18.2 12 18.2 2.8 12 2.8 12z" />
              <circle cx="12" cy="12" r="2.8" />
            </g>
          )}
        </svg>
      </button>
    </div>
  );
}
