import { useEffect, useRef, useState } from "react";
import { generatePassword } from "../ipc/commands";
import type { GenOpts } from "../ipc/types";
import { useClipboard } from "../state/ClipboardContext";
import { useT, useTn } from "../state/LangContext";
import "./GeneratorPopover.css";

type ClassKey = "upper" | "lower" | "digits" | "symbols";

const CLASS_KEYS: ClassKey[] = ["upper", "lower", "digits", "symbols"];
const CLASS_LABEL_KEYS: Record<ClassKey, string> = {
  upper: "generator.uppercase",
  lower: "generator.lowercase",
  digits: "generator.digits",
  symbols: "generator.symbols",
};
const CLASS_MIN_ARIA_KEYS: Record<ClassKey, string> = {
  upper: "generator.uppercaseMin",
  lower: "generator.lowercaseMin",
  digits: "generator.digitsMin",
  symbols: "generator.symbolsMin",
};
const CLASS_SAMPLES: Record<ClassKey, string> = {
  upper: "A-Z",
  lower: "a-z",
  digits: "0-9",
  symbols: "#$%",
};

const MIN_LENGTH = 8;
const MAX_LENGTH = 64;
const DEFAULT_LENGTH = 16;

export interface GeneratorPopoverProps {
  /** Called with the generated password when the user clicks "Use". The
   * caller (EntryEditor.tsx) owns writing it into the target field row's
   * `value`/`dirty`/`revealed` — this component never touches entry/field
   * state itself, only "generate a password from these options". */
  onUse: (password: string) => void;
  onClose: () => void;
  /** Mirrors the editor's own `saving` flag — freezes every control here
   * the same way the rest of the entry form does while a save is in flight. */
  disabled?: boolean;
}

/**
 * Anchored popover: dice-triggered CSPRNG password
 * generator for the entry editor's `field_type === "secret"` rows.
 * EntryEditor.tsx decides WHERE this mounts and owns the `field_type`
 * gate — this component knows nothing about entries/fields at all.
 * Template: ManageTags.tsx's `ColorPopover`/`.kv-color-pop` (position:
 * absolute, icon-button-anchored, z-index 30).
 *
 * Backend contract:
 * `generate_password(opts: GenOptsDto) -> Result<String>`
 * (src-tauri/src/commands.rs) wraps `kokos_core::generator::generate` — a
 * pure CSPRNG draw, no session/vault/save involved, same "pure, returns
 * only the final value" shape as `reveal_field`. The returned string is a
 * secret: it flows generate -> this component's own `value` state ->
 * `onUse` -> the caller's field row, and nowhere else (never logged, never
 * a second IPC argument, never persisted here).
 *
 * Generation re-runs on EVERY option change (length/class toggle/min
 * stepper) via the effect below, not just on mount/Regenerate — so the
 * shown value is always a live preview of the CURRENT options rather than
 * something that silently goes stale the moment a control changes.
 *
 * Invalid-options guard: the two states `generate_password` itself rejects
 * (no class enabled; enabled minimums sum past the length) are checked
 * CLIENT-SIDE first (`invalidReason` below) so the happy path never sends a
 * request that's certain to fail — Regenerate/Use disable themselves and a
 * one-line hint takes the value line's place instead. A real rejection from
 * the IPC call itself (defensive fallback only — every path the UI can
 * reach is already covered by the client guard) is caught locally and shown
 * the same way; it deliberately never reaches EntryEditor's `setSaveError`
 * banner, since nothing here is a save (mirrors EntryEditor.tsx's own
 * `handleCreateTag` — a local catch + `console.error`).
 *
 * Async guard: `closedRef` mirrors EntryEditor.tsx's own `handleReveal`
 * guard — flips true only on unmount, checked before every `setState` in
 * `runGenerate`/the copy-reset timer, so a slow `generate_password`
 * response (or a stray timer) can never write into a popover that's
 * already gone. Generation is not entry- or field-scoped (no id crosses
 * this boundary), so post-unmount setState is the only thing the guard
 * needs to protect against — no cross-entry/cross-field leak is possible
 * even without it.
 */
export function GeneratorPopover({ onUse, onClose, disabled }: GeneratorPopoverProps) {
  const { copySecret } = useClipboard();
  const t = useT();
  const tn = useTn();
  const [length, setLength] = useState(DEFAULT_LENGTH);
  const [enabled, setEnabled] = useState<Record<ClassKey, boolean>>({
    upper: true,
    lower: true,
    digits: true,
    symbols: true,
  });
  const [mins, setMins] = useState<Record<ClassKey, number>>({
    upper: 1,
    lower: 1,
    digits: 1,
    symbols: 1,
  });
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const closedRef = useRef(false);
  useEffect(() => {
    closedRef.current = false;
    return () => {
      closedRef.current = true;
    };
  }, []);

  const anyClassEnabled = enabled.upper || enabled.lower || enabled.digits || enabled.symbols;
  const enabledMinSum =
    (enabled.upper ? mins.upper : 0) +
    (enabled.lower ? mins.lower : 0) +
    (enabled.digits ? mins.digits : 0) +
    (enabled.symbols ? mins.symbols : 0);
  const invalidReason = !anyClassEnabled
    ? t("generator.enableAtLeastOneClass")
    : enabledMinSum > length
      ? t("generator.minimumsExceedLength")
      : null;

  async function runGenerate() {
    if (invalidReason) return;
    setError(null);
    const opts: GenOpts = {
      length,
      upper: enabled.upper,
      lower: enabled.lower,
      digits: enabled.digits,
      symbols: enabled.symbols,
      min_upper: enabled.upper ? mins.upper : 0,
      min_lower: enabled.lower ? mins.lower : 0,
      min_digits: enabled.digits ? mins.digits : 0,
      min_symbols: enabled.symbols ? mins.symbols : 0,
    };
    try {
      const pw = await generatePassword(opts);
      if (closedRef.current) return;
      setValue(pw);
    } catch (e) {
      if (closedRef.current) return;
      console.error("generate_password failed:", e);
      setError(String(e));
    }
  }

  useEffect(() => {
    if (invalidReason) {
      setValue("");
      setError(null);
      return;
    }
    void runGenerate();
  }, [
    length,
    enabled.upper,
    enabled.lower,
    enabled.digits,
    enabled.symbols,
    mins.upper,
    mins.lower,
    mins.digits,
    mins.symbols,
  ]);

  function toggleClass(key: ClassKey) {
    const turningOff = enabled[key];
    setEnabled((cur) => ({ ...cur, [key]: !cur[key] }));
    if (turningOff) {
      setMins((cur) => ({ ...cur, [key]: 0 }));
    }
  }

  function setMin(key: ClassKey, raw: number) {
    const v = Number.isFinite(raw) ? Math.min(length, Math.max(0, Math.trunc(raw))) : 0;
    setMins((cur) => ({ ...cur, [key]: v }));
  }

  function handleUse() {
    if (invalidReason || !value) return;
    onUse(value);
    onClose();
  }

  async function handleCopy() {
    if (!value) return;
    try {
      await copySecret(value);
      if (!closedRef.current) setCopied(true);
      setTimeout(() => {
        if (!closedRef.current) setCopied(false);
      }, 1400);
    } catch (e) {
      console.error("clipboard write failed:", e);
    }
  }

  const composition: Record<ClassKey, boolean> = {
    upper: /[A-Z]/.test(value),
    lower: /[a-z]/.test(value),
    digits: /[0-9]/.test(value),
    symbols: /[^A-Za-z0-9]/.test(value),
  };

  return (
    <div
      className="kv-generator-pop"
      role="group"
      aria-label={t("generator.ariaLabel")}
    >
      <div className="kv-generator-length">
        <span className="kv-generator-length-label">{t("generator.length")}</span>
        <input
          type="range"
          className="kv-generator-range"
          min={MIN_LENGTH}
          max={MAX_LENGTH}
          value={length}
          disabled={disabled}
          aria-label={t("generator.passwordLengthAriaLabel")}
          onChange={(e) => setLength(Number(e.target.value))}
        />
        <span className="kv-generator-length-value">{length}</span>
      </div>

      <div className="kv-generator-classes">
        {CLASS_KEYS.map((key) => (
          <div key={key} className="kv-generator-class-row">
            <label className="kv-generator-check">
              <input
                type="checkbox"
                checked={enabled[key]}
                disabled={disabled}
                onChange={() => toggleClass(key)}
              />
              {t(CLASS_LABEL_KEYS[key])}
            </label>
            <div className="kv-generator-min">
              <span className="kv-generator-min-label">{t("generator.minAbbrev")}</span>
              <input
                type="number"
                className="kv-generator-number"
                min={0}
                max={length}
                value={mins[key]}
                disabled={disabled || !enabled[key]}
                aria-label={t(CLASS_MIN_ARIA_KEYS[key])}
                onChange={(e) => setMin(key, Number(e.target.value))}
              />
            </div>
          </div>
        ))}
      </div>

      {invalidReason ? (
        <p className="kv-generator-hint">{invalidReason}</p>
      ) : error ? (
        <p className="kv-generator-hint is-error">{error}</p>
      ) : (
        <div className="kv-generator-value">
          <span className="kv-generator-value-text">{value}</span>
          <button
            type="button"
            className="kv-btn is-icon"
            title={copied ? t("generator.copied") : t("generator.copy")}
            aria-label={t("generator.copyAriaLabel")}
            disabled={disabled || !value}
            style={copied ? { color: "var(--ok)" } : undefined}
            onClick={() => void handleCopy()}
          >
            {copied ? t("generator.copied") : t("generator.copy")}
          </button>
        </div>
      )}

      <div className="kv-generator-meta">
        <span>{tn("generator.charactersCount", value.length)}</span>
        <span className="kv-generator-comp">
          {CLASS_KEYS.map((key) => (
            <span key={key} className={composition[key] ? "is-on" : ""}>
              {CLASS_SAMPLES[key]}
            </span>
          ))}
        </span>
      </div>

      <div className="kv-generator-actions">
        <button
          type="button"
          className="kv-btn is-ghost"
          disabled={disabled || !!invalidReason}
          onClick={() => void runGenerate()}
        >
          {t("generator.regenerate")}
        </button>
        <button
          type="button"
          className="kv-btn is-primary"
          disabled={disabled || !!invalidReason || !value}
          onClick={handleUse}
        >
          {t("generator.use")}
        </button>
      </div>
    </div>
  );
}
