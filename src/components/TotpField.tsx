import { useEffect, useRef, useState } from "react";
import { totpCode } from "../ipc/commands";
import { useClipboard } from "../state/ClipboardContext";
import { useT } from "../state/LangContext";
import "./TotpField.css";

type TotpIcon = "shield" | "copy" | "check";

const ICON_PATHS: Record<TotpIcon, React.ReactNode> = {
  shield: <path d="M12 3l7.5 2.8v5.7c0 4.3-2.9 7.3-7.5 9-4.6-1.7-7.5-4.7-7.5-9V5.8L12 3z" />,
  copy: (
    <g>
      <rect x="8.5" y="8.5" width="11" height="11" rx="2" />
      <path d="M5 14.5V6a2 2 0 012-2h8.5" />
    </g>
  ),
  check: <path d="M5 13l4.2 4.2L19 7.5" />,
};

function Icon({
  name,
  size = 15,
  strokeWidth = 1.7,
  className,
}: {
  name: TotpIcon;
  size?: number;
  strokeWidth?: number;
  className?: string;
}) {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {ICON_PATHS[name]}
    </svg>
  );
}

interface TotpState {
  code: string;
  remaining: number;
  period: number;
}

const RING_R = 9;
const RING_C = 2 * Math.PI * RING_R;

function groupCode(code: string): string {
  const mid = Math.ceil(code.length / 2);
  return `${code.slice(0, mid)} ${code.slice(mid)}`;
}

/**
 * Live TOTP widget. Renders in EntryDetail's field
 * map IN PLACE OF `EntryFieldRow` for `otp`/`tpl_totp` fields only — every
 * other field type keeps `EntryFieldRow` untouched. Reuses the global
 * `.kv-field*` row shell (EntryDetail.css) so it sits consistently among
 * the other rows; only `.kv-totp-*` (TotpField.css) is component-local CSS.
 *
 * READ-ONLY: `totp_code` (src-tauri/src/commands.rs) takes a brief session
 * lock, derives the code from the already-stored secret and the current
 * time, and saves nothing. Viewing a code changes no `EntrySummary` field
 * (`has_totp` already drives the list badge, independent of this widget),
 * so — unlike most of EntryDetail's own handlers — this component makes NO
 * VaultContext call at all: no `refreshEntries`/`refreshFolders`/`refreshTags`.
 *
 * RACE GUARD: `reqRef` is a live monotonic token bumped immediately before
 * every `totpCode` await (the mount fetch AND every period-rollover
 * refetch); a response is dropped unless the ref still reads the same
 * value it did when that particular call started. Mirrors EntryDetail's
 * own `selectionTokenRef` guard on `onToggleReveal`/`onCopySecret`
 * — same shape, just scoped to one field
 * instead of one whole-panel selection. `aliveRef` additionally covers the
 * "unmounted" case (a late fetch resolve, or a tick firing after unmount)
 * that a request-token alone doesn't: it's set false in the effect's own
 * cleanup, checked before every `setState`. `fetchingRef` is a third, purely
 * defensive guard (same "layer a busy flag on top of the token" idiom
 * EntryDetail's own `revealing[fieldId]` uses alongside its token) so a
 * pathologically slow response can't cause the 1s tick to fire a second,
 * overlapping refetch for the same rollover.
 *
 * LAYOUT: the countdown ring is an inline SVG in NORMAL FLOW next to the
 * code — no `position:absolute`, no popover/dropdown. EntryDetail's
 * `.kv-card` is `overflow:hidden` (only `.kv-card-relations` opts out, for
 * RelationPicker's dropdown), so anything positioned outside its own row's box
 * would be silently clipped; staying inline sidesteps that entirely.
 */
export function TotpField({
  entryId,
  fieldId,
  label,
}: {
  entryId: string;
  fieldId: string;
  label: string;
}) {
  const t = useT();
  const [state, setState] = useState<TotpState | null>(null);
  const [error, setError] = useState(false);
  const [copied, setCopied] = useState(false);
  const { copySecret } = useClipboard();

  const reqRef = useRef(0);
  const aliveRef = useRef(true);
  const fetchingRef = useRef(false);
  const stateRef = useRef<TotpState | null>(null);
  stateRef.current = state;

  useEffect(() => {
    aliveRef.current = true;

    async function fetchCode() {
      if (fetchingRef.current) return;
      fetchingRef.current = true;
      const token = ++reqRef.current;
      try {
        const c = await totpCode(entryId, fieldId);
        if (reqRef.current !== token || !aliveRef.current) return;
        const next: TotpState = { code: c.code, remaining: c.remaining, period: c.period };
        stateRef.current = next;
        setState(next);
        setError(false);
      } catch (e) {
        console.error("totp_code failed:", e);
        if (reqRef.current !== token || !aliveRef.current) return;
        stateRef.current = null;
        setState(null);
        setError(true);
      } finally {
        fetchingRef.current = false;
      }
    }

    fetchCode();

    const interval = setInterval(() => {
      if (!aliveRef.current) return;
      const cur = stateRef.current;
      if (!cur) return;
      if (cur.remaining <= 1) {
        const zeroed: TotpState = { ...cur, remaining: 0 };
        stateRef.current = zeroed;
        setState(zeroed);
        fetchCode();
      } else {
        const next: TotpState = { ...cur, remaining: cur.remaining - 1 };
        stateRef.current = next;
        setState(next);
      }
    }, 1000);

    return () => {
      aliveRef.current = false;
      clearInterval(interval);
    };
  }, [entryId, fieldId]);

  async function handleCopy() {
    if (!state) return;
    try {
      await copySecret(state.code);
      if (aliveRef.current) setCopied(true);
      setTimeout(() => {
        if (aliveRef.current) setCopied(false);
      }, 1400);
    } catch (e) {
      console.error("clipboard write failed:", e);
    }
  }

  const frac = state && state.period > 0 ? state.remaining / state.period : 0;
  const dashOffset = RING_C * (1 - frac);

  return (
    <div className="kv-field">
      <Icon name="shield" size={16} className="kv-field-icon" />
      <div className="kv-field-body">
        <div className="kv-field-label">{label}</div>
        <div className="kv-field-value is-mono">
          {error ? (
            <span className="kv-totp-error">{t("totp.invalidSecret")}</span>
          ) : state ? (
            <div className="kv-totp-row">
              <span className="kv-totp-code">{groupCode(state.code)}</span>
              <svg className="kv-totp-ring" width="24" height="24" viewBox="0 0 24 24" aria-hidden="true">
                <circle className="kv-totp-ring-track" cx="12" cy="12" r={RING_R} fill="none" strokeWidth="2.2" />
                <circle
                  className="kv-totp-ring-fill"
                  cx="12"
                  cy="12"
                  r={RING_R}
                  fill="none"
                  strokeWidth="2.2"
                  strokeLinecap="round"
                  strokeDasharray={RING_C}
                  strokeDashoffset={dashOffset}
                  transform="rotate(-90 12 12)"
                />
                <text x="12" y="12" className="kv-totp-ring-label" textAnchor="middle" dominantBaseline="central">
                  {state.remaining}
                </text>
              </svg>
            </div>
          ) : (
            <span className="kv-field-empty">—</span>
          )}
        </div>
      </div>
      {state && !error ? (
        <div className="kv-field-actions">
          <button
            type="button"
            className="kv-btn is-icon"
            title={t("detail.copyAction", { label: label.toLowerCase() })}
            aria-label={t("detail.copyAction", { label })}
            onClick={handleCopy}
            style={copied ? { color: "var(--ok)" } : undefined}
          >
            <Icon name={copied ? "check" : "copy"} strokeWidth={copied ? 2.2 : 1.7} />
          </button>
        </div>
      ) : null}
    </div>
  );
}
