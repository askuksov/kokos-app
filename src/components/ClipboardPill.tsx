import { useClipboard } from "../state/ClipboardContext";
import { useT } from "../state/LangContext";
import "./ClipboardPill.css";

const RING_R = 8;
const RING_C = 2 * Math.PI * RING_R;

/**
 * Bottom-center countdown pill. Purely a view over `ClipboardContext`:
 * renders nothing until a copy starts a countdown, then shows the seconds
 * left with a shrinking ring, and disappears again the instant the
 * countdown stops (fires or is superseded by a newer copy) — all of that
 * timing is owned by the context, not this component.
 *
 * Gated on `active` alone: the context already sets `active: false` for the
 * "0 = never clear" case (no timer started), so there is no separate
 * `total`/`clipboard_seconds` check needed here.
 *
 * Same ring math as TotpField's countdown ring: `frac` is the fraction of
 * the countdown remaining, and
 * `strokeDashoffset` drains the fill circle clockwise from full as `frac`
 * falls, via the same `rotate(-90 …)` + `strokeDasharray={C}` pairing.
 *
 * Never touches the secret itself — only the plain `remaining`/`active`/
 * `total` numbers/bool the context exposes (see ClipboardContext.tsx's own
 * SECRET BOUNDARY note); this component has no access to the copied text.
 */
export function ClipboardPill() {
  const t = useT();
  const { remaining, active, total } = useClipboard();

  if (!active) return null;

  const frac = total > 0 ? remaining / total : 0;
  const dashOffset = RING_C * (1 - frac);

  return (
    <div className="kv-clip-pill">
      <svg className="kv-clip-ring" width="22" height="22" viewBox="0 0 22 22" aria-hidden="true">
        <circle className="kv-clip-ring-track" cx="11" cy="11" r={RING_R} fill="none" strokeWidth="2" />
        <circle
          className="kv-clip-ring-fill"
          cx="11"
          cy="11"
          r={RING_R}
          fill="none"
          strokeWidth="2"
          strokeLinecap="round"
          strokeDasharray={RING_C}
          strokeDashoffset={dashOffset}
          transform="rotate(-90 11 11)"
        />
      </svg>
      <span className="kv-clip-text">{t("clipboard.copied", { seconds: remaining })}</span>
    </div>
  );
}
