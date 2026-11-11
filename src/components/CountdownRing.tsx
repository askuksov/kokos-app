import "./CountdownRing.css";

const RING_R = 9;
const RING_C = 2 * Math.PI * RING_R;

/** A 24px ring that empties as `remaining` counts down to 0, with the seconds
 * left in the middle. Decorative: callers carry the meaning in text. */
export function CountdownRing({ remaining, total }: { remaining: number; total: number }) {
  const frac = total > 0 ? Math.max(0, Math.min(1, remaining / total)) : 0;
  const dashOffset = RING_C * (1 - frac);
  return (
    <svg className="kv-ring" width="24" height="24" viewBox="0 0 24 24" aria-hidden="true">
      <circle className="kv-ring-track" cx="12" cy="12" r={RING_R} fill="none" strokeWidth="2.2" />
      <circle
        className="kv-ring-fill"
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
      <text x="12" y="12" className="kv-ring-label" textAnchor="middle" dominantBaseline="central">
        {remaining}
      </text>
    </svg>
  );
}
