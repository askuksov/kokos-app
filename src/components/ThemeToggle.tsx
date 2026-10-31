import { useState } from "react";
import { cycleTheme, getThemeChoice } from "../lib/theme";
import type { ThemeChoice } from "../lib/theme";
import { useT } from "../state/LangContext";

const ICON_PATHS: Record<ThemeChoice, React.ReactNode> = {
  light: (
    <g>
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2.5v2.5M12 19v2.5M2.5 12H5M19 12h2.5M5 5l1.8 1.8M17.2 17.2L19 19M19 5l-1.8 1.8M6.8 17.2L5 19" />
    </g>
  ),
  dark: <path d="M20 14.5A8.5 8.5 0 119.5 4 7 7 0 0020 14.5z" />,
  system: (
    <g>
      <rect x="3" y="4.5" width="18" height="12" rx="2" />
      <path d="M8.5 20h7M12 16.5V20" />
    </g>
  ),
};

function Icon({ name, className }: { name: ThemeChoice; className?: string }) {
  return (
    <svg
      className={className}
      width={15}
      height={15}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.7}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {ICON_PATHS[name]}
    </svg>
  );
}

const LABEL_KEYS: Record<ThemeChoice, string> = {
  system: "theme.system",
  dark: "theme.dark",
  light: "theme.light",
};

export function ThemeToggle() {
  const t = useT();
  const [choice, setChoice] = useState<ThemeChoice>(getThemeChoice);

  function onClick() {
    setChoice(cycleTheme());
  }

  return (
    <button
      type="button"
      className="kv-side-item"
      onClick={onClick}
      title={t("theme.switchTitle")}
    >
      <Icon name={choice} className="kv-ico" />
      <span className="label">{t(LABEL_KEYS[choice])}</span>
    </button>
  );
}
