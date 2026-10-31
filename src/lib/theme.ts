
const STORAGE_KEY = "kokos.theme";

export type ThemeChoice = "system" | "dark" | "light";
export type ResolvedTheme = "dark" | "light";

export function getThemeChoice(): ThemeChoice {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === "system" || stored === "dark" || stored === "light") return stored;
  } catch {
  }
  return "system";
}

function systemTheme(): ResolvedTheme {
  if (typeof window === "undefined" || !window.matchMedia) return "dark";
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

export function resolveTheme(choice: ThemeChoice): ResolvedTheme {
  return choice === "system" ? systemTheme() : choice;
}

export function applyThemeChoice(choice: ThemeChoice): void {
  document.documentElement.setAttribute("data-theme", resolveTheme(choice));
  try {
    localStorage.setItem(STORAGE_KEY, choice);
  } catch {
  }
}

const CYCLE: readonly ThemeChoice[] = ["system", "dark", "light"];

export function cycleTheme(): ThemeChoice {
  const current = getThemeChoice();
  const next = CYCLE[(CYCLE.indexOf(current) + 1) % CYCLE.length];
  applyThemeChoice(next);
  return next;
}

export function initTheme(): void {
  applyThemeChoice(getThemeChoice());
  if (typeof window === "undefined" || !window.matchMedia) return;
  const mq = window.matchMedia("(prefers-color-scheme: dark)");
  mq.addEventListener("change", () => {
    if (getThemeChoice() === "system") applyThemeChoice("system");
  });
}
