import { createContext, useContext, useMemo } from "react";
import type { ReactNode } from "react";
import { useSettings } from "./SettingsContext";
import { makeT, makeTn, type Lang, type TFn, type TnFn } from "../lib/i18n";

const Ctx = createContext<{ t: TFn; tn: TnFn; lang: Lang } | null>(null);

export function LangProvider({ children }: { children: ReactNode }) {
  const { settings } = useSettings();
  const lang = settings.lang as Lang;
  const t = useMemo(() => makeT(lang), [lang]);
  const tn = useMemo(() => makeTn(lang, t), [lang, t]);
  const value = useMemo(() => ({ t, tn, lang }), [t, tn, lang]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

function ctx() {
  const c = useContext(Ctx);
  if (!c) throw new Error("useT/useTn/useLang outside LangProvider");
  return c;
}
export function useT(): TFn { return ctx().t; }
export function useTn(): TnFn { return ctx().tn; }
export function useLang(): Lang { return ctx().lang; }
