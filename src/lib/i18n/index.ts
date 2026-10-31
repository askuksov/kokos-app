import { en } from "./en";
import { uk } from "./uk";
import { ru } from "./ru";

export type Lang = "en" | "uk" | "ru";

const dicts: Record<Lang, Record<string, string>> = { en, uk, ru };

export function makeT(lang: Lang) {
  return (key: string, vars?: Record<string, string | number>): string => {
    let s = dicts[lang]?.[key] ?? dicts.en[key] ?? key;
    if (vars) for (const [k, v] of Object.entries(vars)) s = s.replaceAll(`{${k}}`, String(v));
    return s;
  };
}

export type TFn = ReturnType<typeof makeT>;

export type TnFn = (base: string, n: number, vars?: Record<string, string | number>) => string;

export function makeTn(lang: Lang, t: ReturnType<typeof makeT>): TnFn {
  const pr = new Intl.PluralRules(lang);
  return (base, n, vars) => t(`${base}.${pr.select(n)}`, { n, ...vars });
}
