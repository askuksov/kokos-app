import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import type { Settings } from "../ipc/commands";
import { getSettings, setSettings } from "../ipc/commands";

const DEFAULTS: Settings = {
  lang: "en",
  auto_lock_minutes: 15,
  lock_on_blur: false,
  lock_on_sleep: true,
  clipboard_seconds: 30,
  clear_clipboard_on_exit: true,
  conceal_on_blur: true,
  conceal_seconds: 30,
  density: "comfortable",
  nmh_enabled: false,
  nmh_confirm_mode: "always",
  nmh_session_minutes: 5,
  nmh_chrome_ids: [],
  nmh_firefox_ids: [],
  hibp_enabled: false,
  open_vaults: [],
  active_vault: null,
  onboarding_eligible: false,
  onboarding_dismissed: false,
  onboarding_collapsed: false,
  onboarding_backup_done: false,
  onboarding_import_done: false,
  onboarding_sync_deferred: false,
};

const Ctx = createContext<{
  settings: Settings;
  update: (p: Partial<Settings>) => Promise<void>;
  refresh: () => Promise<void>;
} | null>(null);

export function SettingsProvider({ children }: { children: React.ReactNode }) {
  const [settings, setS] = useState<Settings | null>(null);

  const settingsRef = useRef<Settings | null>(null);
  useEffect(() => {
    settingsRef.current = settings;
  }, [settings]);

  useEffect(() => {
    getSettings().then(setS).catch(() => setS(DEFAULTS));
  }, []);

  const writeChain = useRef(Promise.resolve());

  const update = useCallback(async (p: Partial<Settings>) => {
    setS((prev) => {
      const next = { ...(prev ?? DEFAULTS), ...p };
      settingsRef.current = next;
      return next;
    });
    const done = writeChain.current.then(async () => {
      let base: Settings;
      try {
        base = await getSettings();
      } catch {
        base = settingsRef.current ?? DEFAULTS;
      }
      const next = { ...base, ...p };
      try {
        await setSettings(next);
      } catch {
      }
      setS(next);
      settingsRef.current = next;
    });
    writeChain.current = done;
    await done;
  }, []);

  const refresh = useCallback(async () => {
    const done = writeChain.current.then(async () => {
      try {
        const fresh = await getSettings();
        setS(fresh);
        settingsRef.current = fresh;
      } catch {
      }
    });
    writeChain.current = done;
    await done;
  }, []);

  if (!settings) return null;
  return <Ctx.Provider value={{ settings, update, refresh }}>{children}</Ctx.Provider>;
}

export const useSettings = () => {
  const c = useContext(Ctx);
  if (!c) throw new Error("useSettings outside provider");
  return c;
};
