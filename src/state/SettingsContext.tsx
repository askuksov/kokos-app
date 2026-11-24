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
  close_to_tray: true,
  lock_on_close: true,
  tray_intro_seen: false,
};

const Ctx = createContext<{
  settings: Settings;
  /** Never rejects: a failed write rolls back and raises `saveFailed`. */
  update: (p: Partial<Settings>) => Promise<void>;
  /** The last settings write was rejected by the backend. */
  saveFailed: boolean;
  dismissSaveFailed: () => void;
  refresh: () => Promise<void>;
} | null>(null);

export function SettingsProvider({ children }: { children: React.ReactNode }) {
  const [settings, setS] = useState<Settings | null>(null);
  const [saveFailed, setSaveFailed] = useState(false);

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
      let committed: Settings;
      try {
        await setSettings(next);
        // The backend sanitizes the ids and keeps its own fields, so read back what it stored.
        committed = await getSettings().catch(() => next);
        setSaveFailed(false);
      } catch (e) {
        console.error("set_settings failed:", e);
        committed = base;
        setSaveFailed(true);
      }
      setS(committed);
      settingsRef.current = committed;
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

  const dismissSaveFailed = useCallback(() => setSaveFailed(false), []);

  if (!settings) return null;
  return (
    <Ctx.Provider value={{ settings, update, saveFailed, dismissSaveFailed, refresh }}>{children}</Ctx.Provider>
  );
}

export const useSettings = () => {
  const c = useContext(Ctx);
  if (!c) throw new Error("useSettings outside provider");
  return c;
};
