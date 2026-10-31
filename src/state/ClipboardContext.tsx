import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { useSettings } from "./SettingsContext";
import { clearClipboard, clearIfUnchanged } from "../lib/clipboard";
import { VAULT_LOCKED } from "../lib/events";
import { setClipboard } from "../ipc/commands";


interface ClipboardCtxValue {
  remaining: number;
  active: boolean;
  total: number;
  /**
   * Writes `text` to the clipboard. When `epoch` (from `copyEpoch()`, captured
   * BEFORE any async reveal) is passed and a lock/reset happened since, the
   * write is refused (rejects) so a late reveal cannot restore plaintext.
   */
  copySecret(text: string, epoch?: number): Promise<void>;
  /** Current generation; bumped by every lock/reset. */
  copyEpoch(): number;
  reset(): void;
}

const Ctx = createContext<ClipboardCtxValue | null>(null);

export function ClipboardProvider({ children }: { children: React.ReactNode }) {
  const { settings } = useSettings();
  const [remaining, setRemaining] = useState(0);
  const [active, setActive] = useState(false);
  const [total, setTotal] = useState(0);

  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const pendingRef = useRef("");
  const remainingRef = useRef(0);
  const copyTokenRef = useRef(0);
  // Generation bumped on lock/reset; lets async copy continuations detect it.
  const epochRef = useRef(0);

  const stop = useCallback(() => {
    if (intervalRef.current !== null) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    pendingRef.current = "";
    remainingRef.current = 0;
  }, []);

  const invalidate = useCallback(() => {
    epochRef.current += 1;
    stop();
  }, [stop]);

  const copyEpoch = useCallback(() => epochRef.current, []);

  const copySecret = useCallback(
    async (text: string, epoch?: number) => {
      const stale = () => epoch !== undefined && epoch !== epochRef.current;
      if (stale()) throw new Error("clipboard invalidated before copy; aborted");
      const token = ++copyTokenRef.current;
      await setClipboard(text);
      if (stale()) {
        // Locked while the native write was in flight: undo it.
        void clearIfUnchanged(text);
        throw new Error("clipboard invalidated during copy; aborted");
      }
      if (copyTokenRef.current !== token) return;

      stop();

      const seconds = settings.clipboard_seconds;
      if (seconds <= 0) {
        setActive(false);
        setRemaining(0);
        setTotal(0);
        return;
      }

      pendingRef.current = text;
      remainingRef.current = seconds;
      setTotal(seconds);
      setRemaining(seconds);
      setActive(true);

      intervalRef.current = setInterval(() => {
        const next = remainingRef.current - 1;
        if (next <= 0) {
          const expired = pendingRef.current;
          stop();
          setActive(false);
          setRemaining(0);
          setTotal(0);
          void clearIfUnchanged(expired);
        } else {
          remainingRef.current = next;
          setRemaining(next);
        }
      }, 1000);
    },
    [settings.clipboard_seconds, stop]
  );

  useEffect(() => stop, [stop]);

  useEffect(() => {
    const un = listen(VAULT_LOCKED, () => {
      void clearClipboard();
      invalidate();
    });
    return () => { un.then((f) => f()); };
  }, [invalidate]);

  const value = useMemo(
    () => ({ remaining, active, total, copySecret, copyEpoch, reset: invalidate }),
    [remaining, active, total, copySecret, copyEpoch, invalidate]
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export const useClipboard = () => {
  const c = useContext(Ctx);
  if (!c) throw new Error("useClipboard outside provider");
  return c;
};
