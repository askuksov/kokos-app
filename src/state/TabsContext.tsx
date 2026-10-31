import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { switchVault, lockVault, lockAll, closeVault, getSettings, recentFiles, reorderVaults } from "../ipc/commands";
import { VAULT_LOCKED, VAULT_UNLOCKED, MENU_NEW_VAULT, MENU_OPEN_VAULT, MENU_CLOSE_VAULT, MENU_LOCK_ALL } from "../lib/events";
import { vaultDisplayName } from "../lib/format";

export type Tab = { vaultId: string; name: string; locked: boolean; registered: boolean };

export interface TabsState {
  tabs: Tab[];
  activeIndex: number;
  adding: boolean;
  addIntent: "open" | "create" | null;
  activeTab: Tab | null;
  activate: (index: number) => void;
  beginAdd: (intent?: "open" | "create") => void;
  clearAddIntent: () => void;
  cancelAdd: () => void;
  closeTab: (vaultId: string) => Promise<void>;
  closeActive: () => Promise<void>;
  lockActive: () => Promise<void>;
  lockAllTabs: () => Promise<void>;
  reorderTabs: (fromVaultId: string, toVaultId: string, place: "before" | "after") => void;
}

const Ctx = createContext<TabsState | null>(null);

export function TabsProvider({ children }: { children: React.ReactNode }) {
  const [tabs, setTabs] = useState<Tab[]>([]);
  const [activeIndex, setActiveIndex] = useState(-1);
  const [adding, setAdding] = useState(false);
  const [addIntent, setAddIntent] = useState<"open" | "create" | null>(null);

  const tabsRef = useRef(tabs);
  tabsRef.current = tabs;
  const activeIndexRef = useRef(activeIndex);
  activeIndexRef.current = activeIndex;
  const switchSeqRef = useRef(0);

  const applyUnlocked = useCallback((vaultId: string) => {
    setAdding(false);
    const prev = tabsRef.current;
    const i = prev.findIndex((t) => t.vaultId === vaultId);
    let next: Tab[];
    if (i >= 0) {
      next = prev.slice();
      next[i] = { ...next[i], locked: false, registered: true };
    } else {
      next = [...prev, { vaultId, name: vaultDisplayName(vaultId), locked: false, registered: true }];
    }
    const idx = next.findIndex((t) => t.vaultId === vaultId);
    ++switchSeqRef.current;
    setTabs(next);
    setActiveIndex(idx);
  }, []);

  const applyLocked = useCallback((vaultId: string | null) => {
    setTabs((prev) =>
      prev.map((t) => (vaultId === null || t.vaultId === vaultId ? { ...t, locked: true } : t)),
    );
  }, []);

  useEffect(() => {
    const uns: Array<Promise<() => void>> = [
      listen<{ vault_id: string }>(VAULT_UNLOCKED, (e) => {
        if (e.payload?.vault_id) applyUnlocked(e.payload.vault_id);
      }),
      listen<{ vault_id: string | null }>(VAULT_LOCKED, (e) => {
        applyLocked(e.payload?.vault_id ?? null);
      }),
    ];
    return () => {
      uns.forEach((u) => u.then((f) => f()));
    };
  }, [applyUnlocked, applyLocked]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      let paths: string[] = [];
      let active: string | null = null;
      try {
        const s = await getSettings();
        paths = s.open_vaults ?? [];
        active = s.active_vault ?? null;
      } catch (e) {
        console.error("get_settings (restore) failed:", e);
        return;
      }
      if (cancelled || paths.length === 0) return;
      await recentFiles().catch(() => {});
      if (cancelled) return;
      if (tabsRef.current.length > 0) return;
      const restored: Tab[] = paths.map((p) => ({
        vaultId: p,
        name: vaultDisplayName(p),
        locked: true,
        registered: false,
      }));
      const ai = active ? Math.max(0, restored.findIndex((t) => t.vaultId === active)) : restored.length - 1;
      setTabs(restored);
      setActiveIndex(ai);
    })();
    return () => { cancelled = true; };
  }, []);

  const activate = useCallback((index: number) => {
    setAdding(false);
    const tab = tabsRef.current[index];
    if (!tab) return;
    const seq = ++switchSeqRef.current;
    if (tab.locked || !tab.registered) {
      setActiveIndex(index);
      return;
    }
    switchVault(tab.vaultId)
      .catch((e) => console.error("switch_vault failed:", e))
      .finally(() => {
        if (seq === switchSeqRef.current) setActiveIndex(index);
      });
  }, []);

  const beginAdd = useCallback((intent?: "open" | "create") => {
    setAddIntent(intent ?? null);
    setAdding(true);
  }, []);
  const clearAddIntent = useCallback(() => setAddIntent(null), []);
  const cancelAdd = useCallback(() => setAdding(false), []);

  const closeTab = useCallback(async (vaultId: string) => {
    const tab = tabsRef.current.find((t) => t.vaultId === vaultId);
    if (tab?.registered) {
      try {
        await switchVault(vaultId);
        await closeVault();
      } catch (e) {
        console.error("close_vault failed:", e);
      }
    }
    const cur = tabsRef.current;
    const idx = cur.findIndex((t) => t.vaultId === vaultId);
    if (idx < 0) return;
    const next = cur.filter((t) => t.vaultId !== vaultId);
    const nextActive = next.length === 0 ? -1 : Math.min(Math.max(idx - 1, 0), next.length - 1);
    const nt = nextActive >= 0 ? next[nextActive] : null;
    ++switchSeqRef.current;
    if (nt && nt.registered && !nt.locked) {
      await switchVault(nt.vaultId).catch((e) => console.error("switch_vault failed:", e));
    }
    setTabs(next);
    setActiveIndex(nextActive);
  }, []);

  const closeActive = useCallback(async () => {
    const t = tabsRef.current[activeIndexRef.current];
    if (t) await closeTab(t.vaultId);
  }, [closeTab]);

  const reorderTabs = useCallback(
    (fromVaultId: string, toVaultId: string, place: "before" | "after") => {
      if (fromVaultId === toVaultId) return;
      const cur = tabsRef.current;
      const fromIdx = cur.findIndex((t) => t.vaultId === fromVaultId);
      if (fromIdx < 0 || !cur.some((t) => t.vaultId === toVaultId)) return;
      const moved = cur[fromIdx];
      const without = cur.filter((_, i) => i !== fromIdx);
      const targetPos = without.findIndex((t) => t.vaultId === toVaultId);
      const insertAt = place === "before" ? targetPos : targetPos + 1;
      const next = without.slice();
      next.splice(insertAt, 0, moved);
      if (next.every((t, i) => t.vaultId === cur[i].vaultId)) return;
      const activeVaultId = cur[activeIndexRef.current]?.vaultId ?? null;
      const nextActive = activeVaultId ? next.findIndex((t) => t.vaultId === activeVaultId) : -1;
      ++switchSeqRef.current;
      setTabs(next);
      setActiveIndex(nextActive);
      reorderVaults(next.map((t) => t.vaultId)).catch((e) => console.error("reorder_vaults failed:", e));
    },
    [],
  );

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const mod = e.metaKey || e.ctrlKey;
      if (!mod) return;
      const list = tabsRef.current;
      const ai = activeIndexRef.current;
      if (e.altKey && (e.key === "ArrowLeft" || e.key === "ArrowRight")) {
        if (list.length === 0) return;
        e.preventDefault();
        const delta = e.key === "ArrowRight" ? 1 : -1;
        const next = (ai + delta + list.length) % list.length;
        activate(next);
        return;
      }
      if (e.altKey) return;
      const k = e.key.toLowerCase();
      if (k >= "1" && k <= "9") {
        const idx = Number(k) - 1;
        if (idx < list.length) {
          e.preventDefault();
          activate(idx);
        }
        return;
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [activate]);

  const lockActive = useCallback(async () => {
    const t = tabsRef.current[activeIndexRef.current];
    if (t?.registered) await lockVault(t.vaultId).catch((e) => console.error("lock_vault failed:", e));
  }, []);
  const lockAllTabs = useCallback(async () => {
    await lockAll().catch((e) => console.error("lock_all failed:", e));
  }, []);

  useEffect(() => {
    const uns: Array<Promise<() => void>> = [
      listen(MENU_NEW_VAULT, () => beginAdd()),
      listen(MENU_OPEN_VAULT, () => beginAdd("open")),
      listen(MENU_CLOSE_VAULT, () => { void closeActive(); }),
      listen(MENU_LOCK_ALL, () => { void lockAllTabs(); }),
    ];
    return () => {
      uns.forEach((u) => u.then((f) => f()));
    };
  }, [beginAdd, closeActive, lockAllTabs]);

  const activeTab = activeIndex >= 0 ? tabs[activeIndex] ?? null : null;

  const value = useMemo<TabsState>(
    () => ({
      tabs, activeIndex, adding, addIntent, activeTab,
      activate, beginAdd, clearAddIntent, cancelAdd, closeTab, closeActive,
      lockActive, lockAllTabs, reorderTabs,
    }),
    [tabs, activeIndex, adding, addIntent, activeTab, activate, beginAdd, clearAddIntent, cancelAdd, closeTab, closeActive, lockActive, lockAllTabs, reorderTabs],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useTabs(): TabsState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useTabs must be used within TabsProvider");
  return v;
}
