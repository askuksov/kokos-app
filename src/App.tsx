import { useEffect, useRef } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { VaultProvider } from "./state/VaultContext";
import { SettingsProvider, useSettings } from "./state/SettingsContext";
import { LangProvider } from "./state/LangContext";
import { ClipboardProvider, useClipboard } from "./state/ClipboardContext";
import { TextImportProvider } from "./state/TextImportContext";
import { TabsProvider, useTabs } from "./state/TabsContext";
import { WelcomeScreen } from "./screens/Welcome";
import { TabLock } from "./screens/TabLock";
import { VaultScreen } from "./screens/Vault";
import { NmhConfirm } from "./components/NmhConfirm";
import { NmhUnlock } from "./components/NmhUnlock";
import { TrayIntro } from "./components/TrayIntro";
import { Topbar } from "./components/Topbar";
import { lockAll } from "./ipc/commands";
import { clearClipboard } from "./lib/clipboard";

/// "Lock when the window loses focus" locks every unlocked vault, not just
/// the one on screen: background tabs and a tab hidden behind the lock or
/// welcome screen would otherwise stay open.
function LockOnBlur() {
  const { settings } = useSettings();
  const { tabs } = useTabs();
  const { reset: resetClipboard } = useClipboard();
  const anyUnlocked = tabs.some((t) => !t.locked);
  const stateRef = useRef({ enabled: settings.lock_on_blur, anyUnlocked, resetClipboard });
  stateRef.current = { enabled: settings.lock_on_blur, anyUnlocked, resetClipboard };

  useEffect(() => {
    const un = getCurrentWindow().onFocusChanged(({ payload: focused }) => {
      const s = stateRef.current;
      if (focused || !s.enabled || !s.anyUnlocked) return;
      void clearClipboard();
      s.resetClipboard();
      lockAll().catch((e) => console.error("lock_all failed:", e));
    });
    return () => {
      un.then((f) => f());
    };
  }, []);
  return null;
}


function TabsBody() {
  const { tabs, activeIndex, adding } = useTabs();
  const activeTab = activeIndex >= 0 ? tabs[activeIndex] : null;
  const openTabs = tabs.filter((t) => !t.locked);
  return (
    <div className="kv-body">
      {openTabs.map((tab) => (
        <VaultProvider key={tab.vaultId} vaultId={tab.vaultId}>
          <TextImportProvider>
            {!adding && activeTab?.vaultId === tab.vaultId ? <VaultScreen /> : null}
          </TextImportProvider>
        </VaultProvider>
      ))}
      {!adding && activeTab?.locked && (
        <TabLock key={activeTab.vaultId} path={activeTab.vaultId} />
      )}
      {adding && (
        <VaultProvider key="__new__">
          <WelcomeScreen />
        </VaultProvider>
      )}
    </div>
  );
}

function Shell() {
  const { tabs } = useTabs();
  if (tabs.length === 0) {
    return (
      <VaultProvider key="__welcome__">
        <WelcomeScreen />
      </VaultProvider>
    );
  }
  return (
    <div className="kv-app">
      <Topbar />
      <TabsBody />
    </div>
  );
}

export default function App() {
  return (
    <SettingsProvider>
      <LangProvider>
        <ClipboardProvider>
          <TabsProvider>
            <Shell />
            <LockOnBlur />
            <NmhConfirm />
            <NmhUnlock />
            <TrayIntro />
          </TabsProvider>
        </ClipboardProvider>
      </LangProvider>
    </SettingsProvider>
  );
}
