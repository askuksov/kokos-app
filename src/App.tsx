import { VaultProvider } from "./state/VaultContext";
import { SettingsProvider } from "./state/SettingsContext";
import { LangProvider } from "./state/LangContext";
import { ClipboardProvider } from "./state/ClipboardContext";
import { TextImportProvider } from "./state/TextImportContext";
import { TabsProvider, useTabs } from "./state/TabsContext";
import { WelcomeScreen } from "./screens/Welcome";
import { TabLock } from "./screens/TabLock";
import { VaultScreen } from "./screens/Vault";
import { NmhConfirm } from "./components/NmhConfirm";
import { Topbar } from "./components/Topbar";


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
            <NmhConfirm />
          </TabsProvider>
        </ClipboardProvider>
      </LangProvider>
    </SettingsProvider>
  );
}
