import { useCallback, useEffect, useMemo, useState } from "react";
import { biometricHas, keychainHas, nmhStatus, syncStatus } from "../ipc/commands";
import type { SyncStatusInfo } from "../ipc/types";
import { IS_MAC } from "./platform";
import { useSettings } from "../state/SettingsContext";
import { useVault } from "../state/VaultContext";
import type { SettingsTab } from "../state/VaultContext";
import { ONBOARDING_STEPS, doneCount } from "./onboarding";
import type { OnboardingCtx } from "./onboarding";

type Probe = {
  nmh: OnboardingCtx["nmh"];
  sync: SyncStatusInfo | null;
  fastUnlock: boolean;
};

const EMPTY_PROBE: Probe = { nmh: null, sync: null, fastUnlock: false };

export function useOnboarding() {
  const { settings, update } = useSettings();
  const { vaultId, status, route, setRoute, setSettingsTab } = useVault();
  const [probe, setProbe] = useState<Probe>(EMPTY_PROBE);

  const visible = settings.onboarding_eligible && !settings.onboarding_dismissed;
  const path = status?.path ?? null;

  // Re-probe when the card becomes relevant and whenever the active vault
  // changes: sync and fast unlock belong to one vault, not to the app.
  useEffect(() => {
    if (!visible || route !== "main") return;
    let ignore = false;
    Promise.allSettled([
      nmhStatus(),
      syncStatus(vaultId),
      path ? keychainHas(path) : Promise.resolve(false),
      path ? biometricHas(path) : Promise.resolve(false),
    ]).then(([nmhR, syncR, khR, bhR]) => {
      if (ignore) return;
      setProbe({
        nmh: nmhR.status === "fulfilled" ? nmhR.value : null,
        sync: syncR.status === "fulfilled" ? syncR.value : null,
        fastUnlock:
          (khR.status === "fulfilled" && khR.value) || (bhR.status === "fulfilled" && bhR.value),
      });
    });
    return () => {
      ignore = true;
    };
  }, [visible, route, vaultId, path]);

  const ctx: OnboardingCtx = useMemo(
    () => ({ nmh: probe.nmh, sync: probe.sync, fastUnlock: probe.fastUnlock, settings }),
    [probe, settings],
  );

  const goTo = useCallback(
    (tab: SettingsTab) => {
      setSettingsTab(tab);
      setRoute("settings");
    },
    [setSettingsTab, setRoute],
  );

  return {
    visible,
    collapsed: settings.onboarding_collapsed,
    steps: ONBOARDING_STEPS.map((step) => ({ step, done: step.done(ctx) })),
    done: doneCount(ctx),
    total: ONBOARDING_STEPS.length,
    isMac: IS_MAC,
    setCollapsed: (v: boolean) => void update({ onboarding_collapsed: v }),
    dismiss: () => void update({ onboarding_dismissed: true }),
    deferSync: () => void update({ onboarding_sync_deferred: true }),
    goTo,
  };
}

export type Onboarding = ReturnType<typeof useOnboarding>;
