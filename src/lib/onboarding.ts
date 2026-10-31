import type { Settings } from "../ipc/commands";
import type { SyncStatusInfo } from "../ipc/types";
import type { SettingsTab } from "../state/VaultContext";

/// Everything the five steps need, gathered once by useOnboarding. A null
/// member means its probe failed (locked vault, no vault open) — the step then
/// reads as not done rather than breaking the card.
export type OnboardingCtx = {
  nmh: { enabled: boolean; chrome_registered: boolean; firefox_registered: boolean } | null;
  sync: SyncStatusInfo | null;
  fastUnlock: boolean;
  settings: Settings;
};

export type OnboardingStepId = "browser" | "backup" | "sync" | "fastUnlock" | "import";

export type OnboardingStep = {
  id: OnboardingStepId;
  titleKey: string;
  /// macOS says "Touch ID" where the other platforms say "Fast unlock".
  titleKeyMac?: string;
  descKey: string;
  tab: SettingsTab;
  done: (c: OnboardingCtx) => boolean;
  /// Only the sync step can be completed by answering "Later".
  deferrable?: boolean;
};

/// Ordered by descending value: connecting the browser is the
/// hardest step and the main future source of support tickets.
export const ONBOARDING_STEPS: OnboardingStep[] = [
  {
    id: "browser",
    titleKey: "onboarding.browser.title",
    descKey: "onboarding.browser.desc",
    tab: "browser",
    // The step must not stay ticked once the browser integration itself is
    // switched off, even if a host is still registered.
    done: (c) => !!c.nmh && c.nmh.enabled && (c.nmh.chrome_registered || c.nmh.firefox_registered),
  },
  {
    id: "backup",
    titleKey: "onboarding.backup.title",
    descKey: "onboarding.backup.desc",
    tab: "data",
    done: (c) => c.settings.onboarding_backup_done,
  },
  {
    id: "sync",
    titleKey: "onboarding.sync.title",
    descKey: "onboarding.sync.desc",
    tab: "sync",
    deferrable: true,
    done: (c) => (!!c.sync && c.sync.kind !== "none") || c.settings.onboarding_sync_deferred,
  },
  {
    id: "fastUnlock",
    titleKey: "onboarding.fastUnlock.title",
    titleKeyMac: "onboarding.fastUnlock.titleMac",
    descKey: "onboarding.fastUnlock.desc",
    tab: "security",
    done: (c) => c.fastUnlock,
  },
  {
    id: "import",
    titleKey: "onboarding.import.title",
    descKey: "onboarding.import.desc",
    tab: "data",
    done: (c) => c.settings.onboarding_import_done,
  },
];

export function stepTitleKey(step: OnboardingStep, isMac: boolean): string {
  return isMac && step.titleKeyMac ? step.titleKeyMac : step.titleKey;
}

export function doneCount(ctx: OnboardingCtx): number {
  return ONBOARDING_STEPS.filter((s) => s.done(ctx)).length;
}
