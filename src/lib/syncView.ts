
import type { SyncStatusInfo } from "../ipc/types";

export type SyncPhase = "idle" | "syncing" | "error";
export type SyncVisualState = "synced" | "syncing" | "warning" | "error" | "off";

export interface SyncProviderLine {
  id: "folder" | "gdrive";
  labelKey: string;
  lastSync: number;
  warning: boolean;
}

export interface SyncView {
  state: SyncVisualState;
  providers: SyncProviderLine[];
  configured: boolean;
}

function deriveProviders(info: SyncStatusInfo | null): {
  providers: SyncProviderLine[];
  configured: boolean;
} {
  if (info === null || info.kind === "none") {
    return { providers: [], configured: false };
  }
  const warning = info.not_synced_warning || info.conflicts.length > 0;
  return {
    providers: [
      {
        id: info.kind,
        labelKey: info.kind === "folder" ? "sync.folder" : "sync.gdrive",
        lastSync: info.last_sync,
        warning,
      },
    ],
    configured: true,
  };
}

export function deriveSyncView(info: SyncStatusInfo | null, phase: SyncPhase): SyncView {
  if (info === null) {
    return { state: "off", providers: [], configured: false };
  }

  if (phase === "syncing") {
    const { providers, configured } = deriveProviders(info);
    return { state: "syncing", providers, configured };
  }

  if (phase === "error") {
    const { providers, configured } = deriveProviders(info);
    return { state: "error", providers, configured };
  }

  if (info.kind === "none") {
    return { state: "off", providers: [], configured: false };
  }

  const warning = info.not_synced_warning || info.conflicts.length > 0;
  const { providers, configured } = deriveProviders(info);
  return { state: warning ? "warning" : "synced", providers, configured };
}

export type RelTime =
  | { kind: "now" }
  | { kind: "min" | "hour" | "day"; value: number }
  | { kind: "date"; iso: string };

export function relTime(epochSec: number, nowMs: number): RelTime | null {
  if (epochSec <= 0) return null;

  const deltaSec = Math.max(0, Math.floor(nowMs / 1000) - epochSec);

  if (deltaSec < 45) return { kind: "now" };
  if (deltaSec < 3600) return { kind: "min", value: Math.max(1, Math.round(deltaSec / 60)) };
  if (deltaSec < 86400) return { kind: "hour", value: Math.floor(deltaSec / 3600) };
  if (deltaSec < 604800) return { kind: "day", value: Math.max(1, Math.floor(deltaSec / 86400)) };

  return { kind: "date", iso: new Date(epochSec * 1000).toISOString() };
}
