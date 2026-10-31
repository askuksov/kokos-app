import { useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { useVault } from "../state/VaultContext";
import { useSettings } from "../state/SettingsContext";
import { useT, useLang } from "../state/LangContext";
import { errorMessage } from "../lib/errors";
import { IS_MAC, IS_WINDOWS } from "../lib/platform";
import {
  keychainHas,
  keychainEnable,
  keychainDisable,
  biometricAvailable,
  biometricHas,
  biometricEnable,
  biometricDisable,
  getVaultHeaderInfo,
  pickAnyFile,
  pickFolder,
  verifyPassword,
  changeMasterPassword,
  setVaultHint as setVaultHintCmd,
  listAudit,
  clearAudit,
  exportJson,
  exportVaultCopy,
  pickSavePath,
  importJson,
  pickKdbxFile,
  importKdbx,
  syncStatus,
  syncSetFolder,
  syncDisable,
  gdriveConnect,
  gdriveConnectCancel,
  gdriveDisconnect,
  gdriveSetNote,
  syncNow,
  nmhStatus,
  nmhSetEnabled,
  hibpSetEnabled,
  nmhInstall,
  nmhUninstall,
  nmhGrantsList,
  nmhGrantForget,
  nmhGrantsForgetOrigin,
  aiStatus,
  aiModelDownload,
  aiModelDownloadCancel,
  aiEnable,
  aiDisable,
  aiIndexStatus,
  aiBackfill,
  aiGenModelStatus,
  aiGenModelDownload,
  aiGenModelDownloadCancel,
  aiGenModelDownloadStatus,
  appVersion,
  type KeyfileAction,
  type NmhStatus,
  type NmhGrantDto,
} from "../ipc/commands";
import { MAX_HINT_BYTES, type AuditEntry, type ImportReport, type SyncStatusInfo, type AiStatus, type AiIndexStatus, type GenModelStatus } from "../ipc/types";
import { PasswordField } from "./PasswordField";
import { KeyfileField } from "./KeyfileField";
import { ManageFieldTemplates } from "./ManageFieldTemplates";
import { PasswordHealth } from "./PasswordHealth";
import type { SettingsTab } from "../state/VaultContext";
import { useTextImport } from "../state/TextImportContext";
import "./Settings.css";

type StorageMode = "off" | "password" | "touchid";

type SettingsIcon = "chevronLeft";

const ICON_PATHS: Record<SettingsIcon, React.ReactNode> = {
  chevronLeft: <path d="M14.5 6.5l-5.5 5.5 5.5 5.5" />,
};

function Icon({
  name,
  size = 13,
  strokeWidth = 2,
}: {
  name: SettingsIcon;
  size?: number;
  strokeWidth?: number;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {ICON_PATHS[name]}
    </svg>
  );
}

const AUDIT_EVENTS = new Set([
  "unlock",
  "lock",
  "master_password_changed",
  "keyfile_changed",
  "hint_changed",
  "keychain_enabled",
  "keychain_disabled",
  "exported",
  "imported",
  "sync_connected",
  "sync_disconnected",
  "hibp_enabled",
  "hibp_disabled",
  "ai_enabled",
  "ai_disabled",
  "ai_model_downloaded",
  "ai_gen_model_downloaded",
  "ai_text_import_analyzed",
  "extension_connected",
  "extension_secret",
  "extension_totp",
  "extension_login_saved",
  "extension_login_updated",
  "extension_denied",
  "extension_grant_added",
  "extension_grant_revoked",
  "extension_secret_granted",
  "extension_totp_granted",
]);

const NMH_CONFIRM_MODES: readonly { value: string; labelKey: string }[] = [
  { value: "always", labelKey: "settings.nmhConfirmAlways" },
  { value: "session_domain", labelKey: "settings.nmhConfirmSession" },
  { value: "remember_site", labelKey: "settings.nmhConfirmRemember" },
  { value: "trust_extension", labelKey: "settings.nmhConfirmTrust" },
];

type NmhGrantGroup = { origin: string; browser: string; grants: NmhGrantDto[] };

function groupGrantsByOrigin(rows: readonly NmhGrantDto[]): NmhGrantGroup[] {
  const groups: NmhGrantGroup[] = [];
  for (const g of rows) {
    const last = groups[groups.length - 1];
    if (last && last.origin === g.origin) last.grants.push(g);
    else groups.push({ origin: g.origin, browser: g.browser, grants: [g] });
  }
  return groups;
}

function formatBytes(n: number): string {
  const mb = n / (1024 * 1024);
  return mb >= 1024 ? `${(mb / 1024).toFixed(1)} GB` : `${Math.round(mb)} MB`;
}

function ProgressRow({
  label,
  done,
  total,
  detail,
}: {
  label: string;
  done: number;
  total: number;
  detail: string;
}) {
  const pct = Math.round((done / total) * 100);
  return (
    <div className="kv-settings-row">
      <div
        className="kv-ai-progress"
        role="progressbar"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={total}
        aria-valuenow={done}
      >
        <div className="kv-ai-progress-fill" style={{ width: `${pct}%` }} />
      </div>
      <span className="kv-settings-row-hint">{`${pct}% · ${detail}`}</span>
    </div>
  );
}

const SETTINGS_TABS: SettingsTab[] = [
  "general",
  "security",
  "browser",
  "sync",
  "privacy",
  "ai",
  "data",
  "templates",
  "health",
  "about",
];
const SETTINGS_TAB_LABEL: Record<SettingsTab, string> = {
  general: "settings.tabGeneral",
  security: "settings.tabSecurity",
  browser: "settings.tabBrowser",
  sync: "settings.tabSync",
  privacy: "settings.tabPrivacy",
  ai: "settings.tabAi",
  data: "settings.tabData",
  templates: "settings.tabTemplates",
  health: "settings.tabHealth",
  about: "settings.tabAbout",
};

async function verifyCurrent(
  pw: string,
  keyfilePath: string | null,
  requiresKeyfile: boolean,
  wrongMsg: string,
  setError: (s: string | null) => void,
  vaultId: string | undefined,
): Promise<boolean> {
  try {
    const ok = await verifyPassword(pw, requiresKeyfile ? keyfilePath : null, vaultId);
    if (!ok) {
      setError(wrongMsg);
      return false;
    }
    return true;
  } catch (err) {
    setError(String(err));
    return false;
  }
}

/**
 * Full-page Settings hub.
 * Structure mirrors the sibling `.kv-settings` pages (ManageFolders.tsx/
 * ManageTags.tsx/Trash.tsx/ManageFieldTemplates.tsx): a Back button + an
 * `<h1>` + a one-line `.kv-settings-sub` description, reusing that shared
 * shell (nothing here redeclares `.kv-settings`/`.kv-settings-inner`/
 * `.kv-settings-sub`/`.kv-settings-back`).
 *
 * Below the header, a left rail of tabs (`SETTINGS_TABS`, the active one
 * kept in VaultContext's `settingsTab`) selects which panel renders; the
 * Templates and Health tabs host ManageFieldTemplates and PasswordHealth
 * in `embedded` mode.
 *
 * App-wide preferences go through `useSettings().update()` → `setSettings`
 * IPC → settings.json; e.g. the General tab's density control
 * (Comfortable/Compact) lands as `data-density` on `.kv-window`
 * (src/screens/Vault.tsx) → base.css's compact override.
 */
export function Settings() {
  const { vaultId, setRoute, status, refreshStatus, entries, refreshEntries, refreshFolders, refreshTags, settingsTab, setSettingsTab, select } =
    useVault();
  const { settings, update, refresh: refreshSettings } = useSettings();
  const t = useT();
  const lang = useLang();

  const [version, setVersion] = useState("");
  useEffect(() => {
    appVersion().then(setVersion).catch(() => setVersion(""));
  }, []);

  const [mode, setMode] = useState<StorageMode>("off");
  const [available, setAvailable] = useState(false);
  const [pending, setPending] = useState<"password" | "touchid" | null>(null);
  const [pw, setPw] = useState("");
  const [confirmingOff, setConfirmingOff] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [requiresKeyfile, setRequiresKeyfile] = useState(false);
  const [kfAction, setKfAction] = useState<null | "set" | "remove">(null);
  const [kfCurPw, setKfCurPw] = useState("");
  const [kfCurKeyfile, setKfCurKeyfile] = useState<string | null>(null);
  const [kfNewPw, setKfNewPw] = useState("");
  const [kfNewPwConfirm, setKfNewPwConfirm] = useState("");
  const [kfNewKeyfile, setKfNewKeyfile] = useState<string | null>(null);
  const [kfBusy, setKfBusy] = useState(false);
  const [kfError, setKfError] = useState<string | null>(null);
  const [confirmingRemove, setConfirmingRemove] = useState(false);
  const [kfReload, setKfReload] = useState(0);

  const [headerReload, setHeaderReload] = useState(0);

  const [vaultHint, setVaultHint] = useState("");

  const [mpOpen, setMpOpen] = useState(false);
  const [mpCurPw, setMpCurPw] = useState("");
  const [mpCurKeyfile, setMpCurKeyfile] = useState<string | null>(null);
  const [mpNewPw, setMpNewPw] = useState("");
  const [mpNewPwConfirm, setMpNewPwConfirm] = useState("");
  const [mpBusy, setMpBusy] = useState(false);
  const [mpError, setMpError] = useState<string | null>(null);

  const [hintOpen, setHintOpen] = useState(false);
  const [hintDraft, setHintDraft] = useState("");
  const [hintBusy, setHintBusy] = useState(false);
  const [hintError, setHintError] = useState<string | null>(null);

  const [auditEntries, setAuditEntries] = useState<AuditEntry[]>([]);
  const [auditReload, setAuditReload] = useState(0);
  const [confirmingClearAudit, setConfirmingClearAudit] = useState(false);

  const entryCount = entries.length;
  const [exportWarnOpen, setExportWarnOpen] = useState(false);
  const [dataMsg, setDataMsg] = useState<string | null>(null);

  const [kdbxPath, setKdbxPath] = useState<string | null>(null);
  const [kdbxPassword, setKdbxPassword] = useState("");
  const [kdbxBusy, setKdbxBusy] = useState(false);
  const [kdbxErr, setKdbxErr] = useState<string | null>(null);

  const [syncSt, setSyncSt] = useState<SyncStatusInfo | null>(null);
  const [syncBusy, setSyncBusy] = useState(false);
  const [syncMsg, setSyncMsg] = useState<string | null>(null);
  const [oauthWaiting, setOauthWaiting] = useState(false);

  const refreshSync = async () => {
    try {
      setSyncSt(await syncStatus());
    } catch {
    }
  };
  useEffect(() => {
    refreshSync();
  }, []);

  const [noteDraft, setNoteDraft] = useState("");
  useEffect(() => {
    setNoteDraft(syncSt?.note ?? "");
  }, [syncSt?.note]);
  const onSaveNote = async () => {
    setSyncBusy(true);
    try {
      await gdriveSetNote(noteDraft.trim());
      await refreshSync();
    } catch {
      setSyncMsg(t("sync.error"));
    } finally {
      setSyncBusy(false);
    }
  };

  const onTargetChange = async (kind: string) => {
    setSyncBusy(true);
    setSyncMsg(null);
    try {
      if (kind === "none") await syncDisable();
      else if (kind === "folder") await syncSetFolder();
      else if (kind === "gdrive") {
        setSyncMsg(t("sync.connecting"));
        setOauthWaiting(true);
        await gdriveConnect();
      }
      await refreshSync();
    } catch (e) {
      setSyncMsg(String(e).includes("oauth_cancelled") ? null : t("sync.error"));
      await refreshSync();
    } finally {
      setOauthWaiting(false);
      setSyncBusy(false);
    }
  };
  const onCancelConnect = async () => {
    try {
      await gdriveConnectCancel();
    } catch {
    }
  };
  const onGdriveDisconnect = async () => {
    setSyncBusy(true);
    try {
      await gdriveDisconnect();
      await refreshSync();
    } finally {
      setSyncBusy(false);
    }
  };
  const onSyncNow = async () => {
    setSyncBusy(true);
    setSyncMsg(t("sync.syncing"));
    try {
      const o = await syncNow();
      if (o.requires_reopen) {
        setSyncMsg(t("sync.pulled"));
        await refreshStatus();
      } else if (o.pushed) setSyncMsg(t("sync.pushed"));
      else setSyncMsg(t("sync.inSync"));
      await refreshSync();
    } catch {
      setSyncMsg(t("sync.error"));
      await refreshSync();
    } finally {
      setSyncBusy(false);
    }
  };
  const fmtLast = (t0: number) => (t0 > 0 ? new Date(t0 * 1000).toLocaleString() : t("sync.never"));

  useEffect(() => {
    const p = status?.path;
    if (!p) {
      setMode("off");
      setAvailable(false);
      return;
    }
    let ignore = false;
    Promise.allSettled([keychainHas(p), biometricHas(p), biometricAvailable()]).then(
      ([khR, bhR, avR]) => {
        if (ignore) return;
        const kh = khR.status === "fulfilled" && khR.value;
        const bh = bhR.status === "fulfilled" && bhR.value;
        const av = avR.status === "fulfilled" && avR.value;
        setMode(bh ? "touchid" : kh ? "password" : "off");
        setAvailable(av);
      },
    );
    return () => {
      ignore = true;
    };
  }, [status?.path, kfReload]);

  useEffect(() => {
    if (!confirmingOff) return;
    const onDown = (e: MouseEvent) => {
      const t = e.target as HTMLElement | null;
      if (t?.closest('[data-confirming="true"]')) return;
      setConfirmingOff(false);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [confirmingOff]);

  useEffect(() => {
    const p = status?.path;
    if (!p) {
      setRequiresKeyfile(false);
      setVaultHint("");
      return;
    }
    let ignore = false;
    getVaultHeaderInfo(p)
      .then((h) => {
        if (!ignore) {
          setRequiresKeyfile(h.requires_keyfile);
          setVaultHint(h.hint);
        }
      })
      .catch(() => {
        if (!ignore) {
          setRequiresKeyfile(false);
          setVaultHint("");
        }
      });
    return () => {
      ignore = true;
    };
  }, [status?.path, headerReload]);

  useEffect(() => {
    if (!confirmingRemove) return;
    const onDown = (e: MouseEvent) => {
      const t = e.target as HTMLElement | null;
      if (t?.closest('[data-confirming-kf="true"]')) return;
      setConfirmingRemove(false);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [confirmingRemove]);

  useEffect(() => {
    const p = status?.path;
    if (!p) {
      setAuditEntries([]);
      return;
    }
    let ignore = false;
    listAudit(500)
      .then((rows) => {
        if (!ignore) setAuditEntries(rows);
      })
      .catch(() => {
        if (!ignore) setAuditEntries([]);
      });
    return () => {
      ignore = true;
    };
  }, [status?.path, auditReload]);

  useEffect(() => {
    if (!confirmingClearAudit) return;
    const onDown = (e: MouseEvent) => {
      const t = e.target as HTMLElement | null;
      if (t?.closest('[data-confirming-audit="true"]')) return;
      setConfirmingClearAudit(false);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [confirmingClearAudit]);

  function onSelectStorage(target: StorageMode) {
    if (busy) return;
    if (target === mode) {
      setPending(null);
      setConfirmingOff(false);
      setPw("");
      setError(null);
      return;
    }
    setError(null);
    if (target === "off") {
      setPending(null);
      setPw("");
      setConfirmingOff(true);
      return;
    }
    setConfirmingOff(false);
    setPending(target);
    setPw("");
  }

  async function onConfirmOff() {
    setError(null);
    setBusy(true);
    try {
      // Both deletes are idempotent (missing entry = Ok), so a failure here is
      // a real credential-store error: keep the mode and let the user retry.
      await keychainDisable();
      // biometricDisable errors on platforms without Touch ID; only call it
      // when the biometric entry can exist.
      if (mode === "touchid" || available) await biometricDisable();
      setMode("off");
    } catch {
      setError(t("errors.fastUnlockRevokeFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function onPendingSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!pw || !pending) return;
    setError(null);
    setBusy(true);
    const target = pending;
    const from = mode;
    try {
      // The new credential is already stored when the old one fails to go, so the
      // switch stands; the user is told the old one is still there.
      let oldKept = false;
      if (target === "password") {
        await keychainEnable(pw);
        if (from === "touchid") {
          try {
            await biometricDisable();
          } catch {
            oldKept = true;
          }
        }
      } else {
        await biometricEnable(pw);
        if (from === "password") {
          try {
            await keychainDisable();
          } catch {
            oldKept = true;
          }
        }
      }
      setMode(target);
      setPending(null);
      if (oldKept) setError(t("settings.oldCredentialKept"));
    } catch (err) {
      setError(errorMessage(err, t));
    } finally {
      setPw("");
      setBusy(false);
    }
  }

  function onKfOpen(action: "set" | "remove") {
    setKfAction(action);
    setKfCurPw("");
    setKfCurKeyfile(null);
    setKfNewPw("");
    setKfNewPwConfirm("");
    setKfNewKeyfile(null);
    setKfError(null);
    setConfirmingRemove(false);
  }

  function onKfCancel() {
    setKfAction(null);
    setKfCurPw("");
    setKfCurKeyfile(null);
    setKfNewPw("");
    setKfNewPwConfirm("");
    setKfNewKeyfile(null);
    setKfError(null);
    setConfirmingRemove(false);
  }

  async function pickKfCurKeyfile() {
    const p = await pickAnyFile();
    if (p) setKfCurKeyfile(p);
  }

  async function pickKfNewKeyfile() {
    const p = await pickAnyFile();
    if (p) setKfNewKeyfile(p);
  }

  async function onKfSave() {
    if (kfBusy) return;
    // Capture once: verify + rotate must hit the same vault even if the active tab switches mid-await.
    const targetVaultId = vaultId;
    if (!kfCurPw) {
      setKfError(t("settings.keyfileErrEnterCurrentPassword"));
      return;
    }
    if (requiresKeyfile && !kfCurKeyfile) {
      setKfError(t("settings.keyfileErrChooseCurrentFile"));
      return;
    }
    if (kfAction === "set" && !kfNewKeyfile) {
      setKfError(t("settings.keyfileErrChooseFile"));
      return;
    }
    if (kfNewPw && kfNewPw !== kfNewPwConfirm) {
      setKfError(t("settings.keyfileErrPasswordsMismatch"));
      return;
    }

    setKfError(null);
    setKfBusy(true);
    try {
      const ok = await verifyCurrent(
        kfCurPw,
        kfCurKeyfile,
        requiresKeyfile,
        t("settings.keyfileErrWrongPassword"),
        setKfError,
        targetVaultId,
      );
      if (!ok) return;

      const action: KeyfileAction =
        kfAction === "remove" ? { kind: "remove" } : { kind: "set", path: kfNewKeyfile! };
      const finalPw = kfNewPw || kfCurPw;

      try {
        await changeMasterPassword(finalPw, null, action, targetVaultId);
      } catch (err) {
        setKfError(String(err));
        return;
      }


      setKfAction(null);
      setKfCurPw("");
      setKfCurKeyfile(null);
      setKfNewPw("");
      setKfNewPwConfirm("");
      setKfNewKeyfile(null);
      setConfirmingRemove(false);
      setKfReload((n) => n + 1);
      setHeaderReload((n) => n + 1);
      setAuditReload((n) => n + 1);
      await refreshStatus();
    } finally {
      setKfBusy(false);
    }
  }

  function onMpClose() {
    setMpOpen(false);
    setMpCurPw("");
    setMpCurKeyfile(null);
    setMpNewPw("");
    setMpNewPwConfirm("");
    setMpError(null);
  }

  async function pickMpCurKeyfile() {
    const p = await pickAnyFile();
    if (p) setMpCurKeyfile(p);
  }

  async function onMpSave() {
    if (mpBusy) return;
    // Capture once: verify + rotate must hit the same vault even if the active tab switches mid-await.
    const targetVaultId = vaultId;
    if (!mpCurPw) {
      setMpError(t("settings.masterPwErrEnterCurrent"));
      return;
    }
    if (requiresKeyfile && !mpCurKeyfile) {
      setMpError(t("settings.masterPwErrChooseKeyfile"));
      return;
    }
    if (!mpNewPw) {
      setMpError(t("settings.masterPwErrEnterNew"));
      return;
    }
    if (mpNewPw !== mpNewPwConfirm) {
      setMpError(t("settings.masterPwErrMismatch"));
      return;
    }

    setMpError(null);
    setMpBusy(true);
    try {
      const ok = await verifyCurrent(
        mpCurPw,
        mpCurKeyfile,
        requiresKeyfile,
        t("settings.masterPwErrWrong"),
        setMpError,
        targetVaultId,
      );
      if (!ok) return;

      const action: KeyfileAction = requiresKeyfile
        ? { kind: "resupply", path: mpCurKeyfile! }
        : { kind: "keep" };
      try {
        await changeMasterPassword(mpNewPw, null, action, targetVaultId);
      } catch (err) {
        setMpError(String(err));
        return;
      }

      onMpClose();
      setKfReload((n) => n + 1);
      setHeaderReload((n) => n + 1);
      setAuditReload((n) => n + 1);
      await refreshStatus();
    } finally {
      setMpBusy(false);
    }
  }

  function onMpFormSubmit(e: React.FormEvent) {
    e.preventDefault();
    void onMpSave();
  }

  const hintBytes = new TextEncoder().encode(hintDraft).length;
  const hintTooLong = hintBytes > MAX_HINT_BYTES;

  function onHintOpen() {
    setHintDraft(vaultHint);
    setHintError(null);
    setHintOpen(true);
  }

  function onHintClose() {
    setHintOpen(false);
    setHintDraft("");
    setHintError(null);
  }

  async function saveHint(next: string) {
    if (hintBusy) return;
    if (new TextEncoder().encode(next).length > MAX_HINT_BYTES) {
      setHintError(t("settings.hintErrTooLong", { max: String(MAX_HINT_BYTES) }));
      return;
    }
    setHintError(null);
    setHintBusy(true);
    try {
      await setVaultHintCmd(next);
      onHintClose();
      setAuditReload((n) => n + 1);
      setHeaderReload((n) => n + 1);
      await refreshStatus();
    } catch (err) {
      setHintError(String(err));
    } finally {
      setHintBusy(false);
    }
  }

  function onHintFormSubmit(e: React.FormEvent) {
    e.preventDefault();
    void saveHint(hintDraft);
  }

  async function onKfFormSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (kfAction === "remove" && !confirmingRemove) {
      setConfirmingRemove(true);
      return;
    }
    await onKfSave();
  }

  function onClearAudit() {
    if (!confirmingClearAudit) {
      setConfirmingClearAudit(true);
      return;
    }
    setConfirmingClearAudit(false);
    clearAudit()
      .then(() => setAuditReload((n) => n + 1))
      .catch(() => {});
  }

  function defaultExportName() {
    const d = new Date();
    const p = (n: number) => String(n).padStart(2, "0");
    return `kokos-export-${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}.json`;
  }

  async function doExportJson() {
    setExportWarnOpen(false);
    const path = await pickSavePath(defaultExportName());
    if (!path) return;
    await exportJson(path);
    await refreshSettings();
    setDataMsg(t("settings.exportDone", { count: entryCount }));
  }

  async function doExportCopy() {
    const path = await pickSavePath("kokos-backup.kokos");
    if (!path) return;
    await exportVaultCopy(path);
    await refreshSettings();
    setDataMsg(t("settings.exportCopyDone"));
  }

  async function doImport() {
    const path = await pickAnyFile();
    if (!path) return;
    let report: ImportReport;
    try {
      report = await importJson(path);
      await refreshSettings();
    } catch {
      setDataMsg(t("settings.importFailed"));
      return;
    }
    setDataMsg(
      t("settings.importDone", {
        entries: report.entries,
        folders: report.folders_new,
        tags: report.tags_new,
        relations: report.relations,
      })
    );
    setAuditReload((n) => n + 1);
    void Promise.all([refreshEntries(), refreshFolders(), refreshTags()]).catch((e) =>
      console.error("post-import refresh failed:", e)
    );
  }

  const KDBX_ERROR_KEYS: Record<string, string> = {
    kdbx_wrong_password: "settings.kdbxErrWrongPassword",
    kdbx_corrupt: "settings.kdbxErrCorrupt",
    kdbx_unsupported: "settings.kdbxErrUnsupported",
    kdbx_too_large: "settings.kdbxErrTooLarge",
  };
  function mapKdbxError(raw: unknown): string {
    return t(KDBX_ERROR_KEYS[String(raw)] ?? "settings.kdbxErrGeneric");
  }

  async function doImportKdbx() {
    const p = await pickKdbxFile();
    if (!p) return;
    setKdbxErr(null);
    setKdbxPassword("");
    setKdbxPath(p);
  }

  async function confirmImportKdbx() {
    if (!kdbxPath) return;
    setKdbxBusy(true);
    setKdbxErr(null);
    let report: ImportReport;
    try {
      report = await importKdbx(kdbxPath, kdbxPassword);
      await refreshSettings();
    } catch (err) {
      setKdbxErr(mapKdbxError(err));
      setKdbxBusy(false);
      return;
    }
    setKdbxBusy(false);
    setKdbxPassword("");
    setKdbxPath(null);
    setDataMsg(
      t("settings.kdbxImportDone", {
        entries: report.entries,
        folders: report.folders_new,
      })
    );
    setAuditReload((n) => n + 1);
    void Promise.all([refreshEntries(), refreshFolders(), refreshTags()]).catch((e) =>
      console.error("post-kdbx-import refresh failed:", e)
    );
  }

  const [nmhSt, setNmhSt] = useState<NmhStatus | null>(null);
  const [nmhBusy, setNmhBusy] = useState(false);
  const [nmhErr, setNmhErr] = useState<string | null>(null);
  const [chromeId, setChromeId] = useState("");
  const [firefoxId, setFirefoxId] = useState("");

  const [hibpBusy, setHibpBusy] = useState(false);

  const [aiSt, setAiSt] = useState<AiStatus | null>(null);
  const [aiIdx, setAiIdx] = useState<AiIndexStatus | null>(null);
  const [aiBusy, setAiBusy] = useState(false);
  const [aiErr, setAiErr] = useState<string | null>(null);
  const [aiIndexProgress, setAiIndexProgress] = useState<{ done: number; total: number } | null>(null);
  const [aiModelProgress, setAiModelProgress] = useState<{ downloaded: number; total: number } | null>(null);
  const [aiModelBusy, setAiModelBusy] = useState(false);
  const aiEnabled = aiSt?.enabled ?? false;
  const aiModelPresent = aiSt?.model_present ?? false;
  const [genStatus, setGenStatus] = useState<GenModelStatus | null>(null);
  const [genBusy, setGenBusy] = useState(false);
  const [genErr, setGenErr] = useState<string | null>(null);
  const [genProgress, setGenProgress] = useState<{ what: string; downloaded: number; total: number } | null>(null);
  const textImport = useTextImport();

  const refreshNmh = async (seed?: "chrome" | "firefox" | "both") => {
    try {
      const st = await nmhStatus();
      setNmhSt(st);
      if (seed === "both" || seed === "chrome") setChromeId(st.chrome_ids[0] ?? "");
      if (seed === "both" || seed === "firefox") setFirefoxId(st.firefox_ids[0] ?? "");
    } catch {
      setNmhErr(t("settings.nmhGenericError"));
    }
  };
  useEffect(() => {
    void refreshNmh("both");
  }, []);

  const NMH_ERROR_KEYS: Record<string, string> = {
    bad_chrome_id: "settings.nmhBadChromeId",
    bad_firefox_id: "settings.nmhBadFirefoxId",
    host_missing: "settings.nmhHostMissing",
    unsupported_platform: "settings.nmhUnsupportedPlatform",
  };
  function mapNmhError(raw: unknown): string {
    return t(NMH_ERROR_KEYS[String(raw)] ?? "settings.nmhGenericError");
  }

  async function onNmhToggle(next: boolean) {
    if (nmhBusy) return;
    setNmhErr(null);
    setNmhBusy(true);
    try {
      await nmhSetEnabled(next);
    } catch (err) {
      setNmhErr(mapNmhError(err));
      setNmhBusy(false);
      return;
    }
    await refreshNmh();
    await refreshSettings();
    setNmhBusy(false);
  }

  async function onHibpToggle(next: boolean) {
    if (hibpBusy) return;
    setHibpBusy(true);
    try {
      await hibpSetEnabled(next);
    } catch {
      setHibpBusy(false);
      return;
    }
    await refreshSettings();
    setAuditReload((n) => n + 1);
    setHibpBusy(false);
  }

  const refreshAi = async () => {
    try {
      const [st, idx] = await Promise.all([aiStatus(), aiIndexStatus()]);
      setAiSt(st);
      setAiIdx(idx);
    } catch {
    }
  };
  const refreshGen = async () => {
    try {
      setGenStatus(await aiGenModelStatus());
    } catch {
    }
  };
  const rehydrateGenDownload = async () => {
    try {
      const s = await aiGenModelDownloadStatus();
      if (s.active) {
        setGenBusy(true);
        if (s.total > 0) setGenProgress({ what: s.what, downloaded: s.downloaded, total: s.total });
      } else {
        setGenBusy(false);
      }
    } catch {
    }
  };
  useEffect(() => {
    void refreshAi();
    void refreshGen();
    void rehydrateGenDownload();
  }, []);

  useEffect(() => {
    const un = listen<{ done: number; total: number }>("ai_backfill_progress", (e) => {
      setAiIndexProgress(e.payload);
    });
    return () => {
      void un.then((f) => f());
    };
  }, []);

  useEffect(() => {
    const un = listen<{ downloaded: number; total: number }>("ai_download_progress", (e) => {
      setAiModelProgress(e.payload);
    });
    return () => {
      void un.then((f) => f());
    };
  }, []);

  useEffect(() => {
    const un = listen<{ what: string; downloaded: number; total: number }>("ai_gen_model_progress", (e) => {
      setGenProgress(e.payload);
    });
    return () => {
      void un.then((f) => f());
    };
  }, []);

  useEffect(() => {
    const un = listen<{ ok: boolean; error?: string | null }>("ai_gen_model_done", (e) => {
      setGenBusy(false);
      setGenProgress(null);
      if (!e.payload.ok && e.payload.error !== "cancelled") {
        setGenErr(t("settings.genDownloadFailed") + (e.payload.error ? " " + e.payload.error : ""));
      }
      void refreshGen();
      setAuditReload((n) => n + 1);
    });
    return () => {
      void un.then((f) => f());
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function onModelDownload() {
    if (aiModelBusy) return;
    setAiErr(null);
    setAiModelBusy(true);
    setAiModelProgress(null);
    try {
      await aiModelDownload();
    } catch (e) {
      // A user-cancelled download is not a failure: just unlock the UI.
      if (String(e).includes("cancelled")) {
        setAiModelBusy(false);
        setAiModelProgress(null);
        await refreshAi();
        return;
      }
      setAiErr(t("settings.aiModelDownloadFailed") + " " + errorMessage(e, t));
      setAiModelBusy(false);
      return;
    }
    await refreshAi();
    setAuditReload((n) => n + 1);
    setAiModelBusy(false);
  }

  async function onModelDownloadCancel() {
    if (!aiModelBusy) return;
    try {
      await aiModelDownloadCancel();
    } catch {
      // The download may have finished between render and click; the
      // completion path clears the busy state itself.
    }
  }

  async function onAiToggle(next: boolean) {
    if (aiBusy) return;
    setAiErr(null);
    setAiBusy(true);
    setAiIndexProgress(null);
    try {
      if (next) await aiEnable();
      else await aiDisable();
    } catch {
      setAiErr(t("settings.aiEnableFailed"));
      await refreshAi();
      setAiBusy(false);
      return;
    }
    await refreshSettings();
    await refreshAi();
    setAuditReload((n) => n + 1);
    setAiBusy(false);
  }

  async function onReindex() {
    if (aiBusy) return;
    setAiErr(null);
    setAiBusy(true);
    setAiIndexProgress(null);
    try {
      await aiBackfill();
    } catch {
      setAiErr(t("settings.aiReindexFailed"));
    }
    await refreshAi();
    setAiBusy(false);
  }

  async function onGenDownload() {
    if (genBusy) return;
    setGenErr(null);
    setGenBusy(true);
    setGenProgress(null);
    try {
      await aiGenModelDownload();
    } catch (e) {
      if (String(e).includes("gen_download_in_progress")) {
        void rehydrateGenDownload();
        return;
      }
      // A user-cancelled download is not a failure; the `ai_gen_model_done`
      // event (error "cancelled") clears the busy state quietly.
      if (String(e).includes("cancelled")) {
        return;
      }
      setGenErr(t("settings.genDownloadFailed") + " " + errorMessage(e, t));
      setGenBusy(false);
      return;
    }
    await refreshGen();
    setAuditReload((n) => n + 1);
    setGenBusy(false);
  }

  async function onGenDownloadCancel() {
    if (!genBusy) return;
    try {
      await aiGenModelDownloadCancel();
    } catch {
      // The download may have finished between render and click; the
      // `ai_gen_model_done` event clears the busy state itself.
    }
  }

  async function startTextImport() {
    const p = await pickAnyFile();
    if (!p) return;
    setDataMsg(null);
    textImport.start({ kind: "file", path: p });
  }
  async function startFolderImport() {
    const d = await pickFolder();
    if (!d) return;
    setDataMsg(null);
    textImport.start({ kind: "folder", dir: d });
  }

  async function onNmhInstall(browser: "chrome" | "firefox") {
    if (nmhBusy) return;
    const id = (browser === "chrome" ? chromeId : firefoxId).trim();
    if (!id) return;
    setNmhErr(null);
    setNmhBusy(true);
    try {
      await nmhInstall(browser, id);
    } catch (err) {
      setNmhErr(mapNmhError(err));
      setNmhBusy(false);
      return;
    }
    await refreshNmh(browser);
    await refreshSettings();
    setNmhBusy(false);
  }

  async function onNmhUninstall(browser: "chrome" | "firefox") {
    if (nmhBusy) return;
    setNmhErr(null);
    setNmhBusy(true);
    try {
      await nmhUninstall(browser);
    } catch (err) {
      setNmhErr(mapNmhError(err));
      setNmhBusy(false);
      return;
    }
    await refreshNmh(browser);
    await refreshSettings();
    setNmhBusy(false);
  }

  const [grants, setGrants] = useState<NmhGrantDto[]>([]);
  const refreshGrants = async () => {
    try {
      setGrants(await nmhGrantsList());
    } catch {
    }
  };
  useEffect(() => {
    void refreshGrants();
  }, []);

  async function onGrantForget(origin: string, domain: string) {
    if (nmhBusy) return;
    setNmhErr(null);
    setNmhBusy(true);
    try {
      await nmhGrantForget(origin, domain);
    } catch (err) {
      setNmhErr(mapNmhError(err));
      setNmhBusy(false);
      return;
    }
    await refreshGrants();
    setNmhBusy(false);
  }

  async function onGrantsForgetAll(origin: string) {
    if (nmhBusy) return;
    setNmhErr(null);
    setNmhBusy(true);
    try {
      await nmhGrantsForgetOrigin(origin);
    } catch (err) {
      setNmhErr(mapNmhError(err));
      setNmhBusy(false);
      return;
    }
    await refreshGrants();
    setNmhBusy(false);
  }

  const nmhEnabled = nmhSt?.enabled ?? settings.nmh_enabled;
  const nmhListenerDown = !!nmhSt?.enabled && !nmhSt.running;
  const isSessionMode = settings.nmh_confirm_mode === "session_domain";
  const nmhBrowserRows = [
    {
      browser: "chrome" as const,
      label: t("settings.nmhChromeLabel"),
      hint: t("settings.nmhBadChromeId"),
      id: chromeId,
      setId: setChromeId,
      registered: nmhSt?.chrome_registered ?? false,
      idCount: nmhSt?.chrome_ids.length ?? 0,
    },
    {
      browser: "firefox" as const,
      label: t("settings.nmhFirefoxLabel"),
      hint: t("settings.nmhBadFirefoxId"),
      id: firefoxId,
      setId: setFirefoxId,
      registered: nmhSt?.firefox_registered ?? false,
      idCount: nmhSt?.firefox_ids.length ?? 0,
    },
  ];
  const grantGroups = groupGrantsByOrigin(grants);
  const fmtGrantDate = (t0: number) =>
    new Intl.DateTimeFormat(lang, { dateStyle: "medium", timeStyle: "short" }).format(new Date(t0 * 1000));

  const securityBusy = mpBusy || hintBusy || kfBusy;

  return (
    <main className="kv-settings kv-settings-hub" data-screen-label="Settings page">
      <div className="kv-settings-inner">
        <button type="button" className="kv-btn is-ghost kv-settings-back" onClick={() => setRoute("main")}>
          <Icon name="chevronLeft" /> {t("common.back")}
        </button>
        <h1>{t("settings.title")}</h1>
        <p className="kv-settings-sub">{t("settings.subtitle")}</p>

        <div className="kv-settings-cols">
          <nav className="kv-settings-rail" aria-label={t("settings.tabsAriaLabel")}>
            {SETTINGS_TABS.map((id) => (
              <button
                key={id}
                type="button"
                className={"kv-settings-tab" + (settingsTab === id ? " is-active" : "")}
                aria-current={settingsTab === id ? "page" : undefined}
                onClick={() => setSettingsTab(id)}
              >
                {t(SETTINGS_TAB_LABEL[id])}
              </button>
            ))}
          </nav>
          <div className="kv-settings-panel">
            {settingsTab === "security" && (
              <section className="kv-settings-section">
                <h2>{t("settings.security")}</h2>

          <div className="kv-settings-row">
            <div className="kv-settings-row-text">
              <span className="kv-settings-row-label">{t("settings.autoLockLabel")}</span>
              <span className="kv-settings-row-hint">{t("settings.autoLockHint")}</span>
            </div>
            <span className="kv-settings-select-wrap">
              <select
                className="kv-settings-select"
                aria-label={t("settings.autoLockAriaLabel")}
                value={String(settings.auto_lock_minutes)}
                onChange={(e) => void update({ auto_lock_minutes: Number(e.target.value) })}
              >
                <option value="1">{t("settings.afterMinutes1")}</option>
                <option value="5">{t("settings.afterMinutes5")}</option>
                <option value="15">{t("settings.afterMinutes15")}</option>
                <option value="30">{t("settings.afterMinutes30")}</option>
                <option value="60">{t("settings.afterMinutes60")}</option>
                <option value="0">{t("common.never")}</option>
              </select>
            </span>
          </div>

          <div className="kv-settings-row">
            <div className="kv-settings-row-text">
              <span className="kv-settings-row-label">{t("settings.lockOnBlurLabel")}</span>
              <span className="kv-settings-row-hint">{t("settings.lockOnBlurHint")}</span>
            </div>
            <div className="kv-settings-segmented" role="group" aria-label={t("settings.lockOnBlurLabel")}>
              <button
                type="button"
                className={"kv-settings-seg-btn" + (settings.lock_on_blur ? " is-active" : "")}
                aria-pressed={settings.lock_on_blur}
                onClick={() => void update({ lock_on_blur: true })}
              >
                {t("common.on")}
              </button>
              <button
                type="button"
                className={"kv-settings-seg-btn" + (!settings.lock_on_blur ? " is-active" : "")}
                aria-pressed={!settings.lock_on_blur}
                onClick={() => void update({ lock_on_blur: false })}
              >
                {t("common.off")}
              </button>
            </div>
          </div>

          <div className="kv-settings-row">
            <div className="kv-settings-row-text">
              <span className="kv-settings-row-label">{t("settings.lockOnSleepLabel")}</span>
              <span className="kv-settings-row-hint">{t("settings.lockOnSleepHint")}</span>
            </div>
            <div className="kv-settings-segmented" role="group" aria-label={t("settings.lockOnSleepLabel")}>
              <button
                type="button"
                className={"kv-settings-seg-btn" + (settings.lock_on_sleep ? " is-active" : "")}
                aria-pressed={settings.lock_on_sleep}
                onClick={() => void update({ lock_on_sleep: true })}
              >
                {t("common.on")}
              </button>
              <button
                type="button"
                className={"kv-settings-seg-btn" + (!settings.lock_on_sleep ? " is-active" : "")}
                aria-pressed={!settings.lock_on_sleep}
                onClick={() => void update({ lock_on_sleep: false })}
              >
                {t("common.off")}
              </button>
            </div>
          </div>

          <div className="kv-settings-row">
            <div className="kv-settings-row-text">
              <span className="kv-settings-row-label">{t("settings.clipboardClearLabel")}</span>
              <span className="kv-settings-row-hint">{t("settings.clipboardClearHint")}</span>
            </div>
            <span className="kv-settings-select-wrap">
              <select
                className="kv-settings-select"
                aria-label={t("settings.clipboardClearAriaLabel")}
                value={String(settings.clipboard_seconds)}
                onChange={(e) => void update({ clipboard_seconds: Number(e.target.value) })}
              >
                <option value="10">{t("settings.afterSeconds10")}</option>
                <option value="30">{t("settings.afterSeconds30")}</option>
                <option value="60">{t("settings.afterSeconds60")}</option>
                <option value="0">{t("common.never")}</option>
              </select>
            </span>
          </div>

          <div className="kv-settings-row">
            <div className="kv-settings-row-text">
              <span className="kv-settings-row-label">{t("settings.clipboardOnExitLabel")}</span>
              <span className="kv-settings-row-hint">{t("settings.clipboardOnExitHint")}</span>
            </div>
            <div className="kv-settings-segmented" role="group" aria-label={t("settings.clipboardOnExitLabel")}>
              <button
                type="button"
                className={"kv-settings-seg-btn" + (settings.clear_clipboard_on_exit ? " is-active" : "")}
                aria-pressed={settings.clear_clipboard_on_exit}
                onClick={() => void update({ clear_clipboard_on_exit: true })}
              >
                {t("common.on")}
              </button>
              <button
                type="button"
                className={"kv-settings-seg-btn" + (!settings.clear_clipboard_on_exit ? " is-active" : "")}
                aria-pressed={!settings.clear_clipboard_on_exit}
                onClick={() => void update({ clear_clipboard_on_exit: false })}
              >
                {t("common.off")}
              </button>
            </div>
          </div>

          <div className="kv-settings-row">
            <div className="kv-settings-row-text">
              <span className="kv-settings-row-label">{t("settings.concealOnBlurLabel")}</span>
              <span className="kv-settings-row-hint">{t("settings.concealOnBlurHint")}</span>
            </div>
            <div className="kv-settings-segmented" role="group" aria-label={t("settings.concealOnBlurLabel")}>
              <button
                type="button"
                className={"kv-settings-seg-btn" + (settings.conceal_on_blur ? " is-active" : "")}
                aria-pressed={settings.conceal_on_blur}
                onClick={() => void update({ conceal_on_blur: true })}
              >
                {t("common.on")}
              </button>
              <button
                type="button"
                className={"kv-settings-seg-btn" + (!settings.conceal_on_blur ? " is-active" : "")}
                aria-pressed={!settings.conceal_on_blur}
                onClick={() => void update({ conceal_on_blur: false })}
              >
                {t("common.off")}
              </button>
            </div>
          </div>

          <div className="kv-settings-row">
            <div className="kv-settings-row-text">
              <span className="kv-settings-row-label">{t("settings.concealSecondsLabel")}</span>
              <span className="kv-settings-row-hint">{t("settings.concealSecondsHint")}</span>
            </div>
            <span className="kv-settings-select-wrap">
              <select
                className="kv-settings-select"
                aria-label={t("settings.concealSecondsAriaLabel")}
                value={String(settings.conceal_seconds)}
                onChange={(e) => void update({ conceal_seconds: Number(e.target.value) })}
              >
                <option value="10">{t("settings.afterSeconds10")}</option>
                <option value="30">{t("settings.afterSeconds30")}</option>
                <option value="60">{t("settings.afterSeconds60")}</option>
                <option value="0">{t("common.never")}</option>
              </select>
            </span>
          </div>

          <div className="kv-settings-row">
            <div className="kv-settings-row-text">
              <span className="kv-settings-row-label">{t("settings.storageLabel")}</span>
              <span className="kv-settings-row-hint">
                {t(IS_MAC ? "settings.storageHintMac" : IS_WINDOWS ? "settings.storageHintWindows" : "settings.storageHintLinux")}
              </span>
            </div>
            {requiresKeyfile ? (
              <span className="kv-settings-row-hint">{t("settings.storageKeyfileUnsupported")}</span>
            ) : (
              <span className="kv-settings-select-wrap">
                <select
                  className="kv-settings-select"
                  aria-label={t("settings.storageLabel")}
                  value={pending ?? (confirmingOff ? "off" : mode)}
                  disabled={busy}
                  onChange={(e) => onSelectStorage(e.target.value as StorageMode)}
                >
                  <option value="off">{t("common.off")}</option>
                  <option value="password">{t("settings.storagePassword")}</option>
                  {available && <option value="touchid">{t("settings.storageTouchId")}</option>}
                </select>
              </span>
            )}
          </div>
          {confirmingOff && (
            <div
              style={{ display: "flex", justifyContent: "flex-end", gap: 8, padding: "10px 4px" }}
              data-confirming="true"
            >
              <button type="button" className="kv-btn is-ghost" onClick={() => setConfirmingOff(false)}>
                {t("common.cancel")}
              </button>
              <button
                type="button"
                className="kv-btn is-primary"
                onClick={() => {
                  setConfirmingOff(false);
                  void onConfirmOff();
                }}
              >
                {t("settings.storageOffConfirm")}
              </button>
            </div>
          )}
          {pending && (
            <form className="kv-settings-row" onSubmit={onPendingSubmit}>
              <div className="kv-settings-row-text" style={{ flex: 1 }}>
                <PasswordField
                  value={pw}
                  onChange={setPw}
                  placeholder={t("common.masterPasswordPlaceholder")}
                  autoComplete="current-password"
                  disabled={busy}
                  autoFocus
                />
              </div>
              <button
                type="button"
                className="kv-btn is-ghost"
                disabled={busy}
                onClick={() => {
                  setPending(null);
                  setPw("");
                  setError(null);
                }}
              >
                {t("common.cancel")}
              </button>
              <button type="submit" className="kv-btn is-primary" disabled={busy || !pw}>
                {t("common.save")}
              </button>
            </form>
          )}
          {error && (
            <p className="kv-settings-warn" role="alert">
              {error}
            </p>
          )}
          <p className="kv-settings-warn">{t(IS_MAC ? "settings.storageWarningMac" : "settings.storageWarning")}</p>

          <div className="kv-settings-row">
            <div className="kv-settings-row-text">
              <span className="kv-settings-row-label">{t("settings.masterPwLabel")}</span>
              <span className="kv-settings-row-hint">{t("settings.masterPwHint")}</span>
            </div>
            <button
              type="button"
              className="kv-btn is-ghost"
              onClick={() => (mpOpen ? onMpClose() : setMpOpen(true))}
              disabled={securityBusy}
            >
              {mpOpen ? t("common.cancel") : t("settings.masterPwChange")}
            </button>
          </div>

          {mpOpen && (
            <form onSubmit={onMpFormSubmit}>
              <div className="kv-settings-row">
                <div className="kv-settings-row-text" style={{ flex: 1 }}>
                  <PasswordField
                    value={mpCurPw}
                    onChange={setMpCurPw}
                    placeholder={t("settings.masterPwCurrent")}
                    autoComplete="current-password"
                    disabled={mpBusy}
                    autoFocus
                  />
                </div>
              </div>

              {requiresKeyfile && (
                <div className="kv-settings-row">
                  <div className="kv-settings-row-text" style={{ flex: 1 }}>
                    <span className="kv-settings-row-label">{t("settings.masterPwCurrentFile")}</span>
                    <KeyfileField
                      value={mpCurKeyfile}
                      onPick={() => void pickMpCurKeyfile()}
                      onClear={() => setMpCurKeyfile(null)}
                      disabled={mpBusy}
                    />
                  </div>
                </div>
              )}

              <div className="kv-settings-row">
                <div className="kv-settings-row-text" style={{ flex: 1 }}>
                  <PasswordField
                    value={mpNewPw}
                    onChange={setMpNewPw}
                    placeholder={t("settings.masterPwNew")}
                    autoComplete="new-password"
                    disabled={mpBusy}
                  />
                </div>
              </div>

              <div className="kv-settings-row">
                <div className="kv-settings-row-text" style={{ flex: 1 }}>
                  <PasswordField
                    value={mpNewPwConfirm}
                    onChange={setMpNewPwConfirm}
                    placeholder={t("settings.masterPwConfirm")}
                    autoComplete="new-password"
                    disabled={mpBusy}
                  />
                </div>
              </div>

              {mpError && (
                <p className="kv-settings-warn" role="alert">
                  {mpError}
                </p>
              )}

              <div className="kv-settings-row" style={{ justifyContent: "flex-end", gap: 10 }}>
                <button type="button" className="kv-btn is-ghost" onClick={onMpClose} disabled={mpBusy}>
                  {t("common.cancel")}
                </button>
                <button type="submit" className="kv-btn is-primary" disabled={mpBusy}>
                  {t("common.save")}
                </button>
              </div>
            </form>
          )}

          <div className="kv-settings-row kv-settings-hint-row">
            <div className="kv-settings-row-text">
              <span className="kv-settings-row-label">{t("settings.hintLabel")}</span>
              <span className="kv-settings-row-hint">
                {vaultHint ? vaultHint : t("settings.hintNone")}
              </span>
            </div>
            <button
              type="button"
              className="kv-btn is-ghost"
              onClick={() => (hintOpen ? onHintClose() : onHintOpen())}
              disabled={securityBusy}
            >
              {hintOpen ? t("common.cancel") : t("settings.hintEdit")}
            </button>
          </div>

          <p className="kv-settings-row-hint">{t("settings.hintWarning")}</p>

          {hintOpen && (
            <form onSubmit={onHintFormSubmit}>
              <div className="kv-settings-row">
                <div className="kv-settings-row-text" style={{ flex: 1 }}>
                  <input
                    className="kv-input"
                    value={hintDraft}
                    onChange={(e) => setHintDraft(e.target.value)}
                    placeholder={t("settings.hintPlaceholder")}
                    disabled={hintBusy}
                    autoFocus
                  />
                  <span className="kv-settings-row-hint">
                    {hintBytes + " / " + MAX_HINT_BYTES}
                  </span>
                </div>
              </div>

              {(hintTooLong || hintError) && (
                <p className="kv-settings-warn" role="alert">
                  {hintTooLong ? t("settings.hintErrTooLong", { max: String(MAX_HINT_BYTES) }) : hintError}
                </p>
              )}

              <div className="kv-settings-row" style={{ justifyContent: "flex-end", gap: 10 }}>
                <button
                  type="button"
                  className="kv-btn is-danger"
                  onClick={() => void saveHint("")}
                  disabled={hintBusy || !vaultHint}
                >
                  {t("settings.hintClear")}
                </button>
                <button type="button" className="kv-btn is-ghost" onClick={onHintClose} disabled={hintBusy}>
                  {t("common.cancel")}
                </button>
                <button
                  type="submit"
                  className="kv-btn is-primary"
                  disabled={hintBusy || hintTooLong}
                >
                  {t("common.save")}
                </button>
              </div>
            </form>
          )}

          <div className="kv-settings-row">
            <div className="kv-settings-row-text">
              <span className="kv-settings-row-label">{t("settings.keyfileLabel")}</span>
              <span className="kv-settings-row-hint">{t("settings.keyfileHint")}</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span className="kv-settings-row-hint">
                {requiresKeyfile ? t("settings.keyfileConfigured") : t("settings.keyfileNone")}
              </span>
              {!requiresKeyfile ? (
                <button
                  type="button"
                  className="kv-btn is-ghost"
                  onClick={() => onKfOpen("set")}
                  disabled={securityBusy}
                >
                  {t("settings.keyfileAdd")}
                </button>
              ) : (
                <>
                  <button
                    type="button"
                    className="kv-btn is-ghost"
                    onClick={() => onKfOpen("set")}
                    disabled={securityBusy}
                  >
                    {t("settings.keyfileReplace")}
                  </button>
                  <button
                    type="button"
                    className="kv-btn is-ghost"
                    onClick={() => onKfOpen("remove")}
                    disabled={securityBusy}
                  >
                    {t("settings.keyfileRemove")}
                  </button>
                </>
              )}
            </div>
          </div>

          {kfAction !== null && (
            <form onSubmit={onKfFormSubmit}>
              <div className="kv-settings-row">
                <div className="kv-settings-row-text" style={{ flex: 1 }}>
                  <PasswordField
                    value={kfCurPw}
                    onChange={setKfCurPw}
                    placeholder={t("settings.keyfileCurrentPassword")}
                    autoComplete="current-password"
                    disabled={kfBusy}
                    autoFocus
                  />
                </div>
              </div>

              {requiresKeyfile && (
                <div className="kv-settings-row">
                  <div className="kv-settings-row-text" style={{ flex: 1 }}>
                    <span className="kv-settings-row-label">{t("settings.keyfileCurrentFile")}</span>
                    <KeyfileField
                      value={kfCurKeyfile}
                      onPick={() => void pickKfCurKeyfile()}
                      onClear={() => setKfCurKeyfile(null)}
                      disabled={kfBusy}
                    />
                  </div>
                </div>
              )}

              {kfAction === "set" && (
                <div className="kv-settings-row">
                  <div className="kv-settings-row-text" style={{ flex: 1 }}>
                    <span className="kv-settings-row-label">{t("settings.keyfileNewFile")}</span>
                    <KeyfileField
                      value={kfNewKeyfile}
                      onPick={() => void pickKfNewKeyfile()}
                      onClear={() => setKfNewKeyfile(null)}
                      disabled={kfBusy}
                    />
                  </div>
                </div>
              )}

              <div className="kv-settings-row">
                <div className="kv-settings-row-text" style={{ flex: 1 }}>
                  <PasswordField
                    value={kfNewPw}
                    onChange={setKfNewPw}
                    placeholder={t("settings.keyfileNewPassword")}
                    autoComplete="new-password"
                    disabled={kfBusy}
                  />
                </div>
              </div>

              {kfNewPw && (
                <div className="kv-settings-row">
                  <div className="kv-settings-row-text" style={{ flex: 1 }}>
                    <PasswordField
                      value={kfNewPwConfirm}
                      onChange={setKfNewPwConfirm}
                      placeholder={t("settings.keyfileConfirmNewPassword")}
                      autoComplete="new-password"
                      disabled={kfBusy}
                    />
                  </div>
                </div>
              )}

              {kfError && (
                <p className="kv-settings-warn" role="alert">
                  {kfError}
                </p>
              )}

              <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, padding: "10px 4px" }}>
                <button type="button" className="kv-btn is-ghost" onClick={onKfCancel} disabled={kfBusy}>
                  {t("common.cancel")}
                </button>
                {kfAction === "remove" ? (
                  <button
                    type="submit"
                    className="kv-btn is-ghost is-danger"
                    data-confirming-kf={confirmingRemove ? "true" : undefined}
                    disabled={kfBusy}
                  >
                    {confirmingRemove ? t("settings.keyfileRemoveConfirm") : t("settings.keyfileRemove")}
                  </button>
                ) : (
                  <button type="submit" className="kv-btn is-primary" disabled={kfBusy}>
                    {t("common.save")}
                  </button>
                )}
              </div>
            </form>
          )}
        </section>
            )}

            {settingsTab === "privacy" && (
              <section className="kv-settings-section" aria-busy={hibpBusy}>
                <h2>{t("settings.hibpTitle")}</h2>
          <div className="kv-settings-row">
            <div className="kv-settings-row-text">
              <span className="kv-settings-row-label">{t("settings.hibpEnabledLabel")}</span>
              <span className="kv-settings-row-hint">{t("settings.hibpEnabledHint")}</span>
            </div>
            <div className="kv-settings-segmented" role="group" aria-label={t("settings.hibpEnabledLabel")}>
              <button
                type="button"
                className={"kv-settings-seg-btn" + (settings.hibp_enabled ? " is-active" : "")}
                aria-pressed={settings.hibp_enabled}
                disabled={hibpBusy}
                onClick={() => void onHibpToggle(true)}
              >
                {t("common.on")}
              </button>
              <button
                type="button"
                className={"kv-settings-seg-btn" + (!settings.hibp_enabled ? " is-active" : "")}
                aria-pressed={!settings.hibp_enabled}
                disabled={hibpBusy}
                onClick={() => void onHibpToggle(false)}
              >
                {t("common.off")}
              </button>
            </div>
          </div>
        </section>
            )}

            {settingsTab === "ai" && (
              <section className="kv-settings-section" aria-busy={aiBusy || aiModelBusy}>
                <h2>{t("settings.aiTitle")}</h2>

                <div className="kv-settings-row">
                  <div className="kv-settings-row-text">
                    <span className="kv-settings-row-label">{t("settings.aiEnabledLabel")}</span>
                    <span className="kv-settings-row-hint">
                      {t("settings.aiEnabledHint")}
                      {!aiModelPresent ? " " + t("settings.aiNeedsModel") : ""}
                    </span>
                  </div>
                  <div className="kv-settings-segmented" role="group" aria-label={t("settings.aiEnabledLabel")}>
                    <button
                      type="button"
                      className={"kv-settings-seg-btn" + (aiEnabled ? " is-active" : "")}
                      aria-pressed={aiEnabled}
                      disabled={aiBusy || aiModelBusy || !aiModelPresent}
                      onClick={() => void onAiToggle(true)}
                    >
                      {t("common.on")}
                    </button>
                    <button
                      type="button"
                      className={"kv-settings-seg-btn" + (!aiEnabled ? " is-active" : "")}
                      aria-pressed={!aiEnabled}
                      disabled={aiBusy}
                      onClick={() => void onAiToggle(false)}
                    >
                      {t("common.off")}
                    </button>
                  </div>
                </div>

                {aiErr && (
                  <p className="kv-settings-warn" role="alert">{aiErr}</p>
                )}

                <div className="kv-settings-row">
                  <div className="kv-settings-row-text">
                    <span className="kv-settings-row-label">{t("settings.aiModelLabel")}</span>
                    <span className="kv-settings-row-hint">{t("settings.aiModelPurpose")}</span>
                    <span className="kv-settings-row-hint">
                      {aiSt ? aiSt.model_id : "—"}
                      {aiSt ? " · " + t(aiSt.model_present ? "settings.aiModelInstalled" : "settings.aiModelMissing") : ""}
                    </span>
                  </div>
                  <button
                    type="button"
                    className="kv-btn is-ghost"
                    disabled={aiModelBusy || aiModelPresent}
                    onClick={() => void onModelDownload()}
                  >
                    {t("settings.aiModelDownload")}
                  </button>
                  {aiModelBusy && (
                    <button
                      type="button"
                      className="kv-btn is-ghost"
                      onClick={() => void onModelDownloadCancel()}
                    >
                      {t("common.cancel")}
                    </button>
                  )}
                </div>
                {aiModelBusy && aiModelProgress && aiModelProgress.total > 0 && (
                  <ProgressRow
                    label={t("settings.aiModelProgressAria")}
                    done={aiModelProgress.downloaded}
                    total={aiModelProgress.total}
                    detail={`${formatBytes(aiModelProgress.downloaded)} / ${formatBytes(aiModelProgress.total)}`}
                  />
                )}

                <div className="kv-settings-row">
                  <div className="kv-settings-row-text">
                    <span className="kv-settings-row-label">{t("settings.aiIndexLabel")}</span>
                    <span className="kv-settings-row-hint">{aiIdx ? aiIdx.indexed + " / " + aiIdx.total : "—"}</span>
                  </div>
                  <button
                    type="button"
                    className="kv-btn is-ghost"
                    disabled={aiBusy || !aiEnabled}
                    onClick={() => void onReindex()}
                  >
                    {aiBusy ? t("settings.aiReindexing") : t("settings.aiReindex")}
                  </button>
                </div>
                {aiBusy && aiIndexProgress && aiIndexProgress.total > 0 && (
                  <ProgressRow
                    label={t("settings.aiProgressAria")}
                    done={aiIndexProgress.done}
                    total={aiIndexProgress.total}
                    detail={`${aiIndexProgress.done} / ${aiIndexProgress.total}`}
                  />
                )}

                <div className="kv-settings-row">
                  <div className="kv-settings-row-text">
                    <span className="kv-settings-row-label">{t("settings.genModelLabel")}</span>
                    <span className="kv-settings-row-hint">{t("settings.genModelPurpose")}</span>
                    <span className="kv-settings-row-hint">
                      {genStatus?.present ? t("settings.genModelHintPresent") : t("settings.genModelHintMissing")}
                    </span>
                  </div>
                  <button
                    type="button"
                    className="kv-btn is-ghost"
                    disabled={genBusy || (genStatus?.present ?? false)}
                    onClick={() => void onGenDownload()}
                  >
                    {t("settings.genModelDownload")}
                  </button>
                  {genBusy && (
                    <button
                      type="button"
                      className="kv-btn is-ghost"
                      onClick={() => void onGenDownloadCancel()}
                    >
                      {t("common.cancel")}
                    </button>
                  )}
                </div>
                {genBusy && genProgress && genProgress.total > 0 && (
                  <ProgressRow
                    label={t("settings.genProgressAria")}
                    done={genProgress.downloaded}
                    total={genProgress.total}
                    detail={`${formatBytes(genProgress.downloaded)} / ${formatBytes(genProgress.total)}`}
                  />
                )}
                {genErr && <p className="kv-settings-warn" role="alert">{genErr}</p>}
              </section>
            )}

            {settingsTab === "browser" && (
              <section className="kv-settings-section" aria-busy={nmhBusy}>
                <h2>{t("settings.browserIntegration")}</h2>

          <div className="kv-settings-row">
            <div className="kv-settings-row-text">
              <span className="kv-settings-row-label">{t("settings.nmhEnabledLabel")}</span>
              <span className="kv-settings-row-hint">{t("settings.nmhEnabledHint")}</span>
            </div>
            <div className="kv-settings-segmented" role="group" aria-label={t("settings.nmhEnabledLabel")}>
              <button
                type="button"
                className={"kv-settings-seg-btn" + (nmhEnabled ? " is-active" : "")}
                aria-pressed={nmhEnabled}
                disabled={nmhBusy}
                onClick={() => void onNmhToggle(true)}
              >
                {t("common.on")}
              </button>
              <button
                type="button"
                className={"kv-settings-seg-btn" + (!nmhEnabled ? " is-active" : "")}
                aria-pressed={!nmhEnabled}
                disabled={nmhBusy}
                onClick={() => void onNmhToggle(false)}
              >
                {t("common.off")}
              </button>
            </div>
          </div>

          {nmhListenerDown && (
            <p className="kv-settings-warn" role="alert">
              {t("settings.nmhListenerDown")}
            </p>
          )}

          {nmhBrowserRows.map((row) => {
            const hasIds = row.idCount > 0;
            return (
              <div key={row.browser}>
                <div className="kv-settings-row">
                  <div className="kv-settings-row-text">
                    <span className="kv-settings-row-label">{row.label}</span>
                    <span className="kv-settings-row-hint">{row.hint}</span>
                  </div>
                  <div className="kv-nmh-row-controls">
                    <input
                      className="kv-input kv-nmh-id"
                      aria-label={row.label}
                      value={row.id}
                      onChange={(e) => row.setId(e.target.value)}
                      disabled={nmhBusy}
                      autoCapitalize="off"
                      autoCorrect="off"
                      spellCheck={false}
                    />
                    <span
                      className={"kv-nmh-dot" + (row.registered ? " is-on" : "")}
                      aria-hidden="true"
                    />
                    <span className="kv-settings-row-hint">
                      {row.registered ? t("settings.nmhRegistered") : t("settings.nmhNotRegistered")}
                    </span>
                    {(row.registered || hasIds) && (
                      <button
                        type="button"
                        className="kv-btn is-ghost"
                        disabled={nmhBusy}
                        onClick={() => void onNmhUninstall(row.browser)}
                      >
                        {t("settings.nmhRemove")}
                      </button>
                    )}
                    <button
                      type="button"
                      className="kv-btn is-primary"
                      disabled={nmhBusy || !row.id.trim() || !nmhSt?.host_path}
                      onClick={() => void onNmhInstall(row.browser)}
                    >
                      {t("settings.nmhInstall")}
                    </button>
                  </div>
                </div>
                {row.idCount > 1 && (
                  <div className="kv-settings-row">
                    <span className="kv-settings-row-hint">
                      {t("settings.nmhExtraIds", { count: row.idCount })}
                    </span>
                  </div>
                )}
              </div>
            );
          })}

          <div className="kv-settings-row">
            <span className="kv-settings-row-hint">
              {nmhSt?.host_path
                ? t("settings.nmhHostPath", { path: nmhSt.host_path })
                : t("settings.nmhHostMissing")}
            </span>
          </div>

          {nmhErr && (
            <p className="kv-settings-warn" role="alert">
              {nmhErr}
            </p>
          )}

          <div className="kv-settings-row">
            <div className="kv-settings-row-text">
              <span className="kv-settings-row-label">{t("settings.nmhConfirmModeLabel")}</span>
              <span className="kv-settings-row-hint">{t("settings.nmhConfirmModeHint")}</span>
            </div>
            <span className="kv-settings-select-wrap">
              <select
                className="kv-settings-select"
                aria-label={t("settings.nmhConfirmModeLabel")}
                value={settings.nmh_confirm_mode}
                onChange={(e) => void update({ nmh_confirm_mode: e.target.value })}
              >
                {NMH_CONFIRM_MODES.map((m) => (
                  <option key={m.value} value={m.value}>
                    {t(m.labelKey)}
                  </option>
                ))}
              </select>
            </span>
          </div>

          {settings.nmh_confirm_mode === "trust_extension" && (
            <p className="kv-settings-row-hint">{t("settings.nmhTrustWarning")}</p>
          )}

          {isSessionMode && (
            <div className="kv-settings-row">
              <div className="kv-settings-row-text">
                <span className="kv-settings-row-label">{t("settings.nmhSessionMinutesLabel")}</span>
                <span className="kv-settings-row-hint">{t("settings.nmhSessionMinutesHint")}</span>
              </div>
              <span className="kv-settings-select-wrap">
                <select
                  className="kv-settings-select"
                  aria-label={t("settings.nmhSessionMinutesLabel")}
                  value={String(settings.nmh_session_minutes)}
                  onChange={(e) => void update({ nmh_session_minutes: Number(e.target.value) })}
                >
                  <option value="1">{t("settings.nmhMinutes1")}</option>
                  <option value="5">{t("settings.nmhMinutes5")}</option>
                  <option value="15">{t("settings.nmhMinutes15")}</option>
                  <option value="60">{t("settings.nmhMinutes60")}</option>
                </select>
              </span>
            </div>
          )}

          {grantGroups.length > 0 && (
            <>
              <p className="kv-settings-row-label" style={{ marginTop: 8 }}>
                {t("settings.nmhGrantsTitle")}
              </p>
              {grantGroups.map((group) => (
                <div className="kv-nmh-grant-group" key={group.origin}>
                  <div className="kv-settings-row">
                    <div className="kv-settings-row-text">
                      <span className="kv-settings-row-label">
                        {group.browser === "chrome" ? "Chrome" : "Firefox"}
                      </span>
                      <span className="kv-settings-row-hint">{group.origin}</span>
                    </div>
                    <button
                      type="button"
                      className="kv-btn is-ghost"
                      disabled={nmhBusy}
                      onClick={() => void onGrantsForgetAll(group.origin)}
                    >
                      {t("settings.nmhGrantsForgetAll")}
                    </button>
                  </div>
                  {group.grants.map((g) => (
                    <div className="kv-settings-row" key={g.domain}>
                      <div className="kv-settings-row-text">
                        <span className="kv-settings-row-label">{g.domain}</span>
                        <span className="kv-settings-row-hint">
                          {t("settings.nmhGrantsAdded", { date: fmtGrantDate(g.created_at) })}
                          {g.last_used_at != null &&
                            " · " +
                              t("settings.nmhGrantsUsed", { date: fmtGrantDate(g.last_used_at) })}
                        </span>
                      </div>
                      <button
                        type="button"
                        className="kv-btn is-icon"
                        disabled={nmhBusy}
                        aria-label={t("settings.nmhGrantsForget", { domain: g.domain })}
                        onClick={() => void onGrantForget(g.origin, g.domain)}
                      >
                        ×
                      </button>
                    </div>
                  ))}
                </div>
              ))}
            </>
          )}
        </section>
            )}

            {settingsTab === "sync" && (
              <section className="kv-settings-section" aria-busy={syncBusy}>
                <h2>{t("sync.title")}</h2>
          <div className="kv-settings-row">
            <div className="kv-settings-row-text">
              <span className="kv-settings-row-label">{t("sync.target")}</span>
              <span className="kv-settings-row-hint">
                {syncSt?.kind === "gdrive" ? t("sync.gdriveHint") : t("sync.folderHint")}
              </span>
            </div>
            <span className="kv-settings-select-wrap">
              <select
                className="kv-settings-select"
                aria-label={t("sync.target")}
                disabled={syncBusy}
                value={syncSt?.kind ?? "none"}
                onChange={(e) => onTargetChange(e.target.value)}
              >
                <option value="none">{t("sync.none")}</option>
                <option value="folder">{t("sync.folder")}</option>
                <option value="gdrive">{t("sync.gdrive")}</option>
              </select>
            </span>
          </div>

          {syncSt?.kind === "gdrive" && (
            <div className="kv-settings-row">
              <div className="kv-settings-row-text">
                <span className="kv-settings-row-label">{t("sync.connected")}</span>
                <span className="kv-settings-row-hint">{t("sync.lastSync", { time: fmtLast(syncSt.last_sync) })}</span>
              </div>
              <button className="kv-btn is-danger" disabled={syncBusy} onClick={onGdriveDisconnect}>
                {t("sync.disconnect")}
              </button>
            </div>
          )}

          {syncSt?.kind === "gdrive" && (
            <div className="kv-settings-row">
              <div className="kv-settings-row-text">
                <span className="kv-settings-row-label">{t("sync.noteLabel")}</span>
                <span className="kv-settings-row-hint">{t("sync.noteHint")}</span>
              </div>
              <span className="kv-settings-note-controls">
                <input
                  className="kv-input"
                  type="text"
                  maxLength={80}
                  disabled={syncBusy}
                  placeholder={t("sync.notePlaceholder")}
                  value={noteDraft}
                  onChange={(e) => setNoteDraft(e.target.value)}
                />
                <button
                  className="kv-btn is-ghost"
                  disabled={syncBusy || noteDraft.trim() === (syncSt.note ?? "")}
                  onClick={onSaveNote}
                >
                  {t("common.save")}
                </button>
              </span>
            </div>
          )}

          {syncSt?.kind === "folder" && syncSt.not_synced_warning && (
            <p className="kv-settings-warn" role="alert">
              {t("sync.notSyncedWarn")}
            </p>
          )}
          {syncSt && syncSt.conflicts.length > 0 && (
            <p className="kv-settings-warn" role="alert">
              {t("sync.conflictWarn", { files: syncSt.conflicts.join(", ") })}
            </p>
          )}

          {syncSt && syncSt.kind !== "none" && (
            <div className="kv-settings-row">
              <div className="kv-settings-row-text">
                <span className="kv-settings-row-label">{t("sync.now")}</span>
                <span className="kv-settings-row-hint">{t("sync.lastSync", { time: fmtLast(syncSt.last_sync) })}</span>
              </div>
              <button className="kv-btn is-primary" disabled={syncBusy} onClick={onSyncNow}>
                {t("sync.now")}
              </button>
            </div>
          )}
          {syncMsg && (
            <p className="kv-settings-row-hint" role="status" style={{ marginTop: 8 }}>
              {syncMsg}
              {oauthWaiting && (
                <button
                  className="kv-btn is-ghost"
                  style={{ marginLeft: 8 }}
                  onClick={onCancelConnect}
                >
                  {t("common.cancel")}
                </button>
              )}
            </p>
          )}
        </section>
            )}

            {settingsTab === "general" && (
              <>
                <section className="kv-settings-section">
                  <h2>{t("settings.appearance")}</h2>
          <div className="kv-settings-row">
            <div className="kv-settings-row-text">
              <span className="kv-settings-row-label">{t("settings.densityLabel")}</span>
              <span className="kv-settings-row-hint">{t("settings.densityHint")}</span>
            </div>
            <div className="kv-settings-segmented" role="group" aria-label={t("settings.densityLabel")}>
              <button
                type="button"
                className={"kv-settings-seg-btn" + (settings.density === "comfortable" ? " is-active" : "")}
                aria-pressed={settings.density === "comfortable"}
                onClick={() => void update({ density: "comfortable" })}
              >
                {t("settings.densityComfortable")}
              </button>
              <button
                type="button"
                className={"kv-settings-seg-btn" + (settings.density === "compact" ? " is-active" : "")}
                aria-pressed={settings.density === "compact"}
                onClick={() => void update({ density: "compact" })}
              >
                {t("settings.densityCompact")}
              </button>
            </div>
          </div>
                </section>
                <section className="kv-settings-section">
                  <h2>{t("settings.language")}</h2>
          <div className="kv-settings-row">
            <div className="kv-settings-row-text">
              <span className="kv-settings-row-label">{t("settings.languageLabel")}</span>
              <span className="kv-settings-row-hint">{t("settings.languageHint")}</span>
            </div>
            <span className="kv-settings-select-wrap">
              <select
                className="kv-settings-select"
                aria-label={t("settings.language")}
                value={settings.lang}
                onChange={(e) => void update({ lang: e.target.value })}
              >
                <option value="en">English</option>
                <option value="uk">Українська</option>
                <option value="ru">Русский</option>
              </select>
            </span>
          </div>
                </section>
              </>
            )}

            {settingsTab === "data" && (
              <section className="kv-settings-section">
          <h2>{t("settings.data")}</h2>

          <div className="kv-settings-row">
            <div className="kv-settings-row-text">
              <span className="kv-settings-row-label">{t("settings.exportJsonLabel")}</span>
              <span className="kv-settings-row-hint">{t("settings.exportJsonHint")}</span>
            </div>
            {!exportWarnOpen && (
              <button type="button" className="kv-btn is-ghost" onClick={() => setExportWarnOpen(true)}>
                {t("settings.exportJsonBtn")}
              </button>
            )}
          </div>
          {exportWarnOpen && (
            <div className="kv-settings-confirm">
              <span className="kv-settings-warn">{t("settings.exportWarn", { count: entryCount })}</span>
              <button type="button" className="kv-btn is-ghost" onClick={() => setExportWarnOpen(false)}>
                {t("settings.cancel")}
              </button>
              <button type="button" className="kv-btn is-primary" onClick={() => void doExportJson()}>
                {t("settings.exportConfirm")}
              </button>
            </div>
          )}

          <div className="kv-settings-row">
            <div className="kv-settings-row-text">
              <span className="kv-settings-row-label">{t("settings.exportCopyLabel")}</span>
              <span className="kv-settings-row-hint">{t("settings.exportCopyHint")}</span>
            </div>
            <button type="button" className="kv-btn is-ghost" onClick={() => void doExportCopy()}>
              {t("settings.exportCopyBtn")}
            </button>
          </div>

          <div className="kv-settings-row">
            <div className="kv-settings-row-text">
              <span className="kv-settings-row-label">{t("settings.importJsonLabel")}</span>
              <span className="kv-settings-row-hint">{t("settings.importJsonHint")}</span>
            </div>
            <button type="button" className="kv-btn is-ghost" onClick={() => void doImport()}>
              {t("settings.importJsonBtn")}
            </button>
          </div>

          <div className="kv-settings-row">
            <div className="kv-settings-row-text">
              <span className="kv-settings-row-label">{t("settings.importKdbxLabel")}</span>
              <span className="kv-settings-row-hint">{t("settings.importKdbxHint")}</span>
            </div>
            <button type="button" className="kv-btn is-ghost" onClick={() => void doImportKdbx()}>
              {t("settings.importKdbxBtn")}
            </button>
          </div>

          <div className="kv-settings-row">
            <div className="kv-settings-row-text">
              <span className="kv-settings-row-label">{t("settings.textImportLabel")}</span>
              <span className="kv-settings-row-hint">
                {aiEnabled && genStatus?.present ? t("settings.textImportHint") : t("settings.textImportGateHint")}
              </span>
            </div>
            <div className="kv-settings-row-actions">
              <button
                type="button"
                className="kv-btn is-ghost"
                disabled={!aiEnabled || !genStatus?.present}
                onClick={() => void startTextImport()}
              >
                {t("settings.textImportBtn")}
              </button>
              <button
                type="button"
                className="kv-btn is-ghost"
                disabled={!aiEnabled || !genStatus?.present}
                onClick={() => void startFolderImport()}
              >
                {t("settings.folderImportBtn")}
              </button>
            </div>
          </div>

          {dataMsg && (
            <p className="kv-settings-row-hint" role="status" style={{ marginTop: 8 }}>
              {dataMsg}
            </p>
          )}
        </section>
            )}

            {settingsTab === "security" && (
              <section className="kv-settings-section">
                <h2>{t("audit.title")}</h2>
          <p className="kv-settings-row-hint" style={{ marginBottom: 8 }}>
            {t("audit.hint")}
          </p>
          {auditEntries.length === 0 ? (
            <div className="kv-settings-row">
              <span className="kv-settings-row-hint">{t("audit.empty")}</span>
            </div>
          ) : (
            <>
              <ul className="kv-audit-log">
                {auditEntries.map((e, i) => (
                  <li className="kv-audit-row" key={i}>
                    <span className="kv-audit-event">
                      {AUDIT_EVENTS.has(e.event) ? t("audit." + e.event) : e.event}
                    </span>
                    {e.detail && <span className="kv-audit-detail">{e.detail}</span>}
                    <span className="kv-audit-date">
                      {new Intl.DateTimeFormat(lang, { dateStyle: "medium", timeStyle: "short" }).format(
                        new Date(e.created_at * 1000),
                      )}
                    </span>
                  </li>
                ))}
              </ul>
              <div className="kv-settings-row" style={{ justifyContent: "flex-end" }}>
                <button
                  type="button"
                  className="kv-btn is-danger"
                  data-confirming-audit={confirmingClearAudit ? "true" : undefined}
                  onClick={onClearAudit}
                >
                  {confirmingClearAudit ? t("audit.clearConfirm") : t("audit.clear")}
                </button>
              </div>
            </>
          )}
        </section>
            )}

            {settingsTab === "templates" && <ManageFieldTemplates embedded />}
            {settingsTab === "health" && <PasswordHealth embedded />}

            {settingsTab === "about" && (
              <section className="kv-settings-section">
                <h2>{t("settings.tabAbout")}</h2>
                {version && (
                  <div className="kv-settings-row">
                    <div className="kv-settings-row-text">
                      <span className="kv-settings-row-label">{t("settings.aboutVersion", { version })}</span>
                      <span className="kv-settings-row-hint">{t("settings.aboutLicense")}</span>
                    </div>
                  </div>
                )}
                {settings.onboarding_eligible && (
                  <div className="kv-settings-row">
                    <div className="kv-settings-row-text">
                      <span className="kv-settings-row-label">{t("settings.aboutGettingStarted")}</span>
                    </div>
                    <button
                      type="button"
                      className="kv-btn is-ghost"
                      onClick={() => {
                        void update({ onboarding_dismissed: false, onboarding_collapsed: false });
                        // The card renders only in the detail panel's
                        // no-selection state, so restoring it has to clear the
                        // selection too.
                        select(null);
                        setRoute("main");
                      }}
                    >
                      {t("settings.aboutShowGettingStarted")}
                    </button>
                  </div>
                )}
              </section>
            )}
          </div>
        </div>
      </div>

      {kdbxPath && (
        <div
          className="kv-modal-scrim"
          role="presentation"
          onMouseDown={() => {
            if (!kdbxBusy) {
              setKdbxPath(null);
              setKdbxPassword("");
            }
          }}
        >
          <form
            className="kv-modal kv-kdbx-modal"
            role="dialog"
            aria-modal="true"
            onMouseDown={(e) => e.stopPropagation()}
            onSubmit={(e) => {
              e.preventDefault();
              void confirmImportKdbx();
            }}
          >
            <div className="kv-modal-header">
              <h2>{t("settings.kdbxModalTitle")}</h2>
            </div>
            <div className="kv-modal-body">
              <p className="kv-settings-row-hint">{t("settings.kdbxModalHint")}</p>
              <PasswordField
                value={kdbxPassword}
                onChange={setKdbxPassword}
                placeholder={t("settings.kdbxModalPlaceholder")}
                autoComplete="current-password"
                disabled={kdbxBusy}
                autoFocus
              />
              {kdbxErr && (
                <p className="kv-settings-warn" role="alert">
                  {kdbxErr}
                </p>
              )}
            </div>
            <div className="kv-modal-footer">
              <button
                type="button"
                className="kv-btn is-ghost"
                onClick={() => {
                  setKdbxPath(null);
                  setKdbxPassword("");
                }}
                disabled={kdbxBusy}
              >
                {t("common.cancel")}
              </button>
              <button type="submit" className="kv-btn is-primary" disabled={kdbxBusy}>
                {kdbxBusy ? t("settings.kdbxImporting") : t("settings.kdbxImportConfirm")}
              </button>
            </div>
          </form>
        </div>
      )}

    </main>
  );
}
