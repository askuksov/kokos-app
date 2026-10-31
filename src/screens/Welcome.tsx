import { useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { homeDir } from "@tauri-apps/api/path";
import {
  biometricAvailable,
  biometricHas,
  createVault,
  getVaultHeaderInfo,
  keychainHas,
  keychainUnlock,
  openVault,
  pickAnyFile,
  pickVaultPath,
  recentFiles,
  takePendingOpen,
  touchidUnlock,
} from "../ipc/commands";
import { MAX_HINT_BYTES, type RecentFile } from "../ipc/types";
import { useVault } from "../state/VaultContext";
import { useTabs } from "../state/TabsContext";
import { useT } from "../state/LangContext";
import { PasswordField } from "../components/PasswordField";
import { fileBasename, tildify } from "../lib/format";
import { errorMessage } from "../lib/errors";
import kokosLogo from "../assets/kokos-logo.png";
import "./Welcome.css";

const DEFAULT_KDF = { memory_kib: 65536, time_cost: 3, parallelism: 4 };

type Pending = { kind: "open" | "create"; path: string };

type WelcomeIcon = "plus" | "folder" | "clock" | "chevron" | "lock" | "note" | "shield" | "cloud";

const ICON_PATHS: Record<WelcomeIcon, React.ReactNode> = {
  plus: <path d="M12 5.5v13M5.5 12h13" />,
  folder: <path d="M3.5 7a2 2 0 012-2h4l2 2.2h7a2 2 0 012 2V17a2 2 0 01-2 2h-13a2 2 0 01-2-2V7z" />,
  clock: (
    <g>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 7.5V12l3.5 2" />
    </g>
  ),
  chevron: <path d="M9.5 6.5l5.5 5.5-5.5 5.5" />,
  lock: (
    <g>
      <rect x="5" y="10.5" width="14" height="9.5" rx="2" />
      <path d="M8.5 10.5V7.5a3.5 3.5 0 017 0v3" />
    </g>
  ),
  note: (
    <g>
      <path d="M5 4.5h14v11l-4 4H5v-15z" />
      <path d="M15 19.5v-4h4" />
    </g>
  ),
  shield: <path d="M12 3l7.5 2.8v5.7c0 4.3-2.9 7.3-7.5 9-4.6-1.7-7.5-4.7-7.5-9V5.8L12 3z" />,
  cloud: <path d="M7 18.5a4.2 4.2 0 01-.6-8.35 5.3 5.3 0 0110.3-1.9A4.6 4.6 0 0117.2 18.5H7z" />,
};

const VAULT_EXT = ".kokos";
const LEGACY_VAULT_EXT = ".vault";
function recentVaultName(path: string): string {
  const last = path.split(/[\\/]/).pop();
  const base = last && last.length > 0 ? last : path;
  const ext = base.endsWith(VAULT_EXT)
    ? VAULT_EXT
    : base.endsWith(LEGACY_VAULT_EXT)
      ? LEGACY_VAULT_EXT
      : null;
  return ext && base.length > ext.length ? base.slice(0, -ext.length) : base;
}

function Icon({
  name,
  size = 15,
  strokeWidth = 1.7,
  className,
}: {
  name: WelcomeIcon;
  size?: number;
  strokeWidth?: number;
  className?: string;
}) {
  return (
    <svg
      className={className}
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

export function WelcomeScreen() {
  const t = useT();
  const { refreshStatus } = useVault();
  const { addIntent, clearAddIntent } = useTabs();
  const [pending, setPending] = useState<Pending | null>(null);
  const [password, setPassword] = useState("");
  const [hint, setHint] = useState("");
  const [createKeyfile, setCreateKeyfile] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recents, setRecents] = useState<RecentFile[]>([]);
  const [home, setHome] = useState<string | null>(null);
  const [openHint, setOpenHint] = useState<string | null>(null);
  const [openRequiresKeyfile, setOpenRequiresKeyfile] = useState(false);
  const [openKeyfile, setOpenKeyfile] = useState<string | null>(null);
  const [pendingHasSaved, setPendingHasSaved] = useState(false);
  const [pendingHasBiometric, setPendingHasBiometric] = useState(false);
  const openedRef = useRef(false);
  useEffect(() => {
    recentFiles().then(setRecents).catch(() => {});
  }, []);
  useEffect(() => {
    homeDir().then(setHome).catch(() => setHome(null));
  }, []);

  useEffect(() => {
    if (pending?.kind !== "open") {
      setOpenHint(null);
      setOpenRequiresKeyfile(false);
      return;
    }
    let ignore = false;
    getVaultHeaderInfo(pending.path)
      .then((h) => {
        if (ignore) return;
        setOpenHint(h.hint || null);
        setOpenRequiresKeyfile(h.requires_keyfile);
      })
      .catch((err) => {
        if (ignore) return;
        setOpenHint(null);
        setOpenRequiresKeyfile(false);
        // Surface the refusal now (e.g. a hidden folder under snap) instead of
        // after the user has typed the master password.
        setError(errorMessage(err, t));
      });
    return () => {
      ignore = true;
    };
  }, [pending?.kind, pending?.path]);

  useEffect(() => {
    if (pending?.kind !== "open") {
      setPendingHasSaved(false);
      return;
    }
    let ignore = false;
    keychainHas(pending.path)
      .then((h) => {
        if (!ignore) setPendingHasSaved(h);
      })
      .catch(() => {
        if (!ignore) setPendingHasSaved(false);
      });
    return () => {
      ignore = true;
    };
  }, [pending?.kind, pending?.path]);

  useEffect(() => {
    if (pending?.kind !== "open") {
      setPendingHasBiometric(false);
      return;
    }
    let ignore = false;
    Promise.all([biometricAvailable(), biometricHas(pending.path)])
      .then(([available, has]) => {
        if (!ignore) setPendingHasBiometric(available && has);
      })
      .catch(() => {
        if (!ignore) setPendingHasBiometric(false);
      });
    return () => {
      ignore = true;
    };
  }, [pending?.kind, pending?.path]);

  function reset() {
    setPending(null);
    setPassword("");
    setHint("");
    setCreateKeyfile(null);
    setOpenKeyfile(null);
    setError(null);
  }

  async function pick(kind: "open" | "create") {
    setError(null);
    const path = await pickVaultPath(kind === "open" ? "open" : "save");
    if (!path) return;
    setPassword("");
    setHint("");
    setCreateKeyfile(null);
    setOpenKeyfile(null);
    setPending({ kind, path });
  }

  useEffect(() => {
    if (!addIntent) {
      openedRef.current = false;
      return;
    }
    if (openedRef.current) return;
    openedRef.current = true;
    const intent = addIntent;
    clearAddIntent();
    void pick(intent);
  }, [addIntent, clearAddIntent]);

  function openRecent(path: string) {
    setError(null);
    setPassword("");
    setHint("");
    setCreateKeyfile(null);
    setOpenKeyfile(null);
    setPending({ kind: "open", path });
  }

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    takePendingOpen().then((p) => {
      if (!cancelled && p) openRecent(p);
    });
    listen<string>("open-file-request", (e) => {
      openRecent(e.payload);
      void takePendingOpen();
    }).then((u) => {
      if (cancelled) u();
      else unlisten = u;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  async function pickCreateKeyfile() {
    const p = await pickAnyFile();
    if (p) setCreateKeyfile(p);
  }

  async function pickOpenKeyfile() {
    const p = await pickAnyFile();
    if (p) setOpenKeyfile(p);
  }

  async function onFastUnlock() {
    if (pending?.kind !== "open") return;
    setError(null);
    setBusy(true);
    try {
      await keychainUnlock(pending.path);
      await refreshStatus();
    } catch (err) {
      setPendingHasSaved(false);
      setError(errorMessage(err, t));
    } finally {
      setBusy(false);
    }
  }

  async function onTouchIdUnlock() {
    if (pending?.kind !== "open") return;
    setError(null);
    setBusy(true);
    try {
      await touchidUnlock(pending.path);
      await refreshStatus();
    } catch (err) {
      setError(errorMessage(err, t));
    } finally {
      setBusy(false);
    }
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!pending || !password) return;
    setError(null);
    setBusy(true);
    try {
      if (pending.kind === "open") {
        await openVault(pending.path, password, openKeyfile);
      } else {
        if (new TextEncoder().encode(hint).length > MAX_HINT_BYTES) {
          setError(t("settings.hintErrTooLong", { max: String(MAX_HINT_BYTES) }));
          return;
        }
        await createVault(pending.path, password, hint, DEFAULT_KDF, createKeyfile);
      }
      await refreshStatus();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="kv-onboard">
      <div className="kv-onboard-bar kv-titlebar" data-tauri-drag-region />
      <div className="kv-onboard-body">
        <div className="kv-onboard-glow" aria-hidden="true" />
        <div className="kv-onboard-card">
          <div className="kv-logomark">
            <img className="kv-logomark-img" src={kokosLogo} alt={t("welcome.logoAlt")} />
          </div>
          <div className="kv-onboard-head">
            <h1>Kokos</h1>
            <p className="kv-onboard-tag">{t("welcome.tagline")}</p>
          </div>

          {pending ? (
            <>
              {pending.kind === "open" && pendingHasBiometric && !openRequiresKeyfile && (
                <button
                  type="button"
                  className="kv-btn is-primary is-lg is-block"
                  onClick={onTouchIdUnlock}
                  disabled={busy}
                >
                  {t("common.unlockTouchId")}
                </button>
              )}
              {pending.kind === "open" && pendingHasSaved && !openRequiresKeyfile && (
                <button
                  type="button"
                  className={`kv-btn is-lg is-block ${pendingHasBiometric ? "is-ghost" : "is-primary"}`}
                  onClick={onFastUnlock}
                  disabled={busy}
                >
                  {t("common.unlockSavedPassword")}
                </button>
              )}
              {pending.kind === "open" && openHint && (
                <p className="kv-onboard-hint">{t("common.hint", { hint: openHint })}</p>
              )}
              {pending.kind === "open" && openRequiresKeyfile && (
                <p className="kv-onboard-hint">{t("welcome.needsKeyfile")}</p>
              )}
              <form className="kv-onboard-actions" onSubmit={onSubmit}>
                <div className={`kv-onboard-field${error ? " has-error" : ""}`}>
                  <span className="kv-onboard-field-ico">
                    <Icon name="lock" />
                  </span>
                  <PasswordField
                    value={password}
                    onChange={setPassword}
                    placeholder={
                      pending.kind === "create"
                        ? t("welcome.newMasterPasswordPlaceholder")
                        : t("common.masterPasswordPlaceholder")
                    }
                    autoFocus
                    autoComplete={pending.kind === "create" ? "new-password" : "current-password"}
                    disabled={busy}
                  />
                </div>
                {pending.kind === "open" && openRequiresKeyfile && (
                  <div className="kv-onboard-field">
                    {openKeyfile === null ? (
                      <button
                        type="button"
                        className="kv-btn is-lg is-block"
                        onClick={pickOpenKeyfile}
                        disabled={busy}
                      >
                        {t("common.chooseKeyfile")}
                      </button>
                    ) : (
                      <>
                        <input
                          className="kv-input"
                          style={{ paddingLeft: 12 }}
                          value={fileBasename(openKeyfile)}
                          title={openKeyfile}
                          readOnly
                          disabled={busy}
                          autoCapitalize="off"
                          autoCorrect="off"
                          spellCheck={false}
                        />
                        <button
                          type="button"
                          className="kv-linkbtn"
                          style={{ marginRight: 6 }}
                          onClick={() => setOpenKeyfile(null)}
                          disabled={busy}
                        >
                          {t("common.clear")}
                        </button>
                      </>
                    )}
                  </div>
                )}
                {pending.kind === "create" && (
                  <div className="kv-onboard-field">
                    <span className="kv-onboard-field-ico">
                      <Icon name="note" />
                    </span>
                    <input
                      className="kv-input"
                      value={hint}
                      onChange={(e) => setHint(e.target.value)}
                      placeholder={t("welcome.hintPlaceholder")}
                      disabled={busy}
                      autoCapitalize="off"
                      autoCorrect="off"
                      spellCheck={false}
                    />
                  </div>
                )}
                {pending.kind === "create" && (
                  <div className="kv-onboard-field">
                    {createKeyfile === null ? (
                      <button
                        type="button"
                        className="kv-btn is-lg is-block"
                        onClick={pickCreateKeyfile}
                        disabled={busy}
                      >
                        {t("welcome.addKeyfile")}
                      </button>
                    ) : (
                      <>
                        <input
                          className="kv-input"
                          style={{ paddingLeft: 12 }}
                          value={fileBasename(createKeyfile)}
                          title={createKeyfile}
                          readOnly
                          disabled={busy}
                          autoCapitalize="off"
                          autoCorrect="off"
                          spellCheck={false}
                        />
                        <button
                          type="button"
                          className="kv-linkbtn"
                          style={{ marginRight: 6 }}
                          onClick={() => setCreateKeyfile(null)}
                          disabled={busy}
                        >
                          {t("common.clear")}
                        </button>
                      </>
                    )}
                  </div>
                )}
                {error && <p className="kv-onboard-error">{error}</p>}
                <button
                  type="submit"
                  className={`kv-btn is-lg is-block ${pending.kind === "open" && (pendingHasBiometric || pendingHasSaved) ? "is-ghost" : "is-primary"}`}
                  disabled={busy || !password}
                >
                  {pending.kind === "create" ? t("welcome.createVaultSubmit") : t("welcome.openVaultSubmit")}
                </button>
              </form>
              <div className="kv-onboard-links">
                <button type="button" className="kv-linkbtn" onClick={reset} disabled={busy}>
                  {t("common.cancel")}
                </button>
              </div>
            </>
          ) : (
            <>
              <div className="kv-onboard-actions">
                <button
                  type="button"
                  className="kv-btn is-primary is-lg is-block"
                  disabled={busy}
                  onClick={() => pick("create")}
                >
                  <Icon name="plus" />
                  {t("welcome.createNewVault")}
                </button>
                <button
                  type="button"
                  className="kv-btn is-ghost is-lg is-block"
                  disabled={busy}
                  onClick={() => pick("open")}
                >
                  <Icon name="folder" />
                  {t("welcome.openExistingVault")}
                </button>
              </div>
              <div className="kv-recent-list">
                {recents.map((rv) => (
                  <button
                    key={rv.path}
                    type="button"
                    className="kv-recent-vault"
                    disabled={busy}
                    title={rv.path}
                    onClick={() => openRecent(rv.path)}
                  >
                    <span className="kv-recent-ico">
                      <Icon name="clock" />
                    </span>
                    <span className="kv-recent-body">
                      <span className="kv-recent-name">{recentVaultName(rv.path)}</span>
                      <span className="kv-recent-path">{tildify(rv.path, home)}</span>
                    </span>
                    <span className="kv-recent-go">
                      <Icon name="chevron" />
                    </span>
                  </button>
                ))}
              </div>
            </>
          )}
        </div>
        <div className="kv-onboard-foot">
          <span>
            <Icon name="shield" size={13} />
            {t("welcome.e2ee")}
          </span>
          <span className="dot">·</span>
          <span>{t("welcome.offlineFirst")}</span>
          <span className="dot">·</span>
          <span>{t("welcome.openFormat")}</span>
        </div>
      </div>
    </div>
  );
}
