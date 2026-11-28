import { useState } from "react";
import { useT } from "../state/LangContext";
import { useTabs } from "../state/TabsContext";
import { UnlockForm } from "../components/UnlockForm";
import { takeImportInterrupted } from "../lib/importInterrupted";
import kokosLogo from "../assets/kokos-logo.png";
import "./Lock.css";

export function TabLock({ path }: { path: string }) {
  const t = useT();
  const { closeTab } = useTabs();
  const [importInterrupted] = useState(() => takeImportInterrupted(path));
  // The vault file is gone (deleted, moved, volume not mounted): a password
  // prompt could never succeed, so offer to close the tab or look again.
  const [missing, setMissing] = useState(false);
  // Bumped by "Check again" to remount the form, which re-probes the file.
  const [probe, setProbe] = useState(0);

  if (missing) {
    return (
      <div className="kv-lock">
        <div className="kv-lock-logo">
          <img className="kv-lock-logo-img" src={kokosLogo} alt={t("lock.title")} />
        </div>
        <div className="kv-lock-head" role="alert">
          <h2>{t("welcome.missingTitle")}</h2>
          <p className="kv-lock-path" title={path}>
            {path}
          </p>
        </div>
        <p className="kv-lock-hint">{t("welcome.missingBody")}</p>
        <button
          type="button"
          className="kv-btn is-primary is-lg is-block"
          onClick={() => void closeTab(path)}
          autoFocus
        >
          {t("lock.closeTab")}
        </button>
        <button
          type="button"
          className="kv-btn is-ghost is-lg is-block"
          onClick={() => {
            setMissing(false);
            setProbe((n) => n + 1);
          }}
        >
          {t("lock.checkAgain")}
        </button>
      </div>
    );
  }

  return (
    <div className="kv-lock">
      <div className="kv-lock-logo">
        <img className="kv-lock-logo-img" src={kokosLogo} alt={t("lock.title")} />
      </div>
      <div className="kv-lock-head">
        <h2>{t("lock.title")}</h2>
        <p>{t("lock.subtitle")}</p>
      </div>
      {importInterrupted && (
        <p className="kv-lock-hint" role="status">
          {t(importInterrupted === "saved" ? "textImport.lockedSaved" : "textImport.interruptedByLock")}
        </p>
      )}
      <UnlockForm key={probe} path={path} onMissing={() => setMissing(true)} />
    </div>
  );
}
