import { useState } from "react";
import { useT } from "../state/LangContext";
import { UnlockForm } from "../components/UnlockForm";
import { takeImportInterrupted } from "../lib/importInterrupted";
import kokosLogo from "../assets/kokos-logo.png";
import "./Lock.css";

export function TabLock({ path }: { path: string }) {
  const t = useT();
  const [importInterrupted] = useState(() => takeImportInterrupted(path));

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
      <UnlockForm path={path} />
    </div>
  );
}
