import { useEffect } from "react";
import { useT } from "../state/LangContext";
import type { TextImportReport } from "../ipc/types";
import "./TextImportReview.css";

export function ImportDoneToast({ report, onDismiss }: { report: TextImportReport; onDismiss: () => void }) {
  const t = useT();
  useEffect(() => {
    const id = window.setTimeout(onDismiss, 4000);
    return () => window.clearTimeout(id);
  }, [report, onDismiss]);
  const msg =
    report.failed > 0
      ? t("textImport.donePartial", { imported: report.imported, failed: report.failed })
      : t("textImport.done", { imported: report.imported });
  return (
    <div className="kv-import-toast" role="status">
      <span className="kv-import-toast-msg">{msg}</span>
      <button type="button" className="kv-btn is-ghost kv-import-toast-x" onClick={onDismiss} aria-label={t("common.cancel")}>
        ✕
      </button>
    </div>
  );
}
