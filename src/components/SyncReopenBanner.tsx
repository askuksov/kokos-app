import { useT } from "../state/LangContext";
import "./SyncReopenBanner.css";

function CloseIcon() {
  return (
    <svg
      width={14}
      height={14}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.7}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M6 6l12 12M18 6L6 18" />
    </svg>
  );
}

export function SyncReopenBanner({
  onReopen,
  onDismiss,
  busy,
}: {
  onReopen: () => void;
  onDismiss: () => void;
  busy: boolean;
}) {
  const t = useT();
  return (
    <div className="kv-reopen-banner" role="status">
      <span>{t("sync.remoteNewer")}</span>
      <div className="kv-reopen-banner-actions">
        <button type="button" className="kv-btn is-primary" onClick={onReopen} disabled={busy}>
          {t("sync.remoteNewerReopen")}
        </button>
        <button
          type="button"
          className="kv-btn is-icon"
          onClick={onDismiss}
          disabled={busy}
          aria-label={t("sync.remoteNewerDismiss")}
          title={t("sync.remoteNewerDismiss")}
        >
          <CloseIcon />
        </button>
      </div>
    </div>
  );
}
