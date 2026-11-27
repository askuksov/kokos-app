import { formatDate } from "../lib/format";
import { relTime, type SyncView } from "../lib/syncView";
import { useT } from "../state/LangContext";
import "./SyncStatusPopover.css";

export function SyncStatusPopover({
  view,
  busy,
  onSyncNow,
  onRetry,
  onOpenSyncSettings,
}: {
  view: SyncView;
  busy: boolean;
  onSyncNow: () => void;
  onRetry: () => void;
  onOpenSyncSettings: () => void;
}) {
  const t = useT();

  return (
    <div className="kv-sync-pop" role="dialog" aria-label={t("sync.title")}>
      {view.readFailed ? (
        <div className="kv-sync-pop-line kv-sync-pop-warn" role="alert">
          {t("sync.readFailed")}
        </div>
      ) : null}
      {view.readFailed && view.providers.length === 0 ? null : view.providers.length === 0 ? (
        <div className="kv-sync-pop-line kv-sync-pop-muted">{t("sync.notConfigured")}</div>
      ) : (
        view.providers.map((p) => {
          const rel = relTime(p.lastSync, Date.now());
          let relLabel: string | null = null;
          if (rel !== null) {
            switch (rel.kind) {
              case "now":
                relLabel = t("sync.rel.now");
                break;
              case "min":
                relLabel = t("sync.rel.min", { n: rel.value });
                break;
              case "hour":
                relLabel = t("sync.rel.hour", { n: rel.value });
                break;
              case "day":
                relLabel = t("sync.rel.day", { n: rel.value });
                break;
              case "date":
                relLabel = formatDate(rel.iso);
                break;
            }
          }
          return (
            <div className="kv-sync-pop-line" key={p.id}>
              <span>{t(p.labelKey)}</span>
              <span> • </span>
              <span className={p.warning ? "kv-sync-pop-warn" : undefined}>
                {p.warning
                  ? t("sync.needsAttention")
                  : p.pending
                    ? t("sync.state.pending")
                    : t("sync.state.synced")}
              </span>
              {relLabel !== null ? <span> · {relLabel}</span> : null}
            </div>
          );
        })
      )}
      <div className="kv-sync-pop-divider" />
      {view.readFailed && !view.configured ? (
        <button className="kv-btn is-primary is-block" autoFocus onClick={onRetry}>
          {t("sync.retry")}
        </button>
      ) : (
        <button
          className="kv-btn is-primary is-block"
          autoFocus
          disabled={busy || !view.configured}
          onClick={onSyncNow}
        >
          {t("sync.now")}
        </button>
      )}
      <button className="kv-btn is-ghost is-block" onClick={onOpenSyncSettings}>
        {t("sync.settings")}
      </button>
    </div>
  );
}
