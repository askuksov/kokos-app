import { relTime, type SyncView } from "../lib/syncView";
import { useT } from "../state/LangContext";
import "./SyncStatusPopover.css";

export function SyncStatusPopover({
  view,
  busy,
  onSyncNow,
  onOpenSyncSettings,
}: {
  view: SyncView;
  busy: boolean;
  onSyncNow: () => void;
  onOpenSyncSettings: () => void;
}) {
  const t = useT();

  return (
    <div className="kv-sync-pop" role="dialog" aria-label={t("sync.title")}>
      {view.providers.length === 0 ? (
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
                relLabel = new Date(rel.iso).toLocaleDateString();
                break;
            }
          }
          return (
            <div className="kv-sync-pop-line" key={p.id}>
              <span>{t(p.labelKey)}</span>
              <span> • </span>
              <span className={p.warning ? "kv-sync-pop-warn" : undefined}>
                {p.warning ? t("sync.needsAttention") : t("sync.state.synced")}
              </span>
              {relLabel !== null ? <span> · {relLabel}</span> : null}
            </div>
          );
        })
      )}
      <div className="kv-sync-pop-divider" />
      <button
        className="kv-btn is-primary is-block"
        autoFocus
        disabled={busy || !view.configured}
        onClick={onSyncNow}
      >
        {t("sync.now")}
      </button>
      <button className="kv-btn is-ghost is-block" onClick={onOpenSyncSettings}>
        {t("sync.settings")}
      </button>
    </div>
  );
}
