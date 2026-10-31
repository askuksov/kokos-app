import { useCallback, useEffect, useState } from "react";
import { useVault } from "../state/VaultContext";
import { useT, useTn } from "../state/LangContext";
import { healthScan, hibpCheck } from "../ipc/commands";
import type { HealthReport, HibpReport } from "../ipc/types";
import { useSettings } from "../state/SettingsContext";
import "./PasswordHealth.css";

const CHEVRON_LEFT = "M15 18l-6-6 6-6";

export function PasswordHealth({ embedded }: { embedded?: boolean }) {
  const { setRoute } = useVault();
  const t = useT();
  const tn = useTn();
  const [report, setReport] = useState<HealthReport | null>(null);
  const { settings } = useSettings();
  const [hibp, setHibp] = useState<HibpReport | null>(null);
  const [hibpLoading, setHibpLoading] = useState(false);

  const runHibp = useCallback(async () => {
    setHibpLoading(true);
    try {
      setHibp(await hibpCheck());
    } catch (e) {
      console.error("hibp_check failed:", e);
      setHibp({ compromised: [], checked: false, offline: true, enabled: settings.hibp_enabled });
    } finally {
      setHibpLoading(false);
    }
  }, [settings.hibp_enabled]);

  useEffect(() => {
    if (settings.hibp_enabled) void runHibp();
  }, [settings.hibp_enabled, runHibp]);

  const load = useCallback(async () => {
    try {
      setReport(await healthScan());
    } catch (e) {
      console.error("health_scan failed:", e);
      setReport({ weak: [], reused: [] });
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const weak = report?.weak ?? [];
  const reused = report?.reused ?? [];

  const body = (
    <>
      <p className="kv-settings-sub">{t("health.subtitle")}</p>

      <h2 className="kv-health-section">{t("health.weakTitle")}</h2>
      {weak.length === 0 ? (
        <div className="kv-card">
          <p className="kv-health-empty">{t("health.weakEmpty")}</p>
        </div>
      ) : (
        <div className="kv-card">
          {weak.map((w, i) => (
            <div className="kv-manage-row kv-health-row" key={`${w.entry_id}:${w.field_name}:${i}`}>
              <div className="kv-health-row-main">
                <span className="kv-health-title">{w.title}</span>
                <span className="kv-health-meta">{w.field_name}</span>
              </div>
              <span className="kv-health-badge is-weak">{t("strength." + w.strength)}</span>
            </div>
          ))}
        </div>
      )}

      <h2 className="kv-health-section">{t("health.reusedTitle")}</h2>
      {reused.length === 0 ? (
        <div className="kv-card">
          <p className="kv-health-empty">{t("health.reusedEmpty")}</p>
        </div>
      ) : (
        <div className="kv-card">
          {reused.map((g, i) => (
            <div className="kv-manage-row kv-health-row" key={`${g.entries.map((e) => e.entry_id).join("-")}:${i}`}>
              <div className="kv-health-row-main">
                <span className="kv-health-title">
                  {g.entries.map((e) => e.title).join(", ")}
                </span>
                <span className="kv-health-meta">{tn("health.reusedCount", g.count)}</span>
              </div>
              <span className="kv-health-badge is-reused">{g.count}</span>
            </div>
          ))}
        </div>
      )}

      <div className="kv-health-section-head">
        <h2 className="kv-health-section">{t("health.compromisedTitle")}</h2>
        {settings.hibp_enabled && (
          <button
            type="button"
            className="kv-btn is-ghost"
            disabled={hibpLoading}
            onClick={() => void runHibp()}
          >
            {hibpLoading ? t("health.compromisedChecking") : t("health.compromisedCheckBtn")}
          </button>
        )}
      </div>
      {!settings.hibp_enabled ? (
        <div className="kv-card">
          <p className="kv-health-empty">{t("health.compromisedDisabled")}</p>
        </div>
      ) : hibpLoading && !hibp ? (
        <div className="kv-card">
          <p className="kv-health-empty">{t("health.compromisedChecking")}</p>
        </div>
      ) : hibp?.offline ? (
        <div className="kv-card">
          <p className="kv-health-empty">{t("health.compromisedOffline")}</p>
        </div>
      ) : (hibp?.compromised.length ?? 0) === 0 ? (
        <div className="kv-card">
          <p className="kv-health-empty">{t("health.compromisedEmpty")}</p>
        </div>
      ) : (
        <div className="kv-card">
          {hibp!.compromised.map((c, i) => (
            <div className="kv-manage-row kv-health-row" key={`${c.entry_id}:${c.field_name}:${i}`}>
              <div className="kv-health-row-main">
                <span className="kv-health-title">{c.title}</span>
                <span className="kv-health-meta">{tn("health.compromisedCount", c.count)}</span>
              </div>
              <span className="kv-health-badge is-compromised">{c.count}</span>
            </div>
          ))}
        </div>
      )}
    </>
  );

  if (embedded) return body;
  return (
    <main className="kv-settings" data-screen-label="Password Health page">
      <div className="kv-settings-inner">
        <button
          type="button"
          className="kv-btn is-ghost kv-settings-back"
          onClick={() => setRoute("main")}
        >
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
            <path d={CHEVRON_LEFT} />
          </svg>{" "}
          {t("common.back")}
        </button>
        <h1>{t("health.title")}</h1>
        {body}
      </div>
    </main>
  );
}
