import { useT } from "../state/LangContext";
import { stepTitleKey } from "../lib/onboarding";
import type { Onboarding } from "../lib/useOnboarding";
import "./GettingStarted.css";

export function GettingStarted({ onboarding }: { onboarding: Onboarding }) {
  const t = useT();
  const { collapsed, steps, done, total, isMac, setCollapsed, dismiss, deferSync, goTo } = onboarding;
  const progress = t("onboarding.progress", { done, total });

  if (collapsed) {
    return (
      <div className="kv-onboarding is-collapsed">
        <button
          type="button"
          className="kv-onboarding-summary"
          aria-expanded={false}
          aria-label={t("onboarding.expand")}
          onClick={() => setCollapsed(false)}
        >
          <span className="kv-onboarding-name">{t("onboarding.title")}</span>
          <span className="kv-onboarding-count">{progress}</span>
          <span aria-hidden="true">▾</span>
        </button>
        <p className="kv-onboarding-prompt">{t("detail.selectPrompt")}</p>
      </div>
    );
  }

  const allDone = done === total;

  return (
    <section className="kv-onboarding" aria-labelledby="kv-onboarding-title">
      <header className="kv-onboarding-head">
        <h2 id="kv-onboarding-title">{t("onboarding.title")}</h2>
        <span className="kv-onboarding-count">{progress}</span>
      </header>
      <div
        className="kv-onboarding-bar"
        role="progressbar"
        aria-valuenow={done}
        aria-valuemin={0}
        aria-valuemax={total}
        aria-labelledby="kv-onboarding-title"
      >
        <span style={{ width: `${(done / total) * 100}%` }} />
      </div>

      <ul className="kv-onboarding-steps">
        {steps.map(({ step, done: stepDone }) => {
          const title = t(stepTitleKey(step, isMac));
          return (
            <li key={step.id} className={"kv-onboarding-step" + (stepDone ? " is-done" : "")}>
              <span role="checkbox" aria-checked={stepDone} aria-disabled="true" aria-label={title}>
                {stepDone ? "☑" : "☐"}
              </span>
              <span className="kv-onboarding-step-text">
                <strong>{title}</strong>
                <small>{t(step.descKey)}</small>
              </span>
              {!stepDone && (
                <span className="kv-onboarding-step-actions">
                  {step.deferrable && (
                    <button type="button" className="kv-btn is-ghost" onClick={deferSync}>
                      {t("onboarding.later")}
                    </button>
                  )}
                  <button
                    type="button"
                    className="kv-btn"
                    aria-label={t("onboarding.openStep", { step: title })}
                    onClick={() => goTo(step.tab)}
                  >
                    →
                  </button>
                </span>
              )}
            </li>
          );
        })}
      </ul>

      {allDone && <p className="kv-onboarding-alldone">{t("onboarding.allDone")}</p>}

      <footer className="kv-onboarding-foot">
        {!allDone && (
          <button type="button" className="kv-btn is-ghost" onClick={() => setCollapsed(true)}>
            {t("onboarding.collapse")}
          </button>
        )}
        <button type="button" className="kv-btn is-primary" onClick={dismiss}>
          {allDone ? t("onboarding.done") : t("onboarding.dismiss")}
        </button>
      </footer>
    </section>
  );
}
