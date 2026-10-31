import { useRef, useState } from "react";
import type { DragEvent } from "react";
import { useTabs } from "../state/TabsContext";
import { useT } from "../state/LangContext";
import "./Topbar.css";

function CloseIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
      <path d="M6 6l12 12M18 6L6 18" />
    </svg>
  );
}
function PlusIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden="true">
      <path d="M12 5.5v13M5.5 12h13" />
    </svg>
  );
}
function LockIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="5" y="10.5" width="14" height="9.5" rx="2" />
      <path d="M8.5 10.5V7.5a3.5 3.5 0 017 0v3" />
    </svg>
  );
}

type DropTarget = { id: string; place: "before" | "after" };

export function Topbar() {
  const t = useT();
  const { tabs, activeIndex, activeTab, adding, activate, beginAdd, cancelAdd, closeTab, reorderTabs } = useTabs();

  const [dragId, setDragId] = useState<string | null>(null);
  const [drop, setDrop] = useState<DropTarget | null>(null);
  const dragIdRef = useRef<string | null>(null);
  const dropRef = useRef<DropTarget | null>(null);

  function onDragStart(ev: DragEvent<HTMLDivElement>, vaultId: string) {
    dragIdRef.current = vaultId;
    setDragId(vaultId);
    ev.dataTransfer.effectAllowed = "move";
  }
  function commit() {
    const dId = dragIdRef.current;
    const d = dropRef.current;
    dragIdRef.current = null;
    dropRef.current = null;
    setDragId(null);
    setDrop(null);
    if (dId && d) reorderTabs(dId, d.id, d.place);
  }
  function onDragEnd() {
    commit();
  }
  function onDragOver(ev: DragEvent<HTMLDivElement>, vaultId: string) {
    ev.preventDefault();
    if (!dragId || dragId === vaultId) {
      dropRef.current = null;
      setDrop(null);
      return;
    }
    const rect = ev.currentTarget.getBoundingClientRect();
    const place: "before" | "after" = (ev.clientX - rect.left) / rect.width < 0.5 ? "before" : "after";
    dropRef.current = { id: vaultId, place };
    setDrop({ id: vaultId, place });
  }
  function onDragLeave(vaultId: string) {
    setDrop((prev) => (prev && prev.id === vaultId ? null : prev));
  }
  function onDrop(ev: DragEvent<HTMLDivElement>) {
    ev.preventDefault();
    commit();
  }

  return (
    <div className="kv-topbar">
      <div className="kv-topbar-titlebar" data-tauri-drag-region>
        {adding
          ? <span className="kv-topbar-title">{t("tab.newVault")}</span>
          : activeTab && <span className="kv-topbar-title">{activeTab.name}</span>}
      </div>
      <div className="kv-tabbar">
        {tabs.map((tab, i) => {
          const dropPlace = drop && drop.id === tab.vaultId ? drop.place : null;
          return (
            <div
              key={tab.vaultId}
              className={
                "kv-tab" +
                (i === activeIndex && !adding ? " is-active" : "") +
                (dragId === tab.vaultId ? " is-dragging" : "") +
                (dropPlace === "before" ? " is-drop-before" : dropPlace === "after" ? " is-drop-after" : "")
              }
              title={tab.vaultId}
              role="button"
              draggable
              onDragStart={(e) => onDragStart(e, tab.vaultId)}
              onDragEnd={onDragEnd}
              onDragOver={(e) => onDragOver(e, tab.vaultId)}
              onDragLeave={() => onDragLeave(tab.vaultId)}
              onDrop={onDrop}
              onClick={() => activate(i)}
            >
              <span className="kv-tab-ico">{tab.locked ? <LockIcon /> : null}</span>
              <span className="kv-tab-label">{tab.name}</span>
              <button
                type="button"
                className="kv-tab-close"
                draggable={false}
                aria-label={t("tab.closeTitle")}
                title={t("tab.closeTitle")}
                onClick={(e) => {
                  e.stopPropagation();
                  void closeTab(tab.vaultId);
                }}
              >
                <CloseIcon />
              </button>
            </div>
          );
        })}
        {adding && (
          <div key="__new__" className="kv-tab is-active is-new" title={t("tab.newVault")}>
            <span className="kv-tab-label">{t("tab.newVault")}</span>
            <button
              type="button"
              className="kv-tab-close"
              aria-label={t("tab.closeTitle")}
              title={t("tab.closeTitle")}
              onClick={(e) => {
                e.stopPropagation();
                cancelAdd();
              }}
            >
              <CloseIcon />
            </button>
          </div>
        )}
        <button
          type="button"
          className="kv-tab-new"
          aria-label={t("tab.newTabTitle")}
          title={t("tab.newTabTitle")}
          onClick={() => beginAdd()}
        >
          <PlusIcon />
        </button>
      </div>
    </div>
  );
}
