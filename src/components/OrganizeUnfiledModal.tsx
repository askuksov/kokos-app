import { useEffect, useRef, useState } from "react";
import { useT } from "../state/LangContext";
import { aiOrganizeUnfiled, aiApplyOrganize } from "../ipc/commands";
import type { OrganizeGroup, OrganizeApplyGroup } from "../ipc/types";
import "./OrganizeUnfiledModal.css";

type Props = { onClose: () => void; onApplied: () => void };

type GroupState = {
  group: OrganizeGroup;
  name: string;
  checked: Set<string>;
};

export default function OrganizeUnfiledModal({ onClose, onApplied }: Props) {
  const t = useT();
  const [loading, setLoading] = useState(true);
  const [groups, setGroups] = useState<GroupState[]>([]);
  const [applying, setApplying] = useState(false);
  const panelRef = useRef<HTMLDivElement>(null);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useEffect(() => {
    let cancelled = false;
    aiOrganizeUnfiled()
      .then((p) => {
        if (cancelled) return;
        setGroups(
          p.groups.map((group) => ({
            group,
            name: group.name,
            checked: new Set(group.entries.map((e) => e.entry_id)),
          })),
        );
        setLoading(false);
      })
      .catch((e) => {
        console.error("ai_organize_unfiled failed:", e);
        if (!cancelled) {
          setGroups([]);
          setLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    panelRef.current?.focus({ preventScroll: true });
    function onKeyDown(ev: KeyboardEvent) {
      if (ev.key === "Escape") {
        ev.stopPropagation();
        onCloseRef.current();
      }
    }
    document.addEventListener("keydown", onKeyDown, true);
    return () => document.removeEventListener("keydown", onKeyDown, true);
  }, []);

  function toggle(gi: number, entryId: string) {
    setGroups((prev) =>
      prev.map((g, i) => {
        if (i !== gi) return g;
        const checked = new Set(g.checked);
        checked.has(entryId) ? checked.delete(entryId) : checked.add(entryId);
        return { ...g, checked };
      }),
    );
  }
  function rename(gi: number, name: string) {
    setGroups((prev) => prev.map((g, i) => (i === gi ? { ...g, name } : g)));
  }

  async function handleApply() {
    if (applying) return;
    const payload: OrganizeApplyGroup[] = groups
      .filter((g) => g.checked.size > 0)
      .filter((g) => g.group.kind === "existing" || g.name.trim().length > 0)
      .map((g) => ({
        folder_id: g.group.kind === "existing" ? g.group.folder_id : null,
        new_folder_name: g.group.kind === "new" ? g.name.trim() : null,
        entry_ids: g.group.entries.map((e) => e.entry_id).filter((id) => g.checked.has(id)),
      }));
    if (payload.length === 0) {
      onClose();
      return;
    }
    setApplying(true);
    try {
      await aiApplyOrganize(payload);
      onApplied();
      onClose();
    } catch (e) {
      console.error("ai_apply_organize failed:", e);
      setApplying(false);
    }
  }

  const isEmpty = !loading && groups.length === 0;

  return (
    <div className="kv-modal-scrim kv-organize-scrim" onClick={onClose}>
      <div
        className="kv-modal kv-organize"
        role="dialog"
        aria-modal="true"
        aria-label={t("organize.title")}
        tabIndex={-1}
        ref={panelRef}
        onClick={(ev) => ev.stopPropagation()}
      >
        <div className="kv-modal-header">
          <h2>{t("organize.title")}</h2>
        </div>
        <div className="kv-modal-body">
          {loading ? (
            <p className="kv-organize-status">{t("organize.loading")}</p>
          ) : isEmpty ? (
            <div className="kv-organize-empty">
              <p>{t("organize.empty")}</p>
              <p className="kv-organize-hint">{t("organize.emptyHint")}</p>
            </div>
          ) : (
            groups.map((g, gi) => (
              <div className="kv-organize-group" key={gi}>
                <div className="kv-organize-group-head">
                  <span className={`kv-organize-badge is-${g.group.kind}`}>
                    {g.group.kind === "new" ? t("organize.newBadge") : t("organize.existingBadge")}
                  </span>
                  {g.group.kind === "new" ? (
                    <input
                      className="kv-input kv-organize-name"
                      value={g.name}
                      placeholder={t("organize.namePlaceholder")}
                      onChange={(e) => rename(gi, e.target.value)}
                    />
                  ) : (
                    <span className="kv-organize-name-static">{g.name}</span>
                  )}
                  <span className="kv-organize-count">
                    {t("organize.count", { count: g.checked.size })}
                  </span>
                </div>
                <ul className="kv-organize-entries">
                  {g.group.entries.map((e) => (
                    <li className="kv-organize-entry" key={e.entry_id}>
                      <label>
                        <input
                          type="checkbox"
                          checked={g.checked.has(e.entry_id)}
                          onChange={() => toggle(gi, e.entry_id)}
                        />
                        <span className="kv-organize-entry-title">{e.title}</span>
                        <span className="kv-organize-score">{Math.round(e.score * 100)}%</span>
                      </label>
                    </li>
                  ))}
                </ul>
              </div>
            ))
          )}
        </div>
        <div className="kv-modal-footer">
          <button type="button" className="kv-btn is-ghost" onClick={onClose} disabled={applying}>
            {t("organize.cancel")}
          </button>
          {!isEmpty && (
            <button type="button" className="kv-btn is-primary" onClick={handleApply} disabled={applying || loading}>
              {applying ? t("organize.applying") : t("organize.apply")}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
