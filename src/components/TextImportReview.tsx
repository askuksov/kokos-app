import { useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { useT } from "../state/LangContext";
import { useVault } from "../state/VaultContext";
import { useSettings } from "../state/SettingsContext";
import { EntryTypeSelect } from "./EntryTypeSelect";
import { PasswordField } from "./PasswordField";
import { aiTextImportAnalyze, aiTextImportAnalyzeFolder, aiTextImportCancel, aiTextImportCommit, aiTextImportStash } from "../ipc/commands";
import { seedDrafts, draftsToCommit, baseName, defaultFieldName, isAutoFieldName, LOW_CONFIDENCE, type DraftEntry, type FolderChoice } from "../lib/textImportMap";
import type { EntryType } from "../lib/entryTypes";
import type { FolderNode, TextImportReport, UnparsedBlock } from "../ipc/types";
import type { ImportSnapshot, ImportSource } from "../state/TextImportContext";
import { newEta, feedEta, etaSeconds, formatEta, overallFraction, fileFraction, type EtaState, type ImportProgress } from "../lib/textImportEta";
import "./TextImportReview.css";

const FIELD_TYPES = ["text", "secret", "url", "email", "otp", "date", "phone"] as const;
const PROTECTED_TYPES = new Set(["secret", "otp"]);

export type { ImportSource };

export function TextImportReview({
  source,
  snapshot = null,
  onClose,
  minimized = false,
  onMinimize,
  onResume,
  variant = "modal",
}: {
  source: ImportSource;
  snapshot?: ImportSnapshot | null;
  onClose: (result?: TextImportReport) => void;
  minimized?: boolean;
  onMinimize?: () => void;
  onResume?: () => void;
  variant?: "modal" | "panel";
}) {
  const t = useT();
  const { folders } = useVault();
  const { refresh: refreshSettings } = useSettings();
  const [phase, setPhase] = useState<"analyzing" | "review" | "committing">(snapshot ? "review" : "analyzing");
  const [stage, setStage] = useState<string>("read");
  const [progress, setProgress] = useState<ImportProgress | null>(null);
  const etaRef = useRef<EtaState>(newEta());
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (phase !== "analyzing") return;
    const id = window.setInterval(() => setNow(Date.now()), 500);
    return () => window.clearInterval(id);
  }, [phase]);
  const [entries, setEntries] = useState<DraftEntry[]>((snapshot?.entries as DraftEntry[] | undefined) ?? []);
  const [unparsed, setUnparsed] = useState<UnparsedBlock[]>((snapshot?.unparsed as UnparsedBlock[] | undefined) ?? []);
  const [dropped, setDropped] = useState<number>(snapshot?.entriesDropped ?? 0);
  const [error, setError] = useState<string | null>(null);
  const firedRef = useRef(snapshot !== null);
  const dialogRef = useRef<HTMLDivElement>(null);
  const [confirmingClose, setConfirmingClose] = useState(false);

  useEffect(() => {
    if (firedRef.current) return;
    firedRef.current = true;
    const req =
      source.kind === "folder" ? aiTextImportAnalyzeFolder(source.dir) : aiTextImportAnalyze([source.path]);
    req
      .then((p) => {
        setEntries(seedDrafts(p, flattenFolders(folders)));
        setUnparsed(p.unparsed ?? []);
        setDropped(p.entries_dropped ?? 0);
        setPhase("review");
      })
      .catch((e) => {
        setError(
          String(e).includes("gen_model_not_ready")
            ? t("textImport.modelNotReady")
            : t("textImport.analyzeFailed"),
        );
        setPhase("review");
      });
  }, [source, t, folders]);

  // Keep a sealed copy of the review (with the user's edits) in the backend so
  // an auto-lock while away cannot lose the analysis result. Debounced; the
  // backend encrypts it with the vault key and keeps no plaintext.
  useEffect(() => {
    if (phase !== "review" || entries.length === 0) return;
    const id = window.setTimeout(() => {
      const snap: ImportSnapshot = { source, entries, unparsed, entriesDropped: dropped };
      void aiTextImportStash(JSON.stringify(snap)).catch(() => {});
    }, 800);
    return () => window.clearTimeout(id);
  }, [phase, entries, unparsed, source, dropped]);

  useEffect(() => {
    const un = listen<{
      file_index: number;
      files_total: number;
      stage: string;
      file_name?: string;
      file_bytes?: number;
      bytes_done?: number;
      bytes_total?: number;
      chunk_done?: number;
      chunk_total?: number;
    }>("ai_text_import_progress", (e) => {
      const d = e.payload;
      const next: ImportProgress = {
        fileIndex: d.file_index,
        filesTotal: d.files_total,
        fileName: d.file_name ?? "",
        fileBytes: d.file_bytes ?? 0,
        bytesDone: d.bytes_done ?? 0,
        bytesTotal: d.bytes_total ?? 0,
        chunkDone: d.chunk_done ?? 0,
        chunkTotal: d.chunk_total ?? 0,
      };
      etaRef.current = feedEta(etaRef.current, next, Date.now());
      setStage(d.stage);
      setProgress(next);
    });
    return () => {
      void un.then((f) => f());
    };
  }, []);

  useEffect(() => {
    if (minimized || variant === "panel") return;
    function onKeyDown(ev: KeyboardEvent) {
      if (ev.key === "Escape" && phase !== "committing") {
        if (dialogRef.current?.querySelector(".kv-typeselect-pop, .kv-fieldtypeselect-pop, .kv-foldercombo-pop")) return;
        ev.stopPropagation();
        if (confirmingClose) setConfirmingClose(false);
        else requestClose();
        return;
      }
      if (ev.key !== "Tab" || !dialogRef.current) return;
      const focusable = dialogRef.current.querySelectorAll<HTMLElement>(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
      );
      const list = Array.from(focusable).filter((el) => !el.hasAttribute("disabled"));
      if (list.length < 2) return;
      const first = list[0];
      const last = list[list.length - 1];
      const active = document.activeElement;
      if (ev.shiftKey && (active === first || !dialogRef.current.contains(active))) {
        ev.preventDefault();
        last.focus({ preventScroll: true });
      } else if (!ev.shiftKey && active === last) {
        ev.preventDefault();
        first.focus({ preventScroll: true });
      }
    }
    document.addEventListener("keydown", onKeyDown, true);
    return () => document.removeEventListener("keydown", onKeyDown, true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [phase, minimized, confirmingClose]);

  useEffect(() => {
    if (!confirmingClose) return;
    function onDown(ev: MouseEvent) {
      const el = ev.target as HTMLElement | null;
      if (!el?.closest?.('[data-confirming="true"]')) setConfirmingClose(false);
    }
    document.addEventListener("mousedown", onDown, true);
    return () => document.removeEventListener("mousedown", onDown, true);
  }, [confirmingClose]);

  function doClose() {
    if (phase === "committing") return;
    if (phase === "analyzing") void aiTextImportCancel();
    setConfirmingClose(false);
    onClose();
  }
  function requestClose() {
    if (phase === "committing") return;
    if (phase !== "analyzing" && entries.length > 0 && !confirmingClose) {
      setConfirmingClose(true);
      return;
    }
    doClose();
  }

  function patchEntry(idx: number, patch: Partial<DraftEntry>) {
    setEntries((es) => es.map((e, i) => (i === idx ? { ...e, ...patch } : e)));
  }
  function patchField(ei: number, fi: number, patch: Partial<DraftEntry["fields"][number]>) {
    setEntries((es) =>
      es.map((e, i) =>
        i === ei ? { ...e, fields: e.fields.map((f, j) => (j === fi ? { ...f, ...patch } : f)) } : e,
      ),
    );
  }
  function onFieldTypeChange(ei: number, fi: number, ft: string, currentName: string) {
    const patch: Partial<DraftEntry["fields"][number]> = { fieldType: ft, isProtected: PROTECTED_TYPES.has(ft) };
    if (isAutoFieldName(currentName)) patch.name = defaultFieldName(ft);
    patchField(ei, fi, patch);
  }
  function discardEntry(ei: number) {
    setEntries((es) => es.filter((_, i) => i !== ei));
  }
  function discardField(ei: number, fi: number) {
    setEntries((es) => es.map((e, i) => (i === ei ? { ...e, fields: e.fields.filter((_, j) => j !== fi) } : e)));
  }
  function addField(ei: number) {
    setEntries((es) =>
      es.map((e, i) =>
        i === ei
          ? { ...e, fields: [...e.fields, { name: defaultFieldName("text"), fieldType: "text", isProtected: false, value: "", confidence: 1 }] }
          : e,
      ),
    );
  }

  async function confirm() {
    if (phase !== "review" || entries.length === 0) return;
    setPhase("committing");
    setError(null);
    try {
      const report = await aiTextImportCommit(draftsToCommit(entries));
      await refreshSettings();
      onClose(report);
    } catch {
      setError(t("textImport.commitFailed"));
      setPhase("review");
    }
  }

  if (minimized) {
    return (
      <button type="button" className="kv-textimport-pill" onClick={() => onResume?.()}>
        {phase === "analyzing"
          ? t("textImport.analyzingPill")
          : t("textImport.resume", { count: entries.length })}
      </button>
    );
  }

  const isPanel = variant === "panel";

  const content = (
    <div
      className={"kv-textimport" + (isPanel ? " is-panel" : "")}
      role={isPanel ? undefined : "dialog"}
      aria-modal={isPanel ? undefined : "true"}
      aria-label={t("textImport.title")}
      tabIndex={isPanel ? undefined : -1}
      ref={dialogRef}
      onMouseDown={isPanel ? undefined : (e) => e.stopPropagation()}
    >
        <div className="kv-textimport-head">
          <h2>{t("textImport.title")}</h2>
          <span className="kv-textimport-count">{t("textImport.entryCount", { count: entries.length })}</span>
          <FolderCombo
            folders={folders}
            value={{ mode: "existing", id: "" }}
            triggerLabel={t("textImport.setAll")}
            onChange={(c) => setEntries((es) => es.map((e) => ({ ...e, folder: c })))}
            disabled={phase === "committing" || entries.length === 0}
          />
          {onMinimize && !isPanel && (
            <button
              type="button"
              className="kv-btn is-ghost kv-textimport-min"
              onClick={onMinimize}
              disabled={phase === "committing"}
              aria-label={t("textImport.minimize")}
            >
              —
            </button>
          )}
          {!isPanel && (
            <button
              type="button"
              className="kv-btn is-ghost kv-textimport-x"
              data-confirming={confirmingClose ? "true" : undefined}
              onClick={requestClose}
              disabled={phase === "committing"}
              aria-label={t("common.cancel")}
            >
              ✕
            </button>
          )}
        </div>

        <div className="kv-textimport-body">
          {phase === "analyzing" ? (
            <div className="kv-textimport-loading" aria-busy="true">
              {progress && progress.filesTotal > 1 && (
                <div className="kv-textimport-progress">
                  {t("textImport.analyzingProgress", { current: progress.fileIndex + 1, total: progress.filesTotal })}
                </div>
              )}
              {progress && progress.filesTotal > 1 && (
                <progress
                  className="kv-textimport-bar"
                  max={1}
                  value={overallFraction(progress)}
                  aria-label={t("textImport.overall")}
                />
              )}
              {progress && progress.filesTotal > 1 && (
                <div className="kv-textimport-eta">
                  {(() => {
                    const sec = etaSeconds(etaRef.current, progress);
                    return sec === null
                      ? t("textImport.etaEstimating")
                      : t("textImport.eta", {
                          time: formatEta(sec, {
                            s: t("textImport.unit.s"),
                            min: t("textImport.unit.min"),
                            h: t("textImport.unit.h"),
                          }),
                        });
                  })()}
                </div>
              )}
              {progress && progress.fileName && (
                <div className="kv-textimport-file" title={progress.fileName}>
                  {t("textImport.currentFile", { name: progress.fileName })}
                </div>
              )}
              {progress && progress.chunkTotal > 0 && (() => {
                const f = fileFraction(etaRef.current, progress, now);
                return (
                  <progress
                    className="kv-textimport-bar is-file"
                    max={1}
                    {...(f === null ? {} : { value: f })}
                    aria-label={t("textImport.currentFile", { name: progress.fileName })}
                  />
                );
              })()}
              {progress && progress.chunkTotal > 1 && (
                <div className="kv-textimport-eta">
                  {t("textImport.chunkProgress", { current: Math.min(progress.chunkDone + 1, progress.chunkTotal), total: progress.chunkTotal })}
                </div>
              )}
              <div>{t("textImport.stage." + stage)}</div>
            </div>
          ) : (
            <>
              {dropped > 0 && (
                <div className="kv-textimport-unparsed" role="status">
                  <p className="kv-textimport-unparsed-head">{t("textImport.entriesDropped", { count: dropped })}</p>
                </div>
              )}
              {unparsed.length > 0 && (
                <div className="kv-textimport-unparsed" role="status">
                  <p className="kv-textimport-unparsed-head">{t("textImport.unparsed", { count: unparsed.length })}</p>
                  {unparsed.map((b, bi) => (
                    <details className="kv-textimport-raw" key={bi}>
                      <summary>
                        {t("textImport.unparsedBlock", { n: bi + 1 })}
                        {b.sourceFile && <> · {baseName(b.sourceFile)}</>}
                      </summary>
                      <pre className="kv-textimport-raw-body">{b.text}</pre>
                    </details>
                  ))}
                </div>
              )}
              {entries.length === 0 ? (
                <p className="kv-textimport-empty">{error ?? t("textImport.empty")}</p>
              ) : (
                entries.map((e, ei) => (
                  <div className="kv-textimport-card" key={ei}>
                    {(e.sourceFolder || e.sourceFile) && (
                      <div className="kv-textimport-prov" title={e.sourceFile ?? undefined} aria-label={t("textImport.source")}>
                        {e.sourceFolder && (
                          <>
                            <span className="kv-textimport-prov-folder">{e.sourceFolder}</span>
                            <span className="kv-textimport-prov-sep" aria-hidden="true">/</span>
                          </>
                        )}
                        {e.sourceFile && <span className="kv-textimport-prov-file">{baseName(e.sourceFile)}</span>}
                      </div>
                    )}
                    <div className="kv-textimport-card-head">
                      <input
                        className="kv-input kv-textimport-title"
                        value={e.title}
                        placeholder={t("textImport.titlePlaceholder")}
                        onChange={(ev) => patchEntry(ei, { title: ev.target.value })}
                      />
                      <EntryTypeSelect value={e.entryType} onChange={(et: EntryType) => patchEntry(ei, { entryType: et })} hideLabel />
                      <FolderCombo
                        folders={folders}
                        value={e.folder}
                        onChange={(c) => patchEntry(ei, { folder: c })}
                        disabled={phase === "committing"}
                      />
                      <button
                        type="button"
                        className="kv-btn is-ghost kv-textimport-discard"
                        onClick={() => discardEntry(ei)}
                        aria-label={t("textImport.discardEntry")}
                      >
                        <TrashIcon />
                      </button>
                    </div>
                    {e.fields.map((f, fi) => (
                      <div className={"kv-textimport-field" + (f.confidence < LOW_CONFIDENCE ? " is-low" : "")} key={fi}>
                        <span className="kv-textimport-lock" aria-hidden="true" title={f.isProtected ? t("textImport.protected") : undefined}>
                          {f.isProtected ? "🔒" : ""}
                        </span>
                        <input
                          className="kv-input kv-textimport-field-name-input"
                          value={f.name}
                          aria-label={t("textImport.fieldNameLabel")}
                          onChange={(ev) => patchField(ei, fi, { name: ev.target.value })}
                        />
                        <FieldTypeSelect value={f.fieldType} onChange={(ft) => onFieldTypeChange(ei, fi, ft, f.name)} />
                        {f.isProtected ? (
                          // Masked by default; eye toggle reveals and the value stays editable.
                          <div className="kv-textimport-value">
                            <PasswordField
                              value={f.value}
                              onChange={(v) => patchField(ei, fi, { value: v })}
                              autoComplete="off"
                            />
                          </div>
                        ) : (
                          <input
                            className="kv-input kv-textimport-value"
                            value={f.value}
                            onChange={(ev) => patchField(ei, fi, { value: ev.target.value })}
                          />
                        )}
                        {f.confidence < LOW_CONFIDENCE && (
                          <span className="kv-textimport-low" title={t("textImport.lowConfidence")} aria-hidden="true">
                            ⚠
                          </span>
                        )}
                        <button
                          type="button"
                          className="kv-btn is-ghost kv-textimport-discard"
                          onClick={() => discardField(ei, fi)}
                          aria-label={t("textImport.discardField")}
                        >
                          <TrashIcon />
                        </button>
                      </div>
                    ))}
                    <button
                      type="button"
                      className="kv-btn is-ghost kv-textimport-addfield"
                      onClick={() => addField(ei)}
                    >
                      + {t("textImport.addField")}
                    </button>
                    {e.sourceText && (
                      <RawSource text={e.sourceText} secrets={e.fields.filter((f) => f.isProtected).map((f) => f.value)} />
                    )}
                  </div>
                ))
              )}
            </>
          )}
        </div>

        <div className="kv-textimport-foot">
          {error && entries.length > 0 && (
            <span className="kv-settings-warn" role="alert">
              {error}
            </span>
          )}
          <button
            type="button"
            className="kv-btn is-ghost"
            data-confirming={confirmingClose ? "true" : undefined}
            onClick={requestClose}
            disabled={phase === "committing"}
          >
            {confirmingClose ? t("textImport.discardConfirm", { count: entries.length }) : t("common.cancel")}
          </button>
          <button
            type="button"
            className="kv-btn is-primary"
            onClick={() => void confirm()}
            disabled={phase !== "review" || entries.length === 0}
          >
            {phase === "committing" ? t("textImport.committing") : t("textImport.confirm", { count: entries.length })}
          </button>
        </div>
      </div>
  );

  if (isPanel) {
    return <div className="kv-textimport-panel">{content}</div>;
  }

  return (
    <div className="kv-textimport-scrim" role="presentation" onMouseDown={() => onMinimize?.()}>
      {content}
    </div>
  );
}

function FolderCombo({
  folders,
  value,
  onChange,
  disabled,
  triggerLabel,
}: {
  folders: FolderNode[];
  value: FolderChoice;
  onChange: (c: FolderChoice) => void;
  disabled?: boolean;
  triggerLabel?: string;
}) {
  const t = useT();
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number; width: number } | null>(null);
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const flat = flattenFolders(folders);
  const label =
    triggerLabel ??
    (value.mode === "new"
      ? t("textImport.newFolder", { name: value.name })
      : flat.find((f) => f.id === value.id)?.name ?? t("textImport.rootFolder"));
  const norm = q.trim().toLowerCase();
  const matches = flat.filter((f) => !norm || f.name.toLowerCase().includes(norm));
  const exact = flat.some((f) => f.name.toLowerCase() === norm);
  const canCreate = norm.length > 0 && !exact;

  function openPop() {
    const r = triggerRef.current?.getBoundingClientRect();
    if (r) setPos({ top: r.bottom + 6, left: r.left, width: r.width });
    setOpen(true);
  }

  useEffect(() => {
    if (!open) return;
    function onDown(ev: PointerEvent) {
      if (rootRef.current && !rootRef.current.contains(ev.target as Node)) setOpen(false);
    }
    function onKey(ev: KeyboardEvent) {
      if (ev.key === "Escape") {
        ev.stopPropagation();
        setOpen(false);
        triggerRef.current?.focus();
      }
    }
    function onScroll(ev: Event) {
      if (rootRef.current?.contains(ev.target as Node)) return;
      setOpen(false);
    }
    function onResize() {
      setOpen(false);
    }
    document.addEventListener("pointerdown", onDown);
    document.addEventListener("keydown", onKey, true);
    document.addEventListener("scroll", onScroll, true);
    window.addEventListener("resize", onResize);
    return () => {
      document.removeEventListener("pointerdown", onDown);
      document.removeEventListener("keydown", onKey, true);
      document.removeEventListener("scroll", onScroll, true);
      window.removeEventListener("resize", onResize);
    };
  }, [open]);

  return (
    <div className={"kv-foldercombo" + (open ? " is-open" : "")} ref={rootRef}>
      <button
        type="button"
        ref={triggerRef}
        className="kv-input kv-foldercombo-trigger"
        disabled={disabled}
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => (open ? setOpen(false) : openPop())}
      >
        <span className="kv-foldercombo-current">{label}</span>
        <span className="kv-foldercombo-caret" aria-hidden="true">▾</span>
      </button>
      {open && pos && (
        <div
          className="kv-foldercombo-pop"
          style={{ position: "fixed", top: pos.top, left: pos.left, minWidth: Math.max(pos.width, 200) }}
        >
          <input
            className="kv-input kv-foldercombo-search"
            autoFocus
            value={q}
            placeholder={t("textImport.folderSearch")}
            onChange={(e) => setQ(e.target.value)}
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
          />
          <div className="kv-foldercombo-list" role="listbox">
            {matches.map((f) => (
              <button
                key={f.id}
                type="button"
                role="option"
                aria-selected={value.mode === "existing" && value.id === f.id}
                className="kv-foldercombo-opt"
                onClick={() => {
                  onChange({ mode: "existing", id: f.id });
                  setOpen(false);
                  setQ("");
                }}
              >
                {" ".repeat(f.depth * 2) + f.name}
              </button>
            ))}
            {canCreate && (
              <button
                type="button"
                className="kv-foldercombo-opt kv-foldercombo-create"
                onClick={() => {
                  onChange({ mode: "new", name: q.trim() });
                  setOpen(false);
                  setQ("");
                }}
              >
                {t("textImport.createFolder", { name: q.trim() })}
              </button>
            )}
            {matches.length === 0 && !canCreate && <div className="kv-foldercombo-empty">{t("textImport.noFolders")}</div>}
          </div>
        </div>
      )}
    </div>
  );
}

function flattenFolders(nodes: FolderNode[], depth = 0): { id: string; name: string; depth: number }[] {
  const out: { id: string; name: string; depth: number }[] = [];
  for (const n of nodes) {
    out.push({ id: n.id, name: n.name, depth });
    out.push(...flattenFolders(n.children, depth + 1));
  }
  return out;
}

const RAW_MASK = "••••••";

// Raw source panel: protected values are redacted until the user explicitly reveals the full text.
// Redaction is best-effort (exact matches only); the reveal gate covers secrets that were not mapped.
function RawSource({ text, secrets }: { text: string; secrets: string[] }) {
  const t = useT();
  const [revealed, setRevealed] = useState(false);
  let shown = text;
  if (!revealed) {
    const uniq = Array.from(new Set(secrets.filter((v) => v.length > 0))).sort((a, b) => b.length - a.length);
    for (const v of uniq) shown = shown.split(v).join(RAW_MASK);
  }
  return (
    <details className="kv-textimport-raw">
      <summary>{t("textImport.rawData")}</summary>
      <pre className="kv-textimport-raw-body">{shown}</pre>
      <button type="button" className="kv-btn is-ghost" onClick={() => setRevealed((r) => !r)} aria-pressed={revealed}>
        {revealed ? t("detail.conceal") : t("detail.reveal")}
      </button>
    </details>
  );
}

function FieldTypeSelect({
  value,
  onChange,
  disabled,
}: {
  value: string;
  onChange: (ft: string) => void;
  disabled?: boolean;
}) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number; width: number } | null>(null);
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);

  function openPop() {
    const r = triggerRef.current?.getBoundingClientRect();
    if (r) setPos({ top: r.bottom + 6, left: r.left, width: r.width });
    setOpen(true);
  }

  useEffect(() => {
    if (!open) return;
    function onPointerDown(e: PointerEvent) {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    }
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") {
        e.stopPropagation();
        setOpen(false);
        triggerRef.current?.focus();
      }
    }
    function onScroll(e: Event) {
      if (rootRef.current?.contains(e.target as Node)) return;
      setOpen(false);
    }
    function onResize() {
      setOpen(false);
    }
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown, true);
    document.addEventListener("scroll", onScroll, true);
    window.addEventListener("resize", onResize);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown, true);
      document.removeEventListener("scroll", onScroll, true);
      window.removeEventListener("resize", onResize);
    };
  }, [open]);

  return (
    <div className="kv-typeselect kv-textimport-ft" ref={rootRef}>
      <button
        type="button"
        ref={triggerRef}
        className="kv-input kv-typeselect-trigger"
        disabled={disabled}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={t("textImport.fieldType")}
        onClick={() => (open ? setOpen(false) : openPop())}
      >
        <span className="kv-typeselect-current">{t("textImport.ft." + value)}</span>
        <span className="kv-typeselect-caret" aria-hidden="true">▾</span>
      </button>
      {open && pos ? (
        <div
          className="kv-typeselect-pop kv-fieldtypeselect-pop"
          role="listbox"
          aria-label={t("textImport.fieldType")}
          style={{ position: "fixed", top: pos.top, left: pos.left, minWidth: Math.max(pos.width, 140) }}
        >
          {FIELD_TYPES.map((ft, i) => (
            <button
              key={ft}
              type="button"
              role="option"
              aria-selected={ft === value}
              autoFocus={i === 0}
              className={"kv-typeselect-option" + (ft === value ? " is-active" : "")}
              onClick={() => {
                onChange(ft);
                setOpen(false);
                triggerRef.current?.focus();
              }}
            >
              {t("textImport.ft." + ft)}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function TrashIcon({ size = 15 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.7}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M4.5 7h15" />
      <path d="M9.5 7V5.2A1.2 1.2 0 0110.7 4h2.6a1.2 1.2 0 011.2 1.2V7" />
      <path d="M6.5 7l.8 12a1.5 1.5 0 001.5 1.4h6.4a1.5 1.5 0 001.5-1.4l.8-12" />
      <path d="M10 11v5.5M14 11v5.5" />
    </svg>
  );
}
