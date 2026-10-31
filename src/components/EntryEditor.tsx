import { Fragment, useEffect, useId, useRef, useState } from "react";
import type { KeyboardEvent as ReactKeyboardEvent } from "react";
import { useVault } from "../state/VaultContext";
import { useT } from "../state/LangContext";
import {
  aiStatus,
  aiSuggestFolders,
  aiSuggestFoldersForDraft,
  aiSuggestTags,
  aiSuggestTagsForDraft,
  createEntry,
  createTag,
  deleteAttachment,
  entryTypeDefaultFields,
  getEntry,
  listAttachments,
  pickAnyFile,
  revealField,
  setEntryTags,
  updateEntry,
  uploadAttachment,
} from "../ipc/commands";
import type {
  AttachmentMeta,
  EntryPatch,
  FieldInput,
  FieldSeed,
  FieldTemplate,
  FieldValue,
  FolderNode,
  FolderSuggestion,
  NewEntry,
  NewField,
  Tag,
  TagSuggestion,
} from "../ipc/types";
import { formatBytes } from "../lib/format";
import { tagColor } from "../lib/tagColors";
import {
  entryTypeMeta,
  SECURE_NOTE_BODY_FIELD_NAME,
  WIFI_SECURITY_FIELD_NAME,
  WIFI_SECURITY_OPTIONS,
  type EntryType,
} from "../lib/entryTypes";
import { GeneratorPopover } from "./GeneratorPopover";
import { PasswordField } from "./PasswordField";
import { EntryTypeSelect } from "./EntryTypeSelect";
import "./EntryEditor.css";

function CloseIcon() {
  return (
    <svg
      width={16}
      height={16}
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

function RemoveTagIcon() {
  return (
    <svg
      width={11}
      height={11}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2.2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M6 6l12 12M18 6L6 18" />
    </svg>
  );
}

function CreateTagIcon() {
  return (
    <svg
      width={13}
      height={13}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.7}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M12 5.5v13M5.5 12h13" />
    </svg>
  );
}

function ChevronUpIcon() {
  return (
    <svg
      width={11}
      height={11}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2.2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M6.5 14.5l5.5-5.5 5.5 5.5" />
    </svg>
  );
}

function ChevronDownIcon() {
  return (
    <svg
      width={11}
      height={11}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2.2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M6.5 9.5l5.5 5.5 5.5-5.5" />
    </svg>
  );
}

function ClipIcon() {
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
      <path d="M20 11.5l-7.6 7.6a5 5 0 01-7-7L13 4.5a3.3 3.3 0 014.7 4.7l-7.6 7.5a1.7 1.7 0 01-2.3-2.3l7-7" />
    </svg>
  );
}

function DiceIcon() {
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
      <rect x="3.5" y="3.5" width="17" height="17" rx="4" />
      <circle cx="8.1" cy="8.1" r="1.15" fill="currentColor" stroke="none" />
      <circle cx="15.9" cy="8.1" r="1.15" fill="currentColor" stroke="none" />
      <circle cx="12" cy="12" r="1.15" fill="currentColor" stroke="none" />
      <circle cx="8.1" cy="15.9" r="1.15" fill="currentColor" stroke="none" />
      <circle cx="15.9" cy="15.9" r="1.15" fill="currentColor" stroke="none" />
    </svg>
  );
}

function FloatInput({
  label,
  value,
  onChange,
  mono,
  textarea,
  autoFocus,
  disabled,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  mono?: boolean;
  textarea?: boolean;
  autoFocus?: boolean;
  disabled?: boolean;
}) {
  const inputId = useId();
  const inputClass = "kv-input" + (mono ? " is-mono" : "");
  return (
    <div className={"kv-float" + (value ? " has-value" : "")}>
      {textarea ? (
        <textarea
          id={inputId}
          className={inputClass}
          value={value}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value)}
          autoCapitalize="off"
          autoCorrect="off"
          spellCheck={false}
        />
      ) : (
        <input
          id={inputId}
          className={inputClass}
          type="text"
          value={value}
          autoFocus={autoFocus}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value)}
          autoCapitalize="off"
          autoCorrect="off"
          spellCheck={false}
        />
      )}
      <label htmlFor={inputId}>{label}</label>
    </div>
  );
}

function PasswordRow({
  label,
  value,
  onChange,
  disabled,
  trailing,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
  trailing?: React.ReactNode;
}) {
  const inputId = useId();
  return (
    <div className={"kv-float" + (value ? " has-value" : "")}>
      <div className="kv-generator-field-wrap">
        <PasswordField
          id={inputId}
          value={value}
          onChange={onChange}
          disabled={disabled}
          autoComplete="off"
        />
        {trailing}
      </div>
      <label htmlFor={inputId}>{label}</label>
    </div>
  );
}

function DateInput({
  label,
  value,
  onChange,
  disabled,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
}) {
  const inputId = useId();
  return (
    <div className="kv-float has-value">
      <input
        id={inputId}
        className="kv-input"
        type="date"
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value)}
        autoCapitalize="off"
        autoCorrect="off"
        spellCheck={false}
      />
      <label htmlFor={inputId}>{label}</label>
    </div>
  );
}

interface EditableField {
  id: string | null;
  template_id: string | null;
  name: string;
  field_type: string;
  is_protected: boolean;
  value: string;
  revealed: boolean;
  dirty: boolean;
  clientKey: number;
  customChosen?: boolean;
  fixed?: boolean;
}

const FIELD_MASK = "•".repeat(10);

function MaskedFieldRow({
  label,
  onReveal,
  busy,
  trailing,
}: {
  label: string;
  onReveal: () => void;
  busy: boolean;
  trailing?: React.ReactNode;
}) {
  const t = useT();
  const inputId = useId();
  return (
    <div className="kv-float has-value">
      <div className="kv-field-masked-row">
        <input
          id={inputId}
          className="kv-input is-mono"
          type="text"
          value={FIELD_MASK}
          readOnly
          disabled
          aria-label={t("editor.fieldHidden", { name: label })}
          autoCapitalize="off"
          autoCorrect="off"
          spellCheck={false}
        />
        <button type="button" className="kv-btn is-ghost" onClick={onReveal} disabled={busy}>
          {busy ? t("editor.revealing") : t("editor.revealToEdit")}
        </button>
        {trailing}
      </div>
      <label htmlFor={inputId}>{label}</label>
    </div>
  );
}

const ADHOC_FIELD_TYPES: { value: string; labelKey: string }[] = [
  { value: "text", labelKey: "fieldType.text" },
  { value: "secret", labelKey: "fieldType.secret" },
  { value: "url", labelKey: "fieldType.url" },
  { value: "email", labelKey: "fieldType.email" },
  { value: "otp", labelKey: "fieldType.otp" },
  { value: "date", labelKey: "fieldType.date" },
  { value: "phone", labelKey: "fieldType.phone" },
];

const CUSTOM_TEMPLATE_OPTION = "__custom__";

function AdHocFieldRow({
  row,
  onChange,
  onNameChange,
  onTypeChange,
  templates,
  onPickTemplate,
  onChooseCustom,
  disabled,
  trailing,
  entryType,
}: {
  row: EditableField;
  onChange: (value: string) => void;
  onNameChange: (name: string) => void;
  onTypeChange: (type: string) => void;
  templates: FieldTemplate[];
  onPickTemplate: (templateId: string) => void;
  onChooseCustom: () => void;
  disabled?: boolean;
  entryType: EntryType;
  trailing?: React.ReactNode;
}) {
  const t = useT();
  const typeSelectId = useId();
  const templateSelectId = useId();

  if (!row.customChosen) {
    return (
      <div className="kv-field-adhoc">
        <div className="kv-float has-value">
          <select
            id={templateSelectId}
            className="kv-input"
            value=""
            disabled={disabled}
            onChange={(e) => {
              if (e.target.value === CUSTOM_TEMPLATE_OPTION) onChooseCustom();
              else if (e.target.value) onPickTemplate(e.target.value);
            }}
          >
            <option value="">{t("editor.fromTemplateOption")}</option>
            {templates.map((tpl) => (
              <option key={tpl.id} value={tpl.id}>
                {tpl.name}
              </option>
            ))}
            <option value={CUSTOM_TEMPLATE_OPTION}>{t("editor.customOption")}</option>
          </select>
          <label htmlFor={templateSelectId}>{t("editor.fromTemplateLabel")}</label>
        </div>
      </div>
    );
  }

  return (
    <div className="kv-field-adhoc">
      <FloatInput label={t("editor.fieldNameLabel")} value={row.name} onChange={onNameChange} disabled={disabled} />
      <div className="kv-float has-value">
        <select
          id={typeSelectId}
          className="kv-input"
          value={row.field_type}
          disabled={disabled}
          onChange={(e) => onTypeChange(e.target.value)}
        >
          {ADHOC_FIELD_TYPES.map((ft) => (
            <option key={ft.value} value={ft.value}>
              {t(ft.labelKey)}
            </option>
          ))}
        </select>
        <label htmlFor={typeSelectId}>{t("editor.typeLabel")}</label>
      </div>
      {entryType === "wifi" && row.name === WIFI_SECURITY_FIELD_NAME ? (
        <div className="kv-float has-value">
          <select
            className="kv-input"
            value={row.value}
            disabled={disabled}
            onChange={(e) => onChange(e.target.value)}
          >
            {WIFI_SECURITY_OPTIONS.map((opt) => (
              <option key={opt} value={opt}>
                {opt}
              </option>
            ))}
          </select>
          <label>{t("editor.valueLabel")}</label>
        </div>
      ) : row.is_protected ? (
        <PasswordRow label={t("editor.valueLabel")} value={row.value} onChange={onChange} disabled={disabled} trailing={trailing} />
      ) : row.field_type === "date" ? (
        <DateInput label={t("editor.valueLabel")} value={row.value} onChange={onChange} disabled={disabled} />
      ) : (
        <FloatInput label={t("editor.valueLabel")} value={row.value} onChange={onChange} mono disabled={disabled} />
      )}
    </div>
  );
}

function EditableFieldRow({
  row,
  onChange,
  onNameChange,
  onTypeChange,
  onReveal,
  revealing,
  templates,
  onPickTemplate,
  onChooseCustom,
  disabled,
  generatorOpen,
  onToggleGenerator,
  entryType,
}: {
  row: EditableField;
  onChange: (value: string) => void;
  onNameChange: (name: string) => void;
  onTypeChange: (type: string) => void;
  onReveal: () => void;
  revealing: boolean;
  templates: FieldTemplate[];
  onPickTemplate: (templateId: string) => void;
  onChooseCustom: () => void;
  disabled?: boolean;
  generatorOpen: boolean;
  onToggleGenerator: () => void;
  entryType: EntryType;
}) {
  const t = useT();
  const generatorTrigger =
    row.field_type === "secret" && row.template_id === "tpl_password" ? (
      <button
        type="button"
        className="kv-btn is-icon"
        title={t("editor.generatePassword")}
        aria-label={t("editor.generatePasswordFor", { name: row.name })}
        aria-haspopup="true"
        aria-expanded={generatorOpen}
        disabled={disabled}
        onClick={onToggleGenerator}
      >
        <DiceIcon />
      </button>
    ) : null;

  if (row.id === null && row.template_id === null && !row.fixed) {
    return (
      <AdHocFieldRow
        row={row}
        onChange={onChange}
        onNameChange={onNameChange}
        onTypeChange={onTypeChange}
        templates={templates}
        onPickTemplate={onPickTemplate}
        onChooseCustom={onChooseCustom}
        disabled={disabled}
        trailing={generatorTrigger}
        entryType={entryType}
      />
    );
  }

  if (row.is_protected && !row.revealed) {
    return (
      <MaskedFieldRow label={row.name} onReveal={onReveal} busy={revealing || !!disabled} trailing={generatorTrigger} />
    );
  }
  if (row.is_protected) {
    return (
      <PasswordRow
        label={row.name}
        value={row.value}
        onChange={onChange}
        disabled={disabled}
        trailing={generatorTrigger}
      />
    );
  }
  if (row.field_type === "date") {
    return <DateInput label={row.name} value={row.value} onChange={onChange} disabled={disabled} />;
  }
  if (entryType === "secure_note" && row.name === SECURE_NOTE_BODY_FIELD_NAME) {
    return <FloatInput label={row.name} value={row.value} onChange={onChange} textarea disabled={disabled} />;
  }
  if (entryType === "wifi" && row.name === WIFI_SECURITY_FIELD_NAME) {
    return (
      <div className="kv-float has-value">
        <select
          className="kv-input"
          value={row.value}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value)}
        >
          {WIFI_SECURITY_OPTIONS.map((opt) => (
            <option key={opt} value={opt}>
              {opt}
            </option>
          ))}
        </select>
        <label>{row.name}</label>
      </div>
    );
  }
  return <FloatInput label={row.name} value={row.value} onChange={onChange} mono disabled={disabled} />;
}

interface FlatFolder {
  node: FolderNode;
  depth: number;
}

function flattenFolders(nodes: FolderNode[], depth = 0): FlatFolder[] {
  const out: FlatFolder[] = [];
  for (const node of nodes) {
    out.push({ node, depth });
    out.push(...flattenFolders(node.children, depth + 1));
  }
  return out;
}

interface TagOption {
  kind: "tag";
  tag: Tag;
}
interface CreateTagOption {
  kind: "create";
  name: string;
}
type TagSelectOption = TagOption | CreateTagOption;

function TagMultiSelect({
  tags,
  selected,
  onToggle,
  onCreate,
  disabled,
}: {
  tags: Tag[];
  selected: string[];
  onToggle: (id: string) => void;
  onCreate: (name: string) => Promise<string | null>;
  disabled?: boolean;
}) {
  const t = useT();
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const rootRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const selectedTags = selected
    .map((id) => tags.find((t) => t.id === id))
    .filter((t): t is Tag => t !== undefined);
  const norm = q.trim().toLowerCase();
  const candidates = tags
    .filter((t) => !selected.includes(t.id) && (!norm || t.name.toLowerCase().includes(norm)))
    .sort((a, b) => b.usage - a.usage);
  const exact = tags.some((t) => t.name.toLowerCase() === norm);
  const canCreate = norm.length > 0 && !exact;
  const tagOptions: TagOption[] = candidates.map((t) => ({ kind: "tag", tag: t }));
  const options: TagSelectOption[] = canCreate
    ? [...tagOptions, { kind: "create", name: q.trim() }]
    : tagOptions;

  useEffect(() => {
    function onDown(ev: PointerEvent) {
      if (rootRef.current && !rootRef.current.contains(ev.target as Node)) setOpen(false);
    }
    document.addEventListener("pointerdown", onDown);
    return () => document.removeEventListener("pointerdown", onDown);
  }, []);
  useEffect(() => setActive(0), [q, open]);

  async function choose(opt: TagSelectOption | undefined) {
    if (!opt) return;
    if (opt.kind === "create") {
      const id = await onCreate(opt.name);
      if (id) onToggle(id);
    } else {
      onToggle(opt.tag.id);
    }
    setQ("");
    setActive(0);
    inputRef.current?.focus();
  }

  function onKeyDown(ev: ReactKeyboardEvent<HTMLInputElement>) {
    if (ev.key === "ArrowDown") {
      ev.preventDefault();
      setOpen(true);
      setActive((i) => Math.min(i + 1, options.length - 1));
    } else if (ev.key === "ArrowUp") {
      ev.preventDefault();
      setActive((i) => Math.max(i - 1, 0));
    } else if (ev.key === "Enter") {
      ev.preventDefault();
      if (open && options.length) void choose(options[Math.min(active, options.length - 1)]);
    } else if (ev.key === "Escape") {
      if (open) {
        ev.stopPropagation();
        setOpen(false);
      }
    } else if (ev.key === "Backspace" && q === "" && selectedTags.length) {
      onToggle(selectedTags[selectedTags.length - 1].id);
    }
  }

  return (
    <div>
      <div className="kv-field-label">{t("editor.tagsLabel")}</div>
      <div className={"kv-tagselect" + (open ? " is-open" : "")} ref={rootRef}>
        <div
          className="kv-tagselect-control"
          onClick={() => {
            if (disabled) return;
            setOpen(true);
            inputRef.current?.focus();
          }}
        >
          {selectedTags.map((tag) => (
            <span key={tag.id} className="kv-tagselect-chip">
              <span className="kv-tag-dot" style={{ background: tagColor(tag.color) }} />
              {tag.name}
              <button
                type="button"
                title={t("editor.removeTagNamed", { name: tag.name })}
                disabled={disabled}
                onClick={(e) => {
                  e.stopPropagation();
                  onToggle(tag.id);
                }}
              >
                <RemoveTagIcon />
              </button>
            </span>
          ))}
          <input
            ref={inputRef}
            className="kv-tagselect-input"
            placeholder={selectedTags.length ? t("editor.addTagPlaceholder") : t("editor.searchOrCreateTagsPlaceholder")}
            value={q}
            disabled={disabled}
            onChange={(e) => {
              setQ(e.target.value);
              setOpen(true);
            }}
            onFocus={() => setOpen(true)}
            onKeyDown={onKeyDown}
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
          />
        </div>
        {open && !disabled ? (
          <div className="kv-tagselect-pop">
            {options.length === 0 ? (
              <div className="kv-tagselect-empty">{norm ? t("editor.noMatchingTags") : t("editor.allTagsAdded")}</div>
            ) : (
              options.map((opt, i) =>
                opt.kind === "create" ? (
                  <div
                    key="__create"
                    className={"kv-tagselect-opt" + (i === active ? " is-active" : "")}
                    onMouseEnter={() => setActive(i)}
                    onClick={() => void choose(opt)}
                  >
                    <CreateTagIcon />
                    <span className="name">{t("editor.createTagNamed", { name: opt.name })}</span>
                    <span className="new-badge">{t("editor.newBadge")}</span>
                  </div>
                ) : (
                  <div
                    key={opt.tag.id}
                    className={"kv-tagselect-opt" + (i === active ? " is-active" : "")}
                    onMouseEnter={() => setActive(i)}
                    onClick={() => void choose(opt)}
                  >
                    <span className="kv-tag-dot" style={{ background: tagColor(opt.tag.color) }} />
                    <span className="name">{opt.tag.name}</span>
                    <span className="count">{opt.tag.usage || ""}</span>
                  </div>
                ),
              )
            )}
          </div>
        ) : null}
      </div>
    </div>
  );
}

interface FormState {
  title: string;
  notes: string;
}

const BLANK_FORM: FormState = { title: "", notes: "" };


interface EntryEditorProps {
  /** null = create mode. Non-null = edit this entry (getEntry; protected fields fetch via revealField on demand — see handleReveal). */
  entryId: string | null;
  /** Create mode only: pre-select this folder / tag in the new-entry form,
   * from whatever the user was viewing when "+" was clicked. Ignored in edit
   * mode (the loaded entry's own folder/tags win). */
  initialFolderId?: string | null;
  initialTagId?: string | null;
  onClose: () => void;
  /**
   * Fired after a successful EDIT save only (not create — see the call site
   * in Vault.tsx). `update_entry`'s field write (an id-keyed diff)
   * plus the title/notes patch — and the `setEntryTags` call in
   * `handleSave` — mean EntryDetail's own cached `entry` state goes stale
   * the instant this save lands if the edited entry is the one it's
   * currently showing, and nothing else invalidates it: EntryDetail only
   * refetches when `selectedId` itself changes, which an in-place edit
   * never does.
   */
  onSaved?: () => void;
}

/**
 * Slide-over create/edit entry form. Besides the title, notes and fields it
 * carries a folder `<select>` (defaulting to the entry's
 * `folder_id ?? "root"`) and a `TagMultiSelect` (below), whose selection is
 * applied via `setEntryTags` only once the entry itself exists (see
 * `handleSave`'s ordering). Neither touches the field-editing model the
 * SECURITY note below documents: a folder is entry-level and tags are their
 * own relation, never part of `entry_fields`. There is no strength meter in
 * the editor itself (`PasswordField` declines to carry one — see its own
 * docstring; the canonical strength bar lives in EntryDetail, off the
 * backend-computed `Field.strength`, once a value is saved) and no exit
 * animation — see the SECURITY note below for why closing unmounts
 * immediately instead of after a delay. The password row
 * (`field_type === "secret"`, `template_id === "tpl_password"`) gets a dice
 * trigger that opens `GeneratorPopover`, scoped entirely to this file's own
 * secret-row rendering — see `EditableFieldRow`'s `generatorTrigger` below —
 * never added to the shared `PasswordField` itself (also used by
 * Welcome/Lock, which must never grow a dice button).
 *
 * Fields are a dynamic `fields: EditableField[]` list below, rendered in
 * full regardless of `template_id` rather than matched into fixed
 * username/password/url slots: an entry whose fields all have
 * `template_id = NULL` would otherwise render as a blank form.
 *
 * SECURITY: a protected field loads MASKED (`value: ""`,
 * `revealed: false`); nothing is fetched until the user clicks that row's
 * own "Reveal to edit" (`handleReveal` below), which calls `revealField`
 * for just that one field. The plaintext goes ONLY into that row's own
 * `value` in local `fields` state — never VaultContext, never
 * `console.log`'d — and is discarded the instant this component unmounts
 * (`closedRef` below also drops a slow `revealField` response from an
 * already-closed editor rather than let it land in state). A field the
 * user never reveals is sent as `Keep` on save (`buildFieldInputs`), so its
 * plaintext never leaves Rust at all — not just "isn't logged." That's also
 * why open/close is a plain conditional mount in Vault.tsx (mount on open,
 * unmount on close) rather than an animate-then-unmount pattern:
 * a closing-animation window is a window where a revealed secret would
 * still be sitting in memory for no reason.
 */
export function EntryEditor({ entryId, onClose, onSaved, initialFolderId, initialTagId }: EntryEditorProps) {
  const { refreshEntries, refreshTags, refreshFolders, setSaveError, folders, tags, templates } = useVault();
  const t = useT();

  const [form, setForm] = useState<FormState>(BLANK_FORM);
  const [isFavorite, setIsFavorite] = useState(false);
  const [entryType, setEntryType] = useState<EntryType>("login");
  const [folderId, setFolderId] = useState(initialFolderId ?? "root");
  const [selectedTagIds, setSelectedTagIds] = useState<string[]>(initialTagId ? [initialTagId] : []);
  const folderSelectId = useId();
  const [fields, setFields] = useState<EditableField[]>([]);
  const [revealingIds, setRevealingIds] = useState<Record<string, boolean>>({});
  const [generatorFor, setGeneratorFor] = useState<number | null>(null);
  const [loading, setLoading] = useState(entryId !== null);
  const [loadError, setLoadError] = useState(false);
  const [saving, setSaving] = useState(false);
  const [attachments, setAttachments] = useState<AttachmentMeta[]>([]);
  const [uploading, setUploading] = useState(false);
  const [aiOn, setAiOn] = useState(false);
  const [folderSuggestions, setFolderSuggestions] = useState<FolderSuggestion[]>([]);
  const [tagSuggestions, setTagSuggestions] = useState<TagSuggestion[]>([]);
  const [suggesting, setSuggesting] = useState(false);
  const [suggested, setSuggested] = useState(false);
  const suggestTokenRef = useRef(0);
  const closedRef = useRef(false);
  useEffect(() => {
    closedRef.current = false;
    return () => {
      closedRef.current = true;
    };
  }, []);
  useEffect(() => {
    let cancelled = false;
    const probe = () => {
      aiStatus()
        .then((st) => {
          if (!cancelled) setAiOn(st.enabled);
        })
        .catch(() => {
          if (!cancelled) setAiOn(false);
        });
    };
    probe();
    window.addEventListener("focus", probe);
    return () => {
      cancelled = true;
      window.removeEventListener("focus", probe);
    };
  }, []);
  const entryIdRef = useRef(entryId);
  entryIdRef.current = entryId;
  const nextClientKeyRef = useRef(0);
  function nextClientKey(): number {
    return nextClientKeyRef.current++;
  }
  const addFieldBtnRef = useRef<HTMLButtonElement>(null);
  const seedTokenRef = useRef(0);

  async function seedFields(type: EntryType) {
    const token = ++seedTokenRef.current;
    const seeds: FieldSeed[] = await entryTypeDefaultFields(type);
    if (token !== seedTokenRef.current) return;
    setFields(
      seeds.map((s) => ({
        id: null,
        template_id: s.template_id,
        name: s.name,
        field_type: s.field_type,
        is_protected: s.is_protected,
        value: s.value ?? "",
        revealed: true,
        dirty: false,
        clientKey: nextClientKey(),
        fixed: true,
      })),
    );
  }

  useEffect(() => {
    ++seedTokenRef.current;
    ++suggestTokenRef.current;
    setFolderSuggestions([]);
    setTagSuggestions([]);
    setSuggested(false);
    setSuggesting(false);
    if (entryId === null) {
      setForm(BLANK_FORM);
      setIsFavorite(false);
      setFolderId(initialFolderId ?? "root");
      setSelectedTagIds(initialTagId ? [initialTagId] : []);
      setEntryType("login");
      void seedFields("login");
      setRevealingIds({});
      setLoading(false);
      setLoadError(false);
      return;
    }

    let cancelled = false;
    setLoading(true);
    setLoadError(false);

    getEntry(entryId)
      .then((entry) => {
        if (cancelled) return;
        setForm({ title: entry.title, notes: entry.notes ?? "" });
        setIsFavorite(entry.is_favorite);
        setFolderId(entry.folder_id ?? "root");
        setSelectedTagIds(entry.tags.map((t) => t.id));
        setEntryType(entry.entry_type as EntryType);
        setFields(
          entry.fields.map((f) => ({
            id: f.id,
            template_id: f.template_id,
            name: f.name,
            field_type: f.field_type,
            is_protected: f.is_protected,
            value: f.is_protected ? "" : (f.value ?? ""),
            revealed: !f.is_protected,
            dirty: false,
            clientKey: nextClientKey(),
          })),
        );
        setRevealingIds({});
        setLoading(false);
      })
      .catch((e) => {
        console.error("get_entry failed:", e);
        if (!cancelled) {
          setLoadError(true);
          setLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [entryId, initialFolderId, initialTagId]);

  useEffect(() => {
    if (entryId === null) {
      setAttachments([]);
      return;
    }
    let cancelled = false;
    listAttachments(entryId)
      .then((a) => {
        if (!cancelled) setAttachments(a);
      })
      .catch((e) => {
        console.error("list_attachments failed:", e);
      });
    return () => {
      cancelled = true;
    };
  }, [entryId]);

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key !== "Escape" || saving) return;
      if (generatorFor !== null) {
        setGeneratorFor(null);
        return;
      }
      onClose();
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose, saving, generatorFor]);

  async function handleReveal(row: EditableField) {
    if (row.id === null || row.revealed || revealingIds[row.id]) return;
    const fieldId = row.id;
    const currentId = entryId;
    if (currentId === null) return;
    setRevealingIds((r) => ({ ...r, [fieldId]: true }));
    try {
      const plaintext = await revealField(currentId, fieldId);
      if (closedRef.current || entryIdRef.current !== currentId) return;
      setFields((fs) =>
        fs.map((f) => (f.id === fieldId ? { ...f, value: plaintext ?? "", revealed: true } : f)),
      );
    } catch (e) {
      console.error("reveal_field failed:", e);
    } finally {
      if (!closedRef.current) {
        setRevealingIds((r) => ({ ...r, [fieldId]: false }));
      }
    }
  }

  function onChangeType(next: EntryType) {
    setEntryType(next);
    void seedFields(next);
  }

  function handleAddField() {
    setFields((fs) => [
      ...fs,
      {
        id: null,
        template_id: null,
        name: "",
        field_type: "text",
        is_protected: false,
        value: "",
        revealed: true,
        dirty: true,
        clientKey: nextClientKey(),
        customChosen: false,
      },
    ]);
  }

  function handleRemoveField(index: number) {
    setFields((fs) => fs.filter((_, j) => j !== index));
    addFieldBtnRef.current?.focus();
  }

  function handleMoveField(index: number, direction: -1 | 1) {
    setFields((fs) => {
      const target = index + direction;
      if (target < 0 || target >= fs.length) return fs;
      const next = fs.slice();
      [next[index], next[target]] = [next[target], next[index]];
      return next;
    });
  }

  const canSave = form.title.trim().length > 0 && !loading && !loadError;

  function buildNewFields(): NewField[] {
    return fields
      .filter((f) => f.value !== "" || f.fixed)
      .map((f) => ({
        template_id: f.template_id,
        name: f.name,
        value: f.value === "" ? null : f.value,
        is_protected: f.is_protected,
        field_type: f.field_type,
      }));
  }

  function buildFieldInputs(): FieldInput[] {
    return fields
      .filter((f) => !(f.id === null && f.name.trim() === "" && f.value === ""))
      .map((f): FieldInput => {
        if (f.id !== null && f.is_protected && !f.dirty) {
          return {
            id: f.id,
            template_id: f.template_id,
            name: f.name,
            is_protected: f.is_protected,
            field_type: f.field_type,
            value: { kind: "keep" },
          };
        }
        const value: FieldValue = f.value === "" ? { kind: "clear" } : { kind: "set", value: f.value };
        return {
          id: f.id,
          template_id: f.template_id,
          name: f.name,
          is_protected: f.is_protected,
          field_type: f.field_type,
          value,
        };
      });
  }

  function toggleTag(id: string) {
    setSelectedTagIds((cur) => (cur.includes(id) ? cur.filter((t) => t !== id) : [...cur, id]));
  }

  async function handleCreateTag(name: string): Promise<string | null> {
    try {
      const tag = await createTag(name, null);
      await refreshTags();
      return tag.id;
    } catch (e) {
      console.error("create_tag failed:", e);
      return null;
    }
  }

  function draftUrl(): string {
    const f = fields.find(
      (fld) => !fld.is_protected && (fld.field_type === "url" || fld.template_id === "tpl_url"),
    );
    return f?.value ?? "";
  }

  async function handleSuggest() {
    if (suggesting) return;
    const title = form.title.trim();
    const url = draftUrl().trim();
    if (entryId === null && !title && !url) return;
    const token = ++suggestTokenRef.current;
    setSuggesting(true);
    try {
      const [folderRes, tagRes] =
        entryId === null
          ? await Promise.all([
              aiSuggestFoldersForDraft(title, url, entryType, 3),
              aiSuggestTagsForDraft(title, url, entryType, 3),
            ])
          : await Promise.all([aiSuggestFolders(entryId, 3), aiSuggestTags(entryId, 3)]);
      if (suggestTokenRef.current !== token) return;
      setFolderSuggestions(folderRes);
      setTagSuggestions(tagRes);
      setSuggested(true);
    } catch (e) {
      console.error("ai suggest failed:", e);
      if (suggestTokenRef.current === token) {
        setFolderSuggestions([]);
        setTagSuggestions([]);
        setSuggested(true);
      }
    } finally {
      if (suggestTokenRef.current === token) setSuggesting(false);
    }
  }

  function applyFolderSuggestion(id: string) {
    setFolderId(id);
  }
  function applyTagSuggestion(id: string) {
    setSelectedTagIds((prev) => (prev.includes(id) ? prev : [...prev, id]));
  }

  async function handleSave() {
    if (!canSave || saving) return;
    setSaveError(null);
    setSaving(true);
    try {
      let savedId: string;
      if (entryId === null) {
        const newEntry: NewEntry = {
          title: form.title.trim(),
          folder_id: folderId,
          notes: form.notes.trim() ? form.notes : null,
          entry_type: entryType,
          fields: buildNewFields(),
        };
        const created = await createEntry(newEntry);
        savedId = created.id;
      } else {
        const patch: EntryPatch = {
          title: form.title.trim(),
          notes: form.notes,
          is_favorite: isFavorite,
          folder_id: folderId,
          fields: buildFieldInputs(),
        };
        await updateEntry(entryId, patch);
        savedId = entryId;
      }
      await setEntryTags(savedId, selectedTagIds);
      if (entryId !== null) onSaved?.();
      await refreshEntries();
      await refreshTags();
      await refreshFolders();
      onClose();
    } catch (err) {
      setSaveError(String(err));
    } finally {
      setSaving(false);
    }
  }

  async function handleAddFile() {
    if (entryId === null || uploading) return;
    setUploading(true);
    try {
      const path = await pickAnyFile();
      if (!path) return;
      const meta = await uploadAttachment(entryId, path);
      if (entryIdRef.current !== entryId) return;
      setAttachments((prev) => [...prev, meta]);
      await refreshEntries();
    } catch (e) {
      console.error("upload_attachment failed:", e);
      setSaveError(String(e));
    } finally {
      setUploading(false);
    }
  }

  async function handleRemoveAttachment(id: string) {
    try {
      await deleteAttachment(id);
      setAttachments((prev) => prev.filter((a) => a.id !== id));
      await refreshEntries();
    } catch (e) {
      console.error("delete_attachment failed:", e);
      setSaveError(String(e));
    }
  }

  return (
    <div
      className="kv-slideover"
      role="dialog"
      aria-modal="true"
      aria-label={entryId ? t("editor.editEntryTitle") : t("editor.newEntryTitle")}
    >
        <div className="kv-slideover-head">
          <h2>{entryId ? t("editor.editEntryTitle") : t("editor.newEntryTitle")}</h2>
          <button
            type="button"
            className="kv-btn is-icon"
            onClick={onClose}
            disabled={saving}
            aria-label={t("editor.close")}
          >
            <CloseIcon />
          </button>
        </div>
        <div className="kv-slideover-body">
          <div className="kv-editor-inner">
          {loading ? (
            <p className="kv-editor-status">{t("common.loading")}</p>
          ) : loadError ? (
            <p className="kv-editor-status">{t("editor.loadError")}</p>
          ) : (
            <>
              {entryId === null ? (
                <EntryTypeSelect value={entryType} onChange={onChangeType} disabled={saving} />
              ) : (
                <div className="kv-editor-type-chip" style={{ color: entryTypeMeta(entryType).color }}>
                  {t(entryTypeMeta(entryType).labelKey)}
                </div>
              )}
              <FloatInput
                label={entryId === null ? t(entryTypeMeta(entryType).titleLabelKey) : t("editor.titleLabel")}
                value={form.title}
                onChange={(v) => setForm((f) => ({ ...f, title: v }))}
                autoFocus
                disabled={saving}
              />
              {fields.map((row, i) => (
                <Fragment key={row.clientKey}>
                  <div className="kv-field-row">
                    <div className="kv-field-row-main">
                      <EditableFieldRow
                        row={row}
                        disabled={saving}
                        entryType={entryType}
                        revealing={row.id !== null && !!revealingIds[row.id]}
                        onReveal={() => void handleReveal(row)}
                        generatorOpen={generatorFor === row.clientKey}
                        onToggleGenerator={() =>
                          setGeneratorFor((cur) => (cur === row.clientKey ? null : row.clientKey))
                        }
                        onChange={(v) =>
                          setFields((fs) => fs.map((f, j) => (j === i ? { ...f, value: v, dirty: true } : f)))
                        }
                        onNameChange={(v) =>
                          setFields((fs) => fs.map((f, j) => (j === i ? { ...f, name: v, dirty: true } : f)))
                        }
                        onTypeChange={(t) =>
                          setFields((fs) =>
                            fs.map((f, j) =>
                              j === i
                                ? {
                                    ...f,
                                    field_type: t,
                                    is_protected: t === "secret" || t === "otp",
                                    value:
                                      t === "date" && !/^\d{4}-\d{2}-\d{2}$/.test(f.value) ? "" : f.value,
                                    dirty: true,
                                  }
                                : f,
                            ),
                          )
                        }
                        templates={templates}
                        onPickTemplate={(templateId) =>
                          setFields((fs) =>
                            fs.map((f, j) => {
                              if (j !== i) return f;
                              const t = templates.find((x) => x.id === templateId);
                              if (!t) return f;
                              return {
                                ...f,
                                template_id: t.id,
                                name: t.name,
                                field_type: t.field_type,
                                is_protected: t.is_protected,
                                dirty: true,
                              };
                            }),
                          )
                        }
                        onChooseCustom={() =>
                          setFields((fs) => fs.map((f, j) => (j === i ? { ...f, customChosen: true } : f)))
                        }
                      />
                    </div>
                    <div className="kv-field-row-actions">
                      <button
                        type="button"
                        className="kv-btn is-icon"
                        title={t("editor.moveUp")}
                        aria-label={t("editor.moveFieldUp", { name: row.name || t("editor.fieldFallback") })}
                        disabled={saving || i === 0}
                        onClick={() => handleMoveField(i, -1)}
                      >
                        <ChevronUpIcon />
                      </button>
                      <button
                        type="button"
                        className="kv-btn is-icon"
                        title={t("editor.moveDown")}
                        aria-label={t("editor.moveFieldDown", { name: row.name || t("editor.fieldFallback") })}
                        disabled={saving || i === fields.length - 1}
                        onClick={() => handleMoveField(i, 1)}
                      >
                        <ChevronDownIcon />
                      </button>
                      <button
                        type="button"
                        className="kv-btn is-icon"
                        title={t("editor.removeFieldTitle")}
                        aria-label={t("editor.removeFieldNamed", { name: row.name || t("editor.fieldFallback") })}
                        disabled={saving}
                        onClick={() => handleRemoveField(i)}
                      >
                        <RemoveTagIcon />
                      </button>
                    </div>
                  </div>
                  {generatorFor === row.clientKey &&
                  row.field_type === "secret" &&
                  row.template_id === "tpl_password" ? (
                    <div className="kv-generator-inline">
                      <GeneratorPopover
                        onUse={(password) =>
                          setFields((fs) =>
                            fs.map((f) =>
                              f.clientKey === row.clientKey
                                ? { ...f, value: password, dirty: true, revealed: true }
                                : f,
                            ),
                          )
                        }
                        onClose={() => setGeneratorFor(null)}
                        disabled={saving}
                      />
                    </div>
                  ) : null}
                </Fragment>
              ))}
              <button
                type="button"
                ref={addFieldBtnRef}
                className="kv-btn is-ghost is-block"
                disabled={saving}
                onClick={handleAddField}
              >
                {t("editor.addField")}
              </button>
              <div className="kv-float has-value">
                <select
                  id={folderSelectId}
                  className="kv-input"
                  value={folderId}
                  disabled={saving}
                  onChange={(e) => setFolderId(e.target.value)}
                >
                  {flattenFolders(folders).map(({ node, depth }) => (
                    <option key={node.id} value={node.id}>
                      {" ".repeat(depth) + node.name}
                    </option>
                  ))}
                </select>
                <label htmlFor={folderSelectId}>{t("editor.folderLabel")}</label>
              </div>
              {aiOn ? (
                <div className="kv-editor-suggest">
                  <button
                    type="button"
                    className="kv-btn is-ghost kv-suggest-trigger"
                    disabled={
                      saving ||
                      suggesting ||
                      (entryId === null && !form.title.trim() && !draftUrl().trim())
                    }
                    onClick={handleSuggest}
                  >
                    {suggesting ? t("editor.suggestLoading") : t("editor.suggest")}
                  </button>
                  {suggested && folderSuggestions.length === 0 && tagSuggestions.length === 0 ? (
                    <span className="kv-suggest-empty">{t("editor.suggestNone")}</span>
                  ) : null}
                  {folderSuggestions.length > 0 ? (
                    <div className="kv-suggest-row">
                      <span className="kv-suggest-label">{t("editor.suggestFolders")}</span>
                      <div
                        className="kv-suggest-chips"
                        role="list"
                        aria-label={t("editor.suggestFolders")}
                      >
                        {folderSuggestions.map((sug) => (
                          <button
                            key={sug.folder_id}
                            type="button"
                            role="listitem"
                            className="kv-suggest-chip"
                            disabled={saving || folderId === sug.folder_id}
                            onClick={() => applyFolderSuggestion(sug.folder_id)}
                            title={t("editor.suggestApply", { name: sug.name })}
                          >
                            {sug.name}
                            <span className="kv-suggest-score">
                              {Math.round(sug.score * 100)}%
                            </span>
                          </button>
                        ))}
                      </div>
                    </div>
                  ) : null}
                  {tagSuggestions.length > 0 ? (
                    <div className="kv-suggest-row">
                      <span className="kv-suggest-label">{t("editor.suggestTags")}</span>
                      <div
                        className="kv-suggest-chips"
                        role="list"
                        aria-label={t("editor.suggestTags")}
                      >
                        {tagSuggestions.map((sug) => {
                          const added = selectedTagIds.includes(sug.tag_id);
                          return (
                            <button
                              key={sug.tag_id}
                              type="button"
                              role="listitem"
                              className="kv-suggest-chip"
                              disabled={saving || added}
                              onClick={() => applyTagSuggestion(sug.tag_id)}
                              title={t("editor.suggestApply", { name: sug.name })}
                            >
                              <span
                                className="kv-tag-dot"
                                style={{ background: tagColor(sug.color) }}
                              />
                              {sug.name}
                              <span className="kv-suggest-score">
                                {Math.round(sug.score * 100)}%
                              </span>
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  ) : null}
                </div>
              ) : null}
              <TagMultiSelect
                tags={tags}
                selected={selectedTagIds}
                onToggle={toggleTag}
                onCreate={handleCreateTag}
                disabled={saving}
              />
              <FloatInput
                label={t("editor.notesLabel")}
                value={form.notes}
                onChange={(v) => setForm((f) => ({ ...f, notes: v }))}
                textarea
                disabled={saving}
              />
              {entryId !== null ? (
                <div className="kv-attach-section">
                  <div className="kv-field-label">{t("editor.attachmentsLabel")}</div>
                  {attachments.length > 0 ? (
                    <div className="kv-attach-list">
                      {attachments.map((a) => (
                        <div key={a.id} className="kv-manage-row">
                          <ClipIcon />
                          <div className="kv-attach-info">
                            <span className="kv-attach-name">{a.filename}</span>
                            <span className="kv-attach-meta">{formatBytes(a.size)}</span>
                          </div>
                          <button
                            type="button"
                            className="kv-btn is-icon"
                            title={t("editor.attachmentRemove")}
                            aria-label={t("editor.attachmentRemoveNamed", { name: a.filename })}
                            disabled={saving}
                            onClick={() => handleRemoveAttachment(a.id)}
                          >
                            <RemoveTagIcon />
                          </button>
                        </div>
                      ))}
                    </div>
                  ) : null}
                  <button
                    type="button"
                    className="kv-btn is-ghost is-block"
                    disabled={saving || uploading}
                    onClick={handleAddFile}
                  >
                    {uploading ? t("editor.uploading") : t("editor.addFile")}
                  </button>
                </div>
              ) : null}
            </>
          )}
          </div>
        </div>
        <div className="kv-slideover-foot">
          <button type="button" className="kv-btn is-ghost" onClick={onClose} disabled={saving}>
            {t("common.cancel")}
          </button>
          <button
            type="button"
            className="kv-btn is-primary"
            disabled={!canSave || saving}
            onClick={handleSave}
          >
            {entryId ? t("editor.saveChanges") : t("editor.createEntry")}
          </button>
        </div>
    </div>
  );
}
