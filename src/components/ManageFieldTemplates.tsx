import { useEffect, useState } from "react";
import { useVault } from "../state/VaultContext";
import { useT } from "../state/LangContext";
import { createTemplate, deleteTemplate, updateTemplate } from "../ipc/commands";
import type { FieldTemplate } from "../ipc/types";
import "./ManageFieldTemplates.css";

type ManageIcon = "plus" | "trash" | "chevronLeft";

const ICON_PATHS: Record<ManageIcon, React.ReactNode> = {
  plus: <path d="M12 5.5v13M5.5 12h13" />,
  trash: (
    <g>
      <path d="M4.5 7h15" />
      <path d="M9.5 7V5.2A1.2 1.2 0 0110.7 4h2.6a1.2 1.2 0 011.2 1.2V7" />
      <path d="M6.5 7l.8 12a1.5 1.5 0 001.5 1.4h6.4a1.5 1.5 0 001.5-1.4l.8-12" />
      <path d="M10 11v5.5M14 11v5.5" />
    </g>
  ),
  chevronLeft: <path d="M14.5 6.5l-5.5 5.5 5.5 5.5" />,
};

function Icon({
  name,
  size = 15,
  strokeWidth = 1.7,
  style,
}: {
  name: ManageIcon;
  size?: number;
  strokeWidth?: number;
  style?: React.CSSProperties;
}) {
  return (
    <svg
      style={style}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {ICON_PATHS[name]}
    </svg>
  );
}

const FIELD_TYPES: { value: string; labelKey: string }[] = [
  { value: "text", labelKey: "fieldType.text" },
  { value: "secret", labelKey: "fieldType.secret" },
  { value: "url", labelKey: "fieldType.url" },
  { value: "email", labelKey: "fieldType.email" },
  { value: "otp", labelKey: "fieldType.otp" },
  { value: "date", labelKey: "fieldType.date" },
  { value: "phone", labelKey: "fieldType.phone" },
];

function TemplateRow({
  template,
  onUpdate,
  onDelete,
}: {
  template: FieldTemplate;
  onUpdate: (id: string, name: string, fieldType: string, isProtected: boolean) => void;
  onDelete: (id: string) => void;
}) {
  const t = useT();
  const [name, setName] = useState(template.name);
  useEffect(() => setName(template.name), [template.id, template.name]);

  function commit() {
    const trimmed = name.trim();
    if (trimmed && trimmed !== template.name) {
      onUpdate(template.id, trimmed, template.field_type, template.is_protected);
    } else {
      setName(template.name);
    }
  }

  const builtin = template.is_builtin;

  return (
    <div className="kv-manage-row">
      <input
        className="kv-input"
        value={name}
        aria-label={t("templates.nameAriaLabel")}
        disabled={builtin}
        title={builtin ? t("templates.builtinNoRename") : undefined}
        onChange={(e) => setName(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => {
          if (e.key === "Enter") e.currentTarget.blur();
        }}
        autoCapitalize="off"
        autoCorrect="off"
        spellCheck={false}
      />
      <select
        className="kv-input kv-tpl-type"
        aria-label={t("templates.fieldTypeAriaLabel")}
        value={template.field_type}
        disabled={builtin}
        title={builtin ? t("templates.builtinNoTypeChange") : undefined}
        onChange={(e) => onUpdate(template.id, name.trim() || template.name, e.target.value, template.is_protected)}
      >
        {FIELD_TYPES.map((ft) => (
          <option key={ft.value} value={ft.value}>
            {t(ft.labelKey)}
          </option>
        ))}
      </select>
      <input
        type="checkbox"
        className="kv-tpl-protected"
        aria-label={t("templates.protected")}
        title={builtin ? t("templates.builtinNoProtectedChange") : t("templates.protected")}
        checked={template.is_protected}
        disabled={builtin}
        onChange={(e) => onUpdate(template.id, name.trim() || template.name, template.field_type, e.target.checked)}
      />
      {builtin ? (
        <span className="kv-count">{t("templates.builtin")}</span>
      ) : (
        <button
          type="button"
          className="kv-btn is-icon is-danger"
          title={t("templates.deleteTitle")}
          aria-label={t("common.deleteNamed", { name: template.name })}
          onClick={() => onDelete(template.id)}
        >
          <Icon name="trash" size={14} />
        </button>
      )}
    </div>
  );
}

/**
 * Full-page field-template management screen.
 * Clone of ManageTags.tsx: same `.kv-settings` page chrome (Back button +
 * `<h1>` + `.kv-settings-sub` + a `.kv-card` of rows + an add-row), same
 * row-is-a-child-component split — but simpler, since a template has no
 * color popover: a name (rename), a `field_type` select, and an
 * `is_protected` checkbox, all three written through the same
 * `update_template` call (the atomic name+type+protected update),
 * plus delete.
 *
 * Built-in templates (`is_builtin`) are fully read-only here — disabled
 * inputs/select/checkbox and a "Built-in" `.kv-count` label in place of the
 * delete button — mirroring how ManageFolders.tsx's FolderRow locks down
 * the root folder row. The backend enforces the same rule independently
 * (`update_template`/`delete_template` on a `tpl_*` id reject with
 * `TemplateProtected`); this UI half exists so the user never issues a call
 * the backend would reject anyway, not as the only guard.
 *
 * Unlike ManageTags.tsx's handlers, none of these refresh `refreshEntries`:
 * field templates are NOT denormalized onto `EntrySummary` the way tags
 * are (`EntrySummary.tags`) — an existing entry's fields carry their own
 * name/value/field_type independent of the template they were created
 * from, and deleting a user template only NULLs `entry_fields.template_id`
 * via the FK, which changes no displayed data. So a template mutation only
 * ever needs `refreshTemplates`.
 *
 * Rendered inside the Settings hub's "Templates" tab (hosted via
 * `embedded` — see the `body` split below) rather than as its own full-page
 * route; the standalone `<main>` return below is reachable only if a
 * caller renders this component un-embedded.
 */
export function ManageFieldTemplates({ embedded }: { embedded?: boolean }) {
  const { templates, refreshTemplates, setRoute } = useVault();
  const t = useT();
  const [newName, setNewName] = useState("");
  const [newType, setNewType] = useState("text");
  const [newProtected, setNewProtected] = useState(false);

  async function handleUpdate(id: string, name: string, fieldType: string, isProtected: boolean) {
    try {
      await updateTemplate(id, name, fieldType, isProtected);
      await refreshTemplates();
    } catch (e) {
      console.error("update_template failed:", e);
    }
  }

  async function handleDelete(id: string) {
    try {
      await deleteTemplate(id);
      await refreshTemplates();
    } catch (e) {
      console.error("delete_template failed:", e);
    }
  }

  async function handleAdd() {
    const n = newName.trim();
    if (!n) return;
    try {
      await createTemplate(n, newType, newProtected);
      setNewName("");
      setNewType("text");
      setNewProtected(false);
      await refreshTemplates();
    } catch (e) {
      console.error("create_template failed:", e);
    }
  }

  const body = (
    <>
      <p className="kv-settings-sub">{t("templates.subtitle")}</p>

      <div className="kv-card">
        {templates.map((template) => (
          <TemplateRow key={template.id} template={template} onUpdate={handleUpdate} onDelete={handleDelete} />
        ))}
        <div className="kv-manage-row">
          <input
            className="kv-input"
            placeholder={t("templates.newNamePlaceholder")}
            aria-label={t("templates.newNameAriaLabel")}
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") handleAdd();
            }}
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
          />
          <select
            className="kv-input kv-tpl-type"
            aria-label={t("templates.newFieldTypeAriaLabel")}
            value={newType}
            onChange={(e) => setNewType(e.target.value)}
          >
            {FIELD_TYPES.map((ft) => (
              <option key={ft.value} value={ft.value}>
                {t(ft.labelKey)}
              </option>
            ))}
          </select>
          <input
            type="checkbox"
            className="kv-tpl-protected"
            aria-label={t("templates.protected")}
            title={t("templates.protected")}
            checked={newProtected}
            onChange={(e) => setNewProtected(e.target.checked)}
          />
          <button type="button" className="kv-btn is-ghost" onClick={handleAdd}>
            <Icon name="plus" size={13} /> {t("templates.addTemplate")}
          </button>
        </div>
      </div>
    </>
  );

  if (embedded) return body;
  return (
    <main className="kv-settings" data-screen-label="Manage field templates page">
      <div className="kv-settings-inner">
        <button type="button" className="kv-btn is-ghost kv-settings-back" onClick={() => setRoute("main")}>
          <Icon name="chevronLeft" size={13} strokeWidth={2} /> {t("common.back")}
        </button>
        <h1>{t("templates.title")}</h1>
        {body}
      </div>
    </main>
  );
}
