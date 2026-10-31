import type { EntryType } from "./entryTypes";
import type { ImportProposal, EntryKindAI, FieldTypeAI, CommitProposal, CommitEntry, CommitField } from "../ipc/types";

/** Fields at or below this confidence get the low-confidence highlight. */
export const LOW_CONFIDENCE = 0.5;

/** kokos-ai EntryKind → vault entry_type. login/apiKey/totp collapse to
 *  "login"; secureNote → "secure_note"; wifi → "wifi". card is reachable
 *  only by a user re-pick. */
const KIND_TO_ENTRY_TYPE: Record<EntryKindAI, EntryType> = {
  login: "login",
  apiKey: "login",
  secureNote: "secure_note",
  totp: "login",
  wifi: "wifi",
};

interface VaultFieldSeed { name: string; fieldType: string; isProtected: boolean; }
/** kokos-ai FieldType → (display name, vault field_type, is_protected). The seven vault
 *  field_type values are text|secret|url|email|otp|date|phone. secret/otp are protected. */
const FIELD_MAP: Record<FieldTypeAI, VaultFieldSeed> = {
  login:            { name: "Username",          fieldType: "text",   isProtected: false },
  password:         { name: "Password",          fieldType: "secret", isProtected: true  },
  url:              { name: "URL",               fieldType: "url",    isProtected: false },
  email:            { name: "Email",             fieldType: "email",  isProtected: false },
  totpSecret:       { name: "TOTP secret",       fieldType: "otp",    isProtected: true  },
  apiKey:           { name: "API key",           fieldType: "secret", isProtected: true  },
  securityQuestion: { name: "Security question", fieldType: "text",   isProtected: false },
  securityAnswer:   { name: "Security answer",   fieldType: "secret", isProtected: true  },
  note:             { name: "Note",              fieldType: "text",   isProtected: false },
  phone:            { name: "Phone",             fieldType: "phone",  isProtected: false },
  // Same name as the Wi-Fi default field in kokos-core (entries::default_fields).
  ssid:             { name: "Network name (SSID)", fieldType: "text", isProtected: false },
};

/** Default display name per vault field_type — used to relabel a field when the
 * user changes its type in the review UI (GUI). */
const VAULT_TYPE_DEFAULT_NAME: Record<string, string> = {
  text: "Text",
  secret: "Password",
  url: "URL",
  email: "Email",
  otp: "TOTP secret",
  date: "Date",
  phone: "Phone",
};

/** Names the app itself generated (the FIELD_MAP seeds + the per-type defaults).
 *  A field whose name is still one of these is treated as auto-labeled → safe to
 *  relabel on a type change; a name the user typed is left alone. */
const AUTO_FIELD_NAMES = new Set<string>([
  ...Object.values(FIELD_MAP).map((m) => m.name),
  ...Object.values(VAULT_TYPE_DEFAULT_NAME),
]);

export function defaultFieldName(vaultType: string): string {
  return VAULT_TYPE_DEFAULT_NAME[vaultType] ?? "Field";
}
export function isAutoFieldName(name: string): boolean {
  return AUTO_FIELD_NAMES.has(name);
}

/** A single-value folder destination: an existing folder id (may be "root") OR
 * a new folder name to create-under-root at commit. Shared by the
 *  per-entry picker and the header "Set all" bulk control. */
export type FolderChoice = { mode: "existing"; id: string } | { mode: "new"; name: string };

export interface DraftField { name: string; fieldType: string; isProtected: boolean; value: string; confidence: number; }
export interface DraftEntry { title: string; entryType: EntryType; fields: DraftField[]; folder: FolderChoice; sourceFile: string | null; sourceFolder: string | null; sourceText: string | null; }

/** The default destination for an entry when the review opens. Folder
 *  imports carry a `sourceFolder` (the enclosing subfolder name): match it against
 *  an existing folder by name → point there; else propose a new folder of that name
 *  (created + deduped at commit). Paste / single-file (no sourceFolder) → Root. This
 *  mirrors the source folder structure into the vault by default. */
export function initialFolderChoice(sourceFolder: string | null, flatFolders: { id: string; name: string }[]): FolderChoice {
  if (!sourceFolder) return { mode: "existing", id: "root" };
  const match = flatFolders.find((f) => f.name.toLowerCase() === sourceFolder.toLowerCase());
  return match ? { mode: "existing", id: match.id } : { mode: "new", name: sourceFolder };
}

/** Seed the editable review model from the analyze proposal, in vault-type space.
 *  `flatFolders` (the vault's folders, pre-flattened by the caller) seeds each
 *  entry's default destination — see `initialFolderChoice`. */
export function seedDrafts(p: ImportProposal, flatFolders: { id: string; name: string }[] = []): DraftEntry[] {
  return p.entries.map((e) => {
    const fields: DraftField[] = e.fields.map((f) => {
      const m = FIELD_MAP[f.fieldType];
      return { name: m.name, fieldType: m.fieldType, isProtected: m.isProtected, value: f.value, confidence: f.confidence };
    });
    const sourceFolder = folderOf(e.sourceFile);
    return {
      title: e.title ?? deriveTitle(fields, e.sourceFile),
      entryType: KIND_TO_ENTRY_TYPE[e.kind],
      fields,
      folder: initialFolderChoice(sourceFolder, flatFolders),
      sourceFile: e.sourceFile,
      sourceFolder,
      sourceText: e.sourceText,
    };
  });
}

/** A null title (ProposedEntry.title) becomes the filename stem
 *  (codeanywhere.com.txt → codeanywhere.com), else the first URL/email value, else
 * a generic label — entries::create requires a non-empty String. The
 *  filename wins: these files are typically named for the site, a far better title
 *  than an incidental login email. */
function deriveTitle(fields: DraftField[], sourceFile: string | null): string {
  const stem = sourceFile ? fileStem(baseName(sourceFile)) : "";
  if (stem) return stem;
  const host = fields.find((f) => f.fieldType === "url")?.value
    ?? fields.find((f) => f.fieldType === "email")?.value;
  return host && host.trim() ? host.trim() : "Imported entry";
}

/** Last path segment. Handles both '/' and '\\' separators; trims trailing slashes. */
export function baseName(path: string): string {
  const norm = path.replace(/\\/g, "/").replace(/\/+$/, "");
  const parts = norm.split("/");
  return parts[parts.length - 1] || norm;
}

/** Enclosing folder NAME (second-to-last segment), or null when the path has no parent. */
function folderOf(path: string | null): string | null {
  if (!path) return null;
  const norm = path.replace(/\\/g, "/").replace(/\/+$/, "");
  const parts = norm.split("/");
  return parts.length >= 2 ? parts[parts.length - 2] || null : null;
}

/** Filename without its last extension. A leading-dot dotfile (.env) is kept whole. */
function fileStem(name: string): string {
  const dot = name.lastIndexOf(".");
  return dot > 0 ? name.slice(0, dot) : name;
}

/** Reverse: the reviewed drafts → the snake_case CommitProposal payload for the commit command. */
export function draftsToCommit(entries: DraftEntry[]): CommitProposal {
  return {
    entries: entries.map((e): CommitEntry => ({
      title: e.title,
      entry_type: e.entryType,
      folder_id: e.folder.mode === "existing" ? e.folder.id : null,
      new_folder_name: e.folder.mode === "new" ? e.folder.name : null,
      fields: e.fields.map((f): CommitField => ({
        name: f.name,
        field_type: f.fieldType,
        is_protected: f.isProtected,
        value: f.value,
      })),
    })),
  };
}
