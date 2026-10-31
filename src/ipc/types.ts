export interface StatusInfo {
  open: boolean;
  locked: boolean;
  path: string | null;
  hint: string | null;
  migrated: boolean;
}

export interface SyncStatusInfo {
  kind: "none" | "folder" | "gdrive";
  folder_path: string | null;
  gdrive_connected: boolean;
  last_sync: number;
  conflicts: string[];
  not_synced_warning: boolean;
  note: string | null;
}

export interface SyncOutcome {
  pushed: boolean;
  pulled: boolean;
  requires_reopen: boolean;
  remote_newer: boolean;
  conflicts: string[];
}

export interface TagRef {
  id: string;
  name: string;
  color: string | null;
}

export interface EntrySummary {
  id: string;
  title: string;
  username: string | null;
  is_favorite: boolean;
  has_totp: boolean;
  has_attachments: boolean;
  updated_at: number;
  folder_id: string | null;
  tags: TagRef[];
  entry_type: string;
  password_field_id: string | null;
}

export interface WeakField {
  entry_id: string;
  title: string;
  field_name: string;
  strength: number;
}

export interface HealthEntryRef {
  entry_id: string;
  title: string;
}

export interface ReusedGroup {
  count: number;
  entries: HealthEntryRef[];
}

export interface HealthReport {
  weak: WeakField[];
  reused: ReusedGroup[];
}

export interface CompromisedField {
  entry_id: string;
  title: string;
  field_name: string;
  count: number;
}

export interface HibpReport {
  compromised: CompromisedField[];
  checked: boolean;
  offline: boolean;
  enabled: boolean;
}

export interface SearchFilters {
  folder_id?: string | null;
  tag_id?: string | null;
  favorites_only?: boolean;
  regex?: boolean;
}

export interface Field {
  id: string;
  template_id: string | null;
  name: string;
  value: string | null;
  is_protected: boolean;
  field_type: string;
  sort_order: number;
  strength: number | null;
}

export interface Entry {
  id: string;
  folder_id: string | null;
  title: string;
  notes: string | null;
  is_favorite: boolean;
  created_at: number;
  updated_at: number;
  fields: Field[];
  tags: TagRef[];
  entry_type: string;
}

export interface NewField {
  template_id: string | null;
  name: string;
  value: string | null;
  is_protected: boolean;
  field_type: string;
}

export interface NewEntry {
  title: string;
  folder_id: string | null;
  notes: string | null;
  entry_type: string;
  fields: NewField[];
}

export interface FieldSeed {
  template_id: string | null;
  name: string;
  value: string | null;
  is_protected: boolean;
  field_type: string;
}

export type FieldValue =
  | { kind: "keep" }
  | { kind: "set"; value: string }
  | { kind: "clear" };

export interface FieldInput {
  id: string | null;
  template_id: string | null;
  name: string;
  is_protected: boolean;
  field_type: string;
  value: FieldValue;
}

export interface EntryPatch {
  title?: string;
  notes?: string;
  is_favorite?: boolean;
  folder_id?: string;
  fields?: FieldInput[];
}

export type View = "all" | "favorites" | "recent";

export interface Folder {
  id: string;
  parent_id: string | null;
  name: string;
  sort_order: number;
}

export interface FolderNode {
  id: string;
  parent_id: string | null;
  name: string;
  sort_order: number;
  entry_count: number;
  children: FolderNode[];
}

export interface Tag {
  id: string;
  name: string;
  color: string | null;
  usage: number;
}

export interface FieldTemplate {
  id: string;
  name: string;
  field_type: string;
  is_protected: boolean;
  sort_order: number;
  is_builtin: boolean;
}

export interface TrashItem {
  id: string;
  title: string;
  folder_name: string | null;
  deleted_at: number | null;
  updated_at: number;
}

export interface RecentFile {
  path: string;
  last_opened: number;
  has_keyfile: boolean;
}

export interface RestoreFile {
  id: string;
  name: string;
  modified_time: string;
  size: number | null;
  vault_name: string | null;
  note: string | null;
}

export const MAX_HINT_BYTES = 255;

export interface HeaderInfo {
  hint: string;
  requires_keyfile: boolean;
  format_version: number;
}

export interface AttachmentMeta {
  id: string;
  entry_id: string;
  filename: string;
  mime_type: string | null;
  size: number;
  created_at: number;
}

export interface AttachmentBytes {
  mime: string | null;
  filename: string;
  size: number;
  data_base64: string;
}

export interface RelationView {
  relation_id: string;
  other_id: string;
  other_title: string;
  other_is_deleted: boolean;
  relation_type: string;
}

export interface HistoryEntry {
  id: string;
  value: string | null;
  changed_at: number;
}

export interface AuditEntry {
  event: string;
  detail: string | null;
  created_at: number;
}

export interface GenOpts {
  length: number;
  upper: boolean;
  lower: boolean;
  digits: boolean;
  symbols: boolean;
  min_upper: number;
  min_lower: number;
  min_digits: number;
  min_symbols: number;
}

export interface TotpCode {
  code: string;
  remaining: number;
  period: number;
}

export interface ImportReport {
  entries: number;
  folders_new: number;
  tags_new: number;
  templates_new: number;
  relations: number;
  skipped_relations: number;
  skipped_attachments: number;
}

export type EntryKindAI = "login" | "apiKey" | "secureNote" | "totp" | "wifi";
export type FieldTypeAI =
  | "login" | "password" | "url" | "email"
  | "totpSecret" | "apiKey" | "securityQuestion" | "securityAnswer" | "note" | "phone" | "ssid";
export interface ProposedField {
  fieldType: FieldTypeAI;
  value: string;
  confidence: number;
}
export interface ProposedEntry {
  title: string | null;
  kind: EntryKindAI;
  sourceFile: string | null;
  sourceText: string | null;
  fields: ProposedField[];
}
export interface UnparsedBlock {
  text: string;
  sourceFile: string | null;
}
export interface ImportProposal {
  entries: ProposedEntry[];
  unparsed: UnparsedBlock[];
  entries_dropped: number;
}
export interface CommitField {
  name: string;
  field_type: string;
  is_protected: boolean;
  value: string;
}
export interface CommitEntry {
  title: string;
  entry_type: string;
  fields: CommitField[];
  folder_id?: string | null;
  new_folder_name?: string | null;
}
export interface CommitProposal {
  entries: CommitEntry[];
}
export interface TextImportReport {
  imported: number;
  failed: number;
}
export interface GenModelStatus {
  present: boolean;
}
export interface GenDownloadStatus {
  active: boolean;
  what: string;
  downloaded: number;
  total: number;
}

export interface AiStatus {
  enabled: boolean;
  model_id: string;
  model_present: boolean;
}
export interface AiIndexStatus {
  model_id: string;
  indexed: number;
  total: number;
}

export interface SemanticHit {
  entry: EntrySummary;
  score: number;
}

export interface FolderSuggestion {
  folder_id: string;
  name: string;
  score: number;
}

export interface TagSuggestion {
  tag_id: string;
  name: string;
  color: string | null;
  score: number;
}

export interface OrganizeEntry {
  entry_id: string;
  title: string;
  score: number;
}
export interface OrganizeGroup {
  kind: "existing" | "new";
  folder_id: string | null;
  name: string;
  score: number;
  entries: OrganizeEntry[];
}
export interface OrganizeProposal {
  groups: OrganizeGroup[];
}
export interface OrganizeApplyGroup {
  folder_id: string | null;
  new_folder_name: string | null;
  entry_ids: string[];
}
