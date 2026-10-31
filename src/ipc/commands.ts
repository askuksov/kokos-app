import { invoke } from "@tauri-apps/api/core";
import type { AttachmentBytes, AttachmentMeta, AuditEntry, Entry, EntryPatch, EntrySummary, FieldSeed, FieldTemplate, Folder, FolderNode, GenOpts, HealthReport, HeaderInfo, HibpReport, HistoryEntry, ImportReport, NewEntry, RecentFile, RelationView, RestoreFile, SearchFilters, StatusInfo, SyncOutcome, SyncStatusInfo, Tag, TotpCode, TrashItem, View, AiStatus, AiIndexStatus, SemanticHit, FolderSuggestion, TagSuggestion, OrganizeProposal, OrganizeApplyGroup, ImportProposal, CommitProposal, TextImportReport, GenModelStatus, GenDownloadStatus } from "./types";

export const vaultStatus = (vaultId?: string) => invoke<StatusInfo>("vault_status", { vaultId });
export const pickVaultPath = (mode: "open" | "save") =>
  invoke<string | null>("pick_vault_path", { mode });

export const createVault = (
  path: string,
  password: string,
  hint: string,
  kdf: { memory_kib: number; time_cost: number; parallelism: number },
  keyfilePath: string | null,
) => invoke<unknown>("create_vault", { path, password, hint, kdf, keyfilePath });

export const openVault = (path: string, password: string, keyfilePath: string | null) =>
  invoke<unknown>("open_vault", { path, password, keyfilePath });

export const lockVault = (vaultId?: string) => invoke<void>("lock_vault", { vaultId });
export const lockAll = () => invoke<void>("lock_all");
export const unlockVault = (password: string, keyfilePath: string | null) =>
  invoke<unknown>("unlock_vault", { password, keyfilePath });
export const keychainHas = (path: string) => invoke<boolean>("keychain_has", { path });
export const keychainUnlock = (path: string) => invoke<unknown>("keychain_unlock", { path });
export const keychainEnable = (masterPassword: string) => invoke<void>("keychain_enable", { masterPassword });
export const keychainDisable = () => invoke<void>("keychain_disable");
export const biometricAvailable = () => invoke<boolean>("biometric_available");
export const biometricHas = (path: string) => invoke<boolean>("biometric_has", { path });
export const touchidUnlock = (path: string) => invoke<unknown>("touchid_unlock", { path });
export const biometricEnable = (masterPassword: string) => invoke<void>("biometric_enable", { masterPassword });
export const biometricDisable = () => invoke<void>("biometric_disable");
export type KeyfileAction =
  | { kind: "keep" }
  | { kind: "set"; path: string }
  | { kind: "resupply"; path: string }
  | { kind: "remove" };

export const verifyPassword = (password: string, keyfilePath: string | null, vaultId?: string) =>
  invoke<boolean>("verify_password", { password, keyfilePath, vaultId });

export const changeMasterPassword = (
  newPassword: string,
  hint: string | null,
  keyfile: KeyfileAction,
  vaultId?: string,
) => invoke<void>("change_master_password", { newPassword, newHint: hint, keyfile, vaultId });
export const setVaultHint = (hint: string, vaultId?: string) =>
  invoke<void>("set_vault_hint", { hint, vaultId });
export const closeVault = () => invoke<void>("close_vault");
export const switchVault = (vaultId: string) => invoke<void>("switch_vault", { vaultId });
export const reorderVaults = (orderedIds: string[]) =>
  invoke<void>("reorder_vaults", { orderedIds });
export const saveVault = (vaultId?: string) => invoke<void>("save_vault", { vaultId });

export const listEntries = (view: View, vaultId?: string) => invoke<EntrySummary[]>("list_entries", { view, vaultId });
export const searchEntries = (query: string, filters: SearchFilters, vaultId?: string) =>
  invoke<EntrySummary[]>("search_entries", { query, filters, vaultId });
export const getEntry = (id: string, vaultId?: string) => invoke<Entry>("get_entry", { id, vaultId });
export const healthScan = (vaultId?: string) => invoke<HealthReport>("health_scan", { vaultId });
export const hibpCheck = (vaultId?: string) => invoke<HibpReport>("hibp_check", { vaultId });
export const createEntry = (entry: NewEntry, vaultId?: string) => invoke<Entry>("create_entry", { entry, vaultId });

export const aiStatus = () => invoke<AiStatus>("ai_status");
export const aiModelDownload = () => invoke<void>("ai_model_download");
export const aiModelDownloadCancel = () => invoke<void>("ai_model_download_cancel");
export const aiEnable = () => invoke<void>("ai_enable");
export const aiDisable = () => invoke<void>("ai_disable");
export const aiIndexStatus = () => invoke<AiIndexStatus>("ai_index_status");
export const aiBackfill = () => invoke<number>("ai_backfill");
export const aiBackfillCancel = () => invoke<void>("ai_backfill_cancel");

export const aiGenModelStatus = () => invoke<GenModelStatus>("ai_gen_model_status");
export const aiGenModelDownload = () => invoke<void>("ai_gen_model_download");
export const aiGenModelDownloadCancel = () => invoke<void>("ai_gen_model_download_cancel");
export const aiGenModelDownloadStatus = () => invoke<GenDownloadStatus>("ai_gen_model_download_status");
export const aiTextImportAnalyze = (paths: string[]) =>
  invoke<ImportProposal>("ai_text_import_analyze", { paths });
export const aiTextImportAnalyzeFolder = (dir: string) =>
  invoke<ImportProposal>("ai_text_import_analyze_folder", { dir });
export const aiTextImportCancel = () => invoke<void>("ai_text_import_cancel");
export const aiTextImportStash = (payload: string, vaultId?: string) =>
  invoke<void>("ai_text_import_stash", { payload, vaultId });
export const aiTextImportHasStash = (vaultId: string) => invoke<boolean>("ai_text_import_has_stash", { vaultId });
export const aiTextImportRestore = (vaultId?: string) => invoke<string | null>("ai_text_import_restore", { vaultId });
export const aiTextImportDiscard = (vaultId: string) => invoke<void>("ai_text_import_discard", { vaultId });
export const aiTextImportCommit = (proposal: CommitProposal, vaultId?: string) =>
  invoke<TextImportReport>("ai_text_import_commit", { proposal, vaultId });

export const aiSemanticSearch = (query: string, vaultId?: string, limit = 5) =>
  invoke<SemanticHit[]>("ai_semantic_search", { query, vaultId, limit });

export const aiSuggestFolders = (entryId: string, limit = 3, vaultId?: string) =>
  invoke<FolderSuggestion[]>("ai_suggest_folders", { entryId, limit, vaultId });
export const aiSuggestTags = (entryId: string, limit = 3, vaultId?: string) =>
  invoke<TagSuggestion[]>("ai_suggest_tags", { entryId, limit, vaultId });
export const aiSuggestFoldersForDraft = (
  title: string,
  url: string,
  entryType: string,
  limit = 3,
  vaultId?: string,
) =>
  invoke<FolderSuggestion[]>("ai_suggest_folders_for_draft", {
    title,
    url,
    entryType,
    limit,
    vaultId,
  });
export const aiSuggestTagsForDraft = (
  title: string,
  url: string,
  entryType: string,
  limit = 3,
  vaultId?: string,
) =>
  invoke<TagSuggestion[]>("ai_suggest_tags_for_draft", {
    title,
    url,
    entryType,
    limit,
    vaultId,
  });
export const addEntryTag = (entryId: string, tagId: string, vaultId?: string) =>
  invoke<void>("add_entry_tag", { entryId, tagId, vaultId });
export const aiOrganizeUnfiled = (vaultId?: string) =>
  invoke<OrganizeProposal>("ai_organize_unfiled", { vaultId });
export const aiApplyOrganize = (groups: OrganizeApplyGroup[], vaultId?: string) =>
  invoke<void>("ai_apply_organize", { groups, vaultId });
export const entryTypeDefaultFields = (entryType: string) => invoke<FieldSeed[]>("entry_type_default_fields", { entryType });
export const updateEntry = (id: string, patch: EntryPatch, vaultId?: string) =>
  invoke<Entry>("update_entry", { id, patch, vaultId });
export const deleteEntry = (id: string, vaultId?: string) => invoke<void>("delete_entry", { id, vaultId });
export const revealField = (entryId: string, fieldId: string, vaultId?: string) =>
  invoke<string>("reveal_field", { entryId, fieldId, vaultId });

export const totpCode = (entryId: string, fieldId: string, vaultId?: string) =>
  invoke<TotpCode>("totp_code", { entryId, fieldId, vaultId });

export const generatePassword = (opts: GenOpts) => invoke<string>("generate_password", { opts });

export const listFolders = (vaultId?: string) => invoke<FolderNode[]>("list_folders", { vaultId });
export const createFolder = (name: string, parentId: string | null, vaultId?: string) =>
  invoke<Folder>("create_folder", { name, parentId, vaultId });
export const renameFolder = (id: string, name: string, vaultId?: string) => invoke<Folder>("rename_folder", { id, name, vaultId });
export const moveFolder = (id: string, newParent: string | null, vaultId?: string) =>
  invoke<void>("move_folder", { id, newParent, vaultId });

export const reorderFolder = (id: string, targetId: string, place: "before" | "after", vaultId?: string) =>
  invoke<void>("reorder_folder", { id, targetId, place, vaultId });
export const deleteFolder = (id: string, vaultId?: string) => invoke<void>("delete_folder", { id, vaultId });

export const listTags = (vaultId?: string) => invoke<Tag[]>("list_tags", { vaultId });
export const createTag = (name: string, color: string | null, vaultId?: string) =>
  invoke<Tag>("create_tag", { name, color, vaultId });
export const renameTag = (id: string, name: string, vaultId?: string) => invoke<Tag>("rename_tag", { id, name, vaultId });
export const recolorTag = (id: string, color: string | null, vaultId?: string) =>
  invoke<Tag>("recolor_tag", { id, color, vaultId });
export const deleteTag = (id: string, vaultId?: string) => invoke<void>("delete_tag", { id, vaultId });

export const listTemplates = (vaultId?: string) => invoke<FieldTemplate[]>("list_templates", { vaultId });
export const createTemplate = (name: string, fieldType: string, isProtected: boolean, vaultId?: string) =>
  invoke<FieldTemplate>("create_template", { name, fieldType, isProtected, vaultId });
export const updateTemplate = (id: string, name: string, fieldType: string, isProtected: boolean, vaultId?: string) =>
  invoke<FieldTemplate>("update_template", { id, name, fieldType, isProtected, vaultId });
export const deleteTemplate = (id: string, vaultId?: string) => invoke<void>("delete_template", { id, vaultId });

export const listAttachments = (entryId: string, vaultId?: string) =>
  invoke<AttachmentMeta[]>("list_attachments", { entryId, vaultId });
export const uploadAttachment = (entryId: string, path: string, vaultId?: string) =>
  invoke<AttachmentMeta>("upload_attachment", { entryId, path, vaultId });
export const downloadAttachment = (id: string, path: string, vaultId?: string) =>
  invoke<void>("download_attachment", { id, path, vaultId });
export const deleteAttachment = (id: string, vaultId?: string) =>
  invoke<void>("delete_attachment", { id, vaultId });
export const readAttachmentBytes = (id: string, vaultId?: string) =>
  invoke<AttachmentBytes>("read_attachment_bytes", { id, vaultId });
export const pickAnyFile = () => invoke<string | null>("pick_any_file");
export const pickKdbxFile = () => invoke<string | null>("pick_kdbx_file");
export const pickSavePath = (defaultName: string) =>
  invoke<string | null>("pick_save_path", { defaultName });
export const pickFolder = () => invoke<string | null>("pick_folder");

export const listRelations = (entryId: string, vaultId?: string) =>
  invoke<RelationView[]>("list_relations", { entryId, vaultId });
export const addRelation = (sourceId: string, targetId: string, relationType: string, vaultId?: string) =>
  invoke<void>("add_relation", { sourceId, targetId, relationType, vaultId });
export const deleteRelation = (relationId: string, vaultId?: string) =>
  invoke<void>("delete_relation", { relationId, vaultId });

export const listFieldHistory = (entryId: string, fieldName: string, vaultId?: string) =>
  invoke<HistoryEntry[]>("list_field_history", { entryId, fieldName, vaultId });
export const clearFieldHistory = (entryId: string, fieldName: string, vaultId?: string) =>
  invoke<void>("clear_field_history", { entryId, fieldName, vaultId });

export const setEntryTags = (entryId: string, tagIds: string[], vaultId?: string) =>
  invoke<void>("set_entry_tags", { entryId, tagIds, vaultId });
export const toggleFavorite = (entryId: string, vaultId?: string) => invoke<boolean>("toggle_favorite", { entryId, vaultId });

export const listTrash = (vaultId?: string) => invoke<TrashItem[]>("list_trash", { vaultId });
export const restoreEntry = (id: string, vaultId?: string) => invoke<void>("restore_entry", { id, vaultId });
export const permanentDeleteEntry = (id: string, vaultId?: string) => invoke<void>("permanent_delete_entry", { id, vaultId });
export const emptyTrash = (vaultId?: string) => invoke<number>("empty_trash", { vaultId });

export const recentFiles = () => invoke<RecentFile[]>("recent_files");
export const getVaultHeaderInfo = (path: string) => invoke<HeaderInfo>("get_vault_header_info", { path });

export const takePendingOpen = (): Promise<string | null> => invoke("take_pending_open");

export const exportJson = (path: string, ids?: string[], vaultId?: string) =>
  invoke<void>("export_json", { path, ids: ids ?? null, vaultId });
export const exportVaultCopy = (path: string, vaultId?: string) => invoke<void>("export_vault_copy", { path, vaultId });
export const importJson = (path: string, vaultId?: string) => invoke<ImportReport>("import_json", { path, vaultId });
export const importKdbx = (path: string, password: string, vaultId?: string) =>
  invoke<ImportReport>("import_kdbx", { path, password, vaultId });

export const bulkDeleteEntries = (ids: string[], vaultId?: string) => invoke<number>("bulk_delete_entries", { ids, vaultId });
export const bulkMoveEntries = (ids: string[], folderId: string, vaultId?: string) => invoke<void>("bulk_move_entries", { ids, folderId, vaultId });
export const bulkSetTag = (ids: string[], tagId: string, add: boolean, vaultId?: string) => invoke<void>("bulk_set_tag", { ids, tagId, add, vaultId });

export type Settings = {
  lang: string; auto_lock_minutes: number; lock_on_blur: boolean; lock_on_sleep: boolean;
  clipboard_seconds: number; clear_clipboard_on_exit: boolean;
  conceal_on_blur: boolean; conceal_seconds: number; density: string;
  nmh_enabled: boolean; nmh_confirm_mode: string; nmh_session_minutes: number;
  nmh_chrome_ids: string[]; nmh_firefox_ids: string[];
  hibp_enabled: boolean;
  open_vaults: string[];
  active_vault: string | null;
  onboarding_eligible: boolean;
  onboarding_dismissed: boolean;
  onboarding_collapsed: boolean;
  onboarding_backup_done: boolean;
  onboarding_import_done: boolean;
  onboarding_sync_deferred: boolean;
};
export const getSettings = () => invoke<Settings>("get_settings");
export const setSettings = (settings: Settings) => invoke<void>("set_settings", { settings });
export const appVersion = () => invoke<string>("app_version");

export const hibpSetEnabled = (enabled: boolean) => invoke<void>("hibp_set_enabled", { enabled });

export const noteActivity = () => invoke<void>("note_activity");

export const listAudit = (limit: number, vaultId?: string) => invoke<AuditEntry[]>("list_audit", { limit, vaultId });
export const clearAudit = (vaultId?: string) => invoke<void>("clear_audit", { vaultId });

export const setClipboard = (text: string) => invoke<void>("set_clipboard", { text });
export const clearClipboard = () => invoke<void>("clear_clipboard");
export const clearClipboardIfUnchanged = (expected: string) =>
  invoke<void>("clear_clipboard_if_unchanged", { expected });

export const syncStatus = (vaultId?: string) => invoke<SyncStatusInfo>("sync_status", { vaultId });
export const syncSetFolder = (vaultId?: string) => invoke<void>("sync_set_folder", { vaultId });
export const syncDisable = (vaultId?: string) => invoke<void>("sync_disable", { vaultId });

export const gdriveConnect = (vaultId?: string) => invoke<void>("gdrive_connect", { vaultId });
export const gdriveDisconnect = (vaultId?: string) => invoke<void>("gdrive_disconnect", { vaultId });
export const gdriveConnectCancel = () => invoke<void>("gdrive_connect_cancel");

export const gdriveSetNote = (note: string, vaultId?: string) =>
  invoke<void>("gdrive_set_note", { note, vaultId });

export const syncNow = (vaultId?: string) => invoke<SyncOutcome>("sync_now", { vaultId });

export const detectRemoteChanges = (vaultId?: string) =>
  invoke<SyncOutcome>("detect_remote_changes", { vaultId });

export const restoreSignin = () => invoke<RestoreFile[]>("gdrive_restore_signin");
export const restoreDownload = (fileId: string, localPath: string) =>
  invoke<void>("gdrive_restore_download", { fileId, localPath });
export const restoreBind = () => invoke<void>("gdrive_restore_bind");
export const restoreCancel = () => invoke<void>("gdrive_restore_cancel");

export const nmhConfirmReply = (reqId: string, allowed: boolean, remember: boolean) =>
  invoke<void>("nmh_confirm_reply", { reqId, allowed, remember });

export type NmhStatus = {
  enabled: boolean;
  running: boolean;
  chrome_registered: boolean;
  firefox_registered: boolean;
  host_path: string | null;
  chrome_ids: string[];
  firefox_ids: string[];
};
export const nmhStatus = () => invoke<NmhStatus>("nmh_status");
export const nmhSetEnabled = (enabled: boolean) => invoke<void>("nmh_set_enabled", { enabled });
export const nmhInstall = (browser: string, extensionId: string) =>
  invoke<void>("nmh_install", { browser, extensionId });
export const nmhUninstall = (browser: string) => invoke<void>("nmh_uninstall", { browser });

export type NmhGrantDto = {
  origin: string;
  browser: string;
  domain: string;
  created_at: number;
  last_used_at: number | null;
};
export const nmhGrantsList = () => invoke<NmhGrantDto[]>("nmh_grants_list");
export const nmhGrantForget = (origin: string, domain: string) =>
  invoke<void>("nmh_grant_forget", { origin, domain });
export const nmhGrantsForgetOrigin = (origin: string) =>
  invoke<number>("nmh_grants_forget_origin", { origin });
