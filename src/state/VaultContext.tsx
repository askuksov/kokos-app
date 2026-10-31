import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import type { EntrySummary, FieldTemplate, FolderNode, SearchFilters, StatusInfo, Tag, View } from "../ipc/types";
import { listEntries, listFolders, listTags, listTemplates, searchEntries, vaultStatus } from "../ipc/commands";
import { backgroundReconcile } from "../lib/sync";
import { VAULT_CHANGED } from "../lib/events";

export type Nav =
  | { kind: "view"; view: View }
  | { kind: "folder"; id: string }
  | { kind: "tag"; id: string };

export type Route = "main" | "trash" | "manage-folders" | "manage-tags" | "settings";

export type SettingsTab =
  | "general" | "security" | "browser" | "sync" | "privacy" | "ai" | "data" | "templates" | "health" | "about";

export interface SearchUiFilters {
  favoritesOnly: boolean;
  regex: boolean;
}

const serverView = (nav: Nav): View => (nav.kind === "view" ? nav.view : "all");

interface VaultState {
  vaultId: string | undefined;
  status: StatusInfo | null;
  entries: EntrySummary[];
  entriesLoaded: boolean;
  visibleEntries: EntrySummary[];
  selectedId: string | null;
  nav: Nav;
  route: Route;
  folders: FolderNode[];
  tags: Tag[];
  templates: FieldTemplate[];
  saveError: string | null;
  remoteNewer: boolean;
  dismissRemoteNewer: () => void;
  search: string;
  setSearch: (s: string) => void;
  filters: SearchUiFilters;
  setFilters: (f: SearchUiFilters) => void;
  searchInputRef: React.RefObject<HTMLInputElement | null>;
  focusSearch: () => void;
  refreshStatus: () => Promise<void>;
  refreshEntries: () => Promise<void>;
  refreshFolders: () => Promise<void>;
  refreshTags: () => Promise<void>;
  refreshTemplates: () => Promise<void>;
  select: (id: string | null) => void;
  setNav: (n: Nav) => void;
  setRoute: (r: Route) => void;
  settingsTab: SettingsTab;
  setSettingsTab: (t: SettingsTab) => void;
  setSaveError: (e: string | null) => void;
}

const Ctx = createContext<VaultState | null>(null);

export function VaultProvider({ children, vaultId }: { children: React.ReactNode; vaultId?: string }) {
  const [status, setStatus] = useState<StatusInfo | null>(null);
  const [entries, setEntries] = useState<EntrySummary[]>([]);
  const [entriesLoaded, setEntriesLoaded] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [nav, setNavRaw] = useState<Nav>({ kind: "view", view: "all" });
  /// Navigating drops the selection: the selected entry may not belong to the
  /// new view, and leaving it selected would make the detail panel's
  /// no-selection state (the getting-started card) unreachable.
  const setNav = useCallback((n: Nav) => {
    setNavRaw(n);
    setSelectedId(null);
  }, []);
  const [route, setRoute] = useState<Route>("main");
  const [settingsTab, setSettingsTab] = useState<SettingsTab>("general");
  const [folders, setFolders] = useState<FolderNode[]>([]);
  const [tags, setTags] = useState<Tag[]>([]);
  const [templates, setTemplates] = useState<FieldTemplate[]>([]);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [remoteNewerRaw, setRemoteNewerRaw] = useState(false);
  const [remoteNewerDismissed, setRemoteNewerDismissed] = useState(false);
  const remoteNewer = remoteNewerRaw && !remoteNewerDismissed;
  const dismissRemoteNewer = useCallback(() => setRemoteNewerDismissed(true), []);
  const reconcileFiredRef = useRef(false);
  useEffect(() => {
    if (!vaultId || reconcileFiredRef.current) return;
    reconcileFiredRef.current = true;
    backgroundReconcile(vaultId).then((o) => {
      if (o?.remote_newer) setRemoteNewerRaw(true);
    });
  }, [vaultId]);
  const [search, setSearch] = useState("");
  const [searchResults, setSearchResults] = useState<EntrySummary[]>([]);
  const [filters, setFilters] = useState<SearchUiFilters>({ favoritesOnly: false, regex: false });
  const reqTokenRef = useRef(0);
  const searchInputRef = useRef<HTMLInputElement | null>(null);
  const focusSearch = useCallback(() => {
    const el = searchInputRef.current;
    if (el) {
      el.focus();
      el.select();
    }
  }, []);

  const refreshStatus = useCallback(async () => setStatus(await vaultStatus(vaultId)), [vaultId]);
  const refreshEntries = useCallback(async () => {
    setEntries(await listEntries(serverView(nav), vaultId));
    setEntriesLoaded(true);
  }, [nav, vaultId]);
  const refreshFolders = useCallback(async () => setFolders(await listFolders(vaultId)), [vaultId]);
  const refreshTags = useCallback(async () => setTags(await listTags(vaultId)), [vaultId]);
  const refreshTemplates = useCallback(async () => setTemplates(await listTemplates(vaultId)), [vaultId]);

  const refreshEntriesRef = useRef(refreshEntries);
  const refreshStatusRef = useRef(refreshStatus);
  refreshEntriesRef.current = refreshEntries;
  refreshStatusRef.current = refreshStatus;

  useEffect(() => {
    let cancelled = false;
    let unlisten: (() => void) | undefined;
    listen<{ vault_id: string }>(VAULT_CHANGED, (ev) => {
      if (ev.payload.vault_id === vaultId) {
        void refreshEntriesRef.current();
        void refreshStatusRef.current();
      }
    }).then((u) => {
      if (cancelled) u();
      else unlisten = u;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [vaultId]);

  useEffect(() => {
    refreshStatus().catch((e) => {
      console.error("vault_status failed:", e);
      setStatus({ open: false, locked: false, path: null, hint: null, migrated: false });
    });
  }, [refreshStatus]);

  useEffect(() => {
    if (status?.open) refreshEntries().catch((e) => console.error("list_entries failed:", e));
  }, [status?.open, nav, refreshEntries]);

  useEffect(() => {
    const q = search.trim();
    const token = ++reqTokenRef.current;
    if (!status?.open || !q) {
      setSearchResults((prev) => (prev.length ? [] : prev));
      return;
    }
    const handle = setTimeout(() => {
      const payload: SearchFilters = {
        folder_id: nav.kind === "folder" ? nav.id : null,
        tag_id: nav.kind === "tag" ? nav.id : null,
        favorites_only: filters.favoritesOnly || (nav.kind === "view" && nav.view === "favorites"),
        regex: filters.regex,
      };
      searchEntries(q, payload, vaultId)
        .then((res) => {
          if (token === reqTokenRef.current) setSearchResults(res);
        })
        .catch((e) => {
          if (token === reqTokenRef.current) {
            console.error("search_entries failed:", e);
            setSearchResults([]);
          }
        });
    }, 150);
    return () => clearTimeout(handle);
  }, [search, nav, filters, status?.open, vaultId]);

  useEffect(() => {
    if (!status?.open) return;
    refreshFolders().catch((e) => console.error("list_folders failed:", e));
    refreshTags().catch((e) => console.error("list_tags failed:", e));
    refreshTemplates().catch((e) => console.error("list_templates failed:", e));
  }, [status?.open, refreshFolders, refreshTags, refreshTemplates]);

  const visibleEntries = useMemo(() => {
    if (search.trim()) return searchResults;
    let list = entries;
    if (nav.kind === "folder") list = entries.filter((e) => e.folder_id === nav.id);
    else if (nav.kind === "tag") list = entries.filter((e) => e.tags.some((t) => t.id === nav.id));
    return list;
  }, [entries, nav, search, searchResults]);

  const value = useMemo<VaultState>(
    () => ({
      vaultId,
      status,
      entries,
      entriesLoaded,
      visibleEntries,
      selectedId,
      nav,
      route,
      settingsTab,
      folders,
      tags,
      templates,
      saveError,
      remoteNewer,
      dismissRemoteNewer,
      search,
      setSearch,
      filters,
      setFilters,
      searchInputRef,
      focusSearch,
      refreshStatus,
      refreshEntries,
      refreshFolders,
      refreshTags,
      refreshTemplates,
      select: setSelectedId,
      setNav,
      setRoute,
      setSettingsTab,
      setSaveError,
    }),
    [
      vaultId,
      status,
      entries,
      entriesLoaded,
      visibleEntries,
      selectedId,
      nav,
      route,
      settingsTab,
      folders,
      tags,
      templates,
      saveError,
      remoteNewer,
      dismissRemoteNewer,
      search,
      setSearch,
      filters,
      setFilters,
      searchInputRef,
      focusSearch,
      refreshStatus,
      refreshEntries,
      refreshFolders,
      refreshTags,
      refreshTemplates,
      setSelectedId,
      setNav,
      setRoute,
      setSettingsTab,
      setSaveError,
    ]
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useVault() {
  const v = useContext(Ctx);
  if (!v) throw new Error("useVault must be used within VaultProvider");
  return v;
}
