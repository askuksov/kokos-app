import { useEffect, useRef, useState } from "react";
import type { DragEvent } from "react";
import { useVault } from "../state/VaultContext";
import { useT, useTn } from "../state/LangContext";
import { aiStatus, createFolder, deleteFolder, moveFolder, renameFolder, reorderFolder } from "../ipc/commands";
import type { FolderNode } from "../ipc/types";
import OrganizeUnfiledModal from "./OrganizeUnfiledModal";
import "./ManageFolders.css";

type ManageIcon = "folder" | "folderPlus" | "grip" | "trash" | "chevronLeft";

const ICON_PATHS: Record<ManageIcon, React.ReactNode> = {
  folder: <path d="M3.5 7a2 2 0 012-2h4l2 2.2h7a2 2 0 012 2V17a2 2 0 01-2 2h-13a2 2 0 01-2-2V7z" />,
  folderPlus: (
    <g>
      <path d="M3.5 7a2 2 0 012-2h4l2 2.2h7a2 2 0 012 2V17a2 2 0 01-2 2h-13a2 2 0 01-2-2V7z" />
      <path d="M12 10.5v5M9.5 13h5" />
    </g>
  ),
  grip: (
    <g>
      {[7, 12, 17].map((y) =>
        [9.2, 14.8].map((x) => (
          <circle key={`${x}-${y}`} cx={x} cy={y} r={1.15} fill="currentColor" stroke="none" />
        )),
      )}
    </g>
  ),
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

type DropPos = "before" | "after" | "inside";
type DropTarget = { id: string; pos: DropPos };

function findFolder(nodes: FolderNode[], id: string): FolderNode | null {
  for (const n of nodes) {
    if (n.id === id) return n;
    const found = findFolder(n.children, id);
    if (found) return found;
  }
  return null;
}

function subtreeIncludes(node: FolderNode, id: string): boolean {
  return node.id === id || node.children.some((c) => subtreeIncludes(c, id));
}

function isDescendant(folders: FolderNode[], dragId: string, targetId: string): boolean {
  const dragNode = findFolder(folders, dragId);
  return dragNode !== null && subtreeIncludes(dragNode, targetId);
}

function FolderRow({
  node,
  depth,
  dragId,
  dropPos,
  onRename,
  onDelete,
  onGripDragStart,
  onRowDragEnd,
  onRowDragOver,
  onRowDragLeave,
  onRowDrop,
}: {
  node: FolderNode;
  depth: number;
  dragId: string | null;
  dropPos: DropPos | null;
  onRename: (id: string, name: string) => void;
  onDelete: (id: string) => void;
  onGripDragStart: (ev: DragEvent<HTMLSpanElement>, node: FolderNode) => void;
  onRowDragEnd: () => void;
  onRowDragOver: (ev: DragEvent<HTMLDivElement>, node: FolderNode) => void;
  onRowDragLeave: (node: FolderNode) => void;
  onRowDrop: (ev: DragEvent<HTMLDivElement>, node: FolderNode) => void;
}) {
  const t = useT();
  const tn = useTn();
  const isRoot = node.id === "root";
  const [name, setName] = useState(node.name);
  useEffect(() => setName(node.name), [node.id, node.name]);

  function commit() {
    const trimmed = name.trim();
    if (trimmed && trimmed !== node.name) onRename(node.id, trimmed);
    else setName(node.name);
  }

  const count = node.entry_count;
  const countLabel = count === 0 ? "" : tn("common.items", count);

  return (
    <div
      className={
        "kv-manage-row" +
        (dragId === node.id ? " is-dragging" : "") +
        (dropPos === "inside" ? " is-drop-inside" : dropPos === "before" ? " is-drop-before" : dropPos === "after" ? " is-drop-after" : "")
      }
      style={{ paddingLeft: 12 + depth * 26 }}
      onDragOver={(ev) => onRowDragOver(ev, node)}
      onDragLeave={() => onRowDragLeave(node)}
      onDrop={(ev) => onRowDrop(ev, node)}
    >
      {!isRoot ? (
        <span
          className="kv-grip"
          title={t("folders.rowDragTitle")}
          draggable
          onDragStart={(ev) => onGripDragStart(ev, node)}
          onDragEnd={onRowDragEnd}
        >
          <Icon name="grip" size={13} />
        </span>
      ) : (
        <span className="kv-grip-spacer" aria-hidden="true" />
      )}
      <Icon name="folder" size={15} style={{ color: isRoot ? "var(--accent)" : "var(--text-3)" }} />
      <input
        className="kv-input"
        value={name}
        aria-label={t("folders.nameAriaLabel")}
        disabled={isRoot}
        title={isRoot ? t("folders.rootNoRename") : undefined}
        onChange={(e) => setName(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => {
          if (e.key === "Enter") e.currentTarget.blur();
        }}
        autoCapitalize="off"
        autoCorrect="off"
        spellCheck={false}
      />
      <span className="kv-count">{countLabel}</span>
      {!isRoot ? (
        <button
          type="button"
          className="kv-btn is-icon is-danger"
          title={t("folders.deleteTitle")}
          aria-label={t("common.deleteNamed", { name: node.name })}
          onClick={() => onDelete(node.id)}
        >
          <Icon name="trash" size={14} />
        </button>
      ) : (
        <span className="kv-delete-spacer" aria-hidden="true" />
      )}
    </div>
  );
}

/**
 * Full-page folder management screen: a flattened, indented list of every
 * folder in a `.kv-card`, each row inline-renamable and (root excepted)
 * draggable-to-nest and deletable, plus an add-row. Root is the tree's
 * single guaranteed top-level node (kokos-core::folders::list_tree) and is
 * treated specially in four ways: its icon is tinted `--accent` instead of
 * the plain `--text-3` every other row gets, it has no drag handle (a
 * spacer keeps the columns aligned), no delete button (same spacer
 * treatment), and its rename input is `disabled` —
 * `kokos-core::folders::rename` hard-rejects `id == "root"` with
 * `CannotModifyRoot`. An editable-looking input whose commits silently
 * no-op would read as a bug the moment `refreshFolders()` from an
 * unrelated row's edit resynced it back to "Root" out from under a
 * half-typed edit.
 *
 * The drag handle both nests (drop onto a row's middle) and reorders among
 * siblings (drop on its top/bottom edge) via `reorderFolder`.
 */
export function ManageFolders() {
  const { folders, refreshFolders, refreshEntries, nav, setNav, setRoute } = useVault();
  const t = useT();
  const [newName, setNewName] = useState("");
  const [dragId, setDragId] = useState<string | null>(null);
  const [drop, setDrop] = useState<DropTarget | null>(null);
  const [aiOn, setAiOn] = useState(false);
  const [organizing, setOrganizing] = useState(false);
  const dragIdRef = useRef<string | null>(null);
  const dropRef = useRef<DropTarget | null>(null);

  const rows = flattenFolders(folders);

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

  async function handleRename(id: string, name: string) {
    try {
      await renameFolder(id, name);
      await refreshFolders();
    } catch (e) {
      console.error("rename_folder failed:", e);
    }
  }

  async function handleDelete(id: string) {
    try {
      await deleteFolder(id);
      await refreshFolders();
      await refreshEntries();
      if (nav.kind === "folder" && nav.id === id) setNav({ kind: "view", view: "all" });
    } catch (e) {
      console.error("delete_folder failed:", e);
    }
  }

  async function handleAdd() {
    const name = newName.trim();
    if (!name) return;
    try {
      await createFolder(name, null);
      setNewName("");
      await refreshFolders();
    } catch (e) {
      console.error("create_folder failed:", e);
    }
  }

  function onGripDragStart(ev: DragEvent<HTMLSpanElement>, node: FolderNode) {
    dragIdRef.current = node.id;
    setDragId(node.id);
    ev.dataTransfer.effectAllowed = "move";
    const row = ev.currentTarget.closest(".kv-manage-row");
    if (row) ev.dataTransfer.setDragImage(row, 20, 18);
  }

  async function commitMove() {
    const dId = dragIdRef.current;
    const d = dropRef.current;
    dragIdRef.current = null;
    dropRef.current = null;
    setDragId(null);
    setDrop(null);
    if (!dId || !d) return;
    try {
      if (d.pos === "inside") {
        await moveFolder(dId, d.id);
      } else {
        await reorderFolder(dId, d.id, d.pos);
      }
      await refreshFolders();
    } catch (e) {
      console.error("folder move/reorder failed:", e);
    }
  }

  function onRowDragEnd() {
    void commitMove();
  }

  function onRowDragOver(ev: DragEvent<HTMLDivElement>, node: FolderNode) {
    ev.preventDefault();
    if (!dragId || dragId === node.id || isDescendant(folders, dragId, node.id)) {
      dropRef.current = null;
      setDrop(null);
      return;
    }
    const rect = ev.currentTarget.getBoundingClientRect();
    const y = (ev.clientY - rect.top) / rect.height;
    const pos: DropPos = node.id === "root" ? "inside" : y < 0.28 ? "before" : y > 0.72 ? "after" : "inside";
    dropRef.current = { id: node.id, pos };
    setDrop({ id: node.id, pos });
  }

  function onRowDragLeave(node: FolderNode) {
    setDrop((prev) => (prev && prev.id === node.id ? null : prev));
  }

  async function onRowDrop(ev: DragEvent<HTMLDivElement>, _node: FolderNode) {
    ev.preventDefault();
    void commitMove();
  }

  return (
    <main className="kv-settings" data-screen-label="Manage folders page">
      <div className="kv-settings-inner">
        <button type="button" className="kv-btn is-ghost kv-settings-back" onClick={() => setRoute("main")}>
          <Icon name="chevronLeft" size={13} strokeWidth={2} /> {t("common.back")}
        </button>
        <h1>{t("folders.title")}</h1>
        <p className="kv-settings-sub">{t("folders.subtitle")}</p>
        {aiOn && (
          <button
            type="button"
            className="kv-btn is-ghost kv-organize-trigger"
            onClick={() => setOrganizing(true)}
          >
            {t("organize.trigger")}
          </button>
        )}

        <div className="kv-card">
          {rows.map(({ node, depth }) => (
            <FolderRow
              key={node.id}
              node={node}
              depth={depth}
              dragId={dragId}
              dropPos={drop && drop.id === node.id ? drop.pos : null}
              onRename={handleRename}
              onDelete={handleDelete}
              onGripDragStart={onGripDragStart}
              onRowDragEnd={onRowDragEnd}
              onRowDragOver={onRowDragOver}
              onRowDragLeave={onRowDragLeave}
              onRowDrop={onRowDrop}
            />
          ))}
          <div className="kv-manage-row">
            <span className="kv-grip-spacer" aria-hidden="true" />
            <input
              className="kv-input"
              placeholder={t("folders.newNamePlaceholder")}
              aria-label={t("folders.newNameAriaLabel")}
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") handleAdd();
              }}
              autoCapitalize="off"
              autoCorrect="off"
              spellCheck={false}
            />
            <button type="button" className="kv-btn is-ghost" onClick={handleAdd}>
              <Icon name="folderPlus" size={14} /> {t("folders.addFolder")}
            </button>
          </div>
        </div>
      </div>
      {organizing && (
        <OrganizeUnfiledModal
          onClose={() => setOrganizing(false)}
          onApplied={() => {
            void refreshFolders();
            void refreshEntries();
          }}
        />
      )}
    </main>
  );
}
