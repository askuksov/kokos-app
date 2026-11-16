import type { FolderNode } from "../ipc/types";

/**
 * Live entries in a folder and all of its descendants. The backend's
 * `entry_count` covers only entries filed directly in the folder, which is
 * also what the entry list shows when the folder is selected.
 */
export function subtreeCount(node: FolderNode): number {
  return node.children.reduce((sum, child) => sum + subtreeCount(child), node.entry_count);
}
