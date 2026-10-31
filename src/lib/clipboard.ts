
import { clearClipboard as backendClearClipboard, clearClipboardIfUnchanged } from "../ipc/commands";

export async function clearIfUnchanged(expected: string): Promise<void> {
  try {
    await clearClipboardIfUnchanged(expected);
  } catch {
  }
}

export async function clearClipboard(): Promise<void> {
  try {
    await backendClearClipboard();
  } catch {
  }
}
