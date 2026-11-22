import { useEffect, useRef, type RefObject } from "react";

const FOCUSABLE = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled]):not([type='hidden'])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "[tabindex]:not([tabindex='-1'])",
].join(", ");

// Open dialogs, oldest first. Only the last one traps Tab, so a dialog opened
// over another (an extension prompt over the attachment preview) owns the
// keyboard until it closes.
const stack: HTMLElement[] = [];

function focusables(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
    (el) => el.tabIndex >= 0 && el.getClientRects().length > 0,
  );
}

export type ModalFocusOptions = {
  /** Whether the dialog is shown. Defaults to true (the dialog unmounts when closed). */
  open?: boolean;
  /**
   * What to focus on open: a ref, or `false` when the caller moves focus
   * itself. Default: the first focusable control, else the dialog element
   * (give it tabIndex={-1}).
   */
  initialFocus?: RefObject<HTMLElement | null> | false;
  /** While true the hook leaves Tab alone (another layer owns the keyboard). */
  blocked?: () => boolean;
};

/**
 * Modal dialog focus: moves focus in on open, keeps Tab and Shift+Tab inside,
 * and on close gives focus back to the element that had it before, if that
 * element is still on the page and focus has not moved elsewhere meanwhile.
 */
export function useModalFocus(ref: RefObject<HTMLElement | null>, options: ModalFocusOptions = {}): void {
  const { open = true, initialFocus, blocked } = options;
  const initialRef = useRef(initialFocus);
  initialRef.current = initialFocus;
  const blockedRef = useRef(blocked);
  blockedRef.current = blocked;

  useEffect(() => {
    const node = ref.current;
    if (!open || !node) return;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    stack.push(node);

    const initial = initialRef.current;
    if (initial !== false && !node.contains(document.activeElement)) {
      const target = initial?.current ?? focusables(node)[0] ?? node;
      target.focus({ preventScroll: true });
    }

    function onKeyDown(ev: KeyboardEvent) {
      if (ev.key !== "Tab" || stack[stack.length - 1] !== node) return;
      if (blockedRef.current?.()) return;
      const stops = focusables(node!);
      if (stops.length === 0) {
        ev.preventDefault();
        node!.focus({ preventScroll: true });
        return;
      }
      const first = stops[0];
      const last = stops[stops.length - 1];
      const idx = stops.indexOf(document.activeElement as HTMLElement);
      if (ev.shiftKey ? idx <= 0 : idx === -1 || idx === stops.length - 1) {
        ev.preventDefault();
        (ev.shiftKey ? last : first).focus({ preventScroll: true });
      }
    }
    document.addEventListener("keydown", onKeyDown, true);

    return () => {
      document.removeEventListener("keydown", onKeyDown, true);
      const at = stack.lastIndexOf(node);
      if (at >= 0) stack.splice(at, 1);
      // By now the dialog may already be detached; focus left inside it (or
      // dropped to <body>) goes back to where it came from.
      const active = document.activeElement;
      const lost = !active || active === document.body || node.contains(active);
      if (lost && previous && previous !== document.body && previous.isConnected) {
        previous.focus({ preventScroll: true });
      }
    };
  }, [open, ref]);
}
