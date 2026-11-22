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

// The last focus move: where it went and where it came from. A control with
// autoFocus inside a dialog takes focus while React mounts it, before the
// hook's effect runs, so the element to return to is read from here then.
let lastMove: { to: EventTarget | null; from: EventTarget | null } = { to: null, from: null };
if (typeof document !== "undefined") {
  document.addEventListener(
    "focusin",
    (ev) => {
      lastMove = { to: ev.target, from: ev.relatedTarget };
    },
    true,
  );
}

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
  /**
   * Where focus goes on close when the element it came from is gone (the
   * dialog replaced the view it was opened from).
   */
  fallbackFocus?: () => HTMLElement | null;
  /**
   * Pull focus back when something outside takes it (an autoFocus control
   * mounting behind the dialog). Default true; off for a dialog that leaves
   * the rest of the window clickable.
   */
  holdFocus?: boolean;
};

/**
 * Modal dialog focus: moves focus in on open, keeps Tab and Shift+Tab inside,
 * and on close gives focus back to the element that had it before, if that
 * element is still on the page and focus has not moved elsewhere meanwhile.
 */
export function useModalFocus(ref: RefObject<HTMLElement | null>, options: ModalFocusOptions = {}): void {
  const { open = true, initialFocus, blocked, fallbackFocus, holdFocus = true } = options;
  const initialRef = useRef(initialFocus);
  initialRef.current = initialFocus;
  const blockedRef = useRef(blocked);
  blockedRef.current = blocked;
  const fallbackRef = useRef(fallbackFocus);
  fallbackRef.current = fallbackFocus;
  // The control that autoFocus picked, kept for StrictMode's second effect
  // run, which starts after the first cleanup has already moved focus out.
  const autoFocusedRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    const node = ref.current;
    if (!open || !node) return;
    let previous: Element | null = document.activeElement;
    if (previous && node.contains(previous)) {
      if (previous instanceof HTMLElement) autoFocusedRef.current = previous;
      previous = lastMove.to === previous && lastMove.from instanceof Element ? lastMove.from : null;
      if (previous && node.contains(previous)) previous = null;
    }
    stack.push(node);

    const initial = initialRef.current;
    if (initial !== false && !node.contains(document.activeElement)) {
      const auto = autoFocusedRef.current;
      const target = initial?.current ?? (auto && node.contains(auto) ? auto : null) ?? focusables(node)[0] ?? node;
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

    // Focus taken by something outside while this dialog is on top goes back
    // to where it was inside. Another modal layer (the tray intro, the unlock
    // prompt) is left alone: it owns the keyboard while it is open.
    let lastInside: HTMLElement | null = node.contains(document.activeElement) ? (document.activeElement as HTMLElement) : null;
    function onFocusIn(ev: FocusEvent) {
      const target = ev.target;
      if (!(target instanceof Element)) return;
      if (node!.contains(target)) {
        if (target instanceof HTMLElement) lastInside = target;
        return;
      }
      if (!holdFocus || stack[stack.length - 1] !== node || !node!.isConnected) return;
      if (blockedRef.current?.()) return;
      // Only layers outside this stack (tray intro, unlock prompt) keep focus;
      // a dialog lower in the stack (the editor behind a confirmation) does not.
      const layer = target.closest('[aria-modal="true"]');
      if (layer && !stack.includes(layer as HTMLElement)) return;
      const back = lastInside && lastInside.isConnected && node!.contains(lastInside) ? lastInside : (focusables(node!)[0] ?? node!);
      back.focus({ preventScroll: true });
    }
    document.addEventListener("focusin", onFocusIn, true);

    return () => {
      document.removeEventListener("keydown", onKeyDown, true);
      document.removeEventListener("focusin", onFocusIn, true);
      const at = stack.lastIndexOf(node);
      if (at >= 0) stack.splice(at, 1);
      // By now the dialog may already be detached; focus left inside it (or
      // dropped to <body>) goes back to where it came from.
      const active = document.activeElement;
      const lost = !active || active === document.body || node.contains(active);
      if (!lost) return;
      if (previous instanceof HTMLElement && previous !== document.body && previous.isConnected) {
        previous.focus({ preventScroll: true });
      } else {
        fallbackRef.current?.()?.focus({ preventScroll: true });
      }
    };
  }, [open, ref, holdFocus]);
}
