import { useCallback, useEffect, useMemo, useState } from "react";
import { readAttachmentBytes } from "../ipc/commands";
import type { AttachmentMeta } from "../ipc/types";
import { previewKind, TEXT_PREVIEW_MAX } from "../lib/attachmentPreview";
import { useT } from "../state/LangContext";
import { PdfPreview } from "./PdfPreview";
import "./AttachmentLightbox.css";

function LbIcon({ name, size = 18 }: { name: "close" | "prev" | "next"; size?: number }) {
  const paths: Record<string, React.ReactNode> = {
    close: <path d="M6 6l12 12M18 6L6 18" />,
    prev: <path d="M15 6l-6 6 6 6" />,
    next: <path d="M9 6l6 6-6 6" />,
  };
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {paths[name]}
    </svg>
  );
}

function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

type Loaded =
  | { state: "loading" }
  | { state: "error" }
  | { state: "tooLarge" }
  | { state: "image"; src: string }
  | { state: "text"; text: string }
  | { state: "pdf"; bytes: Uint8Array };

export function AttachmentLightbox({
  items,
  startId,
  onClose,
}: {
  items: AttachmentMeta[];
  startId: string;
  onClose: () => void;
}) {
  const t = useT();
  const startIdx = Math.max(0, items.findIndex((a) => a.id === startId));
  const [idx, setIdx] = useState(startIdx);
  const [loaded, setLoaded] = useState<Loaded>({ state: "loading" });
  const current = items[idx];

  const go = useCallback(
    (delta: number) => {
      if (items.length < 2) return;
      setIdx((i) => (i + delta + items.length) % items.length);
    },
    [items.length],
  );

  useEffect(() => {
    let cancelled = false;
    setLoaded({ state: "loading" });
    if (!current) return;
    (async () => {
      try {
        const res = await readAttachmentBytes(current.id);
        if (cancelled) return;
        const kind = previewKind(res.mime, res.filename);
        if (kind === "image") {
          setLoaded({ state: "image", src: `data:${res.mime ?? "application/octet-stream"};base64,${res.data_base64}` });
        } else if (kind === "text") {
          const bytes = b64ToBytes(res.data_base64);
          if (bytes.length > TEXT_PREVIEW_MAX) {
            setLoaded({ state: "tooLarge" });
          } else {
            setLoaded({ state: "text", text: new TextDecoder("utf-8", { fatal: false }).decode(bytes) });
          }
        } else if (kind === "pdf") {
          setLoaded({ state: "pdf", bytes: b64ToBytes(res.data_base64) });
        } else {
          setLoaded({ state: "error" });
        }
      } catch (e) {
        console.error("read_attachment_bytes failed:", e);
        if (!cancelled) setLoaded({ state: "error" });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [current]);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
      else if (e.key === "ArrowLeft") go(-1);
      else if (e.key === "ArrowRight") go(1);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [go, onClose]);

  const body = useMemo(() => {
    switch (loaded.state) {
      case "loading":
        return <div className="kv-lb-msg">{t("common.loading")}</div>;
      case "image":
        return <img className="kv-lb-image" src={loaded.src} alt={current?.filename ?? ""} />;
      case "text":
        return <pre className="kv-lb-text">{loaded.text}</pre>;
      case "tooLarge":
        return <div className="kv-lb-msg">{t("preview.tooLarge")}</div>;
      case "pdf":
        return <PdfPreview bytes={loaded.bytes} onError={() => setLoaded({ state: "error" })} />;
      case "error":
      default:
        return <div className="kv-lb-msg">{t("preview.failed")}</div>;
    }
  }, [loaded, t, current]);

  return (
    <div className="kv-lb-scrim" onClick={onClose}>
      <div className="kv-lb-panel" role="dialog" aria-modal="true" onClick={(e) => e.stopPropagation()}>
        <div className="kv-lb-head">
          <span className="kv-lb-title">{current?.filename}</span>
          {items.length > 1 ? <span className="kv-lb-counter">{idx + 1} / {items.length}</span> : null}
          <button type="button" className="kv-btn is-icon" title={t("preview.close")} aria-label={t("preview.close")} onClick={onClose}>
            <LbIcon name="close" />
          </button>
        </div>
        <div className="kv-lb-body">{body}</div>
        {items.length > 1 ? (
          <>
            <button type="button" className="kv-lb-nav is-prev" title={t("preview.prev")} aria-label={t("preview.prev")} onClick={() => go(-1)}>
              <LbIcon name="prev" size={22} />
            </button>
            <button type="button" className="kv-lb-nav is-next" title={t("preview.next")} aria-label={t("preview.next")} onClick={() => go(1)}>
              <LbIcon name="next" size={22} />
            </button>
          </>
        ) : null}
      </div>
    </div>
  );
}
