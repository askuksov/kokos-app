import { useEffect, useRef } from "react";
// Legacy build: the modern one calls Map.prototype.getOrInsertComputed and
// Math.sumPrecise unpolyfilled, and the system WKWebView / WebKitGTK we run in
// can be too old to have them.
import * as pdfjs from "pdfjs-dist/legacy/build/pdf.mjs";
import workerUrl from "pdfjs-dist/legacy/build/pdf.worker.min.mjs?url";
import "./PdfPreview.css";

pdfjs.GlobalWorkerOptions.workerSrc = workerUrl;

export function PdfPreview({ bytes, onError }: { bytes: Uint8Array; onError: () => void }) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let cancelled = false;
    // No `isEvalSupported: false` here: pdf.js 6 removed its eval-based font
    // path entirely, so there is nothing left to disable.
    const task = pdfjs.getDocument({
      data: bytes.slice(),
      disableAutoFetch: true,
      disableStream: true,
    });
    (async () => {
      try {
        const doc = await task.promise;
        if (cancelled) return;
        const container = containerRef.current;
        if (!container) return;
        container.replaceChildren();
        for (let n = 1; n <= doc.numPages; n++) {
          const page = await doc.getPage(n);
          if (cancelled) return;
          const viewport = page.getViewport({ scale: 1.3 });
          const canvas = document.createElement("canvas");
          canvas.className = "kv-pdf-page";
          canvas.width = viewport.width;
          canvas.height = viewport.height;
          const ctx = canvas.getContext("2d");
          if (!ctx) continue;
          container.appendChild(canvas);
          await page.render({ canvas, canvasContext: ctx, viewport }).promise;
        }
      } catch (e) {
        console.error("pdf preview failed:", e);
        if (!cancelled) onError();
      }
    })();
    return () => {
      cancelled = true;
      void task.destroy();
    };
  }, [bytes, onError]);

  return <div ref={containerRef} className="kv-pdf-container" />;
}
