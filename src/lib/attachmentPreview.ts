
export type PreviewKind = "image" | "text" | "pdf";

export const TEXT_PREVIEW_MAX = 256 * 1024;

const IMAGE_EXT = ["png", "jpg", "jpeg", "gif", "webp"];
const TEXT_EXT = [
  "txt", "md", "markdown", "json", "csv", "log", "xml",
  "yaml", "yml", "ini", "conf", "js", "ts", "css", "html",
];

function ext(filename: string): string {
  const i = filename.lastIndexOf(".");
  return i >= 0 ? filename.slice(i + 1).toLowerCase() : "";
}

export function previewKind(mime: string | null, filename: string): PreviewKind | null {
  const m = (mime ?? "").toLowerCase();
  const e = ext(filename);
  if (m === "image/svg+xml" || e === "svg") return null;
  if (m.startsWith("image/") || IMAGE_EXT.includes(e)) return "image";
  if (m === "application/pdf" || e === "pdf") return "pdf";
  if (
    m.startsWith("text/") ||
    m === "application/json" ||
    m === "application/xml" ||
    TEXT_EXT.includes(e)
  ) return "text";
  return null;
}
