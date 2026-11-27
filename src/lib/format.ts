export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export function fileBasename(path: string): string {
  const last = path.split(/[\\/]/).pop();
  return last && last.length > 0 ? last : path;
}

export function vaultDisplayName(path: string): string {
  const last = path.split(/[\\/]/).pop();
  const base = last && last.length > 0 ? last : path;
  for (const ext of [".kokos", ".vault"]) {
    if (base.endsWith(ext) && base.length > ext.length) return base.slice(0, -ext.length);
  }
  return base;
}

export function tildify(path: string, home: string | null): string {
  if (!home) return path;
  const h = home.replace(/\/+$/, "");
  if (path === h) return "~";
  if (path.startsWith(h + "/")) return "~" + path.slice(h.length);
  return path;
}

export function restoreBackupLabel(name: string): { tag: string | null } {
  const stem = name.replace(/\.(kokos|vault)$/i, "");
  const id = stem.startsWith("kokos-") ? stem.slice("kokos-".length) : null;
  const compact = id ? id.replace(/-/g, "") : null;
  const tag = compact && compact.length >= 4 ? "…" + compact.slice(-4) : null;
  return { tag };
}

const pad2 = (n: number) => String(n).padStart(2, "0");

/** Local date as `YYYY-MM-DD`. Accepts a Date, an ISO string or epoch milliseconds. */
export function formatDate(d: Date | string | number): string {
  const x = d instanceof Date ? d : new Date(d);
  return `${x.getFullYear()}-${pad2(x.getMonth() + 1)}-${pad2(x.getDate())}`;
}

/** Local date-time as `YYYY-MM-DD HH:mm` (24-hour). Accepts a Date, an ISO string or epoch milliseconds. */
export function formatDateTime(d: Date | string | number): string {
  const x = d instanceof Date ? d : new Date(d);
  return `${formatDate(x)} ${pad2(x.getHours())}:${pad2(x.getMinutes())}`;
}

/** Same as `formatDateTime` for a Unix timestamp in seconds. */
export function formatDateTimeSec(unixSeconds: number): string {
  return formatDateTime(unixSeconds * 1000);
}

/** Same as `formatDate` for a Unix timestamp in seconds. */
export function formatDateSec(unixSeconds: number): string {
  return formatDate(unixSeconds * 1000);
}
