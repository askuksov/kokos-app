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
