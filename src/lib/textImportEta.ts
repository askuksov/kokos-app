// ETA for the AI text import: moving average of seconds-per-byte over the files
// finished so far, applied to the bytes still to go. Pure state machine so the
// component only feeds it progress events.

export interface ImportProgress {
  fileIndex: number;
  filesTotal: number;
  fileName: string;
  fileBytes: number;
  bytesDone: number;
  bytesTotal: number;
  chunkDone: number;
  chunkTotal: number;
}

export interface EtaState {
  fileIndex: number;
  fileStartedAt: number;
  fileBytes: number;
  secPerByte: number | null;
  samples: number;
  // Chunk timing: the backend reports only whole chunks, and a chunk can take
  // minutes, so the per-file bar interpolates inside the running chunk.
  chunkKey: string;
  chunkStartedAt: number;
  secPerChunk: number | null;
}

const EMA_ALPHA = 0.35;

export function newEta(): EtaState {
  return { fileIndex: -1, fileStartedAt: 0, fileBytes: 0, secPerByte: null, samples: 0, chunkKey: "", chunkStartedAt: 0, secPerChunk: null };
}

/// Feed one progress event (`nowMs` injected for tests). Returns the next state.
export function feedEta(s: EtaState, p: ImportProgress, nowMs: number): EtaState {
  let next = { ...s };
  if (p.fileIndex !== s.fileIndex) {
    // Previous file finished: fold its duration into the average.
    if (s.fileIndex >= 0 && s.fileBytes > 0) {
      const sample = (nowMs - s.fileStartedAt) / 1000 / s.fileBytes;
      next.secPerByte = next.secPerByte === null ? sample : EMA_ALPHA * sample + (1 - EMA_ALPHA) * next.secPerByte;
      next.samples += 1;
    }
    next.fileIndex = p.fileIndex;
    next.fileStartedAt = nowMs;
    next.fileBytes = p.fileBytes;
  }
  if (p.chunkTotal > 0) {
    const key = `${p.fileIndex}:${p.chunkDone}`;
    if (key !== s.chunkKey) {
      // A chunk finished (same file, next index): fold its duration in.
      if (s.chunkKey !== "" && s.chunkKey.startsWith(`${p.fileIndex}:`) && s.chunkStartedAt > 0) {
        const sample = (nowMs - s.chunkStartedAt) / 1000;
        next.secPerChunk = next.secPerChunk === null ? sample : EMA_ALPHA * sample + (1 - EMA_ALPHA) * next.secPerChunk;
      }
      next.chunkKey = key;
      next.chunkStartedAt = nowMs;
    }
  }
  return next;
}

/// Fraction of the whole job done, 0..1 (byte-weighted; falls back to files).
export function overallFraction(p: ImportProgress): number {
  const chunkFrac = p.chunkTotal > 0 ? p.chunkDone / p.chunkTotal : 0;
  if (p.bytesTotal > 0) return Math.min(1, (p.bytesDone + p.fileBytes * chunkFrac) / p.bytesTotal);
  return p.filesTotal > 0 ? Math.min(1, (p.fileIndex + chunkFrac) / p.filesTotal) : 0;
}

/// Current-file fraction 0..1, or null while the running chunk's duration is
/// still unknown (render an indeterminate bar). Inside a chunk the position is
/// estimated from the average chunk time, capped at 95% until it really ends.
export function fileFraction(s: EtaState, p: ImportProgress, nowMs: number): number | null {
  if (p.chunkTotal <= 0) return 0;
  if (s.secPerChunk === null || s.secPerChunk <= 0) return p.chunkDone > 0 ? p.chunkDone / p.chunkTotal : null;
  const partial = Math.min(0.95, Math.max(0, (nowMs - s.chunkStartedAt) / 1000 / s.secPerChunk));
  return Math.min(1, (p.chunkDone + (p.chunkDone < p.chunkTotal ? partial : 0)) / p.chunkTotal);
}

/// Remaining seconds, or null while there is too little data to say.
export function etaSeconds(s: EtaState, p: ImportProgress): number | null {
  const need = Math.min(2, Math.max(1, p.filesTotal - 1));
  if (s.secPerByte === null || s.samples < need || p.bytesTotal <= 0) return null;
  const chunkFrac = p.chunkTotal > 0 ? p.chunkDone / p.chunkTotal : 0;
  const remaining = Math.max(0, p.bytesTotal - p.bytesDone - p.fileBytes * chunkFrac);
  return remaining * s.secPerByte;
}

/// "~45 s" / "~12 min" / "~1 h 05 min" style, unit labels supplied by i18n.
export function formatEta(
  sec: number,
  u: { s: string; min: string; h: string },
): string {
  const total = Math.max(1, Math.round(sec));
  if (total < 90) return `${total} ${u.s}`;
  const mins = Math.round(total / 60);
  if (mins < 60) return `${mins} ${u.min}`;
  const h = Math.floor(mins / 60);
  return `${h} ${u.h} ${String(mins % 60).padStart(2, "0")} ${u.min}`;
}
