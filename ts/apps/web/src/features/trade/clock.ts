// Timing rules of the epoch clock.

/** Intervals below this get no cutoff warning: it would cover most of the epoch. */
export const WARNING_MIN_INTERVAL_MS = 20_000;
const WARNING_CAP_MS = 10_000;

/** The cutoff warning threshold, `min(10 s, interval / 3)`, or null when it is suppressed. */
export function warningThresholdMs(intervalMs: number): number | null {
  if (!Number.isFinite(intervalMs) || intervalMs < WARNING_MIN_INTERVAL_MS) return null;
  return Math.min(WARNING_CAP_MS, intervalMs / 3);
}

/** Elapsed fraction of the open epoch, clamped to 0..1. */
export function epochProgress(nowMs: number, opensAtMs: number, cutoffMs: number): number {
  const span = cutoffMs - opensAtMs;
  if (span <= 0) return 1;
  return Math.min(1, Math.max(0, (nowMs - opensAtMs) / span));
}

/** "m:ss" for a duration. Used for lifetime estimates. */
export function formatDuration(ms: number): string {
  const total = Math.max(0, Math.round(ms / 1000));
  const minutes = Math.floor(total / 60);
  const hours = Math.floor(minutes / 60);
  const seconds = String(total % 60).padStart(2, '0');
  if (hours > 0) return `${hours}:${String(minutes % 60).padStart(2, '0')}:${seconds}`;
  return `${minutes}:${seconds}`;
}
