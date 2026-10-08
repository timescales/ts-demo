import type { TimescalesApi } from './client.js';

const SAMPLES = 5;
const RESYNC_MS = 5 * 60_000;

interface ClockState {
  /** Server time minus local time. */
  offsetMs: number;
  synced: boolean;
  syncedAt: number;
  api: TimescalesApi | null;
  syncing: Promise<void> | null;
  watchingVisibility: boolean;
}

// The class's declared surface is frozen, so its state lives here.
const STATE = new WeakMap<ServerClock, ClockState>();

function stateOf(c: ServerClock): ClockState {
  let s = STATE.get(c);
  if (s === undefined) {
    s = {
      offsetMs: 0,
      synced: false,
      syncedAt: 0,
      api: null,
      syncing: null,
      watchingVisibility: false,
    };
    STATE.set(c, s);
  }
  return s;
}

/**
 * A server time seen in a response (`server_time_ms`). It seeds the offset
 * until the first full sync. One sample is never trusted over the median.
 */
export function observeServerTime(
  clock: ServerClock,
  serverTimeMs: number,
  sentAt: number,
  receivedAt: number,
): void {
  const s = stateOf(clock);
  if (!s.synced) s.offsetMs = serverTimeMs + (receivedAt - sentAt) / 2 - receivedAt;
}

function backgroundSync(clock: ServerClock, s: ClockState): void {
  if (s.api !== null && s.syncing === null) clock.sync(s.api).catch(() => undefined);
}

/** Server time from the median of 5 `/v1/time` samples, RTT/2 corrected. */
export class ServerClock {
  /** Re-runs on `visibilitychange -> visible`, on `SKEW` and every 5 minutes once it has an API. */
  sync(api: TimescalesApi): Promise<void> {
    const s = stateOf(this);
    s.api = api;
    if (!s.watchingVisibility && typeof document !== 'undefined') {
      s.watchingVisibility = true;
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') backgroundSync(this, s);
      });
    }
    if (s.syncing !== null) return s.syncing;
    s.syncing = (async () => {
      const offsets: number[] = [];
      for (let i = 0; i < SAMPLES; i++) {
        const sentAt = Date.now();
        const { serverTimeMs } = await api.time();
        const receivedAt = Date.now();
        offsets.push(serverTimeMs + (receivedAt - sentAt) / 2 - receivedAt);
      }
      offsets.sort((a, b) => a - b);
      s.offsetMs = Math.round(offsets[Math.floor(SAMPLES / 2)]!);
      s.synced = true;
      s.syncedAt = Date.now();
    })().finally(() => {
      s.syncing = null;
    });
    return s.syncing;
  }

  now(): number {
    const s = stateOf(this);
    if (s.synced && Date.now() - s.syncedAt > RESYNC_MS) backgroundSync(this, s);
    return Date.now() + s.offsetMs;
  }

  /** Server time minus local time, in ms (V-12 warns above 1 s). */
  skewMs(): number {
    return stateOf(this).offsetMs;
  }
}
