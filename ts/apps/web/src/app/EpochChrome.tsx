// The open epoch in the chrome: the sticky EpochStrip (desktop) and the
// EpochPill (mobile), on server time (V-12). The countdown is a timer that is
// not announced. Phase changes are announced only with the setting.
import type { CurrentEpoch, MarketDetail, PublicPhase, TapeRow } from '@timescales/sdk/api';
import { useEffect } from 'react';

import { EpochPill, EpochStrip } from '../components/chrome';
import { componentsCopy } from '../components/copy';
import { formatTick } from '../state/format';
import { useServerNow } from '../state/hooks';
import { useClearing, useMarketDetail } from '../state/queries';
import { useRuntime } from '../state/runtime';
import type { Address } from '../state/types';
import { appCopy } from './copy';

export interface EpochView {
  label: string;
  epoch: bigint;
  phase: PublicPhase;
  secondsToCutoff: number;
  progress: number;
  warning: boolean;
  inFlight: { epoch: bigint; phase: PublicPhase } | null;
}

/**
 * The cutoff warning starts at min(10 s, interval / 3) before cutoff and
 * is suppressed for intervals under 20 s.
 */
export function warningThresholdMs(intervalMs: number): number | null {
  if (intervalMs < 20_000) return null;
  return Math.min(10_000, intervalMs / 3);
}

export function epochView(
  current: CurrentEpoch,
  detail: MarketDetail | undefined,
  nowMs: number,
): EpochView | null {
  const open = current.open;
  if (open === null) return null;
  const span = Math.max(1, open.cutoffMs - open.opensAtMs);
  const leftMs = open.cutoffMs - nowMs;
  const threshold = warningThresholdMs(detail?.timing.epochIntervalMs ?? span);
  return {
    label: detail?.name ?? current.market,
    epoch: open.epoch,
    phase: leftMs > 0 ? 'open' : 'closed',
    secondsToCutoff: Math.max(0, leftMs / 1000),
    progress: Math.min(1, Math.max(0, (nowMs - open.opensAtMs) / span)),
    warning: threshold !== null && leftMs > 0 && leftMs <= threshold,
    inFlight: current.inflight,
  };
}

function lastResult(
  rows: readonly TapeRow[] | undefined,
  detail: MarketDetail | undefined,
): string | null {
  const row = rows?.find((r) => r.clearing.length > 0);
  if (row === undefined) return null;
  // Prices only, one per book: the strip is a glance, the tape has the labels.
  const prices = row.clearing.map((c) => formatTick(detail, c.tick)).join(' / ');
  return appCopy.lastResult(String(row.epoch), prices, componentsCopy.phase[row.phase]);
}

export function useEpochChrome(market: Address | null, current: CurrentEpoch | undefined) {
  const now = useServerNow();
  const detail = useMarketDetail(market).data;
  const tape = useClearing(market).data;
  const view = current === undefined ? null : epochView(current, detail, now);
  if (view === null) return { strip: null, pill: null };
  return {
    strip: (
      <EpochStrip
        market={view.label}
        epoch={view.epoch}
        phase={view.phase}
        secondsToCutoff={view.secondsToCutoff}
        progress={view.progress}
        warning={view.warning}
        inFlight={view.inFlight}
        lastResult={lastResult(tape?.items, detail)}
      />
    ),
    pill: (
      <EpochPill
        market={view.label}
        epoch={view.epoch}
        phase={view.phase}
        secondsToCutoff={view.secondsToCutoff}
        progress={view.progress}
        warning={view.warning}
      />
    ),
  };
}

/** Announces the active market's phase changes, only when the setting is on. */
export function useMarketPhaseAnnouncements(market: Address | null): void {
  const runtime = useRuntime();
  useEffect(
    () =>
      runtime.live.onEvent((e) => {
        if (e.kind === 'unknown' || e.kind === 'status.changed' || e.kind === 'program.upgraded') {
          return;
        }
        if (e.market !== market || !('epoch' in e)) return;
        const phase = PHASE_OF_EVENT[e.kind];
        if (phase === undefined) return;
        runtime.announcer.announce(
          appCopy.phaseAnnouncement(String(e.epoch), componentsCopy.phase[phase]),
          'market_phase',
        );
      }),
    [runtime, market],
  );
}

const PHASE_OF_EVENT: Partial<Record<string, PublicPhase>> = {
  'epoch.opened': 'open',
  'epoch.closed': 'closed',
  'epoch.committed': 'committed',
  'epoch.revealed': 'revealed',
  'epoch.executing': 'executing',
  'epoch.posted': 'posted',
  'epoch.settled': 'settled',
  'epoch.aborting': 'aborting',
  'epoch.aborted': 'aborted',
};
