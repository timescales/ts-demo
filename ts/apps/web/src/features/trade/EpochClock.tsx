import type { CurrentEpoch, PublicPhase } from '@timescales/sdk/api';
import { TriangleAlert } from 'lucide-react';
import { useEffect, useRef } from 'react';

import { formatCountdown } from '../../components/chrome';
import { EpochRing } from '../../components/motif';
import { PhaseBadge } from '../../components/primitives';
import { epochProgress, warningThresholdMs } from './clock';
import { tradeCopy } from './copy';
import styles from './trade.module.css';

export interface EpochClockProps {
  current: CurrentEpoch | undefined;
  intervalMs: number;
  /** Server time in ms. */
  now: number;
  /** A draft ticket is focused or has been edited: only then is the cutoff announced. */
  draftActive: boolean;
  announce?: ((message: string) => void) | undefined;
}

export function knownPhase(p: PublicPhase): Exclude<PublicPhase, 'unknown'> | null {
  return p === 'unknown' ? null : p;
}

/** The large clock: 60-tick ring, mm:ss to cutoff (server time) and the epoch in flight. */
export function EpochClock({ current, intervalMs, now, draftActive, announce }: EpochClockProps) {
  const copy = tradeCopy.clock;
  const open = current?.open ?? null;
  const remainingMs = open ? open.cutoffMs - now : 0;
  const threshold = warningThresholdMs(intervalMs);
  const warning =
    open !== null && threshold !== null && remainingMs > 0 && remainingMs <= threshold;
  const announced = useRef<bigint | null>(null);

  useEffect(() => {
    if (!warning || !draftActive || open === null || announce === undefined) return;
    if (announced.current === open.epoch) return;
    announced.current = open.epoch;
    announce(copy.announceCutoff(open.epoch.toString(), Math.ceil(remainingMs / 1000)));
  }, [warning, draftActive, open, announce, remainingMs, copy]);

  const inflight = current?.inflight ?? null;
  const inflightPhase = inflight ? knownPhase(inflight.phase) : null;

  return (
    <section className={styles.clock} aria-label={copy.label} data-warning={warning || undefined}>
      {open ? (
        <>
          <EpochRing
            progress={epochProgress(now, open.opensAtMs, open.cutoffMs)}
            warning={warning}
            size={112}
          />
          <div className={styles.clockText}>
            <p className={styles.clockEpoch}>{copy.epoch(open.epoch.toString())}</p>
            <p>
              <span
                role="timer"
                aria-live="off"
                aria-label={copy.timerLabel(open.epoch.toString())}
                className={styles.countdown}
              >
                {formatCountdown(remainingMs / 1000)}
              </span>{' '}
              <span className={styles.muted}>{copy.toCutoff}</span>
            </p>
            {warning ? (
              <p className={styles.warningText}>
                <TriangleAlert size={16} aria-hidden="true" />
                {copy.nearCutoff}
              </p>
            ) : null}
          </div>
        </>
      ) : (
        <p className={styles.muted}>{copy.noOpen}</p>
      )}
      {inflight ? (
        <p className={styles.inflight}>
          <span>{copy.inFlight(inflight.epoch.toString())}</span>
          {inflightPhase ? <PhaseBadge phase={inflightPhase} /> : null}
        </p>
      ) : null}
      <details className={styles.legend}>
        <summary>{copy.legend}</summary>
        <ul>
          {Object.values(copy.legendItems).map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </details>
    </section>
  );
}
