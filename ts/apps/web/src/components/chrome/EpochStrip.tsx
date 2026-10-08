import type { ReactNode } from 'react';

import { componentsCopy } from '../copy';
import { EpochRing } from '../motif/EpochRing';
import { PhaseBadge } from '../primitives/PhaseBadge';
import type { PublicPhase, U64 } from '../types';
import styles from './EpochStrip.module.css';
import { formatCountdown } from './time';

export interface EpochStripProps {
  /** Market label, e.g. "SOL/USDC". */
  market: string;
  epoch: U64;
  phase: PublicPhase;
  /** Seconds to cutoff by server time. */
  secondsToCutoff: number;
  /** Elapsed fraction of the open epoch, 0 to 1. */
  progress: number;
  /** The caller applies the  warning threshold. */
  warning?: boolean | undefined;
  inFlight?: { epoch: U64; phase: PublicPhase } | null | undefined;
  /** Preformatted, e.g. "#18421 cleared 182.37 * settled". */
  lastResult?: ReactNode;
}

/**
 * The 40 px sticky epoch strip. The countdown is role="timer" with
 * aria-live="off": phase changes and ticks are not announced from here.
 */
export function EpochStrip({
  market,
  epoch,
  phase,
  secondsToCutoff,
  progress,
  warning = false,
  inFlight,
  lastResult,
}: EpochStripProps) {
  const epochText = String(epoch);
  const copy = componentsCopy.epochStrip;
  return (
    <section className={styles.strip} aria-label={copy.label} data-warning={warning || undefined}>
      <div className={styles.open}>
        <span className={styles.market}>{market}</span>
        <span className={styles.epoch}>{copy.epoch(epochText)}</span>
        <PhaseBadge phase={phase} />
        <EpochRing progress={progress} warning={warning} size={20} />
        <span
          className={styles.timer}
          role="timer"
          aria-live="off"
          aria-label={copy.timerLabel(epochText)}
        >
          {formatCountdown(secondsToCutoff)}
        </span>
        <span className={styles.muted}>{copy.cutoff}</span>
      </div>
      <div className={styles.flight}>
        {inFlight ? (
          <>
            <span className={styles.muted}>{copy.inFlight(String(inFlight.epoch))}</span>
            <PhaseBadge phase={inFlight.phase} />
          </>
        ) : (
          <span className={styles.muted}>{copy.noInFlight}</span>
        )}
        {lastResult ? <span className={styles.result}>{lastResult}</span> : null}
      </div>
    </section>
  );
}
