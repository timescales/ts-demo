import { componentsCopy } from '../copy';
import { EpochRing } from '../motif/EpochRing';
import { PhaseBadge } from '../primitives/PhaseBadge';
import type { PublicPhase, U64 } from '../types';
import styles from './EpochPill.module.css';
import { formatCountdown } from './time';

export interface EpochPillProps {
  market: string;
  epoch: U64;
  phase: PublicPhase;
  secondsToCutoff: number;
  progress: number;
  warning?: boolean | undefined;
}

/** The mobile epoch summary: market * #N * mm:ss * phase. */
export function EpochPill({
  market,
  epoch,
  phase,
  secondsToCutoff,
  progress,
  warning = false,
}: EpochPillProps) {
  const epochText = String(epoch);
  const copy = componentsCopy.epochStrip;
  return (
    <div className={styles.pill} data-warning={warning || undefined}>
      <span className={styles.market}>{market}</span>
      <span className={styles.mono}>{copy.epoch(epochText)}</span>
      <EpochRing progress={progress} warning={warning} size={16} />
      <span
        className={styles.timer}
        role="timer"
        aria-live="off"
        aria-label={copy.timerLabel(epochText)}
      >
        {formatCountdown(secondsToCutoff)}
      </span>
      <PhaseBadge phase={phase} />
    </div>
  );
}
