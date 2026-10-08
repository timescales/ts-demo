import { componentsCopy } from '../copy';
import { cx } from '../cx';
import styles from './EpochRing.module.css';

export const RING_TICKS = 60;

export interface EpochRingProps {
  /** Elapsed fraction of the epoch, 0 to 1. Rounded down to whole ticks. */
  progress: number;
  /** Cutoff is near: elapsed ticks take the warning colour. */
  warning?: boolean | undefined;
  size?: number | undefined;
  /** The ring is decorative unless given a label. Mm:ss carries the time. */
  label?: string | undefined;
  className?: string | undefined;
}

export function elapsedTicks(progress: number): number {
  if (!Number.isFinite(progress)) return 0;
  return Math.min(RING_TICKS, Math.max(0, Math.floor(progress * RING_TICKS)));
}

/**
 * Sixty radial ticks. Elapsed ticks are brass. Ticks switch state without
 * transitions, so the ring advances in whole steps with no easing jitter.
 */
export function EpochRing({
  progress,
  warning = false,
  size = 24,
  label,
  className,
}: EpochRingProps) {
  const elapsed = elapsedTicks(progress);
  return (
    <span
      className={cx(styles.root, className)}
      data-warning={warning || undefined}
      style={{ width: size, height: size }}
    >
      <svg
        viewBox="0 0 48 48"
        width={size}
        height={size}
        {...(label ? { role: 'img', 'aria-label': label } : { 'aria-hidden': true })}
      >
        {Array.from({ length: RING_TICKS }, (_, i) => {
          const angle = (i / RING_TICKS) * 2 * Math.PI;
          const x = Math.sin(angle);
          const y = -Math.cos(angle);
          const inner = i % 5 === 0 ? 17 : 19;
          return (
            <line
              key={i}
              x1={24 + x * inner}
              y1={24 + y * inner}
              x2={24 + x * 22.5}
              y2={24 + y * 22.5}
              className={i < elapsed ? styles.elapsed : styles.tick}
            />
          );
        })}
      </svg>
    </span>
  );
}

export function epochRingLabel(progress: number): string {
  return componentsCopy.epochRing(elapsedTicks(progress));
}
