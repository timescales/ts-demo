import type { CSSProperties } from 'react';

import { cx } from '../cx';
import styles from './Slats.module.css';

export interface SlatsProps {
  /** Each slat stands for one epoch. */
  count?: number | undefined;
  /**
   * `closed`: slats drawn (sealed, private). `open`: slats folded away (a
   * verified result). Changing the state animates once, with a 12 ms
   * stagger, unless motion is reduced.
   */
  state?: 'open' | 'closed' | undefined;
  className?: string | undefined;
}

/** The louvre motif. Decorative: state is always also stated in text. */
export function Slats({ count = 5, state = 'closed', className }: SlatsProps) {
  return (
    <span className={cx(styles.root, className)} data-state={state} aria-hidden="true">
      {Array.from({ length: count }, (_, i) => (
        <span key={i} className={styles.slat} style={{ '--i': i } as CSSProperties} />
      ))}
    </span>
  );
}
