import { componentsCopy } from '../copy';
import { cx } from '../cx';
import type { U64 } from '../types';
import styles from './SealGlyph.module.css';

export interface SealGlyphProps {
  epoch: U64;
  size?: number | undefined;
  /** Hide from assistive technology when the text next to it says the same. */
  decorative?: boolean | undefined;
  className?: string | undefined;
}

/** A brass ring holding the epoch number: the order is sealed for that epoch. */
export function SealGlyph({ epoch, size = 32, decorative = false, className }: SealGlyphProps) {
  const text = String(epoch);
  // Long epoch numbers shrink to stay inside the ring.
  const fontSize = Math.min(11, 44 / Math.max(text.length, 1));
  return (
    <svg
      className={cx(styles.seal, className)}
      viewBox="0 0 32 32"
      width={size}
      height={size}
      {...(decorative
        ? { 'aria-hidden': true }
        : { role: 'img', 'aria-label': componentsCopy.seal.sealedFor(text) })}
    >
      <circle cx="16" cy="16" r="14.25" className={styles.ring} />
      <text x="16" y="16" className={styles.epoch} fontSize={fontSize}>
        {text}
      </text>
    </svg>
  );
}
