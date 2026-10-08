import { useId } from 'react';

import { brand } from './brand';
import styles from './Wordmark.module.css';

export interface WordmarkProps {
  /** Rendered height in CSS pixels. The width follows the 196:40 lock-up. */
  height?: number | undefined;
  /** Hide from assistive technology when the surrounding link names it. */
  decorative?: boolean | undefined;
  className?: string | undefined;
}

// Slat geometry of the lock-up: three successive epochs, shortest first.
const SLATS = [
  { y: 14, width: 10 },
  { y: 20, width: 14 },
  { y: 26, width: 18 },
] as const;

/**
 * The wordmark: the lowercase product name in the display face, its letters seen
 * through three slats. Rendered inline (not as <img>) so it uses the
 * self-hosted display font and follows the theme through currentColor.
 */
export function Wordmark({ height = 28, decorative = false, className }: WordmarkProps) {
  const maskId = `wordmark-${useId().replace(/[^a-zA-Z0-9_-]/g, '')}`;
  const slats = SLATS.slice(0, brand.slats);
  return (
    <svg
      className={className ? `${styles.root} ${className}` : styles.root}
      viewBox="0 0 196 40"
      height={height}
      width={(height * 196) / 40}
      {...(decorative ? { 'aria-hidden': true } : { role: 'img', 'aria-label': brand.wordmark })}
    >
      <defs>
        <mask id={maskId} maskUnits="userSpaceOnUse" x="0" y="0" width="196" height="40">
          <rect x="0" y="0" width="196" height="40" fill="white" />
          {slats.map((slat) => (
            <rect key={slat.y} x="24" y={slat.y + 0.5} width="172" height="1.25" fill="black" />
          ))}
        </mask>
      </defs>
      {slats.map((slat) => (
        <rect
          key={slat.y}
          className={styles.slat}
          x={18 - slat.width}
          y={slat.y}
          width={slat.width}
          height="2.25"
          rx="1"
        />
      ))}
      <text
        className={styles.word}
        x="24"
        y="30"
        textLength="168"
        lengthAdjust="spacing"
        mask={`url(#${maskId})`}
      >
        {brand.wordmark}
      </text>
    </svg>
  );
}
