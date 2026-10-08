import { componentsCopy } from '../copy';
import { cx } from '../cx';
import { VisuallyHidden } from '../primitives/VisuallyHidden';
import type { Side } from '../types';
import styles from './DirectionGlyph.module.css';

export interface DirectionGlyphProps {
  side: Side;
  /** Show the word next to the glyph. When false it is still read aloud. */
  showWord?: boolean | undefined;
  className?: string | undefined;
}

/** Side as colour + ▲/▼ + word, never colour alone. */
export function DirectionGlyph({ side, showWord = true, className }: DirectionGlyphProps) {
  const word = componentsCopy.side[side];
  return (
    <span className={cx(styles.root, styles[side], className)}>
      <span aria-hidden="true" className={styles.glyph}>
        {side === 'buy' ? '▲' : '▼'}
      </span>
      {showWord ? <span>{word}</span> : <VisuallyHidden>{word}</VisuallyHidden>}
    </span>
  );
}
