import { Eye, EyeOff } from 'lucide-react';
import type { ReactNode } from 'react';

import { componentsCopy } from '../copy';
import { cx } from '../cx';
import styles from './MaskedValue.module.css';
import { VisuallyHidden } from './VisuallyHidden';

export interface MaskedValueProps {
  /** The private value, rendered only while revealed. */
  children: ReactNode;
  revealed: boolean;
  onRevealedChange: (revealed: boolean) => void;
  className?: string | undefined;
}

/**
 * A private value behind slats. It is a toggle button (aria-pressed =
 * revealed) whose accessible name is "hidden value" while masked.
 */
export function MaskedValue({ children, revealed, onRevealedChange, className }: MaskedValueProps) {
  return (
    <button
      type="button"
      className={cx(styles.root, className)}
      aria-pressed={revealed}
      onClick={() => onRevealedChange(!revealed)}
    >
      {revealed ? (
        <span className={styles.value}>{children}</span>
      ) : (
        <>
          <span className={styles.mask} aria-hidden="true" />
          <VisuallyHidden>{componentsCopy.hiddenValue}</VisuallyHidden>
        </>
      )}
      {revealed ? (
        <EyeOff size={14} aria-hidden="true" className={styles.icon} />
      ) : (
        <Eye size={14} aria-hidden="true" className={styles.icon} />
      )}
    </button>
  );
}
