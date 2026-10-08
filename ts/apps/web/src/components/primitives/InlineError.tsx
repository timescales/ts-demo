import { CircleAlert } from 'lucide-react';
import type { ReactNode } from 'react';

import { componentsCopy } from '../copy';
import styles from './InlineError.module.css';
import { VisuallyHidden } from './VisuallyHidden';

export interface InlineErrorProps {
  /** Referenced by the control's aria-describedby. */
  id?: string | undefined;
  children: ReactNode;
}

/** An error shown next to the control it concerns (never colour alone). */
export function InlineError({ id, children }: InlineErrorProps) {
  return (
    <p className={styles.error} id={id}>
      <CircleAlert size={16} aria-hidden="true" />
      <span>
        <VisuallyHidden>{componentsCopy.errorPrefix} </VisuallyHidden>
        {children}
      </span>
    </p>
  );
}
