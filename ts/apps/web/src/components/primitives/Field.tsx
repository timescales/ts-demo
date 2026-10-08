import type { ReactNode } from 'react';

import styles from './Field.module.css';
import { InlineError } from './InlineError';

export interface FieldProps {
  id: string;
  label: ReactNode;
  hint?: ReactNode;
  error?: ReactNode;
  children: ReactNode;
  /** Rendered between the control and the hint, e.g. an exact-value echo. */
  after?: ReactNode;
  /** `inline` puts the label beside the control (compact chrome such as the top bar). */
  layout?: 'stacked' | 'inline' | undefined;
}

export function hintId(id: string) {
  return `${id}-hint`;
}

export function errorId(id: string) {
  return `${id}-error`;
}

/** The ids a control's aria-describedby lists: hint first, then error. */
export function describedBy(id: string, hint: ReactNode, error: ReactNode): string | undefined {
  const ids = [hint ? hintId(id) : null, error ? errorId(id) : null].filter(Boolean);
  return ids.length > 0 ? ids.join(' ') : undefined;
}

/** Always-visible label, helper text and inline error for one control. */
export function Field({ id, label, hint, error, children, after, layout = 'stacked' }: FieldProps) {
  return (
    <div className={layout === 'inline' ? `${styles.field} ${styles.inline}` : styles.field}>
      <label className={styles.label} htmlFor={id}>
        {label}
      </label>
      {children}
      {after}
      {hint ? (
        <p className={styles.hint} id={hintId(id)}>
          {hint}
        </p>
      ) : null}
      {error ? <InlineError id={errorId(id)}>{error}</InlineError> : null}
    </div>
  );
}
