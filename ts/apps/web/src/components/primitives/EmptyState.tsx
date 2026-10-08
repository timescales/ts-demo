import type { ReactNode } from 'react';

import { cx } from '../cx';
import { Slats } from '../motif/Slats';
import styles from './EmptyState.module.css';

export interface EmptyStateProps {
  title: ReactNode;
  body?: ReactNode;
  action?: ReactNode;
  /** Heading level that fits the surrounding outline. */
  as?: 'h1' | 'h2' | 'h3' | 'p' | undefined;
  className?: string | undefined;
}

export function EmptyState({
  title,
  body,
  action,
  as: Heading = 'h2',
  className,
}: EmptyStateProps) {
  return (
    <div className={cx(styles.root, className)}>
      <Slats count={3} className={styles.slats} />
      <Heading className={styles.title}>{title}</Heading>
      {body ? <p className={styles.body}>{body}</p> : null}
      {action ? <div className={styles.action}>{action}</div> : null}
    </div>
  );
}
