import type { ReactNode } from 'react';

import { cx } from '../cx';
import type { Tone } from '../types';
import styles from './Badge.module.css';

export interface BadgeProps {
  tone?: Tone | undefined;
  /** A glyph next to the text: status is never colour alone. */
  icon?: ReactNode;
  children: ReactNode;
  className?: string | undefined;
}

export function Badge({ tone = 'neutral', icon, children, className }: BadgeProps) {
  return (
    <span className={cx(styles.badge, styles[tone], className)}>
      {icon}
      <span>{children}</span>
    </span>
  );
}
