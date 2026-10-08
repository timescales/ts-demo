import { LoaderCircle } from 'lucide-react';
import type { ComponentPropsWithRef, ReactNode } from 'react';

import { cx } from '../cx';
import styles from './Button.module.css';

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger';

export interface ButtonProps extends ComponentPropsWithRef<'button'> {
  variant?: ButtonVariant | undefined;
  size?: 'sm' | 'md' | undefined;
  /** Leading icon. Replaced by a spinner while busy. */
  icon?: ReactNode;
  busy?: boolean | undefined;
}

export function Button({
  variant = 'secondary',
  size = 'md',
  icon,
  busy = false,
  type = 'button',
  className,
  children,
  ...rest
}: ButtonProps) {
  return (
    <button
      {...rest}
      type={type}
      className={cx(styles.button, styles[variant], styles[size], className)}
      aria-busy={busy || undefined}
    >
      {busy ? <LoaderCircle className={styles.spinner} size={16} aria-hidden="true" /> : icon}
      {children}
    </button>
  );
}
