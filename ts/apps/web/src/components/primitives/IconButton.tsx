import type { ComponentPropsWithRef, ReactNode } from 'react';

import { cx } from '../cx';
import styles from './IconButton.module.css';

export interface IconButtonProps extends Omit<ComponentPropsWithRef<'button'>, 'children'> {
  /** Accessible name. The button shows only the icon. */
  label: string;
  icon: ReactNode;
  variant?: 'ghost' | 'secondary' | undefined;
}

export function IconButton({
  label,
  icon,
  variant = 'ghost',
  type = 'button',
  className,
  ...rest
}: IconButtonProps) {
  return (
    <button
      {...rest}
      type={type}
      aria-label={label}
      className={cx(styles.button, styles[variant], className)}
    >
      {icon}
    </button>
  );
}
