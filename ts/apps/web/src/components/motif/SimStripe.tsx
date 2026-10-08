import type { ReactNode } from 'react';

import { cx } from '../cx';
import styles from './SimStripe.module.css';

export interface SimStripeProps {
  children: ReactNode;
  as?: 'div' | 'span' | undefined;
  className?: string | undefined;
}

/**
 * The 45 degree plum stripe behind simulated or modelled content. Diagonal stripes
 * (simulated) and horizontal slats (private) are distinct concepts.
 * The content must still say "Simulated" in words.
 */
export function SimStripe({ children, as: Tag = 'div', className }: SimStripeProps) {
  return <Tag className={cx(styles.stripe, className)}>{children}</Tag>;
}
