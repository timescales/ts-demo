import type { ReactNode } from 'react';

import styles from './VisuallyHidden.module.css';

/** Text for assistive technology only. */
export function VisuallyHidden({ children, id }: { children: ReactNode; id?: string | undefined }) {
  return (
    <span className={styles.root} id={id}>
      {children}
    </span>
  );
}
