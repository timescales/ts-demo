import { componentsCopy } from '../copy';
import { cx } from '../cx';
import styles from './Skeleton.module.css';
import { VisuallyHidden } from './VisuallyHidden';

export interface SkeletonProps {
  /** Number of placeholder rows. */
  lines?: number | undefined;
  /** Read by screen readers instead of the placeholder shapes. */
  label?: string | undefined;
  className?: string | undefined;
}

/** Slatted placeholder rows while data loads ("slat skeletons"). */
export function Skeleton({ lines = 3, label = componentsCopy.loading, className }: SkeletonProps) {
  return (
    <div className={cx(styles.root, className)}>
      <VisuallyHidden>{label}</VisuallyHidden>
      {Array.from({ length: lines }, (_, i) => (
        <span key={i} className={styles.line} aria-hidden="true" />
      ))}
    </div>
  );
}
