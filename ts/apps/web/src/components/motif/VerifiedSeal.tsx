import { componentsCopy } from '../copy';
import { cx } from '../cx';
import styles from './VerifiedSeal.module.css';

export interface VerifiedSealProps {
  size?: number | undefined;
  /** Accessible name. Defaults to "Verified". */
  label?: string | undefined;
  decorative?: boolean | undefined;
  className?: string | undefined;
}

/** Seal ring with a check: every client-side check for the result passed. */
export function VerifiedSeal({
  size = 20,
  label = componentsCopy.seal.verified,
  decorative = false,
  className,
}: VerifiedSealProps) {
  return (
    <svg
      className={cx(styles.seal, className)}
      viewBox="0 0 24 24"
      width={size}
      height={size}
      {...(decorative ? { 'aria-hidden': true } : { role: 'img', 'aria-label': label })}
    >
      <circle cx="12" cy="12" r="10.25" className={styles.ring} />
      <path d="M7.5 12.5l3 3 6-6.5" className={styles.check} />
    </svg>
  );
}
