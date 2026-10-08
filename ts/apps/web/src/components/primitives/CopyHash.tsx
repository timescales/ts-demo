import { Check, Copy } from 'lucide-react';
import { useState } from 'react';

import { componentsCopy } from '../copy';
import { cx } from '../cx';
import styles from './CopyHash.module.css';
import { IconButton } from './IconButton';
import { VisuallyHidden } from './VisuallyHidden';

export interface CopyHashProps {
  /** The full value (hash, address, signature). */
  value: string;
  /** What the value is, for the copy button's name ("commitment"). */
  label: string;
  head?: number | undefined;
  tail?: number | undefined;
  /** Defaults to the async clipboard API. */
  onCopy?: ((value: string) => Promise<void> | void) | undefined;
  className?: string | undefined;
}

export function truncateMiddle(value: string, head: number, tail: number): string {
  return value.length > head + tail + 1 ? `${value.slice(0, head)}...${value.slice(-tail)}` : value;
}

/** A truncated hash whose full value is what assistive technology reads. */
export function CopyHash({ value, label, head = 6, tail = 4, onCopy, className }: CopyHashProps) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await (onCopy ? onCopy(value) : navigator.clipboard.writeText(value));
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };
  return (
    <span className={cx(styles.root, className)}>
      <code className={styles.value} title={value}>
        <span aria-hidden="true">{truncateMiddle(value, head, tail)}</span>
        <VisuallyHidden>{value}</VisuallyHidden>
      </code>
      <IconButton
        label={componentsCopy.copyLabel(label)}
        icon={
          copied ? <Check size={16} aria-hidden="true" /> : <Copy size={16} aria-hidden="true" />
        }
        onClick={() => void copy()}
        onBlur={() => setCopied(false)}
      />
      <span role="status" className={styles.status}>
        {copied ? componentsCopy.copied : ''}
      </span>
    </span>
  );
}
