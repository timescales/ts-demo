import { cx } from '../cx';
import styles from './KeyboardShortcut.module.css';

export interface KeyboardShortcutProps {
  /** Key names in order, e.g. ['Ctrl', 'Enter']. */
  keys: readonly string[];
  className?: string | undefined;
}

/** A key combination, shown next to the control it triggers. */
export function KeyboardShortcut({ keys, className }: KeyboardShortcutProps) {
  return (
    <kbd className={cx(styles.combo, className)}>
      {keys.map((key, index) => (
        <span key={`${key}-${index}`} className={styles.part}>
          {index > 0 ? <span className={styles.plus}>+</span> : null}
          <kbd className={styles.key}>{key}</kbd>
        </span>
      ))}
    </kbd>
  );
}
