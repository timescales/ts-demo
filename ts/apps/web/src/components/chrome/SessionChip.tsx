import { KeyRound } from 'lucide-react';

import { componentsCopy } from '../copy';
import { cx } from '../cx';
import styles from './SessionChip.module.css';
import { formatRemaining } from './time';

export type SessionState = 'none' | 'active' | 'expired' | 'revoked';

export interface SessionChipProps {
  state: SessionState;
  /** Seconds until the session expires (state `active`). */
  remainingSeconds?: number | undefined;
  /** Below this the chip takes the warning colour. */
  warnBelowSeconds?: number | undefined;
  /** Start (none) or renew (every other state). Renewing costs one wallet signature. */
  onAction: () => void;
}

/** Trading-session status with its expiry countdown. Click to start or renew. */
export function SessionChip({
  state,
  remainingSeconds = 0,
  warnBelowSeconds = 300,
  onAction,
}: SessionChipProps) {
  const copy = componentsCopy.session;
  const remaining = formatRemaining(remainingSeconds);
  const tone =
    state === 'active'
      ? remainingSeconds < warnBelowSeconds
        ? 'warning'
        : 'ok'
      : state === 'none'
        ? 'idle'
        : 'ended';
  const text =
    state === 'none'
      ? copy.start
      : state === 'active'
        ? copy.active(remaining)
        : state === 'expired'
          ? copy.expired
          : copy.revoked;
  return (
    <button
      type="button"
      className={cx(styles.chip, styles[tone])}
      onClick={onAction}
      {...(state === 'active' ? { 'aria-label': copy.activeLabel(remaining) } : {})}
    >
      <KeyRound size={14} aria-hidden="true" />
      <span className={state === 'active' ? styles.mono : undefined}>{text}</span>
    </button>
  );
}
