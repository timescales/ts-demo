import { componentsCopy } from '../copy';
import { Button } from '../primitives/Button';
import { Dialog } from '../primitives/Dialog';
import { InlineError } from '../primitives/InlineError';
import { ToggleGroup } from '../primitives/ToggleGroup';
import styles from './SessionDialog.module.css';
import type { SessionState } from './SessionChip';
import { formatRemaining } from './time';

export type SessionScope = 'market' | 'all';

export interface SessionDialogProps {
  open: boolean;
  onClose: () => void;
  state: SessionState;
  /** Seconds left while active. */
  remainingSeconds?: number | undefined;
  scope: SessionScope;
  onScopeChange: (scope: SessionScope) => void;
  /** The scope toggle is offered only when a market is in view. */
  marketLabel?: string | undefined;
  /** Waiting for the wallet's sign-in signature. */
  busy?: boolean | undefined;
  /**  session copy for the last failure. */
  error?: string | null | undefined;
  onStart: () => void;
  onRevoke: () => void;
}

/**
 * Starts, renews or ends the trading session: one wallet signature
 * authorises a session key. Each order still needs its own signature.
 */
export function SessionDialog({
  open,
  onClose,
  state,
  remainingSeconds = 0,
  scope,
  onScopeChange,
  marketLabel,
  busy = false,
  error,
  onStart,
  onRevoke,
}: SessionDialogProps) {
  const copy = componentsCopy.sessionDialog;
  const ended = state === 'expired' || state === 'revoked';
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={copy.title}
      description={copy.intro}
      footer={
        <div className={styles.actions}>
          {state === 'active' ? (
            <Button variant="ghost" onClick={onRevoke} disabled={busy}>
              {copy.revoke}
            </Button>
          ) : null}
          <Button variant="primary" onClick={onStart} busy={busy}>
            {busy ? copy.waiting : state === 'none' ? copy.start : copy.renew}
          </Button>
        </div>
      }
    >
      <div className={styles.body}>
        {state === 'active' ? (
          <p className={styles.status}>{copy.expires(formatRemaining(remainingSeconds))}</p>
        ) : null}
        {ended ? (
          <p className={styles.status}>
            {state === 'revoked' ? componentsCopy.session.revoked : componentsCopy.session.expired}
          </p>
        ) : null}
        {marketLabel ? (
          <ToggleGroup<SessionScope>
            label={copy.scope}
            value={scope}
            onValueChange={onScopeChange}
            disabled={busy}
            options={[
              { value: 'market', label: copy.scopeMarket(marketLabel) },
              { value: 'all', label: copy.scopeAll },
            ]}
          />
        ) : null}
        <p className={styles.note}>{copy.evictionNote}</p>
        {error ? <InlineError>{error}</InlineError> : null}
      </div>
    </Dialog>
  );
}
