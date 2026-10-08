import { Wallet } from 'lucide-react';

import { componentsCopy } from '../copy';
import { Button } from '../primitives/Button';
import styles from './WalletButton.module.css';
import { shortAddress } from './time';

export type WalletButtonProps =
  | { state: 'disconnected' | 'connecting'; onClick: () => void }
  | {
      state: 'connected';
      walletName: string;
      address: string;
      /** The wallet's Wallet Standard icon (a data: URL). */
      icon?: string | undefined;
      onClick: () => void;
    };

export function WalletButton(props: WalletButtonProps) {
  const copy = componentsCopy.wallet;
  if (props.state !== 'connected') {
    const connecting = props.state === 'connecting';
    return (
      <Button
        variant="primary"
        size="sm"
        busy={connecting}
        icon={<Wallet size={16} aria-hidden="true" />}
        onClick={props.onClick}
      >
        {connecting ? copy.connecting : copy.connect}
      </Button>
    );
  }
  return (
    <Button
      variant="secondary"
      size="sm"
      className={styles.connected}
      icon={
        props.icon ? (
          <img src={props.icon} alt="" width={16} height={16} className={styles.icon} />
        ) : (
          <Wallet size={16} aria-hidden="true" />
        )
      }
      aria-label={copy.connected(props.walletName, shortAddress(props.address))}
      onClick={props.onClick}
    >
      <span className={styles.address}>{shortAddress(props.address)}</span>
    </Button>
  );
}
