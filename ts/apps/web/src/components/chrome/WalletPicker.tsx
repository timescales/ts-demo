import { ShieldCheck, TriangleAlert, Wallet } from 'lucide-react';

import { componentsCopy } from '../copy';
import { Badge } from '../primitives/Badge';
import { Dialog } from '../primitives/Dialog';
import { SimulatedLabel } from '../primitives/SimulatedLabel';
import styles from './WalletPicker.module.css';

export interface WalletOption {
  id: string;
  name: string;
  /** Wallet Standard icon (a data: URL). */
  icon?: string | undefined;
  /** Listed as PASSED in the signed-off wallet matrix. Nothing is by default. */
  tested: boolean;
  /** Offers the wallet features the app needs (V-11). */
  supported: boolean;
}

export interface WalletPickerProps {
  open: boolean;
  onClose: () => void;
  wallets: readonly WalletOption[];
  onSelect: (id: string) => void;
}

/** Wallet Standard picker. Untested wallets say so with a plum label. */
export function WalletPicker({ open, onClose, wallets, onSelect }: WalletPickerProps) {
  const copy = componentsCopy.walletPicker;
  return (
    <Dialog open={open} onClose={onClose} title={copy.title} description={copy.description}>
      {wallets.length === 0 ? (
        <p className={styles.empty}>{copy.empty}</p>
      ) : (
        <ul className={styles.list}>
          {wallets.map((wallet) => (
            <li key={wallet.id}>
              <button
                type="button"
                className={styles.option}
                disabled={!wallet.supported}
                onClick={() => onSelect(wallet.id)}
              >
                {wallet.icon ? (
                  <img src={wallet.icon} alt="" width={28} height={28} className={styles.icon} />
                ) : (
                  <Wallet size={28} aria-hidden="true" />
                )}
                <span className={styles.name}>{wallet.name}</span>
                {!wallet.supported ? (
                  <Badge tone="danger" icon={<TriangleAlert aria-hidden="true" />}>
                    {copy.unsupported}
                  </Badge>
                ) : wallet.tested ? (
                  <Badge tone="buy" icon={<ShieldCheck aria-hidden="true" />}>
                    {copy.tested}
                  </Badge>
                ) : (
                  <SimulatedLabel kind="untested">{copy.untested}</SimulatedLabel>
                )}
              </button>
            </li>
          ))}
        </ul>
      )}
    </Dialog>
  );
}
