import type { Wallet, WalletAccount } from '@wallet-standard/base';
import type { StandardEventsFeature } from '@wallet-standard/features';

const EVENTS = 'standard:events';

/**
 * Subscribes to `standard:events` changes of one wallet as they concern
 * `account`: no accounts left is `disconnected`. Another first account, or
 * ours gone, is `accounts`. A chain change is `chains`.
 */
export function onStandardChange(
  w: Wallet,
  account: WalletAccount,
  f: (e: { kind: 'accounts' | 'chains' | 'disconnected' }) => void,
): () => void {
  const events = (w.features as Partial<StandardEventsFeature>)[EVENTS];
  if (events === undefined) return () => undefined;
  return events.on('change', (props) => {
    if (props.accounts !== undefined) {
      if (props.accounts.length === 0) f({ kind: 'disconnected' });
      else if (props.accounts[0]!.address !== account.address) f({ kind: 'accounts' });
    }
    if (props.chains !== undefined) f({ kind: 'chains' });
  });
}
