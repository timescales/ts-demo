import type { Address } from '@solana/kit';
import type {
  SolanaSignAndSendTransactionFeature,
  SolanaSignInFeature,
  SolanaSignMessageFeature,
  SolanaSignTransactionFeature,
} from '@solana/wallet-standard-features';
import type { IdentifierString, Wallet, WalletAccount } from '@wallet-standard/base';
import { b58 } from '../core/encoding/base58.js';
import { onStandardChange } from './events.js';
import { WalletMutex } from './mutex.js';
import { WalletError, toWalletError, type SiwsInput, type TraderWallet } from './port.js';

type Features = Partial<
  SolanaSignMessageFeature &
    SolanaSignInFeature &
    SolanaSignTransactionFeature &
    SolanaSignAndSendTransactionFeature
>;

async function first<T>(p: Promise<readonly T[]>): Promise<T> {
  let out: readonly T[];
  try {
    out = await p;
  } catch (e) {
    throw toWalletError(e);
  }
  const x = out[0];
  if (x === undefined) throw new WalletError('unknown', 'the wallet returned no result');
  return x;
}

/**
 * The cluster `signAndSendTransaction` sends to. The port has no chain
 * argument, so the account must name exactly one Solana chain (Mobile
 * Wallet Adapter accounts do). Otherwise the caller uses `signTransaction`.
 */
function sendChain(account: WalletAccount): IdentifierString {
  const chains = account.chains.filter((c) => c.startsWith('solana:'));
  if (chains.length !== 1) {
    throw new WalletError(
      'unsupported_feature',
      'the account lists several clusters, so the wallet cannot be told where to send',
    );
  }
  return chains[0]!;
}

/** Adapts a Wallet Standard wallet. Requests are serialised by a per-wallet mutex. */
export function walletFromStandard(w: Wallet, account: WalletAccount): TraderWallet {
  const features = w.features as Features;
  const mutex = new WalletMutex();
  const signMessage = features['solana:signMessage'];
  const signIn = features['solana:signIn'];
  const signTransaction = features['solana:signTransaction'];
  const signAndSend = features['solana:signAndSendTransaction'];

  const wallet: TraderWallet = {
    address: account.address as Address,
    name: w.name,
    features: new Set(account.features),
    signMessage(message, signal) {
      if (signMessage === undefined) {
        return Promise.reject(new WalletError('unsupported_feature', 'no solana:signMessage'));
      }
      return mutex.run(async () => {
        const out = await first(signMessage.signMessage({ account, message }));
        return { signedMessage: out.signedMessage, signature: out.signature };
      }, signal);
    },
    onChange(f) {
      return onStandardChange(w, account, f);
    },
  };
  if (signIn !== undefined) {
    wallet.signIn = (input: SiwsInput, signal?: AbortSignal) =>
      mutex.run(async () => {
        // A localnet grant carries no Chain ID: wallets refuse one they
        // cannot match to the network they are on.
        const { chainId, ...rest } = input;
        const out = await first(
          signIn.signIn({
            ...rest,
            ...(chainId === 'localnet' ? {} : { chainId }),
            resources: [...input.resources],
          }),
        );
        return {
          account: out.account.address as Address,
          signedMessage: out.signedMessage,
          signature: out.signature,
        };
      }, signal);
  }
  if (signTransaction !== undefined) {
    wallet.signTransaction = (wire: Uint8Array, signal?: AbortSignal) =>
      mutex.run(async () => {
        const out = await first(signTransaction.signTransaction({ account, transaction: wire }));
        return out.signedTransaction;
      }, signal);
  }
  if (signAndSend !== undefined) {
    wallet.signAndSendTransaction = (wire: Uint8Array, signal?: AbortSignal) =>
      mutex.run(async () => {
        const chain = sendChain(account);
        const out = await first(
          signAndSend.signAndSendTransaction({ account, transaction: wire, chain }),
        );
        return { signature: b58.encode(out.signature) };
      }, signal);
  }
  return wallet;
}
