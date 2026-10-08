import type { Address } from '@solana/kit';
import { TimescalesError, type WalletErrorCode } from '../errors.js';

/** Sign In With Solana input. The SDK always sets every field. */
export interface SiwsInput {
  domain: string;
  address: Address;
  statement: string;
  uri: string;
  version: '1';
  chainId: string;
  nonce: string;
  issuedAt: string;
  expirationTime: string;
  resources: string[];
}

/** The wallet as the SDK uses it, independent of Wallet Standard. */
export interface TraderWallet {
  readonly address: Address;
  readonly name: string;
  readonly features: ReadonlySet<string>;
  signMessage(
    message: Uint8Array,
    signal?: AbortSignal,
  ): Promise<{ signedMessage: Uint8Array; signature: Uint8Array }>;
  signIn?(
    input: SiwsInput,
    signal?: AbortSignal,
  ): Promise<{ account: Address; signedMessage: Uint8Array; signature: Uint8Array }>;
  signTransaction?(wire: Uint8Array, signal?: AbortSignal): Promise<Uint8Array>;
  signAndSendTransaction?(wire: Uint8Array, signal?: AbortSignal): Promise<{ signature: string }>;
  /** `standard:events`. */
  onChange(f: (e: { kind: 'accounts' | 'chains' | 'disconnected' }) => void): () => void;
}

export class WalletError extends TimescalesError {
  declare readonly kind: 'wallet';
  declare readonly code: WalletErrorCode;

  constructor(code: WalletErrorCode, message?: string, o?: { cause?: unknown; details?: unknown }) {
    super({
      kind: 'wallet',
      code,
      message: message ?? `wallet: ${code}`,
      retryable: code === 'busy' || code === 'timeout',
      cause: o?.cause,
      details: o?.details,
    });
    this.name = 'WalletError';
  }
}

// Error shapes wallets throw: EIP-1193-style numeric codes (Phantom,
// Backpack), wallet-adapter error class names (Solflare and others), and
// free-text messages.
const CODES: Readonly<Record<number, WalletErrorCode>> = {
  4001: 'rejected',
  4100: 'disconnected',
  4200: 'unsupported_feature',
  4900: 'disconnected',
  [-32002]: 'busy',
  [-32601]: 'unsupported_feature',
  [-32603]: 'unknown',
};
const NAMES: Readonly<Record<string, WalletErrorCode>> = {
  WalletNotConnectedError: 'disconnected',
  WalletDisconnectedError: 'disconnected',
  WalletAccountError: 'account_changed',
  WalletWindowClosedError: 'rejected',
  WalletTimeoutError: 'timeout',
};
const MESSAGES: readonly [RegExp, WalletErrorCode][] = [
  [/reject|denied|declin|cancel/i, 'rejected'],
  [/locked/i, 'locked'],
  [/not connected|disconnected/i, 'disconnected'],
  [/pending|already (?:processing|open)|busy/i, 'busy'],
  [/time(?:d)? ?out/i, 'timeout'],
  [/not supported|unsupported/i, 'unsupported_feature'],
];

/** Normalises anything a wallet throws into a {@link WalletError}. */
export function toWalletError(e: unknown): WalletError {
  if (e instanceof WalletError) return e;
  if (e instanceof TimescalesError && e.kind === 'aborted') {
    return new WalletError('abandoned', e.message, { cause: e });
  }
  const x = (e ?? {}) as { code?: unknown; name?: unknown; message?: unknown };
  const message = typeof x.message === 'string' ? x.message : typeof e === 'string' ? e : '';
  let code: WalletErrorCode | undefined;
  if (typeof x.code === 'number') code = CODES[x.code];
  if (code === undefined && typeof x.name === 'string') code = NAMES[x.name];
  if (code === undefined) code = MESSAGES.find(([re]) => re.test(message))?.[1];
  return new WalletError(code ?? 'unknown', message.length > 0 ? message : undefined, {
    cause: e,
  });
}

/**
 * Resolves with `p`, or rejects with `abandoned` as soon as `signal` aborts.
 * A wallet answer that arrives after the abort is ignored.
 */
export function abandonable<T>(p: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (signal === undefined) return p;
  if (signal.aborted) {
    p.catch(() => undefined);
    return Promise.reject(new WalletError('abandoned'));
  }
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => reject(new WalletError('abandoned'));
    signal.addEventListener('abort', onAbort, { once: true });
    p.then(
      (v) => {
        signal.removeEventListener('abort', onAbort);
        resolve(v);
      },
      (e: unknown) => {
        signal.removeEventListener('abort', onAbort);
        reject(e);
      },
    );
  });
}
