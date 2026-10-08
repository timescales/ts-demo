import type { Address } from '@solana/kit';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { b58 } from '../core/encoding/base58.js';
import { bigIntToBytesLE, bytesToBigIntLE, concat, equal, utf8 } from '../core/encoding/bytes.js';
import { ed25519PublicKey, ed25519Sign } from '../core/crypto/ed25519.js';
import { randomBytes } from '../core/crypto/random.js';
import { L } from '../core/crypto/verifyStrict.js';
import type { SiwsInput, TraderWallet } from '../wallet/port.js';

export type TestWalletBehaviour =
  | 'honest'
  | 'prefixing'
  | 'tx_mutating'
  | 'randomized'
  | 'never_resolving'
  | 'late_resolving'
  | 'account_switching'
  | 'phantom_errors'
  | 'solflare_errors'
  | 'backpack_errors';

export interface TestWalletOptions {
  seed: Uint8Array;
  behaviour?: TestWalletBehaviour;
  name?: string;
  features?: string[];
  lateMs?: number;
}

/** A scriptable wallet. `calls` records every request so tests can count prompts. */
export interface TestWallet extends TraderWallet {
  readonly calls: readonly { method: string; atMs: number }[];
  switchAccount(seed: Uint8Array): void;
  disconnect(): void;
}

const ALL_FEATURES = [
  'solana:signMessage',
  'solana:signIn',
  'solana:signTransaction',
  'solana:signAndSendTransaction',
  'standard:events',
];

/** The prefix Ledger-style wallets put before the bytes they are asked to sign. */
const OFFCHAIN_PREFIX = concat(Uint8Array.of(0xff), utf8('solana offchain'));

/** An RFC 8032 signature with a random nonce: valid, but never equal to the deterministic one. */
function randomizedSignature(seed: Uint8Array, msg: Uint8Array): Uint8Array {
  const { scalar, pointBytes } = ed25519.utils.getExtendedPublicKey(seed);
  const r = bytesToBigIntLE(sha512(randomBytes(64))) % L;
  const R = ed25519.Point.BASE.multiply(r === 0n ? 1n : r).toBytes();
  const k = bytesToBigIntLE(sha512(concat(R, pointBytes, msg))) % L;
  const s = ((r === 0n ? 1n : r) + k * scalar) % L;
  return concat(R, bigIntToBytesLE(s, 32));
}

/** The SIWS text a wallet builds from `SiwsInput` (the layout of the Sign In With Solana ABNF). */
function siwsText(input: SiwsInput): string {
  return [
    `${input.domain} wants you to sign in with your Solana account:`,
    input.address,
    '',
    input.statement,
    '',
    `URI: ${input.uri}`,
    `Version: ${input.version}`,
    `Chain ID: ${input.chainId}`,
    `Nonce: ${input.nonce}`,
    `Issued At: ${input.issuedAt}`,
    `Expiration Time: ${input.expirationTime}`,
    'Resources:',
    ...input.resources.map((r) => `- ${r}`),
  ].join('\n');
}

/** Solana's compact-u16. */
function shortVec(b: Uint8Array, at: number): { value: number; next: number } {
  let value = 0;
  for (let i = 0; i < 3; i++) {
    const byte = b[at + i];
    if (byte === undefined) throw new RangeError('truncated transaction');
    value |= (byte & 0x7f) << (7 * i);
    if ((byte & 0x80) === 0) return { value, next: at + i + 1 };
  }
  throw new RangeError('compact-u16 too long');
}

/** Splits a wire transaction into its signature slots and message, and finds a signer's slot. */
function parseWire(wire: Uint8Array): {
  sigCount: number;
  sigAt: number;
  messageAt: number;
  signerIndex(key: Uint8Array): number;
} {
  const sigs = shortVec(wire, 0);
  const messageAt = sigs.next + 64 * sigs.value;
  let at = messageAt;
  if ((wire[at]! & 0x80) !== 0) at++; // versioned message prefix
  const required = wire[at]!;
  at += 3;
  const keys = shortVec(wire, at);
  at = keys.next;
  return {
    sigCount: sigs.value,
    sigAt: sigs.next,
    messageAt,
    signerIndex(key) {
      for (let i = 0; i < Math.min(required, keys.value); i++) {
        if (equal(wire.subarray(at + 32 * i, at + 32 * (i + 1)), key)) return i;
      }
      return -1;
    },
  };
}

function rejection(behaviour: TestWalletBehaviour): unknown {
  switch (behaviour) {
    case 'phantom_errors':
      return Object.assign(new Error('User rejected the request.'), { code: 4001 });
    case 'solflare_errors':
      return Object.assign(new Error('User rejected the request'), {
        name: 'WalletSignMessageError',
      });
    case 'backpack_errors':
      return new Error('Approval Denied');
    default:
      return new Error('rejected');
  }
}

/**
 * A scriptable wallet holding an Ed25519 seed. `honest` signs exactly
 * what it is given. The other behaviours model wallets the SDK must cope
 * with: `prefixing` signs an off-chain-message prefix (fails V-11),
 * `tx_mutating` changes the transaction it signs, `randomized` uses random
 * signature nonces, `never_resolving` never answers, `late_resolving`
 * answers after `lateMs` even if the caller gave up, `account_switching`
 * switches to a fresh account when asked to sign, and the `*_errors`
 * variants reject every request the way that family of wallets reports a
 * rejection (an EIP-1193 code 4001, a wallet-adapter error class, a bare
 * message). The shapes are representative, not captured from the wallets.
 */
export function createTestWallet(o: TestWalletOptions): TestWallet {
  const behaviour = o.behaviour ?? 'honest';
  const features = new Set(o.features ?? ALL_FEATURES);
  const listeners = new Set<(e: { kind: 'accounts' | 'chains' | 'disconnected' }) => void>();
  const calls: { method: string; atMs: number }[] = [];
  let seed = o.seed.slice();
  let publicKey = ed25519PublicKey(seed);
  let connected = true;
  let switched = false;

  const emit = (kind: 'accounts' | 'chains' | 'disconnected'): void => {
    for (const f of [...listeners]) f({ kind });
  };

  const switchTo = (next: Uint8Array): void => {
    seed = next.slice();
    publicKey = ed25519PublicKey(seed);
    emit('accounts');
  };

  const sign = (msg: Uint8Array): Uint8Array =>
    behaviour === 'randomized' ? randomizedSignature(seed, msg) : ed25519Sign(seed, msg);

  /** Runs one request the way the behaviour says, after recording it. */
  const request = <T>(method: string, answer: () => T): Promise<T> => {
    calls.push({ method, atMs: Date.now() });
    if (!connected) {
      return Promise.reject(Object.assign(new Error('Wallet not connected'), { code: 4900 }));
    }
    switch (behaviour) {
      case 'never_resolving':
        return new Promise<T>(() => undefined);
      case 'late_resolving':
        return new Promise<T>((resolve) => setTimeout(() => resolve(answer()), o.lateMs ?? 50));
      case 'phantom_errors':
      case 'solflare_errors':
      case 'backpack_errors':
        return Promise.reject(rejection(behaviour));
      case 'account_switching':
        if (!switched) {
          switched = true;
          switchTo(sha512(concat(seed, utf8('switched'))).slice(0, 32));
        }
        return Promise.resolve().then(answer);
      default:
        return Promise.resolve().then(answer);
    }
  };

  const signWire = (wire: Uint8Array): Uint8Array => {
    const out = wire.slice();
    // A mutating wallet changes the last byte of the message (the last instruction's data).
    if (behaviour === 'tx_mutating') out[out.length - 1]! ^= 0x01;
    const tx = parseWire(out);
    const index = tx.signerIndex(publicKey);
    if (index < 0 || index >= tx.sigCount) throw new Error('this wallet is not a signer');
    out.set(sign(out.subarray(tx.messageAt)), tx.sigAt + 64 * index);
    return out;
  };

  const wallet: TestWallet = {
    get address(): Address {
      return b58.encode(publicKey) as Address;
    },
    name: o.name ?? 'Test wallet',
    features,
    calls,
    signMessage(message, signal) {
      void signal;
      return request('signMessage', () => {
        const signed =
          behaviour === 'prefixing' ? concat(OFFCHAIN_PREFIX, message) : message.slice();
        return { signedMessage: signed, signature: sign(signed) };
      });
    },
    onChange(f) {
      listeners.add(f);
      return () => {
        listeners.delete(f);
      };
    },
    switchAccount(next) {
      switchTo(next);
    },
    disconnect() {
      connected = false;
      emit('disconnected');
    },
  };
  if (features.has('solana:signIn')) {
    wallet.signIn = (input, signal) => {
      void signal;
      return request('signIn', () => {
        const text = utf8(siwsText(input));
        const signed = behaviour === 'prefixing' ? concat(OFFCHAIN_PREFIX, text) : text;
        return { account: wallet.address, signedMessage: signed, signature: sign(signed) };
      });
    };
  }
  if (features.has('solana:signTransaction')) {
    wallet.signTransaction = (wire, signal) => {
      void signal;
      return request('signTransaction', () => signWire(wire));
    };
  }
  if (features.has('solana:signAndSendTransaction')) {
    wallet.signAndSendTransaction = (wire, signal) => {
      void signal;
      return request('signAndSendTransaction', () => {
        const signed = signWire(wire);
        const tx = parseWire(signed);
        return { signature: b58.encode(signed.subarray(tx.sigAt, tx.sigAt + 64)) };
      });
    };
  }
  return wallet;
}
