// Test-only: a TraderWallet that never signs, for screens that only need an
// account (journal, session state, account switching).
import type { TraderWallet } from '@timescales/sdk/wallet';
import { WalletError } from '@timescales/sdk/wallet';

import type { Address } from '../../state/types';

export function viewOnlyWallet(
  address: string,
  name = 'Test wallet',
): TraderWallet & { emit(kind: 'accounts' | 'chains' | 'disconnected'): void; address: Address } {
  const listeners = new Set<(e: { kind: 'accounts' | 'chains' | 'disconnected' }) => void>();
  const wallet = {
    address: address as Address,
    name,
    features: new Set<string>(['solana:signMessage']),
    signMessage: () => Promise.reject(new WalletError('rejected')),
    onChange(f: (e: { kind: 'accounts' | 'chains' | 'disconnected' }) => void) {
      listeners.add(f);
      return () => {
        listeners.delete(f);
      };
    },
    emit(kind: 'accounts' | 'chains' | 'disconnected') {
      for (const f of [...listeners]) f({ kind });
    },
  };
  return wallet;
}

/** Registers a Wallet Standard wallet the way an extension does. Returns its change emitter. */
export function registerStandardWallet(o: { name: string; address: string; features?: string[] }): {
  emitAccounts(addresses: string[]): void;
} {
  const listeners = new Set<(p: { accounts?: unknown[] }) => void>();
  const account = (address: string) => ({
    address,
    publicKey: new Uint8Array(32),
    chains: ['solana:localnet'],
    features: ['solana:signMessage'],
  });
  const features: Record<string, unknown> = {
    'standard:connect': {
      version: '1.0.0',
      connect: async () => ({ accounts: [account(o.address)] }),
    },
    'standard:events': {
      version: '1.0.0',
      on: (_e: string, f: (p: { accounts?: unknown[] }) => void) => {
        listeners.add(f);
        return () => listeners.delete(f);
      },
    },
  };
  for (const f of o.features ?? ['solana:signMessage']) {
    features[f] = { version: '1.0.0', [f.split(':')[1]!]: () => Promise.reject(new Error('test')) };
  }
  const wallet = {
    version: '1.0.0',
    name: o.name,
    icon: 'data:image/svg+xml;base64,PHN2Zy8+',
    chains: ['solana:localnet'],
    accounts: [],
    features,
  };
  window.dispatchEvent(
    new CustomEvent('wallet-standard:register-wallet', {
      detail: ({ register }: { register: (w: unknown) => void }) => register(wallet),
    }),
  );
  return {
    emitAccounts(addresses) {
      for (const f of [...listeners]) f({ accounts: addresses.map(account) });
    },
  };
}
