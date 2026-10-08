// Wallet discovery (Wallet Standard), connection and account changes.
//
// The registry speaks the Wallet Standard app protocol itself: it answers
// `wallet-standard:register-wallet`, announces `wallet-standard:app-ready`
// and drains the older `navigator.wallets` queue, so extension wallets,
// in-wallet browsers and the Mobile Wallet Adapter (registered lazily on
// Android by main.tsx) all appear here.
import type { TraderWallet } from '@timescales/sdk/wallet';
import { WalletError, walletFromStandard } from '@timescales/sdk/wallet';

import type { Store } from './store';
import { createStore } from './store';
import type { Address } from './types';

export type StandardWallet = Parameters<typeof walletFromStandard>[0];
type StandardAccount = Parameters<typeof walletFromStandard>[1];

interface ConnectFeature {
  connect(input?: { silent?: boolean }): Promise<{ accounts: readonly StandardAccount[] }>;
}
interface DisconnectFeature {
  disconnect(): Promise<void>;
}
interface EventsFeature {
  on(
    event: 'change',
    listener: (props: { accounts?: readonly StandardAccount[] }) => void,
  ): () => void;
}

export interface WalletEntry {
  id: string;
  name: string;
  icon: string | undefined;
  /** Offers what orders need: connect and raw `signMessage` (V-11). */
  supported: boolean;
  /** PASSED in the signed-off wallet matrix. */
  tested: boolean;
}

export type WalletNotice =
  { kind: 'switched'; address: Address } | { kind: 'disconnected' } | { kind: 'locked' } | null;

export interface WalletState {
  available: readonly WalletEntry[];
  status: 'disconnected' | 'connecting' | 'connected';
  wallet: TraderWallet | null;
  /** The connected account. Changes when the wallet switches accounts. */
  address: Address | null;
  walletId: string | null;
  icon: string | undefined;
  notice: WalletNotice;
  error: WalletError | null;
}

const REGISTER = 'wallet-standard:register-wallet';
const APP_READY = 'wallet-standard:app-ready';

function feature<T>(w: StandardWallet, name: string): T | undefined {
  return (w.features as Record<string, unknown>)[name] as T | undefined;
}

function supported(w: StandardWallet): boolean {
  return (
    feature(w, 'standard:connect') !== undefined && feature(w, 'solana:signMessage') !== undefined
  );
}

function asWalletError(e: unknown): WalletError {
  if (e instanceof WalletError) return e;
  const x = (e ?? {}) as { code?: unknown; message?: unknown };
  const message = typeof x.message === 'string' ? x.message : undefined;
  return new WalletError(x.code === 4001 ? 'rejected' : 'unknown', message, { cause: e });
}

export interface WalletController {
  readonly state: Store<WalletState>;
  connect(id: string): Promise<void>;
  /** Uses a wallet that does not come from the registry (tests, the E2E build). */
  use(wallet: TraderWallet, meta?: { id?: string; icon?: string }): void;
  disconnect(): Promise<void>;
  /** A wallet call failed: a locked wallet raises its notice. */
  report(e: unknown): void;
  dismissNotice(): void;
  dispose(): void;
}

export function createWalletController(o: {
  testedWallets: readonly string[];
  target?: EventTarget;
}): WalletController {
  const target = o.target ?? globalThis.window;
  const registered = new Map<string, StandardWallet>();
  const state = createStore<WalletState>({
    available: [],
    status: 'disconnected',
    wallet: null,
    address: null,
    walletId: null,
    icon: undefined,
    notice: null,
    error: null,
  });
  let unwatch: (() => void) | null = null;
  let generation = 0;

  const entries = (): WalletEntry[] =>
    [...registered.entries()].map(([id, w]) => ({
      id,
      name: w.name,
      icon: w.icon,
      supported: supported(w),
      tested: o.testedWallets.includes(w.name),
    }));

  const register = (...wallets: StandardWallet[]): (() => void) => {
    for (const w of wallets) registered.set(w.name, w);
    state.set((s) => ({ ...s, available: entries() }));
    return () => {
      for (const w of wallets) if (registered.get(w.name) === w) registered.delete(w.name);
      state.set((s) => ({ ...s, available: entries() }));
    };
  };
  const api = Object.freeze({
    register,
    get: () => [...registered.values()],
    on: () => () => undefined,
  });
  const onRegister = (event: Event) => {
    const callback = (event as CustomEvent<(a: typeof api) => void>).detail;
    if (typeof callback === 'function') callback(api);
  };
  target?.addEventListener(REGISTER, onRegister);
  try {
    target?.dispatchEvent(new CustomEvent(APP_READY, { detail: api }));
  } catch {
    // Not a DOM target (tests without a window): wallets can still use `use`.
  }

  // The deprecated queue older injected wallets push `({ register }) =>...`
  // callbacks onto. As @wallet-standard/app does, run what is queued and
  // replace the array with an object whose `push` registers at once.
  const legacy = target === globalThis.window ? legacyQueue(register) : null;

  const stopWatching = () => {
    unwatch?.();
    unwatch = null;
  };

  const connected = (wallet: TraderWallet, id: string, icon: string | undefined) => {
    state.set((s) => ({
      ...s,
      status: 'connected',
      wallet,
      address: wallet.address as Address,
      walletId: id,
      icon,
      error: null,
    }));
  };

  const dropped = (notice: WalletNotice) => {
    stopWatching();
    state.set((s) => ({
      ...s,
      status: 'disconnected',
      wallet: null,
      address: null,
      walletId: null,
      notice,
    }));
  };

  const switched = (wallet: TraderWallet) => {
    const address = wallet.address as Address;
    state.set((s) => ({ ...s, wallet, address, notice: { kind: 'switched', address } }));
  };

  const watchStandard = (w: StandardWallet, account: StandardAccount) => {
    const events = feature<EventsFeature>(w, 'standard:events');
    if (events === undefined) return;
    let current = account.address;
    unwatch = events.on('change', (props) => {
      if (props.accounts === undefined) return;
      const next = props.accounts[0];
      if (next === undefined) {
        dropped({ kind: 'disconnected' });
        return;
      }
      if (next.address === current) return;
      current = next.address;
      // A new TraderWallet per account: nothing signs as B while showing A.
      switched(walletFromStandard(w, next));
    });
  };

  return {
    state,
    async connect(id) {
      const w = registered.get(id);
      if (w === undefined) return;
      const gen = ++generation;
      stopWatching();
      state.set((s) => ({ ...s, status: 'connecting', error: null, notice: null }));
      try {
        const connect = feature<ConnectFeature>(w, 'standard:connect');
        if (connect === undefined)
          throw new WalletError('unsupported_feature', 'no standard:connect');
        const { accounts } = await connect.connect();
        const account = accounts[0] ?? w.accounts[0];
        if (account === undefined) throw new WalletError('disconnected', 'no account was shared');
        if (gen !== generation) return;
        const wallet = walletFromStandard(w, account);
        watchStandard(w, account);
        connected(wallet, id, w.icon);
      } catch (e) {
        if (gen !== generation) return;
        state.set((s) => ({ ...s, status: 'disconnected', error: asWalletError(e) }));
      }
    },
    use(wallet, meta = {}) {
      ++generation;
      stopWatching();
      unwatch = wallet.onChange((e) => {
        if (e.kind === 'disconnected') {
          dropped({ kind: 'disconnected' });
        } else if (e.kind === 'accounts' && wallet.address !== state.get().address) {
          // The port's address follows the wallet's current account.
          switched(wallet);
        }
      });
      connected(wallet, meta.id ?? wallet.name, meta.icon);
    },
    async disconnect() {
      const id = state.get().walletId;
      const w = id === null ? undefined : registered.get(id);
      ++generation;
      dropped(null);
      const disconnect =
        w === undefined ? undefined : feature<DisconnectFeature>(w, 'standard:disconnect');
      await disconnect?.disconnect().catch(() => undefined);
    },
    report(e) {
      if (e instanceof WalletError && e.code === 'locked') {
        state.set((s) => ({ ...s, notice: { kind: 'locked' } }));
      }
    },
    dismissNotice() {
      state.set((s) => ({ ...s, notice: null }));
    },
    dispose() {
      ++generation;
      stopWatching();
      target?.removeEventListener(REGISTER, onRegister);
      legacy?.release();
    },
  };
}

type LegacyCallback = (api: { register: (...wallets: StandardWallet[]) => () => void }) => void;

function legacyQueue(register: (...wallets: StandardWallet[]) => () => void): {
  release(): void;
} | null {
  const nav = globalThis.navigator as (Navigator & { wallets?: unknown }) | undefined;
  if (nav === undefined) return null;
  const queued = nav.wallets ?? [];
  // Another registry already took the queue over.
  if (!Array.isArray(queued)) return null;
  const push = (...callbacks: unknown[]) => {
    for (const callback of callbacks) {
      if (typeof callback !== 'function') continue;
      try {
        (callback as LegacyCallback)({ register });
      } catch {
        // One faulty wallet does not keep the others from registering.
      }
    }
  };
  const replacement = Object.freeze({ push });
  try {
    Object.defineProperty(nav, 'wallets', { value: replacement, configurable: true });
  } catch {
    return null;
  }
  push(...(queued as unknown[]));
  return {
    release() {
      if (nav.wallets !== replacement) return;
      Object.defineProperty(nav, 'wallets', { value: [], configurable: true, writable: true });
    },
  };
}
