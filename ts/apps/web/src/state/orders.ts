// The connected wallet's journal and order service. One OrderService per
// wallet and RPC. With an active session it is started, and the tab becomes
// the wallet's leader or a follower (navigator.locks). Before a wallet
// is connected a view-only service verifies markets.
import type { Journal } from '@timescales/sdk/journal';
import type { OrderRecord } from '@timescales/sdk/orders';
import { OrderService } from '@timescales/sdk/orders';
import type { TimescalesRpc } from '@timescales/sdk/solana';
import type { TradingSession, TraderWallet } from '@timescales/sdk/wallet';
import type { AppPins } from '@timescales/sdk/verify';
import { TimescalesError } from '@timescales/sdk';

import type { PersistenceProblem } from '../components/chrome';
import type { Services } from './services';
import { createViewJournal } from './services';
import type { Store } from './store';
import { createStore } from './store';
import type { Address } from './types';

export interface OrdersState {
  wallet: Address | null;
  journal: Journal | null;
  service: OrderService | null;
  role: 'leader' | 'follower' | null;
  records: readonly OrderRecord[];
  persistence: PersistenceProblem | null;
  error: TimescalesError | null;
}

export interface OrdersController {
  readonly state: Store<OrdersState>;
  /** The service that verifies markets: the wallet's, or a view-only one. */
  verifier(): OrderService;
  /** Opens the journal for a wallet (null: none connected). */
  attachWallet(wallet: TraderWallet | null): Promise<Journal | null>;
  /** Starts or stops the service as the session comes and goes. */
  attachSession(session: TradingSession | null): Promise<void>;
  /** A journal write failed for lack of space (: blocks sealing). */
  reportStorage(e: unknown): void;
  /** The RPC changed: drops every service built on the old one. The wallet's is rebuilt on the next attach. */
  setRpc(rpc: TimescalesRpc): void;
  dispose(): void;
}

const EMPTY: readonly OrderRecord[] = [];

function persistenceOf(j: Journal): PersistenceProblem | null {
  if (j.available === 'memory') return 'private_window';
  if (j.persisted === false) return 'not_persistent';
  return null;
}

export function createOrdersController(d: {
  services: Services;
  rpc: TimescalesRpc;
  pins: readonly AppPins[];
}): OrdersController {
  const state = createStore<OrdersState>({
    wallet: null,
    journal: null,
    service: null,
    role: null,
    records: EMPTY,
    persistence: null,
    error: null,
  });
  let rpc = d.rpc;
  let view: OrderService | null = null;
  let wallet: TraderWallet | null = null;
  let unsubscribe: (() => void) | null = null;
  let generation = 0;

  const build = (journal: Journal) =>
    new OrderService({
      api: d.services.api,
      rpc,
      journal,
      stream: d.services.stream,
      clock: d.services.clock,
      pins: d.pins,
    });

  const teardown = () => {
    unsubscribe?.();
    unsubscribe = null;
    state.get().service?.dispose();
  };

  return {
    state,
    verifier() {
      const service = state.get().service;
      if (service !== null) return service;
      view ??= build(createViewJournal());
      return view;
    },
    async attachWallet(next) {
      const gen = ++generation;
      teardown();
      wallet = next;
      state.set({
        wallet: (next?.address as Address | undefined) ?? null,
        journal: null,
        service: null,
        role: null,
        records: EMPTY,
        persistence: null,
        error: null,
      });
      if (next === null || d.services.config.programId === null) return null;
      let journal: Journal;
      try {
        journal = await d.services.openJournal({
          cluster: d.services.config.cluster,
          program: d.services.config.programId,
          wallet: next.address as Address,
        });
      } catch (e) {
        if (gen !== generation) return null;
        state.set((s) => ({
          ...s,
          persistence: 'unreadable',
          error: e instanceof TimescalesError ? e : null,
        }));
        return null;
      }
      if (gen !== generation) return null;
      const service = build(journal);
      state.set((s) => ({ ...s, journal, service, persistence: persistenceOf(journal) }));
      // Records are readable before a session exists (Orders, Funds estimates).
      unsubscribe = service.subscribe((records) => {
        if (gen === generation) state.set((s) => ({ ...s, records }));
      });
      return journal;
    },
    async attachSession(session) {
      const { service } = state.get();
      const w = wallet;
      if (service === null || w === null) return;
      const gen = generation;
      if (session === null) {
        await service.stop();
        if (gen === generation) state.set((s) => ({ ...s, role: null }));
        return;
      }
      try {
        const { role } = await service.start(w, session);
        if (gen === generation) state.set((s) => ({ ...s, role, error: null }));
      } catch (e) {
        if (gen === generation) {
          state.set((s) => ({
            ...s,
            role: null,
            error: e instanceof TimescalesError ? e : null,
          }));
        }
      }
    },
    reportStorage(e) {
      if (e instanceof TimescalesError && e.kind === 'storage') {
        const problem: PersistenceProblem = e.code === 'quota_exceeded' ? 'full' : 'unreadable';
        state.set((s) => ({ ...s, persistence: problem }));
      }
    },
    setRpc(next) {
      rpc = next;
      view?.dispose();
      view = null;
      // The wallet's service caches what it verified through the old RPC, so
      // it is dropped now rather than at the next attach: until the wallet is
      // attached again, verifier hands out a view built on the new RPC.
      ++generation;
      teardown();
      state.set((s) => ({
        ...s,
        journal: null,
        service: null,
        role: null,
        records: EMPTY,
        persistence: null,
        error: null,
      }));
    },
    dispose() {
      ++generation;
      teardown();
      view?.dispose();
      view = null;
    },
  };
}
