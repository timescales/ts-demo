// Everything one tab runs, created once at start: SDK services, the query
// cache, and the controllers for wallets, session, orders, verification,
// live updates, RPC health, activity and announcements. React reads them
// through the hooks below. Tests build a runtime with fakes.
import type { QueryClient } from '@tanstack/react-query';
import type { TimescalesRpc } from '@timescales/sdk/solana';
import { TimescalesError } from '@timescales/sdk';
import type { ReactNode } from 'react';
import { createContext, useContext } from 'react';

import type { AppConfig, RpcOption } from '../app/config';
import { allPins } from '../app/config';
import type { ActivityController } from './activity';
import { createActivityController } from './activity';
import type { Announcer } from './announcer';
import { createAnnouncer } from './announcer';
import type { ChainController } from './chain';
import { createChainController } from './chain';
import type { LiveController } from './live';
import { createLiveController } from './live';
import type { OrdersController } from './orders';
import { createOrdersController } from './orders';
import { createAppQueryClient, infoQuery } from './queries';
import type { ServiceOverrides, Services } from './services';
import { ServicesProvider, createServices, crossCheckRpc, selectedRpc } from './services';
import type { SessionController } from './session';
import { createSessionController } from './session';
import { settingsStore } from './settings';
import type { Store } from './store';
import { createStore } from './store';
import type { VerificationController } from './verification';
import { createVerificationController } from './verification';
import type { WalletController } from './wallets';
import { createWalletController } from './wallets';

export interface Runtime {
  config: AppConfig;
  services: Services;
  queryClient: QueryClient;
  rpc: Store<{ option: RpcOption | null; rpc: TimescalesRpc }>;
  wallets: WalletController;
  session: SessionController;
  orders: OrdersController;
  verification: VerificationController;
  live: LiveController;
  chain: ChainController;
  activity: ActivityController;
  announcer: Announcer;
  dispose(): void;
}

export interface RuntimeOptions extends ServiceOverrides {
  queryClient?: QueryClient;
  walletTarget?: EventTarget;
  /** Skip the periodic server-clock sync (tests drive the clock). */
  clockSync?: boolean;
}

const CLOCK_SYNC_MS = 5 * 60_000;

/** The RPC port when the build lists no RPC: every read fails, and says why. */
function missingRpc(): TimescalesRpc {
  const fail = () =>
    Promise.reject(
      new TimescalesError({
        kind: 'network',
        code: 'no_rpc',
        message: 'this build lists no RPC endpoint',
      }),
    );
  return {
    market: fail,
    trader: fail,
    batch: fail,
    account: fail,
    tokenBalance: fail,
    slot: fail,
    genesisHash: fail,
    blockTime: fail,
  };
}

export function createRuntime(config: AppConfig, o: RuntimeOptions = {}): Runtime {
  const services = createServices(config, o);
  const queryClient = o.queryClient ?? createAppQueryClient();
  const rpcOf = (option: RpcOption | null) =>
    option === null ? missingRpc() : services.rpcFor(option);
  const firstOption = selectedRpc(config, settingsStore.get());
  const rpc = createStore({ option: firstOption, rpc: rpcOf(firstOption) });

  const wallets = createWalletController({
    testedWallets: config.testedWallets,
    ...(o.walletTarget ? { target: o.walletTarget } : {}),
  });
  const session = createSessionController({
    api: services.api,
    clock: services.clock,
    info: () => queryClient.fetchQuery(infoQuery(services.api)),
  });
  const orders = createOrdersController({
    services,
    rpc: rpc.get().rpc,
    pins: allPins(config),
  });
  let crossOption = crossCheckRpc(config, settingsStore.get());
  const verification = createVerificationController({
    config,
    orders,
    rpc: rpc.get().rpc,
    crossCheck: crossOption === null ? null : services.rpcFor(crossOption),
  });
  const live = createLiveController({ services, queryClient });
  const chain = createChainController({ rpc: rpc.get().rpc });
  const activity = createActivityController();
  const announcer = createAnnouncer({ settings: settingsStore });

  // Wallet -> journal -> session -> order service, re-run on every change of
  // account. Nothing keeps signing for an account the wallet left.
  let attached: { wallet: unknown; address: string | null } = { wallet: null, address: null };
  let attachments = 0;
  const onWallet = () => {
    const s = wallets.state.get();
    if (s.wallet === attached.wallet && s.address === attached.address) return;
    attached = { wallet: s.wallet, address: s.address };
    const wallet = s.wallet;
    const n = ++attachments;
    void (async () => {
      const journal = await orders.attachWallet(wallet);
      // A later attach (another account, or an RPC change) owns the session now.
      if (n !== attachments) return;
      await session.attach(wallet, journal);
    })();
  };
  let lastSession: unknown = null;
  const onSession = () => {
    const s = session.state.get();
    const active = s.status === 'active' ? s.session : null;
    if (active === lastSession) return;
    lastSession = active;
    void orders.attachSession(active);
  };
  const onSettings = () => {
    const cross = crossCheckRpc(config, settingsStore.get());
    const option = selectedRpc(config, settingsStore.get());
    if (option?.url === rpc.get().option?.url) {
      if (cross?.url !== crossOption?.url) {
        crossOption = cross;
        verification.setCrossCheck(cross === null ? null : services.rpcFor(cross));
      }
      return;
    }
    crossOption = cross;
    const next = rpcOf(option);
    rpc.set({ option, rpc: next });
    orders.setRpc(next);
    verification.setRpc(next, cross === null ? null : services.rpcFor(cross));
    chain.setRpc(next);
    attached = { wallet: null, address: null };
    onWallet();
  };
  const cleanups = [
    wallets.state.subscribe(onWallet),
    session.state.subscribe(onSession),
    settingsStore.subscribe(onSettings),
  ];

  if (o.clockSync !== false) {
    const sync = () => void services.clock.sync(services.api).catch(() => undefined);
    sync();
    const timer = setInterval(sync, CLOCK_SYNC_MS);
    const onVisible = () => {
      if (document.visibilityState === 'visible') sync();
    };
    document.addEventListener('visibilitychange', onVisible);
    cleanups.push(() => {
      clearInterval(timer);
      document.removeEventListener('visibilitychange', onVisible);
    });
  }

  return {
    config,
    services,
    queryClient,
    rpc,
    wallets,
    session,
    orders,
    verification,
    live,
    chain,
    activity,
    announcer,
    dispose() {
      for (const c of cleanups) c();
      live.dispose();
      chain.dispose();
      verification.dispose();
      session.dispose();
      orders.dispose();
      wallets.dispose();
      services.dispose();
      queryClient.clear();
    },
  };
}

const RuntimeContext = createContext<Runtime | null>(null);

export function RuntimeProvider({ runtime, children }: { runtime: Runtime; children: ReactNode }) {
  return (
    <RuntimeContext.Provider value={runtime}>
      <ServicesProvider services={runtime.services}>{children}</ServicesProvider>
    </RuntimeContext.Provider>
  );
}

export function useRuntime(): Runtime {
  const r = useContext(RuntimeContext);
  if (r === null) throw new Error('useRuntime outside RuntimeProvider');
  return r;
}
