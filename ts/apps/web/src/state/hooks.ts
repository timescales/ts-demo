// React hooks over the runtime's controllers. Feature screens use these
// rather than the controllers, so a screen re-renders only on what it reads.
import type { CurrentEpoch } from '@timescales/sdk/api';
import { useQueries } from '@tanstack/react-query';
import { useEffect, useState } from 'react';

import { brand } from '../design/brand';
import type { ActivityEntry } from './activity';
import type { ChainState } from './chain';
import type { LiveState } from './live';
import type { OrdersState } from './orders';
import { marketQuery, useCurrent, useMarkets } from './queries';
import { useRuntime } from './runtime';
import type { SessionState } from './session';
import { createStore, readLocal, useStore, writeLocal } from './store';
import type { Address } from './types';
import type { KeyCheck, MarketCheck, VerificationState } from './verification';
import { canSeal } from './verification';
import type { WalletState } from './wallets';

export function useWallet(): WalletState {
  return useStore(useRuntime().wallets.state);
}

export function useSession(): SessionState {
  return useStore(useRuntime().session.state);
}

export function useOrders(): OrdersState {
  return useStore(useRuntime().orders.state);
}

export function useLive(): LiveState {
  return useStore(useRuntime().live.state);
}

export function useChain(): ChainState {
  return useStore(useRuntime().chain.state);
}

export function useActivity(): readonly ActivityEntry[] {
  return useStore(useRuntime().activity.entries);
}

export function useVerification(): VerificationState {
  return useStore(useRuntime().verification.state);
}

/** Verifies a market (once) and returns its check. */
export function useMarketCheck(market: Address | null): MarketCheck | undefined {
  const runtime = useRuntime();
  const state = useVerification();
  useEffect(() => {
    if (market !== null) runtime.verification.ensure(market);
  }, [runtime, market]);
  return market === null ? undefined : state.markets.get(market);
}

export function useKeyCheck(market: Address | null): KeyCheck | undefined {
  const state = useVerification();
  return market === null ? undefined : state.keys.get(market);
}

/**
 * Follows a market live: its stream topic, its current epoch and the V-3
 * check of each newly opened epoch's key.
 */
export function useLiveMarket(market: Address | null): CurrentEpoch | undefined {
  const runtime = useRuntime();
  useEffect(() => (market === null ? undefined : runtime.live.watch(market)), [runtime, market]);
  const current = useCurrent(market);
  const check = useMarketCheck(market);
  const data = current.data;
  useEffect(() => {
    if (data !== undefined && check?.status === 'ok') runtime.verification.checkCurrent(data);
  }, [runtime, data, check]);
  return data;
}

/** Whether orders may be sealed on `market` right now (verified market, vouched key). */
export function useCanSeal(market: Address | null): boolean {
  const state = useVerification();
  const current = useCurrent(market).data;
  return market !== null && canSeal(state, market, current?.open?.epoch ?? null);
}

/** Server time (V-12), re-rendered every `everyMs`. */
export function useServerNow(everyMs = 1_000): number {
  const { services } = useRuntime();
  const [now, setNow] = useState(() => services.clock.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(services.clock.now()), everyMs);
    return () => clearInterval(timer);
  }, [services, everyMs]);
  return now;
}

/** Wall-clock time (for local durations such as "non-live for 10 s"), re-rendered every `everyMs`. */
export function useWallClock(everyMs = 1_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), everyMs);
    return () => clearInterval(timer);
  }, [everyMs]);
  return now;
}

const LAST_MARKET = `${brand.wordmark}.market.v1`;
const lastMarketStore = createStore<string | null>(readLocal(LAST_MARKET));

export function rememberMarket(market: Address): void {
  if (lastMarketStore.get() === market) return;
  lastMarketStore.set(market);
  writeLocal(LAST_MARKET, market);
}

export interface MarketEntry {
  address: Address;
  label: string;
  /** Null until the market's detail has loaded. */
  flow: 'single_book' | 'dual_flow' | null;
  pinned: boolean;
}

/**
 * Markets to offer: the node's list, each marked whether this build pins it.
 * Pinned markets come first. The default is the last one used, else the
 * first pinned one.
 */
export function useMarketList(): { markets: MarketEntry[]; defaultMarket: Address | null } {
  const { config, services } = useRuntime();
  const summaries = useMarkets().data ?? [];
  const last = useStore(lastMarketStore);
  const addresses = [...new Set([...summaries.map((m) => m.market as Address), ...config.markets])];
  const details = useQueries({ queries: addresses.map((m) => marketQuery(services.api, m)) });
  const markets: MarketEntry[] = addresses
    .map((address, i) => {
      const detail = details[i]?.data;
      const summary = summaries.find((m) => m.market === address);
      return {
        address,
        label: summary?.name ?? detail?.name ?? address,
        flow:
          detail === undefined
            ? null
            : detail.params.flow === 1
              ? ('dual_flow' as const)
              : ('single_book' as const),
        pinned: config.markets.includes(address),
      };
    })
    .sort((a, b) => Number(b.pinned) - Number(a.pinned));
  const lastEntry = markets.find((m) => m.address === last);
  return {
    markets,
    defaultMarket: lastEntry?.address ?? markets[0]?.address ?? null,
  };
}
