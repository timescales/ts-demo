// Server state for the trader screens (TanStack Query) and the order
// records the order service publishes (useSyncExternalStore).
import { useQuery, useQueryClient } from '@tanstack/react-query';
import type { CurrentEpoch, MarketDetail } from '@timescales/sdk/api';
import type { UnitContext } from '@timescales/sdk/core';
import type { OrderRecord } from '@timescales/sdk/orders';
import { useEffect, useState, useSyncExternalStore } from 'react';

import type { Address, OrdersPort } from './services';
import { useServices } from './services';

/** Query keys, exported so the shell can invalidate them from stream events. */
export const queryKeys = {
  info: ['info'] as const,
  markets: ['markets'] as const,
  market: (m: Address) => ['market', m] as const,
  current: (m: Address) => ['current', m] as const,
  clearing: (m: Address, before: bigint | null) =>
    ['clearing', m, before?.toString() ?? ''] as const,
  context: (m: Address, wallet: Address) => ['context', m, wallet] as const,
  trader: (m: Address, wallet: Address) => ['trader', m, wallet] as const,
  funds: (m: Address, wallet: Address) => ['funds', m, wallet] as const,
  evidence: (wallet: Address) => ['evidence', wallet] as const,
};

export function unitsOf(detail: MarketDetail): UnitContext {
  return {
    params: detail.params,
    baseDecimals: detail.baseDecimals,
    quoteDecimals: detail.quoteDecimals,
  };
}

export function useInfo() {
  const { api } = useServices();
  return useQuery({ queryKey: queryKeys.info, queryFn: () => api.info(), staleTime: 60_000 });
}

export function useMarkets() {
  const { api } = useServices();
  return useQuery({ queryKey: queryKeys.markets, queryFn: () => api.markets(), staleTime: 60_000 });
}

export function useMarketDetail(market: Address) {
  const { api } = useServices();
  return useQuery({
    queryKey: queryKeys.market(market),
    queryFn: () => api.market(market),
    staleTime: 30_000,
  });
}

/**
 * The open epoch. It is refetched once per interval and right after each
 * cutoff, so the clock moves on to the next epoch without a stream event.
 */
export function useCurrentEpoch(market: Address, intervalMs: number | undefined) {
  const { api, clock } = useServices();
  const client = useQueryClient();
  const query = useQuery({
    queryKey: queryKeys.current(market),
    queryFn: () => api.current(market),
    enabled: market !== '',
    refetchInterval: intervalMs && intervalMs > 0 ? Math.max(intervalMs, 1000) : false,
  });
  const cutoff = query.data?.open?.cutoffMs;
  useEffect(() => {
    if (cutoff === undefined) return;
    const wait = Math.max(0, cutoff - clock.now()) + 250;
    const timer = setTimeout(() => {
      void client.invalidateQueries({ queryKey: queryKeys.current(market) });
    }, wait);
    return () => clearTimeout(timer);
  }, [client, clock, cutoff, market]);
  return query;
}

export function useTraderAccount(market: Address, intervalMs: number | undefined) {
  const { trader } = useServices();
  const wallet = trader?.wallet.address ?? null;
  return useQuery({
    queryKey: queryKeys.trader(market, wallet ?? ('' as Address)),
    queryFn: () => trader!.account(market),
    enabled: trader !== null,
    refetchInterval: intervalMs && intervalMs > 0 ? Math.max(intervalMs, 1000) : false,
  });
}

/** V-1...V-4 for this market. Refetching after a failure is the user's Re-check. */
export function useVerifiedContext(market: Address) {
  const { trader } = useServices();
  const orders = trader?.orders ?? null;
  return useQuery({
    queryKey: queryKeys.context(market, trader?.wallet.address ?? ('' as Address)),
    queryFn: () => orders!.context(market),
    enabled: orders !== null,
    retry: false,
    staleTime: Infinity,
  });
}

interface RecordsStore {
  subscribe(onChange: () => void): () => void;
  getSnapshot(): readonly OrderRecord[];
}

const EMPTY: readonly OrderRecord[] = Object.freeze([]);
const stores = new WeakMap<OrdersPort, RecordsStore>();

function recordsStore(orders: OrdersPort): RecordsStore {
  let store = stores.get(orders);
  if (store === undefined) {
    let latest: readonly OrderRecord[] = EMPTY;
    const listeners = new Set<() => void>();
    let unsubscribe: (() => void) | null = null;
    store = {
      subscribe(onChange) {
        listeners.add(onChange);
        unsubscribe ??= orders.subscribe((records) => {
          latest = records;
          for (const f of [...listeners]) f();
        });
        return () => {
          listeners.delete(onChange);
          if (listeners.size === 0 && unsubscribe !== null) {
            unsubscribe();
            unsubscribe = null;
          }
        };
      },
      getSnapshot: () => latest,
    };
    stores.set(orders, store);
  }
  return store;
}

const noStore: RecordsStore = { subscribe: () => () => undefined, getSnapshot: () => EMPTY };

/** Every order record of the connected wallet, newest state first as the service orders them. */
export function useOrderRecords(): readonly OrderRecord[] {
  const orders = useServices().trader?.orders ?? null;
  const store = orders === null ? noStore : recordsStore(orders);
  return useSyncExternalStore(store.subscribe, store.getSnapshot, store.getSnapshot);
}

/** Server time, re-read every `stepMs`. */
export function useNow(clock: { now(): number }, stepMs = 1000): number {
  const [now, setNow] = useState(() => clock.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(clock.now()), stepMs);
    return () => clearInterval(timer);
  }, [clock, stepMs]);
  return now;
}

export function epochOf(current: CurrentEpoch | undefined): bigint | null {
  return current?.open?.epoch ?? null;
}
