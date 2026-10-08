// Server state from the node's public API through TanStack Query.
// Stream events and resyncs invalidate these keys (live.ts). Nothing here
// changes an order's state (events are hints).
import type {
  CurrentEpoch,
  EpochDetail,
  EpochSummary,
  Info,
  MarketDetail,
  MarketSummary,
  Page,
  Status,
  TapeRow,
  TimescalesApi,
} from '@timescales/sdk/api';
import { QueryClient, queryOptions, useQuery } from '@tanstack/react-query';
import { TimescalesError } from '@timescales/sdk';

import { useServices } from './services';
import type { Address } from './types';

export const keys = {
  info: ['info'] as const,
  status: ['status'] as const,
  markets: ['markets'] as const,
  market: (m: Address) => ['market', m] as const,
  current: (m: Address) => ['current', m] as const,
  epochs: (m: Address) => ['epochs', m] as const,
  epochsPage: (m: Address, before: bigint | null) =>
    ['epochs', m, before === null ? 'head' : before.toString()] as const,
  epoch: (m: Address, e: bigint) => ['epoch', m, e.toString()] as const,
  clearing: (m: Address) => ['clearing', m] as const,
};

/** Retry only what may recover by itself (the SDK already retried transport errors). */
export function retryable(failures: number, e: unknown): boolean {
  if (failures >= 2) return false;
  return e instanceof TimescalesError ? e.retryable : true;
}

export function createAppQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: retryable,
        refetchOnWindowFocus: false,
        // A failed check or an unreachable node is shown, not hidden by stale data.
        staleTime: 5_000,
      },
    },
  });
}

export const infoQuery = (api: TimescalesApi) =>
  queryOptions<Info>({ queryKey: keys.info, queryFn: () => api.info(), staleTime: 60_000 });

export const statusQuery = (api: TimescalesApi) =>
  queryOptions<Status>({
    queryKey: keys.status,
    queryFn: () => api.status(),
    refetchInterval: 30_000,
  });

export const marketsQuery = (api: TimescalesApi) =>
  queryOptions<MarketSummary[]>({
    queryKey: keys.markets,
    queryFn: () => api.markets(),
    staleTime: 60_000,
  });

export const marketQuery = (api: TimescalesApi, m: Address) =>
  queryOptions<MarketDetail>({
    queryKey: keys.market(m),
    queryFn: () => api.market(m),
    staleTime: 60_000,
  });

export const currentQuery = (api: TimescalesApi, m: Address) =>
  queryOptions<CurrentEpoch>({ queryKey: keys.current(m), queryFn: () => api.current(m) });

export const epochsQuery = (api: TimescalesApi, m: Address, before: bigint | null) =>
  queryOptions<Page<EpochSummary>>({
    queryKey: keys.epochsPage(m, before),
    queryFn: () => api.epochs(m, before === null ? { limit: 50 } : { before, limit: 50 }),
  });

export const epochQuery = (api: TimescalesApi, m: Address, e: bigint) =>
  queryOptions<EpochDetail>({ queryKey: keys.epoch(m, e), queryFn: () => api.epoch(m, e) });

export const clearingQuery = (api: TimescalesApi, m: Address) =>
  queryOptions<Page<TapeRow>>({
    queryKey: keys.clearing(m),
    queryFn: () => api.clearing(m, { limit: 50 }),
  });

export function useInfo() {
  return useQuery(infoQuery(useServices().api));
}

export function useStatus() {
  return useQuery(statusQuery(useServices().api));
}

export function useMarkets() {
  return useQuery(marketsQuery(useServices().api));
}

export function useMarketDetail(m: Address | null) {
  const { api } = useServices();
  return useQuery({ ...marketQuery(api, m ?? ('' as Address)), enabled: m !== null });
}

export function useCurrent(m: Address | null) {
  const { api } = useServices();
  return useQuery({ ...currentQuery(api, m ?? ('' as Address)), enabled: m !== null });
}

export function useEpochs(m: Address | null, before: bigint | null) {
  const { api } = useServices();
  return useQuery({ ...epochsQuery(api, m ?? ('' as Address), before), enabled: m !== null });
}

export function useEpoch(m: Address | null, e: bigint | null) {
  const { api } = useServices();
  return useQuery({
    ...epochQuery(api, m ?? ('' as Address), e ?? 0n),
    enabled: m !== null && e !== null,
  });
}

export function useClearing(m: Address | null) {
  const { api } = useServices();
  return useQuery({ ...clearingQuery(api, m ?? ('' as Address)), enabled: m !== null });
}
