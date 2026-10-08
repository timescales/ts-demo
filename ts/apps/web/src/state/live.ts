// Wires the node's event stream to the query cache. Events are
// hints: they only mark cached views stale, which refetches them over REST.
// A resync (topic_seq gap, changed stream_id, lag, reconnect, a tab that
// becomes visible) refetches the current epoch, the epoch in flight and the
// status. While the socket stays down the stream polls through `onPoll`.
import type { CurrentEpoch, ResyncReason, StreamEvent, StreamState } from '@timescales/sdk/api';
import type { QueryClient } from '@tanstack/react-query';

import { epochQuery, keys } from './queries';
import type { Services } from './services';
import type { Store } from './store';
import { createStore } from './store';
import type { Address } from './types';

export interface LiveState {
  stream: StreamState;
  /** When the stream left `live` (ms), or null while live. */
  nonLiveSince: number | null;
  /** A resync is refetching. Views show "Catching up...". */
  catchingUp: boolean;
  lastResync: ResyncReason | null;
  resyncs: number;
  /** Reconnection attempts since the stream was last live. */
  reconnects: number;
  /** Last stream event per market, for the epoch strip and announcements. */
  lastEvent: StreamEvent | null;
}

export interface LiveController {
  readonly state: Store<LiveState>;
  /** Follows a market's topic while the returned function is not called. */
  watch(market: Address): () => void;
  /** Called with every stream event (announcer, activity). */
  onEvent(f: (e: StreamEvent) => void): () => void;
  /** A view that just took a fresh value, e.g. after a failed check was re-run. */
  refresh(market: Address): Promise<void>;
  dispose(): void;
}

function topicOf(market: Address): string {
  return `market:${market}`;
}

function marketOfTopic(topic: string): Address | null {
  return topic.startsWith('market:') ? (topic.slice('market:'.length) as Address) : null;
}

export function createLiveController(d: {
  services: Services;
  queryClient: QueryClient;
}): LiveController {
  const { stream } = d.services;
  const qc = d.queryClient;
  const state = createStore<LiveState>({
    stream: 'connecting',
    nonLiveSince: Date.now(),
    catchingUp: false,
    lastResync: null,
    resyncs: 0,
    reconnects: 0,
    lastEvent: null,
  });
  const watched = new Map<Address, number>();
  const listeners = new Set<(e: StreamEvent) => void>();

  const inflightOf = (m: Address): bigint | null => {
    const c = qc.getQueryData<CurrentEpoch>(keys.current(m));
    return c?.inflight?.epoch ?? null;
  };

  /** The views a resync or a poll refetches for one market. */
  const refetchMarket = async (m: Address) => {
    await qc.invalidateQueries({ queryKey: keys.current(m) });
    const inflight = inflightOf(m);
    const tasks = [qc.invalidateQueries({ queryKey: keys.clearing(m) })];
    // The epoch in flight is fetched even when no screen shows it: the
    // order service and the strip read it from the cache.
    if (inflight !== null) {
      tasks.push(
        qc.fetchQuery({ ...epochQuery(d.services.api, m, inflight), staleTime: 0 }).then(
          () => undefined,
          () => undefined,
        ),
      );
    }
    await Promise.all(tasks);
  };

  const refetchAll = async () => {
    await Promise.all([
      qc.invalidateQueries({ queryKey: keys.status }),
      ...[...watched.keys()].map(refetchMarket),
    ]);
  };

  const onEvent = (e: StreamEvent) => {
    state.set((s) => ({ ...s, lastEvent: e }));
    for (const f of [...listeners]) f(e);
    if (e.kind === 'status.changed') {
      void qc.invalidateQueries({ queryKey: keys.status });
      return;
    }
    if (e.kind === 'program.upgraded') {
      void qc.invalidateQueries({ queryKey: ['market'] });
      return;
    }
    if (e.kind === 'unknown') return;
    const m = e.market;
    void qc.invalidateQueries({ queryKey: keys.current(m) });
    switch (e.kind) {
      case 'market.state':
      case 'governance.pending':
      case 'governance.applied':
        void qc.invalidateQueries({ queryKey: keys.market(m) });
        void qc.invalidateQueries({ queryKey: keys.markets });
        void qc.invalidateQueries({ queryKey: keys.status });
        return;
      case 'intake.paused':
      case 'intake.resumed':
        void qc.invalidateQueries({ queryKey: keys.status });
        return;
      case 'key.published':
      case 'parked.invalidated':
        return;
      default:
        void qc.invalidateQueries({ queryKey: keys.epoch(m, e.epoch) });
        void qc.invalidateQueries({ queryKey: keys.epochs(m) });
        if (e.kind === 'epoch.settled' || e.kind === 'epoch.posted' || e.kind === 'epoch.aborted') {
          void qc.invalidateQueries({ queryKey: keys.clearing(m) });
        }
    }
  };

  const onResync = (reason: ResyncReason) => {
    state.set((s) => ({ ...s, catchingUp: true, lastResync: reason, resyncs: s.resyncs + 1 }));
    void refetchAll().finally(() => state.set((s) => ({ ...s, catchingUp: false })));
  };

  const onState = (next: StreamState) => {
    state.set((s) => ({
      ...s,
      stream: next,
      nonLiveSince: next === 'live' ? null : (s.nonLiveSince ?? Date.now()),
      reconnects: next === 'live' ? 0 : next === 'reconnecting' ? s.reconnects + 1 : s.reconnects,
    }));
  };

  const cleanups = [
    stream.on('event', onEvent),
    stream.on('resync', onResync),
    stream.on('state', onState),
    d.services.onPoll(async (topics) => {
      const tasks: Promise<void>[] = [];
      for (const t of topics) {
        const m = marketOfTopic(t);
        if (m !== null) tasks.push(refetchMarket(m));
        else if (t === 'status') tasks.push(qc.invalidateQueries({ queryKey: keys.status }));
      }
      await Promise.all(tasks);
    }),
  ];
  stream.subscribe(['status']);

  return {
    state,
    watch(market) {
      const n = watched.get(market) ?? 0;
      watched.set(market, n + 1);
      if (n === 0) stream.subscribe([topicOf(market)]);
      return () => {
        const left = (watched.get(market) ?? 1) - 1;
        if (left > 0) {
          watched.set(market, left);
          return;
        }
        watched.delete(market);
        stream.unsubscribe([topicOf(market)]);
      };
    },
    onEvent(f) {
      listeners.add(f);
      return () => {
        listeners.delete(f);
      };
    },
    refresh: refetchMarket,
    dispose() {
      for (const c of cleanups) c();
      listeners.clear();
    },
  };
}
