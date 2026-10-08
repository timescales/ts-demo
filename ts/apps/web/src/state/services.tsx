// The SDK services one tab uses: API client, server clock, event stream and
// the RPC chosen in Settings (from the build's allowlist only).
import { ServerClock, TimescalesApi, TimescalesStream } from '@timescales/sdk/api';
import type { Journal } from '@timescales/sdk/journal';
import { openJournal } from '@timescales/sdk/journal';
import type { OrderRecord } from '@timescales/sdk/orders';
import type { TimescalesRpc } from '@timescales/sdk/solana';
import { createTimescalesRpc } from '@timescales/sdk/solana';
import type { EvidenceRecord } from '@timescales/sdk/verify';
import type { ReactNode } from 'react';
import { createContext, useContext } from 'react';

import type { AppConfig, RpcOption } from '../app/config';
import type { Settings } from './settings';
import type { Address } from './types';

export type PollHandler = (topics: string[]) => Promise<void>;

export interface Services {
  config: AppConfig;
  api: TimescalesApi;
  clock: ServerClock;
  stream: TimescalesStream;
  /** The RPC client for an allowlisted endpoint. One client per URL. */
  rpcFor(option: RpcOption): TimescalesRpc;
  openJournal(scope: { cluster: string; program: Address; wallet: Address }): Promise<Journal>;
  /** Called while the stream is polling. Live.ts registers the refetches. */
  onPoll(handler: PollHandler): () => void;
  dispose(): void;
}

export interface ServiceOverrides {
  api?: TimescalesApi;
  fetch?: typeof fetch;
  WebSocketImpl?: typeof WebSocket;
  streamUrl?: string;
  rpc?: (url: string) => TimescalesRpc;
  openJournal?: typeof openJournal;
}

export function createServices(config: AppConfig, o: ServiceOverrides = {}): Services {
  const clock = new ServerClock();
  const api =
    o.api ??
    new TimescalesApi({
      baseUrl: config.apiBaseUrl,
      clock,
      ...(o.fetch ? { fetch: o.fetch } : {}),
    });
  const pollers = new Set<PollHandler>();
  const stream = new TimescalesStream({
    url: o.streamUrl ?? config.streamUrl,
    ...(o.WebSocketImpl ? { WebSocketImpl: o.WebSocketImpl } : {}),
    pollFallback: async (topics) => {
      await Promise.all([...pollers].map((p) => p(topics).catch(() => undefined)));
    },
  });
  const rpcs = new Map<string, TimescalesRpc>();
  const makeRpc = o.rpc ?? ((url: string) => createTimescalesRpc(url));
  return {
    config,
    api,
    clock,
    stream,
    rpcFor(option) {
      let rpc = rpcs.get(option.url);
      if (rpc === undefined) {
        rpc = makeRpc(option.url);
        rpcs.set(option.url, rpc);
      }
      return rpc;
    },
    openJournal: o.openJournal ?? openJournal,
    onPoll(handler) {
      pollers.add(handler);
      return () => {
        pollers.delete(handler);
      };
    },
    dispose() {
      stream.close();
    },
  };
}

/** The allowlisted RPC Settings selected, or the first one the build lists. */
export function selectedRpc(config: AppConfig, settings: Settings): RpcOption | null {
  return (
    config.rpcAllowlist.find((r) => r.id === settings.rpcPrimary) ?? config.rpcAllowlist[0] ?? null
  );
}

/** The cross-check RPC Settings chose, if it is allowlisted and not the primary one. */
export function crossCheckRpc(config: AppConfig, settings: Settings): RpcOption | null {
  const primary = selectedRpc(config, settings);
  const option = config.rpcAllowlist.find((r) => r.id === settings.rpcCrossCheck);
  return option === undefined || option.url === primary?.url ? null : option;
}

/**
 * A journal for verifying markets before a wallet is connected: the order
 * service needs one, and holds evidence of a failed check in it. Nothing in
 * it is persisted, and it never holds orders.
 */
export function createViewJournal(): Journal & { evidence(): readonly EvidenceRecord[] } {
  const evidence: EvidenceRecord[] = [];
  const none: OrderRecord[] = [];
  return {
    available: 'memory',
    persisted: false,
    put: () => Promise.reject(new Error('the view journal holds no orders')),
    get: () => Promise.resolve(undefined),
    list: () => Promise.resolve(none),
    putEvidence(e) {
      evidence.push(e);
      return Promise.resolve();
    },
    outbox: () => Promise.resolve([]),
    hide: () => undefined,
    wipe() {
      evidence.length = 0;
      return Promise.resolve();
    },
    evidence: () => evidence,
  };
}

const ServicesContext = createContext<Services | null>(null);

export function ServicesProvider({
  services,
  children,
}: {
  services: Services;
  children: ReactNode;
}) {
  return <ServicesContext.Provider value={services}>{children}</ServicesContext.Provider>;
}

export function useServices(): Services {
  const s = useContext(ServicesContext);
  if (s === null) throw new Error('useServices outside ServicesProvider');
  return s;
}
