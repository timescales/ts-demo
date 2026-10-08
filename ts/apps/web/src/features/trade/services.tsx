// The services the Trade, Orders and Funds screens read and act through.
// The app shell builds them from the SDK (adapters.ts and
//../funds/adapter.ts) and provides them with <TraderServicesProvider>.
// Tests provide fakes. The screens never construct SDK services themselves.
import { QueryClient, QueryClientContext, QueryClientProvider } from '@tanstack/react-query';
import type {
  CurrentEpoch,
  Info,
  MarketDetail,
  MarketSummary,
  Page,
  PageReq,
  TapeRow,
} from '@timescales/sdk/api';
import type { OrderService } from '@timescales/sdk/orders';
import type { Observed, TraderAccount } from '@timescales/sdk/solana';
import type { EvidenceRecord } from '@timescales/sdk/verify';
import type { ReactNode } from 'react';
import { createContext, useContext, useState } from 'react';

import type { FundsPort } from '../funds/port';

/** A public market address (base58). */
export type Address = MarketSummary['market'];

/** The user's declared number format (Settings). Parsing never guesses it. */
export interface NumberFormat {
  decimal: '.' | ',';
  group: ',' | '.' | ' ' | '';
}

export const DEFAULT_NUMBER_FORMAT: NumberFormat = { decimal: '.', group: ',' };

/** The public API calls these screens make (a subset of TimescalesApi). */
export interface PublicApi {
  info(): Promise<Info>;
  markets(): Promise<MarketSummary[]>;
  market(m: Address): Promise<MarketDetail>;
  current(m: Address): Promise<CurrentEpoch>;
  clearing(m: Address, p?: PageReq): Promise<Page<TapeRow>>;
}

/** The order service as these screens use it. OrderService satisfies it. */
export type OrdersPort = Pick<
  OrderService,
  'context' | 'prepare' | 'submit' | 'cancel' | 'reconcile' | 'subscribe'
>;

/** The encrypted local journal: backups and saved evidence. */
export interface JournalPort {
  readonly available: 'indexeddb' | 'memory';
  readonly persisted: boolean | 'unknown';
  listEvidence(): Promise<EvidenceRecord[]>;
  exportBackup(passphrase: string): Promise<Uint8Array>;
  importBackup(
    bundle: Uint8Array,
    passphrase: string,
  ): Promise<{ imported: number; skipped: number }>;
}

/** A connected wallet. `orders` and `journal` exist once a trading session is open. */
export interface TraderPort {
  wallet: { address: Address; name: string };
  orders: OrdersPort | null;
  journal: JournalPort | null;
  /** The wallet's on-chain trader account in a market, or null when it has none. */
  account(market: Address): Promise<Observed<TraderAccount> | null>;
}

export interface TraderServices {
  api: PublicApi;
  /** Server time (ServerClock). */
  clock: { now(): number };
  numberFormat: NumberFormat;
  /** Null while no wallet is connected. */
  trader: TraderPort | null;
  /** Null while no wallet is connected. */
  funds: FundsPort | null;
  /** The app's polite live region. Screens announce own-order progress through it. */
  announce?: ((message: string) => void) | undefined;
  /** Opens the wallet picker. */
  connectWallet?: (() => void) | undefined;
  /** Starts a trading session (one wallet signature). */
  startSession?: (() => void) | undefined;
  /** Opt-in ticket shortcuts (Settings). */
  ticketShortcuts?: boolean | undefined;
  /** Private values start masked (the privacy screen setting). */
  maskByDefault?: boolean | undefined;
}

const ServicesContext = createContext<TraderServices | null>(null);

export function TraderServicesProvider({
  value,
  children,
}: {
  value: TraderServices;
  children: ReactNode;
}) {
  return <ServicesContext.Provider value={value}>{children}</ServicesContext.Provider>;
}

/** The provided services, or null when the shell has not provided them. */
export function useOptionalServices(): TraderServices | null {
  return useContext(ServicesContext);
}

export function useServices(): TraderServices {
  const services = useContext(ServicesContext);
  if (services === null) throw new Error('TraderServicesProvider is missing');
  return services;
}

/**
 * Server state goes through TanStack Query. The shell provides one
 * client for the whole app. A screen rendered without it gets its own, so
 * the feature never depends on mount order.
 */
export function WithQueryClient({ children }: { children: ReactNode }) {
  const existing = useContext(QueryClientContext);
  const [own] = useState(() => (existing ? null : new QueryClient()));
  if (existing || own === null) return <>{children}</>;
  return <QueryClientProvider client={own}>{children}</QueryClientProvider>;
}
