// Test-only doubles for the trader ports. They model what the screens rely
// on (records, steps, outcomes). The SDK's own behaviour is tested in the SDK.
import type { MarketDetail } from '@timescales/sdk/api';
import type { BookId, MarketParams, PriceBand } from '@timescales/sdk/core';
import { bookFor } from '@timescales/sdk/core';
import type {
  OrderDraft,
  OrderRecord,
  OrderState,
  Participation,
  ParticipationState,
  PreparedOrder,
  ReconcileReport,
  SubmitStep,
} from '@timescales/sdk/orders';
import type { Observed, TraderAccount } from '@timescales/sdk/solana';
import type { EvidenceRecord, OwnFill, VerifiedMarketContext } from '@timescales/sdk/verify';

import type { FundsPort } from '../../funds/port';
import { reservationOf } from '../reservation';
import type {
  Address,
  JournalPort,
  OrdersPort,
  PublicApi,
  TraderPort,
  TraderServices,
} from '../services';
import { DEFAULT_NUMBER_FORMAT } from '../services';

export const WALLET = 'Wa11et1111111111111111111111111111111111111' as Address;

let nextId = 0;

export function placeRecord(o: {
  market: Address;
  params: MarketParams;
  side?: 0 | 1;
  role?: 0 | 1;
  kind?: 0 | 1;
  limit?: bigint;
  quantity?: bigint;
  validFrom?: bigint;
  expiresAt?: bigint;
  state?: OrderState;
  epochs?: [bigint, ParticipationState][];
  filled?: bigint;
  fills?: OwnFill[];
  history?: OrderRecord['history'];
  evidence?: string[];
  id?: string;
  commitment?: Uint8Array;
}): OrderRecord {
  const id = o.id ?? `order-${++nextId}`;
  const epochs = new Map<bigint, Participation>(
    (o.epochs ?? []).map(([epoch, state]) => [
      epoch,
      {
        epoch,
        envelopeDigest: new Uint8Array(32).fill(7),
        submission: new Uint8Array(8),
        promise: new Uint8Array(8),
        relayAtSubmission: WALLET,
        state,
      },
    ]),
  );
  return {
    id,
    version: 1,
    market: o.market,
    body: {
      kind: 'place',
      order: {
        market: o.params.market,
        trader: new Uint8Array(32),
        nonce: 1n,
        side: o.side ?? 0,
        role: o.role ?? 0,
        kind: o.kind ?? 0,
        limit: o.kind === 1 ? 0n : (o.limit ?? 15_000n),
        quantity: o.quantity ?? 100n,
        validFrom: o.validFrom ?? 42n,
        expiresAt: o.expiresAt ?? 43n,
      },
    },
    salt: new Uint8Array(32),
    signature: new Uint8Array(64),
    commitment: o.commitment ?? new Uint8Array(32).fill(nextId % 256),
    state: o.state ?? { kind: 'working' },
    epochs,
    filled: o.filled ?? 0n,
    fills: o.fills ?? [],
    history: o.history ?? [{ atMs: 1_000 + nextId, kind: 'prepared' }],
    evidence: o.evidence ?? [],
  };
}

export interface Deferred<T> {
  promise: Promise<T>;
  resolve: (v: T) => void;
  reject: (e: unknown) => void;
}

export function deferred<T>(): Deferred<T> {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

export interface SubmitCall {
  prepared: PreparedOrder;
  signal: AbortSignal | undefined;
  step: (s: SubmitStep) => void;
  result: Deferred<OrderRecord>;
}

export interface CancelCall {
  record: OrderRecord;
  signal: AbortSignal | undefined;
  step: (s: SubmitStep) => void;
  confirmSecondPrompt: (() => Promise<boolean>) | undefined;
  result: Deferred<OrderRecord>;
}

/** An OrdersPort whose prepare is a simple model and whose submit and cancel are driven by the test. */
export class FakeOrders implements OrdersPort {
  records: OrderRecord[] = [];
  submits: SubmitCall[] = [];
  cancels: CancelCall[] = [];
  reconciles: bigint[] = [];
  contextResult: Promise<VerifiedMarketContext>;
  blockers: PreparedOrder['blockers'] = [];
  warnings: PreparedOrder['warnings'] = [];
  /** The first epoch prepare picks. Defaults to the open epoch it was told about. */
  from = 42n;
  signBudgetMs = 18_000;
  private listeners = new Set<(r: readonly OrderRecord[]) => void>();

  constructor(
    private readonly params: MarketParams,
    private readonly band: PriceBand,
    enclave: VerifiedMarketContext['enclaveLabel'] = 'simulated',
  ) {
    this.contextResult = Promise.resolve({
      enclaveLabel: enclave,
      market: { params },
    } as unknown as VerifiedMarketContext);
  }

  context(): Promise<VerifiedMarketContext> {
    return this.contextResult;
  }

  prepare(d: OrderDraft): PreparedOrder {
    const order = {
      market: this.params.market,
      trader: new Uint8Array(32),
      side: d.side,
      role: d.role,
      kind: d.kind,
      limit: d.kind === 1 ? 0n : (d.limitTick ?? 0n),
      quantity: d.quantityLots,
      validFrom: this.from,
      expiresAt: this.from + BigInt(d.lifetimeEpochs - 1),
    };
    const collateral = reservationOf(order, this.params, this.band);
    const to = order.expiresAt;
    const parkedTo = to < this.from + 6n ? to : this.from + 6n;
    return {
      draft: d,
      order,
      book: bookFor(this.params.flow, d.side, d.role) as BookId,
      epochs: { from: this.from, to, parkedTo },
      collateral: { ...collateral, shortfall: this.warnings.includes('undercapitalized') },
      feeEstimate: 12_345n,
      worstNotional: 1_500_000n,
      signBudgetMs: this.signBudgetMs,
      warnings: [...this.warnings],
      blockers: [...this.blockers],
    };
  }

  submit(
    prepared: PreparedOrder,
    o?: { signal?: AbortSignal; onStep?: (s: SubmitStep) => void },
  ): Promise<OrderRecord> {
    const call: SubmitCall = {
      prepared,
      signal: o?.signal,
      step: (s) => o?.onStep?.(s),
      result: deferred(),
    };
    this.submits.push(call);
    return call.result.promise;
  }

  cancel(
    record: OrderRecord,
    o?: {
      signal?: AbortSignal;
      onStep?: (s: SubmitStep) => void;
      confirmSecondPrompt?: () => Promise<boolean>;
    },
  ): Promise<OrderRecord> {
    const call: CancelCall = {
      record,
      signal: o?.signal,
      step: (s) => o?.onStep?.(s),
      confirmSecondPrompt: o?.confirmSecondPrompt,
      result: deferred(),
    };
    this.cancels.push(call);
    return call.result.promise;
  }

  reconcile(fromEpoch: bigint): Promise<ReconcileReport> {
    this.reconciles.push(fromEpoch);
    return Promise.resolve({ attached: 1, foreignFills: 0, outboxResent: 2, inconclusive: 0 });
  }

  subscribe(f: (records: readonly OrderRecord[]) => void): () => void {
    this.listeners.add(f);
    f(this.records);
    return () => this.listeners.delete(f);
  }

  /** Publishes new records, as the order service does after each verified event. */
  publish(records: OrderRecord[]): void {
    this.records = records;
    for (const f of [...this.listeners]) f(records);
  }
}

export class FakeJournal implements JournalPort {
  available: 'indexeddb' | 'memory' = 'indexeddb';
  persisted: boolean | 'unknown' = true;
  evidence: EvidenceRecord[] = [];
  exports: string[] = [];
  imports: { bytes: Uint8Array; passphrase: string }[] = [];
  importResult: Promise<{ imported: number; skipped: number }> = Promise.resolve({
    imported: 3,
    skipped: 1,
  });

  listEvidence(): Promise<EvidenceRecord[]> {
    return Promise.resolve(this.evidence);
  }

  exportBackup(passphrase: string): Promise<Uint8Array> {
    this.exports.push(passphrase);
    return Promise.resolve(new Uint8Array([1, 2, 3]));
  }

  importBackup(bytes: Uint8Array, passphrase: string) {
    this.imports.push({ bytes, passphrase });
    return this.importResult;
  }
}

export function traderAccount(over: Partial<TraderAccount> = {}): TraderAccount {
  return {
    address: WALLET,
    market: WALLET,
    owner: WALLET,
    base: 5_000_000_000n,
    quote: 1_000_000_000n,
    requestedBase: 0n,
    requestedQuote: 0n,
    requestEpoch: 0n,
    lastLeafEpoch: 0n,
    lastChangeSlot: 0n,
    floorEpoch: 0n,
    floorBase: 0n,
    floorQuote: 0n,
    ...over,
  };
}

export function fakeTrader(o: {
  orders?: OrdersPort | null;
  journal?: JournalPort | null;
  account?: TraderAccount | null;
}): TraderPort {
  const account = o.account === undefined ? traderAccount() : o.account;
  return {
    wallet: { address: WALLET, name: 'Test wallet' },
    orders: o.orders ?? null,
    journal: o.journal ?? null,
    account: () =>
      Promise.resolve(
        account === null
          ? null
          : ({
              value: account,
              contextSlot: 1n,
              commitment: 'confirmed',
            } as Observed<TraderAccount>),
      ),
  };
}

export class FixedClock {
  constructor(public ms: number) {}
  now(): number {
    return this.ms;
  }
}

export function services(o: {
  api: PublicApi;
  clock?: { now(): number };
  trader?: TraderPort | null;
  funds?: FundsPort | null;
  announce?: (m: string) => void;
  maskByDefault?: boolean;
  ticketShortcuts?: boolean;
  connectWallet?: () => void;
  startSession?: () => void;
}): TraderServices {
  return {
    api: o.api,
    clock: o.clock ?? new FixedClock(1_791_374_403_400),
    numberFormat: DEFAULT_NUMBER_FORMAT,
    trader: o.trader ?? null,
    funds: o.funds ?? null,
    announce: o.announce,
    maskByDefault: o.maskByDefault ?? true,
    ticketShortcuts: o.ticketShortcuts ?? false,
    connectWallet: o.connectWallet,
    startSession: o.startSession,
  };
}

/** The fixture market's params as the SDK decodes them. */
export function paramsOf(detail: MarketDetail): MarketParams {
  return detail.params;
}

/** The parameters of the sample market (SOL/USDC, dual flow). */
export function fixtureParams(over: Partial<MarketParams> = {}): MarketParams {
  return {
    market: 11329457707578538225n,
    baseLotSize: 1_000_000n,
    tickSize: 10n,
    bandHalfWidth: 32,
    maxOrderLotsLog2: 20,
    maxOrdersPerTrader: 16,
    maxBatchEnvelopes: 1024,
    maxOrderLifetime: 16,
    makerFeeBps: 1,
    takerFeeBps: 5,
    flow: 1,
    rationing: 0,
    commitmentScheme: 0,
    ...over,
  };
}

/** SOL (9 decimals) against USDC (6 decimals): tick t is t / 100 USDC. */
export const FIXTURE_UNITS = { baseDecimals: 9, quoteDecimals: 6 } as const;
